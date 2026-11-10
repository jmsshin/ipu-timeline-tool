#!/usr/bin/env python3
"""
ipu_analyze.py - Windows in-place upgrade (IPU) timeline analyzer.

Feeds on a TSS SetupReport (folder OR .zip OR a direct setupact.log) -- OR, with
--local, reads the IPU logs straight off their well-known locations on the machine
you run it on, no log collection step required -- and produces a self-contained HTML
report that visualizes:
  - the phase timeline (Gantt) and per-phase durations
  - the global-progress % vs time curve (with stall detection)
  - SetupDiag finalize timing telemetry (where the hours actually went)
  - the MIG "Processing File" hotspot histogram (e.g. C:\\Windows\\SystemTemp bloat)
  - the final result / cancellation and CBS component-store corruption summary

Stdlib only. Usage:
  python ipu_analyze.py <tss-folder | tss.zip | setupact.log> [-o report.html] [--json model.json]
  python ipu_analyze.py --local [-o report.html]   # analyze THIS machine directly
"""
import argparse, os, sys, re, zipfile, tempfile, shutil, glob, html, json
from datetime import datetime, timedelta

TS_RE = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),')
PROG_RE = re.compile(r'Mapped Global progress:\s*\[(\d+)%\]')
PHASE_RE = re.compile(r'Setup phase change:\s*\[(\w+)\]\s*->\s*\[(\w+)\]')
SUBPHASE_RE = re.compile(r'Setup SubPhase:\s*\[(\d+)\]')
OPTRACK_RE = re.compile(r'OPERATIONTRACK: Enqueue Operation:\s*(\d+)\|(.+?)\s*$')
OPROW_RE = re.compile(
    r'(\d+)\|(.+?)\s*\|(Yes|No)\s*\|'
    r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\|'
    r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\|'
    r'(\d{2}):(\d{2}):(\d{2})\|.*?\{([0-9A-Fa-f-]+)\}\s*$')
TELEM_RE = re.compile(r'Tracing Data \[DWORD\] -> \[(\w+)\]=\[0x([0-9A-Fa-f]+)\]')
MIG_FILE_RE = re.compile(r'Processing File:\s*(.+?)\s*$')
RESULT_RE = re.compile(r'Result = (0x[0-9A-Fa-f]+)')
# SetupHost's own post-failure diagnostic-analysis pass (ExecuteDiagnosticAnalysis) runs
# AFTER the real install outcome has already been decided and logged; it collects extra
# telemetry about the failure and can itself fail/timeout independently (e.g. 0x800705B4
# ERROR_TIMEOUT). Its Result= code is a secondary symptom, not the terminal install result,
# so it must never be allowed to overwrite the real final_code just because it is the last
# "Result = 0x..." line physically present in setuperr.log.
DIAG_ONLY_RESULT_FUNCS = ('ExecuteDiagnosticAnalysis',)
# A migration plugin's Gather callback failing is reported on two lines:
#   "Failure while calling IDiscovery->Gather for Plugin={ServerPath="X\Y.dll", ...}. Error: 0x..."
# capturing the plugin path + HRESULT pinpoints which plugin actually blocked the USMT
# gather phase, which is usually far more actionable than the generic wrapper code
# (e.g. 0x8007042B ERROR_PROCESS_ABORTED) that bubbles up from CGatherData/CDlpTask.
GATHER_PLUGIN_FAIL_RE = re.compile(
    r'Failure while calling IDiscovery->Gather for Plugin=\{ServerPath="([^"]+)".*?\}\.\s*Error:\s*(0x[0-9A-Fa-f]+)')
# a silence this long in setupact.log means the setup thread was blocked, not working
SILENT_GAP_MIN = 1800
# setupact mixes downlevel and SafeOS/WinPE sections that can run on different clocks;
# a backwards jump at least this big marks a clock change, not real elapsed time
CLOCK_SKEW_MIN = 60

# ---- known result codes (extend over time) ----
CODE_MEANINGS = {
    '0x800704C7': 'ERROR_CANCELLED (operation cancelled / manual rollback)',
    '0x800704D3': 'ERROR_OPERATION_ABORTED',
    '0x800705BB': 'ERROR_INVALID_STATE',
    '0x8007001F': 'ERROR_GEN_FAILURE (a device attached to the system is not functioning - often disk/IO or a stuck driver op)',
    '0x80070001': 'ERROR_INVALID_FUNCTION',
    '0x80070002': 'ERROR_FILE_NOT_FOUND (a file setup expected was missing)',
    '0x80070003': 'ERROR_PATH_NOT_FOUND (a path/junction setup expected was missing - often a reparse point or moved folder)',
    '0x80070070': 'ERROR_DISK_FULL (not enough disk space)',
    '0x80070522': 'ERROR_PRIVILEGE_NOT_HELD',
    '0x8007007F': 'ERROR_PROC_NOT_FOUND (migration plugin export missing - corrupt/mismatched migration DLL)',
    '0x80070005': 'ERROR_ACCESS_DENIED',
    '0x8007042B': 'ERROR_PROCESS_ABORTED (a critical migration/finalize action failed and setup gave up - look at the specific "Operation failed" / plugin Gather failure line for the real cause, this code is just the generic wrapper)',
    '0x800705B4': 'ERROR_TIMEOUT (if this is the LAST code in setuperr.log and the call is CSetupHost::ExecuteDiagnosticAnalysis, it is SetupHost\'s own post-failure diagnostic pass timing out, not the install result - check for an earlier, real failure code first)',
    '0x800f0906': 'CBS_E_DOWNLOAD_FAILURE (could not source replacement payload for store repair)',
    '0x800f0831': 'CBS_E_STORE_CORRUPTION (component store corrupt, needs source repair)',
    '0x800f081f': 'CBS_E_SOURCE_MISSING (repair source not available)',
    '0xC1900101': 'Generic rollback (usually a driver) - check the extended code',
    '0xC1900200': 'Compat: system does not meet minimum requirements',
    '0xC1900208': 'Compat: a blocking app/driver (hard compat block)',
    '0x50015':    'Extended: migration / data phase',
    '0x20017':    'Extended: SafeOS boot / driver',
    '0x30018':    'Extended: first-boot / driver install',
    '0x4000D':    'Extended: migration apply failure',
}

def code_note(code):
    if not code:
        return ''
    up = code.upper().replace('0X', '0x')
    return CODE_MEANINGS.get(up, CODE_MEANINGS.get(up.upper(), ''))

def fmt_dur(sec):
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    if h: return f"{h}h{m:02d}m"
    if m: return f"{m}m{s:02d}s"
    return f"{s}s"

def parse_ts(line):
    m = TS_RE.match(line)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return None

def detect_truncation(path, min_null_run=4096):
    """Detect a setupact.log that was exported/copied while still open (or sparse-
    truncated): a long run of NUL bytes at the very end of the file with no closing
    log content after it. This is a strong, format-agnostic signal that the CAPTURE is
    incomplete - setup may still have been running when the snapshot was taken, so
    whatever is in setuperr.log at that point is not reliably the terminal result.
    Scans backwards from EOF in chunks so a 100+ MB log costs only a few reads."""
    if not path or not os.path.exists(path):
        return None
    try:
        size = os.path.getsize(path)
        if size == 0:
            return None
        chunk = 65536
        pos = size
        last_nonzero = None
        with open(path, 'rb') as fh:
            while pos > 0 and last_nonzero is None:
                read_len = min(chunk, pos)
                pos -= read_len
                fh.seek(pos)
                buf = fh.read(read_len)
                for i in range(len(buf) - 1, -1, -1):
                    if buf[i] != 0:
                        last_nonzero = pos + i
                        break
        if last_nonzero is None:
            return None
        null_bytes = size - 1 - last_nonzero
        if null_bytes < min_null_run:
            return None
        return dict(null_bytes=null_bytes, size=size, last_nonzero_offset=last_nonzero)
    except Exception:
        return None

# --------------------------------------------------------------------------
# log discovery
# --------------------------------------------------------------------------
NEEDED = {
    'downlevel_act':  [r'~bt_Panther[\\/]setupact\.log$'],
    'downlevel_err':  [r'~bt_Panther[\\/]setuperr\.log$'],
    'online_act':     [r'win_Panther[\\/]NewOs[\\/]Panther[\\/]setupact\.log$'],
    'online_err':     [r'win_Panther[\\/]NewOs[\\/]Panther[\\/]setuperr\.log$'],
    'winpanther_act': [r'win_Panther[\\/]setupact\.log$'],
    'winre_act':      [r'WinREAgent[\\/]setupact\.log$'],
    'dpx_act':        [r'DPX[\\/]setupact\.log$'],
    'setupdiag':      [r'SetupDiag[\\/]setupdiagresults\.xml$'],
    'cbs':            [r'logs[\\/]CBS[\\/]CBS\.log$', r'CBS[\\/]CBS\.log$'],
    'bluebox':        [r'MoSetup[\\/]BlueBox\.log$'],
    'miglog':         [r'~bt_Panther[\\/]MigLog\.xml$'],
    'scanresult':     [r'~bt_Panther[\\/]ScanResult\.xml$',
                        r'win_Panther[\\/]NewOs[\\/]Panther[\\/]ScanResult\.xml$'],
}

def discover_from_folder(root):
    found = {}
    allfiles = []
    for dp, _, fns in os.walk(root):
        for fn in fns:
            allfiles.append(os.path.join(dp, fn))
    for key, pats in NEEDED.items():
        for f in allfiles:
            if any(re.search(p, f, re.IGNORECASE) for p in pats):
                # prefer the largest match (the real, most complete log)
                if key not in found or os.path.getsize(f) > os.path.getsize(found[key]):
                    found[key] = f
    return found

# --------------------------------------------------------------------------
# --local mode: read the logs straight off THIS machine, no TSS/export step
# --------------------------------------------------------------------------
# Well-known Windows Setup log locations (downlevel = pre-reboot/old-OS view, online =
# post-reboot/new-OS view). Reference: https://learn.microsoft.com/windows/deployment/upgrade/log-files
def _sysdrive():
    return os.environ.get('SystemDrive', 'C:') + os.sep

def _first_readable(*candidates):
    """Return the first candidate path that exists and can actually be opened (local
    IPU logs are sometimes locked or ACL'd to SYSTEM/Administrators)."""
    for p in candidates:
        if p and os.path.isfile(p):
            try:
                with open(p, 'rb') as fh:
                    fh.read(1)
                return p
            except OSError:
                continue
    return None

def discover_local_system(want_miglog=False):
    """Discover IPU logs directly from their well-known locations on the machine this
    is running on -- no TSS export needed. Only useful while the in-place upgrade's
    working folders still exist: $WINDOWS.~BT is removed automatically roughly 10 days
    after the upgrade finishes/rolls back, or sooner via Disk Cleanup's "Previous
    Windows installation(s)", so run --local as soon as possible after a stuck/failed
    attempt. Returns (found_dict, bt_panther_path_checked)."""
    drive = _sysdrive()
    bt = os.path.join(drive, '$WINDOWS.~BT', 'Sources', 'Panther')
    winp = os.path.join(drive, 'Windows', 'Panther')
    found = {}

    p = _first_readable(os.path.join(bt, 'setupact.log'))
    if p: found['downlevel_act'] = p
    p = _first_readable(os.path.join(bt, 'setuperr.log'))
    if p: found['downlevel_err'] = p
    p = _first_readable(os.path.join(bt, 'ScanResult.xml'))
    if p: found['scanresult'] = p
    if want_miglog:
        p = _first_readable(os.path.join(bt, 'MigLog.xml'), os.path.join(bt, 'miglog.xml'))
        if p: found['miglog'] = p
    # post-reboot / new-OS view (what Setup wrote after OOBE completed)
    p = _first_readable(os.path.join(winp, 'setupact.log'))
    if p: found['online_act'] = p
    p = _first_readable(os.path.join(winp, 'setuperr.log'))
    if p: found['online_err'] = p
    p = _first_readable(os.path.join(drive, 'Windows', 'Logs', 'CBS', 'CBS.log'))
    if p: found['cbs'] = p
    p = _first_readable(os.path.join(drive, 'Windows', 'Logs', 'Mosetup', 'BlueBox.log'))
    if p: found['bluebox'] = p
    p = _first_readable(os.path.join(bt, 'SetupDiagResults.xml'),
                         os.path.join(os.getcwd(), 'SetupDiagResults.xml'))
    if p: found['setupdiag'] = p
    return found, bt

def extract_from_zip(zpath, workdir, want_miglog=False):
    found = {}
    with zipfile.ZipFile(zpath) as z:
        for key, pats in NEEDED.items():
            if key == 'miglog' and not want_miglog:
                continue  # MigLog can be 300 MB+, only extract when requested
            best = None
            for zi in z.infolist():
                nm = zi.filename
                if any(re.search(p, nm, re.IGNORECASE) for p in pats):
                    if best is None or zi.file_size > best.file_size:
                        best = zi
            if best is not None:
                dest = os.path.join(workdir, key + '_' + os.path.basename(best.filename))
                with z.open(best) as src, open(dest, 'wb') as out:
                    shutil.copyfileobj(src, out)
                found[key] = dest
    return found

def open_text(path):
    """Open a log that may be UTF-8 or UTF-16 (BOM-sniffed), streaming, errors replaced."""
    with open(path, 'rb') as fh:
        head = fh.read(4)
    enc = 'utf-8'
    if head[:2] in (b'\xff\xfe', b'\xfe\xff'):
        enc = 'utf-16'
    return open(path, 'r', encoding=enc, errors='replace')

# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------
def _new_attempt(ts):
    return dict(begin=ts, first_ts=ts, last_ts=ts, progress=[], phase_changes=[],
                telemetry={}, mig_total=0, mig_folder={}, mig_first=None, mig_last=None,
                operations={},  # operations keyed by GUID -> dict(id,name,start,end,elapsed)
                # spans with NO log line at all -> a real hang (vs a busy plateau)
                gaps=[], clock_debt=[], prev_ts=None, prev_line=None,
                # the run stops being an upgrade here; anything after is dead time
                cancel_ts=None, session_end_ts=None)

def parse_setupact(path):
    """Single streaming pass -> list of per-attempt dicts (split on SetupHost Logging Begin)."""
    attempts = []
    cur = None
    def ensure(ts):
        nonlocal cur
        if cur is None:
            cur = _new_attempt(ts)
            attempts.append(cur)
        return cur

    with open_text(path) as fh:
        for line in fh:
            ts = parse_ts(line)
            if 'SetupHost Logging Begin' in line and ts:
                cur = _new_attempt(ts)
                attempts.append(cur)
                continue
            if ts:
                a = ensure(ts)
                if a['first_ts'] is None:
                    a['first_ts'] = ts
                if a['prev_ts'] is not None:
                    gap = (ts - a['prev_ts']).total_seconds()
                    if gap <= -CLOCK_SKEW_MIN:
                        # setupact interleaves downlevel and SafeOS/WinPE sections that can use
                        # different clocks; remember the backwards jump so the matching forward
                        # jump is not mistaken for a hang.
                        a['clock_debt'].append(-gap)
                    elif gap >= SILENT_GAP_MIN:
                        skew = next((d for d in a['clock_debt']
                                     if abs(d - gap) <= max(300, 0.1 * d)), None)
                        if skew is not None:
                            a['clock_debt'].remove(skew)
                        else:
                            a['gaps'].append(dict(secs=gap, start=a['prev_ts'], end=ts,
                                                  last_line=a['prev_line']))
                a['last_ts'] = ts
                a['prev_ts'] = ts
                a['prev_line'] = line.rstrip('\n')
            if cur is None:
                continue
            a = cur
            if ts:
                if a['cancel_ts'] is None and 'ConfirmCanceled: User cancel confirmed' in line:
                    a['cancel_ts'] = ts
                if a['session_end_ts'] is None and ('QueryEndSession' in line or 'EndSession' in line):
                    a['session_end_ts'] = ts
            m = PROG_RE.search(line)
            if m and ts:
                a['progress'].append((ts, int(m.group(1)))); continue
            m = PHASE_RE.search(line)
            if m and ts:
                a['phase_changes'].append((ts, m.group(1), m.group(2))); continue
            if '|' in line and '{' in line and ('|Yes' in line or '|No' in line):
                m = OPROW_RE.search(line)
                if m:
                    oid, name, _ex, st, en, hh, mm, ss, guid = m.groups()
                    try:
                        stt = datetime.strptime(st, '%Y-%m-%d %H:%M:%S')
                        ent = datetime.strptime(en, '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        stt = ent = None
                    elapsed = int(hh)*3600 + int(mm)*60 + int(ss)
                    prev = a['operations'].get(guid)
                    # keep the row with the largest elapsed (most complete snapshot)
                    if prev is None or elapsed >= prev['elapsed']:
                        a['operations'][guid] = dict(id=oid, name=name.strip(), start=stt, end=ent,
                                                     elapsed=elapsed, guid=guid)
                    continue
            m = TELEM_RE.search(line)
            if m:
                name = m.group(1); val = int(m.group(2), 16)
                if name.endswith('Time') and 0 < val < 2592000:
                    a['telemetry'][name] = val
                continue
            if 'Processing File:' in line:
                m = MIG_FILE_RE.search(line)
                if m:
                    a['mig_total'] += 1
                    if ts:
                        if a['mig_first'] is None: a['mig_first'] = ts
                        a['mig_last'] = ts
                    b = classify_path(m.group(1))
                    a['mig_folder'][b] = a['mig_folder'].get(b, 0) + 1
    # drop empty leading attempt if it has no ts
    attempts = [a for a in attempts if a['first_ts'] is not None]
    return attempts

def classify_path(p):
    low = p.lower().replace('/', '\\')
    # canonical display names for well-known roots
    DISP = {
        r'c:\windows\systemtemp': r'C:\Windows\SystemTemp',
        r'c:\windows\temp': r'C:\Windows\Temp',
        r'c:\windows\softwaredistribution': r'C:\Windows\SoftwareDistribution',
        r'c:\windows\winsxs': r'C:\Windows\WinSxS',
        r'c:\windows\servicing': r'C:\Windows\servicing',
        r'c:\windows\installer': r'C:\Windows\Installer',
        r'c:\windows\assembly': r'C:\Windows\assembly',
        r'c:\programdata': r'C:\ProgramData',
        r'c:\program files (x86)': r'C:\Program Files (x86)',
        r'c:\program files': r'C:\Program Files',
        r'c:\inetpub': r'C:\inetpub',
    }
    # user temp gets its own bucket, then generic user
    if low.startswith(r'c:\users'):
        if 'appdata\\local\\temp' in low:
            return r'C:\Users\*\AppData\Local\Temp'
        return r'C:\Users\*'
    for k in sorted(DISP, key=len, reverse=True):
        if low.startswith(k):
            return DISP[k]
    if low.startswith(r'c:\windows'):
        return r'C:\Windows\(other)'
    parts = [x for x in low.split('\\') if x]
    return '\\'.join(parts[:2]) if parts else '(other)'

def parse_setuperr_final(path):
    """Return final result code, tail sample, plugin-load-error count, last
    'Operation failed' line (the real failing operation), any migration-plugin Gather
    failure (which plugin DLL + HRESULT actually blocked USMT gather), and a separate
    diag_analysis result when the last Result= line is SetupHost's own post-failure
    diagnostic pass rather than the real install outcome."""
    codes = []
    tail = []
    plugin_errors = 0
    op_failed_line = None
    last_ts = None
    diag_analysis = None
    gather_fail = None
    gather_fail_count = 0
    if not path or not os.path.exists(path):
        return dict(final_code=None, tail=[], plugin_errors=0, op_failed=None,
                    final_ts=None, last_ts=None, diag_analysis=None, gather_fail=None)
    with open_text(path) as fh:
        for line in fh:
            line = line.rstrip('\n')
            if not line.strip():
                continue
            tail.append(line)
            if len(tail) > 14:
                tail.pop(0)
            ts = parse_ts(line)
            if ts:
                last_ts = ts
            m = RESULT_RE.search(line)
            if m:
                if any(fn in line for fn in DIAG_ONLY_RESULT_FUNCS):
                    diag_analysis = dict(code=m.group(1), ts=ts, line=line)
                else:
                    codes.append((m.group(1), ts))
            low = line.lower()
            # migration plugin failed to load (corrupt/mismatched migration DLL)
            if ('0x8007007f' in low or 'gle=0x7f' in low) and ('mig' in low or 'plugin' in low or 'loadlibrary' in low):
                plugin_errors += 1
            if 'operation failed:' in low:
                op_failed_line = line
            m = GATHER_PLUGIN_FAIL_RE.search(line)
            if m:
                gather_fail_count += 1
                gather_fail = dict(plugin=m.group(1), code=m.group(2), ts=ts)
    if gather_fail:
        gather_fail['count'] = gather_fail_count
    final, final_ts = codes[-1] if codes else (None, None)
    return dict(final_code=final, tail=tail, plugin_errors=plugin_errors, op_failed=op_failed_line,
                final_ts=final_ts, last_ts=last_ts, diag_analysis=diag_analysis, gather_fail=gather_fail)

def parse_setupdiag(path):
    if not path or not os.path.exists(path):
        return {}
    try:
        import xml.etree.ElementTree as ET
        with open_text(path) as fh:
            txt = fh.read()
        txt = re.sub(r'xmlns="[^"]+"', '', txt, count=1)
        root = ET.fromstring(txt)
    except Exception:
        return scrape_setupdiag(path)
    out = {}
    def find_text(tag):
        el = root.find('.//' + tag)
        return el.text.strip() if el is not None and el.text else None
    out['profile'] = find_text('ProfileName') or find_text('Name')
    # FailureDetails carries "ErrorCode = 0x..., ExCode = 0x..., Oper = ..."
    fd = find_text('FailureDetails') or ''
    m = re.search(r'ErrorCode\s*=\s*(0x[0-9A-Fa-f]+)', fd)
    if m: out['error_code'] = m.group(1)
    m = re.search(r'ExCode\s*=\s*(0x[0-9A-Fa-f]+)', fd)
    if m: out['ext_code'] = m.group(1)
    m = re.search(r'Oper\s*=\s*([^\r\n,]+)', fd)
    if m: out['oper'] = m.group(1).strip()
    out.setdefault('error_code', find_text('ErrorCode'))
    out.setdefault('ext_code', find_text('ExtendedCode'))
    # the specific failing operation / phase
    for op in root.iter('SetupOperationInfo'):
        nm = op.find('OperationName')
        cs = op.find('CompletedSuccessfully')
        if nm is not None and nm.text and (cs is None or (cs.text or '').lower() == 'false'):
            out['failing_op'] = nm.text.strip(); break
    for ph in root.iter('SetupPhaseInfo'):
        nm = ph.find('PhaseName')
        cs = ph.find('CompletedSuccessfully')
        if nm is not None and nm.text and (cs is None or (cs.text or '').lower() == 'false'):
            out['failing_phase'] = nm.text.strip(); break
    out['log_error_line'] = find_text('LogErrorLine')
    return out

def scrape_setupdiag(path):
    out = {}
    with open_text(path) as fh:
        txt = fh.read()
    for tag in ('ProfileName', 'ErrorCode', 'ExtendedCode', 'Message'):
        m = re.search(r'<%s>(.*?)</%s>' % (tag, tag), txt, re.DOTALL)
        if m:
            out[tag.lower()] = m.group(1).strip()
    return out

DEFENDER_HINT = re.compile(r'(defender|MSFT_Mp|MpSigStub|mpengine|Defender\.psd1|windows-defender)', re.IGNORECASE)
BINARY_EXT = ('.dll', '.exe', '.sys', '.mui', '.tlb', '.ocx', '.cpl')

def parse_cbs_corruption(path):
    if not path or not os.path.exists(path):
        return {}
    detected = repaired = None
    hr = None
    samples = []
    defender = 0
    binaries = 0
    with open_text(path) as fh:
        for line in fh:
            if 'Total Detected Corruption:' in line:
                m = re.search(r'Total Detected Corruption:\s*(\d+)', line)
                if m: detected = int(m.group(1))
            elif 'Total Repaired Corruption:' in line:
                m = re.search(r'Total Repaired Corruption:\s*(\d+)', line)
                if m: repaired = int(m.group(1))
            elif '0x800f0906' in line or '0x800f0831' in line or '0x800f081f' in line:
                m = re.search(r'0x800f0[0-9a-fA-F]{3}', line)
                if m: hr = m.group(0)
            elif 'CSI Payload Corrupt' in line:
                fn = line.split('\\')[-1].strip()
                low = line.lower()
                if DEFENDER_HINT.search(line):
                    defender += 1
                elif fn.lower().endswith(BINARY_EXT):
                    binaries += 1
                if fn and fn not in samples and len(samples) < 12:
                    samples.append(fn)
    if detected is None and not samples:
        return {}
    return dict(detected=detected, repaired=repaired, hr=hr, samples=samples,
                defender=defender, binaries=binaries)

# plugin-id-specific remediation for known pre-flight compat hard blocks (extend as cases arrive)
SCAN_BLOCK_GUIDANCE = {
    'ntdsupg.dll_DsUpgradeCompatibilityCheck': (
        'This VM is an Active Directory <b>domain controller</b> and AD does not yet have the target OS\'s '
        '<code>ADPREP /DOMAINPREP</code> (and likely <code>/FORESTPREP</code>) schema updates applied - setup refuses to '
        'upgrade a DC until that prerequisite is met. The customer did not follow the documented prerequisite step. Two options: '
        '(1) run <code>adprep /forestprep</code> then <code>adprep /domainprep</code> from the target media\'s '
        '<code>\\support\\adprep</code> as an Enterprise/Domain Admin, then retry the IPU; or (2) the '
        '<b>recommended/supported path</b> - stand up a <b>new DC on the target OS</b>, promote it, verify replication, then '
        '<b>demote</b> this older DC instead of upgrading it in place (see "Add a new domain controller with a newer version of '
        'Windows Server" at https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/upgrade-domain-controllers).'),
}

def parse_scan_result(path):
    """Parse a compat ScanResult.xml (CompatReport produced by the pre-flight compat
    scan) for Hard compatibility blocks - the kind that stop setup before it
    meaningfully starts (e.g. a domain controller missing ADPREP /DOMAINPREP, an
    unsigned blocking driver). This is a more authoritative, human-readable explanation
    than a generic Result= code: the compat scan itself refused to let setup proceed."""
    if not path or not os.path.exists(path):
        return {}
    try:
        import xml.etree.ElementTree as ET
        with open_text(path) as fh:
            txt = fh.read()
        txt = re.sub(r'xmlns="[^"]+"', '', txt, count=1)
        root = ET.fromstring(txt)
    except Exception:
        return {}
    blocks = []
    for tag, id_attr in (('HardwareItem', 'HardwareType'), ('Plugin', 'Id'), ('Program', 'Name')):
        for el in root.iter(tag):
            ci = el.find('CompatibilityInfo')
            if ci is None:
                continue
            btype = ci.get('BlockingType') or 'None'
            if btype == 'None':
                continue
            msg_el = el.find('Message')
            msg = msg_el.get('Text') if msg_el is not None else None
            blk_id = el.get(id_attr) or el.tag
            blocks.append(dict(id=blk_id, kind=tag, blocking_type=btype, message=msg,
                               guidance=SCAN_BLOCK_GUIDANCE.get(blk_id)))
    driver_blocks = []
    for dp in root.iter('DriverPackage'):
        if (dp.get('BlockMigration') or '').lower() == 'true':
            driver_blocks.append(dict(inf=dp.get('Inf'),
                                      signed=(dp.get('HasSignedBinaries') or '').lower() == 'true'))
    hard = [b for b in blocks if b['blocking_type'].lower() == 'hard']
    if not blocks and not driver_blocks:
        return {}
    return dict(blocks=blocks, hard_blocks=hard, driver_blocks=driver_blocks)

MIG_PLUGIN_RE = re.compile(r'ReplacementManifests[\\/]([^\\/,]+)')
MIG_DLL_RE = re.compile(r'([A-Za-z0-9_.-]+\.dll)')

def parse_miglog(path, cap=4_000_000):
    """Stream a (possibly huge) MigLog.xml -> what USMT migrated, by component.
    Aggregates MigUnits by Group/Role/Agent and counts migration-plugin actions."""
    if not path or not os.path.exists(path):
        return None
    import xml.etree.ElementTree as ET
    groups, roles, agents, plugins = {}, {}, {}, {}
    sessions = []
    total_units = 0
    try:
        ctx = ET.iterparse(path, events=("start", "end"))
        _, root = next(ctx)
        n = 0
        for ev, el in ctx:
            if ev == 'start':
                if el.tag == 'Session':
                    sessions.append((el.get('Name'), el.get('Type')))
                continue
            if el.tag == 'MigUnit':
                total_units += 1
                g = el.get('Group') or '(uncategorized)'; groups[g] = groups.get(g, 0) + 1
                r = el.get('Role') or '(uncategorized)'; roles[r] = roles.get(r, 0) + 1
                a = el.get('Agent') or '(uncategorized)'; agents[a] = agents.get(a, 0) + 1
            elif el.tag == 'Action':
                cls = el.get('Class') or ''
                m = MIG_PLUGIN_RE.search(cls) or MIG_DLL_RE.search(cls)
                if m:
                    k = m.group(1); plugins[k] = plugins.get(k, 0) + 1
            el.clear()
            n += 1
            if n % 50000 == 0:
                root.clear()
            if n > cap:
                break
    except Exception as e:
        return dict(error=str(e), sessions=sessions, groups=groups, roles=roles,
                    agents=agents, plugins=plugins, total_units=total_units)
    return dict(sessions=sessions, groups=groups, roles=roles, agents=agents,
                plugins=plugins, total_units=total_units)

def assess_corruption(corr, err, diag=None, final_code=None):
    """Judge whether CBS corruption is a likely blocker vs benign noise.
    Honest by design: only calls 'blocker' when the failure itself is a servicing/store
    error; otherwise flags real corruption as 'relevant' (worth repairing, but cannot be
    confirmed as THE blocker from logs alone). Returns (level, reason)."""
    if not corr or not corr.get('detected'):
        return None
    det = corr.get('detected') or 0
    rep = corr.get('repaired') or 0
    unrep = det - rep
    binaries = corr.get('binaries') or 0
    defender = corr.get('defender') or 0
    plugin_err = (err or {}).get('plugin_errors') or 0
    hr = corr.get('hr')
    fc = (final_code or '').upper().replace('0X', '0x')
    fop = ((diag or {}).get('failing_op') or '').lower()
    store_repair_failed = hr in ('0x800f0906', '0x800f0831', '0x800f081f')
    # 1) benign: all Defender mutable files (KB4599986 false positive)
    if det and defender >= det and binaries == 0:
        return ('noise', f'All {det} corruptions are Defender "mutable" files (a known false positive, KB4599986) - '
                         'Defender self-updating its own files. These do not block the upgrade; safe to disregard.')
    # 2) benign: fully repaired
    if det and unrep <= 0:
        return ('noise', f'All {det} detected corruptions were repaired; the store is clean. Unlikely to be the blocker.')
    # 3) real system-binary corruption, unrepaired
    if binaries > 0 and unrep > 0:
        # tie to the failure only when the failure is a servicing/store error
        servicing_failure = fc.startswith('0x800f') or ('servic' in fop or 'package' in fop or 'component' in fop)
        plug = (f' setuperr also shows {plugin_err} migration plugin load failures (gle=0x7f), which can indicate the migration '
                'is hitting the corrupt components (though these are also common benign noise, so treat as supporting, not proof).'
                if plugin_err >= 5 else '')
        repnote = f' Store self-repair failed ({hr}), so it will not fix itself online.' if store_repair_failed else ''
        if servicing_failure:
            return ('blocker', f'{unrep} unrepaired corruptions in real system binaries and the failure is a servicing/store error '
                              f'({fc or hr}) - corruption is the blocker.{repnote} Repair from a matching source and retry.')
        return ('relevant', f'{unrep} unrepaired corruptions in real system binaries (dll/exe/mui/tlb), not benign Defender files.'
                          + repnote + plug + ' Corruption of shared servicing components is a common IPU blocker, but from these '
                          'logs alone it cannot be confirmed as THE blocker here (the run failed/cancelled elsewhere). '
                          'Repair the store from a matching Windows source (DISM /RestoreHealth /Source + SFC), then re-run and '
                          'see if the failure moves - that confirms or rules it out.')
    # 4) corruption present but not in binaries and not clearly Defender
    return ('relevant', f'{det} corruption(s) detected ({unrep} unrepaired), not clearly benign. Repair the store from source and '
                        're-check whether the failure persists to rule it in or out.')

def _temp_hotspot(am):
    """Return (folder, count, pct) if one temp-like folder dominates migration."""
    if not am['mig_total']:
        return None
    top = sorted(am['mig_folder'].items(), key=lambda kv: -kv[1])[:1]
    if not top:
        return None
    k, v = top[0]
    pct = v * 100 // am['mig_total']
    if pct >= 40 and ('temp' in k.lower() or v > 20000):
        return (k, v, pct)
    return None

def build_recommendations(am, err, corr, corr_assess, diag, scan=None, incomplete=None):
    """Rule-based 'what to try next', returned as list of dicts(prio, text)."""
    recs = []
    fc = (err.get('final_code') or (diag or {}).get('error_code') or '')
    fcu = fc.upper().replace('0X', '0x') if fc else ''
    ext = (diag or {}).get('ext_code')
    failing_op = (diag or {}).get('failing_op')
    stall = am['stall']
    hang = am.get('hang')

    # -1) pre-flight compatibility HARD block (ScanResult.xml) - this is often the real
    # reason the run never got anywhere, regardless of whatever Result= code it ended on
    for b in (scan or {}).get('hard_blocks', []):
        text = f'<b>Compatibility hard block ({esc(b["id"])}):</b> ' + esc(b['message'] or '(no message text)')
        if b.get('guidance'):
            text += ' ' + b['guidance']
        else:
            text += (' This block must be resolved (or is dismissible from the Setup UI) before the upgrade can '
                     'proceed - check <code>ScanResult.xml</code> for the full plugin context.')
        recs.append(dict(prio=1, text=text))

    # -0.5) incomplete/truncated capture - no clean exit code can be trusted from this file
    if incomplete:
        recs.append(dict(prio=1, text=(
            '<b>Collect a fresh, complete log capture.</b> This <code>setupact.log</code> is truncated - it cuts off '
            f'abruptly with <b>{incomplete["null_bytes"]:,} bytes</b> of blank/null padding after the last real line - so '
            'there is no reliable terminal result in this file. Re-collect the TSS/SetupReport once the run has actually '
            'finished (or is confirmed still stuck) rather than mid-write.')))

    # -0.25) a migration plugin's Gather callback actually blocked USMT, which is almost
    # always far more actionable than the generic wrapper code (0x8007042B etc.) that
    # bubbles up from CGatherData/CDlpTask once the plugin's failure is treated as critical
    gf = err.get('gather_fail')
    if gf:
        reproducible = f' It failed the <b>same way {gf["count"]}x</b> (including after a retry), so this is deterministic, not transient.' if gf.get('count', 1) > 1 else ''
        note = code_note(gf['code'])
        text = (f'<b>The real blocker is the migration plugin <code>{esc(gf["plugin"])}</code></b>, which failed its '
                f'USMT Gather callback with <b>{esc(gf["code"])}</b>{(" (" + esc(note) + ")") if note else ""} at '
                f'{gf["ts"]:%H:%M:%S}.{reproducible} This plugin is registered as a <b>critical action</b> '
                '(<code>Migration will abort</code> on failure), so its failure - not the generic '
                f'<b>{esc(fc)}</b> wrapper code that follows it - is what actually ends the run. ')
        if 'client-license-platform' in gf['plugin'].lower() or 'clipmig' in gf['plugin'].lower():
            text += (
                'This is the <b>Client License Platform Service Migration</b> plugin (ClipSVC/app-licensing state). '
                'ACCESS_DENIED here is a known, recurring pattern that looks environmental (broken/missing '
                'permissions) rather than a Windows code regression: the usual cause is broken/missing permissions '
                'on ClipSVC\'s license store. Check and repair, then retry:<br>'
                '<code>C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\WSLicense\\</code> must be '
                'readable/writable by SYSTEM and LOCAL SERVICE - verify via Properties &gt; Security, and if broken, '
                'restore with:<br>'
                '<code>icacls "C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\WSLicense" /grant '
                '"LOCAL SERVICE":(OI)(CI)F /T</code><br>'
                'If that does not resolve it, also check the ClipSVC data store/hive '
                '(<code>%ProgramData%\\Microsoft\\Windows\\ClipSVC</code>, '
                '<code>HKLM\\SYSTEM\\CurrentControlSet\\Services\\ClipSVC</code>) for the same ACL/ownership problem, '
                'and rule out a 3rd-party AV/EDR filter driver interfering (this plugin has been seen blocked by '
                'endpoint-protection filter drivers in the wild). If this server does not need Store/app licensing, '
                'disabling the Client License Service before retry is a possible workaround, though with '
                'mixed/unconfirmed results - the ACL fix above is the more targeted first step.')
        else:
            text += ('Search <code>~bt_Panther\\setuperr.log</code> for this plugin\'s <code>ServerPath</code> to see '
                     'its full load/discover/gather sequence and what resource it could not access.')
        recs.append(dict(prio=1, text=text))
    elif err.get('op_failed'):
        recs.append(dict(prio=2, text=(
            f'The specific SP operation that failed: <code>{esc(err["op_failed"])}</code>. '
            'This is usually more actionable than the top-level result code alone.')))

    # 0) genuine hang - setup stopped logging entirely
    if hang:
        last = hang.get('last_line') or ''
        cbs_ish = any(k in last.lower() for k in
                      ('packagemigration', 'package migration', 'fod', 'cbs', 'dism', 'servicing'))
        extra = ''
        if cbs_ish:
            extra = ('The last entry is a <b>servicing/package</b> call, so the block is somewhere in the servicing '
                     'stack. <b>Do not assume a CBS/TrustedInstaller lock without proving it</b> - CBS.log and dism.log '
                     'going quiet is NOT proof, because both logs are also quiet when servicing is simply idle, and '
                     'DISM does not log the return of every API call. To tell a real block from an idle log, check '
                     'whether the <i>rest of the OS</i> was alive during the gap (System event log / Task Scheduler '
                     'events per hour). If the OS was healthy, only the setup thread was stuck and you need a live '
                     'repro: reproduce the hang, then take a user dump of <code>SetupHost.exe</code> (plus '
                     '<code>TiWorker.exe</code>/<code>TrustedInstaller.exe</code> if running) and a Process Monitor '
                     'trace to see what the blocked thread is waiting on. ')
        diag_note = err.get('diag_analysis')
        if diag_note and not cbs_ish:
            extra += (f'Note: setup did not simply go idle - it logged one more line first, <code>{esc(diag_note["line"][:160])}</code>, '
                      'which is SetupHost\'s own post-failure diagnostic-analysis pass also failing/timing out; that pass hanging '
                      'is why the log goes silent afterward, it is not a second, unrelated root cause. ')
        lead = (f'<b>Setup also froze.</b> After reporting <b>{esc(fc)}</b>, '
                if fcu else '<b>Setup did not fail - it froze.</b> ')
        recs.append(dict(prio=1, text=(
            lead + '<code>setupact.log</code> stopped logging entirely for '
            f'<b>{fmt_dur(hang["secs"])}</b> starting {hang["start"]:%Y-%m-%d %H:%M:%S} UTC, which means the setup '
            f'thread was blocked, not working. ' + extra +
            'Separately, before the next attempt make sure nothing else is servicing the box: no pending reboot, no '
            'running <code>cleanmgr</code>/DISM/SFC/Windows Update, and consider suspending the AV/EDR agent for the '
            'upgrade window - these are cheap to rule out even though none of them is proven here.')))
        if last:
            recs.append(dict(prio=2, text=(
                'Last line setup wrote before it froze: <code>' + esc(last[:200]) + '</code>. '
                'Search that string in <code>~bt_Panther\\setupact.log</code> from a healthy run to see what should '
                'have come next.')))

    # 1) temp/USMT hotspot
    hs = _temp_hotspot(am)
    if hs:
        folder, cnt, pct = hs
        saved = ''
        if stall and stall[1] > 3600:
            saved = f' This is where the ~{fmt_dur(stall[1])} at {stall[0]}% went.'
        recs.append(dict(prio=1, text=(
            f'<b>Empty <code>{esc(folder)}</code> before the next attempt</b> (keep the folder, delete its contents). '
            f'USMT migrated <b>{cnt:,}</b> files ({pct}%) from there one-by-one.{saved} '
            'Then identify the process/app generating those files so the bloat does not return: check the file '
            'owner/ACL on a few of them, and/or run Process Monitor filtered to <code>Path contains '
            + esc(folder) + '</code> on the live VM.')))

    # 2) corruption
    if corr_assess:
        level, reason = corr_assess
        if level in ('blocker', 'relevant'):
            recs.append(dict(prio=(1 if level == 'blocker' else 2), text=(
                '<b>Repair the component store from a matching source</b>, then re-run: '
                '<code>DISM /Online /Cleanup-Image /RestoreHealth /Source:wim:&lt;install.wim&gt;:1 /LimitAccess</code> then '
                '<code>sfc /scannow</code> until clean. ' + esc(reason))))
        elif level == 'noise':
            recs.append(dict(prio=3, text='<b>Disregard the CBS corruption.</b> ' + esc(reason)))

    # 3) final-code specific
    if fcu == '0x800704C7':
        recs.append(dict(prio=2, text=(
            '<b>The run was cancelled (0x800704C7), not hard-blocked.</b> Treat the slowness / the next error as the real issue, '
            'not the cancel. If it was cancelled only because it looked hung, note that it was actually progressing '
            '(see the migrated-file loop) and let a cleaned-up run complete.')))
    elif fcu in ('0x80070003', '0x80070002'):
        opnote = f' The failing operation was <b>{esc(failing_op)}</b>.' if failing_op else ''
        recs.append(dict(prio=1, text=(
            f'<b>Setup could not find an expected path/file ({fc}).</b>{opnote} This is usually a broken '
            '<b>reparse point / junction / symlink</b>, a redirected or moved profile folder, or a path the migration expected. '
            'Open <code>~bt_Panther\\setuperr.log</code> around the failure for the exact path, then inspect that path on the VM '
            '(e.g. <code>fsutil reparsepoint query</code>, check <code>C:\\Users</code> junctions and any folder redirection).')))
    elif fcu == '0x8007001F':
        recs.append(dict(prio=1, text=(
            f'<b>Device/IO failure ({fc}) while an operation was running.</b> Check disk health and IO on the VM, and look at '
            'the operation active at the stall point (see Longest operations). A single op grinding for many hours with a device '
            'error often means a bad/oversized file, a failing disk, or a stuck driver op - inspect that operation\'s target.')))
    elif fcu == '0x80070070':
        recs.append(dict(prio=1, text='<b>Free up disk space (0x80070070 = disk full)</b> and retry; IPU needs substantial free space on C:.'))
    elif fcu in ('0xC1900208', '0xC1900200'):
        recs.append(dict(prio=1, text='<b>Compatibility block.</b> Check the compat scan / ScanResult.xml for the blocking app or driver and remove/update it.'))

    # 4) stall with no clear code
    if stall and stall[1] > 3600 and not hs and fcu not in ('0x80070003', '0x80070002', '0x8007001F'):
        recs.append(dict(prio=2, text=(
            f'<b>The upgrade sat at {stall[0]}% for {fmt_dur(stall[1])}.</b> Inspect the operation active at that point '
            '(top of Longest operations) - that is where the time goes. Match its GUID/name in '
            '<code>~bt_Panther\\setupact.log</code> to see what it was doing.')))

    # 5) baseline hygiene (always)
    recs.append(dict(prio=3, text=(
        '<b>Before the next attempt:</b> take a VM snapshot/restore point, make sure the OS has the latest SSU+LCU, delete stale '
        '<code>C:\\$WINDOWS.~BT</code> / <code>C:\\$Windows.~WS</code>, and collect a fresh TSS SetupReport so this tool can '
        'confirm the blocker moved.')))

    recs.sort(key=lambda r: r['prio'])
    return recs

# --------------------------------------------------------------------------
# model building
# --------------------------------------------------------------------------
def build_phase_timeline(phase_changes, end_ts):
    rows = []
    for i, (ts, frm, to) in enumerate(phase_changes):
        start = ts
        end = phase_changes[i+1][0] if i+1 < len(phase_changes) else end_ts
        dur = (end - start).total_seconds() if end else 0
        rows.append(dict(phase=to, start=start, end=end, dur=dur))
    # merge consecutive identical phase names
    merged = []
    for r in rows:
        if merged and merged[-1]['phase'] == r['phase']:
            merged[-1]['end'] = r['end']
            merged[-1]['dur'] += r['dur']
        else:
            merged.append(r)
    return merged

def build_operations(att, attempt_end):
    """Return operations sorted by elapsed desc, plus a synthetic bar for the
    long-running op that never completed (offline apply / USMT migration)."""
    ops = [dict(o, synthetic=False) for o in att['operations'].values()]
    last_end = None
    for o in ops:
        if o.get('end') and (last_end is None or o['end'] > last_end):
            last_end = o['end']
    # the migration/offline-apply op has no completing table row when cancelled:
    # infer it from (last completed op end .. attempt end)
    if last_end and attempt_end and (attempt_end - last_end).total_seconds() > 300:
        gap = (attempt_end - last_end).total_seconds()
        # only call it USMT migration when the log actually shows MIG file processing
        name = ('Offline apply / USMT migration (did not complete)' if att.get('mig_total')
                else 'Unfinished operation after the last completed step (no further logging)')
        ops.append(dict(id='-', name=name,
                        start=last_end, end=attempt_end, elapsed=int(gap),
                        guid='synthetic', synthetic=True))
    ops = [o for o in ops if o['elapsed'] > 0]
    ops.sort(key=lambda o: -o['elapsed'])
    return ops

def svg_ops(ops, maxn=12):
    items = ops[:maxn]
    if not items:
        return '<p class="muted">No per-operation timing rows (SP operation table) in this log.</p>'
    mx = max(o['elapsed'] for o in items) or 1
    rowh, W, LBL = 26, 900, 300
    H = rowh * len(items) + 10
    out = [f'<svg viewBox="0 0 {W} {H}" class="chart">']
    for i, o in enumerate(items):
        yy = 8 + i * rowh
        bw = (o['elapsed'] / mx) * (W - LBL - 110)
        cls = 'badbar' if o.get('synthetic') else 'bar'
        nm = (o['name'][:46] + ('…' if len(o['name']) > 46 else ''))
        out.append(f'<text x="0" y="{yy+13}" class="axl2">{esc(nm)}</text>')
        out.append(f'<rect x="{LBL}" y="{yy+2}" width="{max(1,bw):.1f}" height="16" class="{cls}"/>')
        out.append(f'<text x="{LBL+bw+6:.1f}" y="{yy+14}" class="axl2">{fmt_dur(o["elapsed"])}</text>')
    out.append('</svg>')
    return ''.join(out)

def detect_stall(progress, attempt_end):
    """Largest span the % stayed put -> (pct, seconds, at_time)."""
    if not progress:
        return None
    changes = []
    for ts, p in progress:
        if not changes or changes[-1][1] != p:
            changes.append((ts, p))
    best = None
    for i, (ts, p) in enumerate(changes):
        nxt = changes[i+1][0] if i+1 < len(changes) else attempt_end
        if nxt is None:
            continue
        span = (nxt - ts).total_seconds()
        if best is None or span > best[1]:
            best = (p, span, ts)
    return best

# --------------------------------------------------------------------------
# HTML / SVG rendering
# --------------------------------------------------------------------------
def esc(s):
    return html.escape(str(s)) if s is not None else ''

def svg_progress(progress, attempt_start, attempt_end, stall):
    if not progress:
        return '<p class="muted">No "Mapped Global progress" data in this log.</p>'
    W, H, PADL, PADB, PADT, PADR = 900, 260, 46, 34, 16, 16
    total = (attempt_end - attempt_start).total_seconds() or 1
    def x(ts): return PADL + (ts - attempt_start).total_seconds() / total * (W - PADL - PADR)
    def y(p):  return PADT + (100 - p) / 100.0 * (H - PADT - PADB)
    # extend the line horizontally from the last progress point to the end of the
    # attempt so the "stuck" plateau is drawn as a continuous flat line, not blank space.
    pdata = list(progress)
    if pdata and attempt_end and pdata[-1][0] < attempt_end:
        pdata.append((attempt_end, pdata[-1][1]))
    pts = ' '.join(f"{x(ts):.1f},{y(p):.1f}" for ts, p in pdata)
    grid = []
    for gp in range(0, 101, 25):
        yy = y(gp)
        grid.append(f'<line x1="{PADL}" y1="{yy:.1f}" x2="{W-PADR}" y2="{yy:.1f}" class="grid"/>')
        grid.append(f'<text x="{PADL-6}" y="{yy+3:.1f}" class="axl" text-anchor="end">{gp}%</text>')
    # hour ticks
    hours = int(total // 3600)
    step = max(1, hours // 8)
    t = 0
    tick = []
    while t <= hours:
        xx = PADL + (t*3600)/total*(W-PADL-PADR)
        tick.append(f'<line x1="{xx:.1f}" y1="{PADT}" x2="{xx:.1f}" y2="{H-PADB}" class="grid"/>')
        tick.append(f'<text x="{xx:.1f}" y="{H-PADB+16}" class="axl" text-anchor="middle">{t}h</text>')
        t += step
    stall_band = ''
    if stall and stall[1] > 300:
        p, span, ts = stall
        x0 = x(ts); x1 = x(ts) if False else PADL + min(total,(ts-attempt_start).total_seconds()+span)/total*(W-PADL-PADR)
        stall_band = (f'<rect x="{x0:.1f}" y="{PADT}" width="{max(1,x1-x0):.1f}" height="{H-PADT-PADB}" class="stall"/>'
                      f'<text x="{(x0+x1)/2:.1f}" y="{PADT+14}" class="stalllbl" text-anchor="middle">stuck at {p}% for {fmt_dur(span)}</text>')
    return f'''<svg viewBox="0 0 {W} {H}" class="chart">
      {stall_band}{''.join(grid)}{''.join(tick)}
      <polyline points="{pts}" class="progline"/>
      <text x="{PADL}" y="12" class="cap">Global progress % vs time</text>
    </svg>'''

def svg_hbars(items, unit='', maxw=560, color='bar'):
    """items = list of (label, value, sublabel)."""
    if not items:
        return '<p class="muted">No data.</p>'
    mx = max(v for _, v, _ in items) or 1
    rowh = 26
    H = rowh * len(items) + 10
    W = 900
    LBL = 260
    out = [f'<svg viewBox="0 0 {W} {H}" class="chart">']
    for i, (lbl, val, sub) in enumerate(items):
        yy = 8 + i * rowh
        bw = (val / mx) * (W - LBL - 120)
        out.append(f'<text x="0" y="{yy+13}" class="axl2">{esc(lbl)[:42]}</text>')
        out.append(f'<rect x="{LBL}" y="{yy+2}" width="{max(1,bw):.1f}" height="16" class="{color}"/>')
        vtxt = sub if sub else (fmt_dur(val) if unit == 'dur' else f"{val:,}")
        out.append(f'<text x="{LBL+bw+6:.1f}" y="{yy+14}" class="axl2">{esc(vtxt)}</text>')
    out.append('</svg>')
    return ''.join(out)

def _time_budget(am):
    """Where the wall-clock actually went - separates real work from waiting and dead time."""
    rows = []
    h = am.get('hang')
    work_end = h['start'] if h else am['end']
    if work_end and am['start'] and work_end > am['start']:
        rows.append(('Setup actively working', (work_end - am['start']).total_seconds(),
                     f'{am["start"]:%H:%M:%S} &rarr; {work_end:%H:%M:%S}'))
    if h and am['end'] and am['end'] > h['start']:
        rows.append(('Frozen / waiting', (am['end'] - h['start']).total_seconds(),
                     f'{h["start"]:%H:%M:%S} &rarr; {am["end"]:%H:%M:%S}'))
    if am.get('trailing', 0) > 300:
        lbl = 'Dead time after cancel confirmed' if am.get('cancel_ts') else 'Dead time after the run ended'
        rows.append((lbl, am['trailing'],
                     f'{am["end"]:%H:%M:%S} &rarr; {am["log_end"]:%m-%d %H:%M:%S}'))
    if len(rows) < 2:
        return ''
    tr = ''.join(f'<tr><td>{esc(n)}</td><td class="mono"><b>{fmt_dur(s)}</b></td>'
                 f'<td class="mono small muted">{w}</td></tr>' for n, s, w in rows)
    total = sum(s for _, s, _ in rows)
    return ('<h2 style="margin-top:18px">Where the time went</h2><table class="ref">'
            '<tr><th>Bucket</th><th>Duration</th><th>Window (UTC)</th></tr>' + tr +
            f'<tr><td><b>Total log span</b></td><td class="mono"><b>{fmt_dur(total)}</b></td>'
            f'<td class="mono small muted">{am["start"]:%m-%d %H:%M:%S} &rarr; {am["log_end"]:%m-%d %H:%M:%S}</td></tr>'
            '</table><p class="note">Only the first two rows are upgrade time. Dead time after a confirmed cancel '
            '(setup sitting there until the session ends) is excluded from the headline duration, the stall, and the '
            'operation bars - counting it makes an IPU look far slower than it was.</p>')

def render_attempt_detail(am, idx, total):
    """Cards for a single attempt model."""
    parts = []
    A = '<div class="card">'; Z = '</div>'
    astart, aend = am['start'], am['end']
    hdr = ''
    if total > 1:
        hdr = f'<div class="atag">Attempt {idx+1} of {total} &mdash; {astart:%Y-%m-%d %H:%M} to {aend:%H:%M} UTC &mdash; {fmt_dur(am["dur"])}</div>'
    # progress
    if am['stall']:
        if am.get('hang'):
            h = am['hang']
            silent = fmt_dur(h.get('total_secs', h['secs']))
            plateau = (f'<p class="note">Longest plateau: <b>{am["stall"][0]}%</b> held for '
                       f'<b>{fmt_dur(am["stall"][1])}</b> starting {am["stall"][2]:%Y-%m-%d %H:%M:%S} UTC &mdash; '
                       f'and <b>setupact.log logged nothing for {silent}</b> of it (freeze began '
                       f'{h["start"]:%H:%M:%S}), so this plateau is a genuine <b>hang</b>, not slow work.</p>')
        else:
            plateau = (f'<p class="note">Longest plateau: <b>{am["stall"][0]}%</b> held for '
                       f'<b>{fmt_dur(am["stall"][1])}</b> starting {am["stall"][2]:%Y-%m-%d %H:%M:%S} UTC. '
                       f'Log activity continued through it, so setup was actively working, not hung.</p>')
    else:
        plateau = ''
    parts.append(A + hdr + '<h2>Progress vs time</h2>' +
                 svg_progress(am['progress'], astart, aend, am['stall']) + plateau + _time_budget(am) + Z)
    # phases
    if am['phase_rows']:
        items = [(r['phase'].replace('SetupPhase', ''), r['dur'], fmt_dur(r['dur'])) for r in am['phase_rows']]
        parts.append(A + '<h2>Phase durations</h2>' + svg_hbars(items, unit='dur', color='bar') +
                     '<p class="note">Phases from <code>Setup phase change: [x] -&gt; [y]</code> (downlevel portion; a cancelled IPU never reaches SafeOS/FirstBoot).</p>' + Z)
    # operations (per-op durations)
    if am['operations']:
        parts.append(A + '<h2>Longest operations (SP operation table)</h2>' + svg_ops(am['operations']) +
                     '<p class="note">Per-operation <code>Start/End/Elapsed</code> from the SP operation table. '
                     'Red = the long-running operation that had not completed when the run ended (offline apply / USMT migration), inferred from the gap after the last completed op.</p>' + Z)
    # telemetry
    if am['telemetry']:
        tl = sorted(((k, v) for k, v in am['telemetry'].items() if v and v > 0), key=lambda kv: -kv[1])
        items = [(k, v, fmt_dur(v)) for k, v in tl[:14]]
        parts.append(A + '<h2>Finalize timing telemetry (where the hours went)</h2>' +
                     svg_hbars(items, unit='dur', color='bar2') +
                     '<p class="note">From <code>CSetupDiagnostics: Tracing Data [DWORD]</code>. DriverMigrationTime dominating = USMT file migration is the bottleneck, not imaging.</p>' + Z)
    # mig histogram
    if am['mig_folder']:
        tot = am['mig_total'] or 1
        rows = sorted(am['mig_folder'].items(), key=lambda kv: -kv[1])[:12]
        items = [(k, v, f"{v:,} ({v*100//tot}%)") for k, v in rows]
        parts.append(A + '<h2>Migrated-file hotspots (MIG "Processing File")</h2>' +
                     svg_hbars(items, color='bar3') +
                     f'<p class="note">Total processed = <b>{am["mig_total"]:,}</b>. A single folder dominating (often '
                     '<code>C:\\Windows\\SystemTemp</code>) means USMT is looping millions of tiny files. '
                     'Clearing that folder before the retry is the fix. If it refills, a live process is generating them '
                     '(check file owner/ACL or run ProcMon on the folder).</p>' + Z)
    return '\n'.join(parts)

def render_compare(models, inp):
    """Comparison page across multiple TSS captures (progression of blockers)."""
    parts = []
    A = '<div class="card">'; Z = '</div>'
    parts.append(f'''<div class="hero">
      <h1>IPU Captures Comparison</h1>
      <div class="sub">{esc(inp)} &mdash; {len(models)} TSS captures, oldest to newest</div>
      <div class="verdict">Each capture below is a separate TSS SetupReport (a different attempt/day). This shows how the blocker and slowness changed as fixes were applied. Click a capture to open its full report.</div>
    </div>''')

    # comparison table
    rows = ['<tr><th>#</th><th>Capture (date)</th><th>Primary attempt</th><th>Max %</th>'
            '<th>Longest stall</th><th>Top migrated folder</th><th>Final result</th><th>Corruption</th></tr>']
    for i, m in enumerate(models):
        dt = m['report_date']
        dtxt = f"{dt:%Y-%m-%d %H:%M}" if dt else esc(m['source_label'][:24])
        link = m.get('_link')
        capcell = f"<a href='{esc(link)}'>{esc(dtxt)}</a>" if link else esc(dtxt)
        if m.get('no_ipu'):
            rows.append(f"<tr><td>{i+1}</td><td>{capcell}</td><td colspan='6' class='small'>No IPU run in this capture (image/OOBE or upgrade never started)</td></tr>")
            continue
        a = m['attempts'][m['sel_indices'][0]]
        stall = f"{a['stall'][0]}% / {fmt_dur(a['stall'][1])}" if a['stall'] else '-'
        top = sorted(a['mig_folder'].items(), key=lambda kv: -kv[1])[:1]
        topf = f"{esc(top[0][0])} ({top[0][1]:,})" if top else '-'
        fc = m['final_code']
        if not fc and m.get('incomplete'):
            fctxt = 'INCOMPLETE (truncated)'
        elif not fc and a.get('hang'):
            fctxt = 'HUNG'
        else:
            fctxt = fc or '-'
        corr = m['corruption'] or {}
        ca = m.get('corr_assess')
        corrtxt = '-'
        if corr:
            corrtxt = f"{corr.get('detected')}/{corr.get('repaired')}"
            if ca: corrtxt += f" ({ca[0]})"
        rows.append(f"<tr><td>{i+1}</td><td>{capcell}</td><td>{fmt_dur(a['dur'])}</td><td>{a['max_pct']}%</td>"
                    f"<td>{stall}</td><td class='small'>{topf}</td>"
                    f"<td class='small'><b>{esc(fctxt)}</b></td><td class='small'>{esc(corrtxt)}</td></tr>")
    parts.append(A + '<h2>Captures over time</h2><table class="ref">' + ''.join(rows) + '</table>'
                 '<p class="note">Reading across the rows shows the progression: e.g. a shrinking stall / migrated-file count '
                 'means the slowness fix is working, while a changing final result code means a new blocker surfaced.</p>' + Z)

    # progression narrative + per-capture recommendation
    for i, m in enumerate(models):
        dt = m['report_date']
        dtxt = f"{dt:%Y-%m-%d}" if dt else m['source_label'][:24]
        link = m.get('_link')
        head = f"Capture {i+1} &mdash; {esc(dtxt)}"
        if link: head = f"<a href='{esc(link)}'>{head} &rsaquo;</a>"
        if m.get('no_ipu'):
            parts.append(A + f'<h2>{head}</h2><div class="verdict">No in-place upgrade run in this capture (image/OOBE machine or the upgrade was never started).</div>' + Z)
            continue
        rec0 = m['recommendations'][0]['text'] if m['recommendations'] else ''
        parts.append(A + f'<h2>{head}</h2>'
                     f'<div class="verdict">{m["verdict"]}</div>'
                     + (f'<div class="panel"><b>Next step:</b> {rec0}</div>' if rec0 else '') + Z)

    parts.append(A + '<h2>Which logs to check (IPU cheat-sheet)</h2>' + LOGS_CARD + Z)
    parts.append(A + f'<div class="small muted">Generated {datetime.now():%Y-%m-%d %H:%M} local by ipu_analyze.py.</div>' + Z)
    return HTML_SHELL.replace('{{BODY}}', '\n'.join(parts))

def render_no_ipu(model):
    parts = []
    A = '<div class="card">'; Z = '</div>'
    parts.append(f'''<div class="hero">
      <h1>IPU Timeline Analysis</h1>
      <div class="sub">{esc(model['source_label'])}</div>
      <div class="verdict"><b>No in-place upgrade run found in this SetupReport.</b> The tool did not produce a timeline because this capture does not contain an IPU attempt.</div>
    </div>''')
    reasons = ''.join(f'<li>{r}</li>' for r in model['reasons'])
    parts.append(A + '<h2>Why</h2><ul class="reclist">' + reasons + '</ul>' + Z)
    if model['probes']:
        rows = ['<tr><th>Setup log present</th><th>Build</th><th>Date span</th><th>IPU markers</th><th>Size</th></tr>']
        LBLS = {'winpanther_act': 'win_Panther\\setupact.log (first-boot/OOBE)',
                'winre_act': 'WinREAgent\\setupact.log (WinRE servicing)',
                'dpx_act': 'DPX\\setupact.log', 'online_act': 'win_Panther\\NewOs\\...setupact.log'}
        for key, pm in model['probes']:
            span = (f"{pm['first']:%Y-%m-%d %H:%M} &rarr; {pm['last']:%Y-%m-%d %H:%M}"
                    if pm['first'] and pm['last'] else '-')
            mk = 'progress+phase' if (pm['has_progress'] and pm['has_phase']) else ('some' if (pm['has_progress'] or pm['has_phase']) else 'none')
            rows.append(f"<tr><td class='mono small'>{esc(LBLS.get(key, key))}</td><td>{esc(pm['build'] or '-')}</td>"
                        f"<td class='small'>{span}</td><td>{mk}</td><td>{pm['size']//1024:,} KB</td></tr>")
        parts.append(A + '<h2>Setup logs actually present</h2><table class="ref">' + ''.join(rows) + '</table>'
                     '<p class="note">These are the setupact logs found in the report. First-boot/OOBE logs (from image sysprep) and '
                     'WinREAgent servicing logs are <b>not</b> an in-place upgrade. A real IPU produces '
                     '<code>UpgradeSetup\\~bt_Panther\\setupact.log</code> with progress % and phase changes.</p>' + Z)
    parts.append(A + '<h2>Likely explanations</h2><ul class="reclist">'
                 '<li>The in-place upgrade was <b>never started</b> on this machine (so setup never created <code>~bt_Panther</code>).</li>'
                 '<li>This is an <b>image / golden-image or freshly-sysprepped machine</b> (hostname often contains IMG) - the setupact logs are stale OOBE logs from image creation.</li>'
                 '<li>The TSS was collected <b>before</b> launching the upgrade, or setup logs were not collected / were cleaned up.</li>'
                 '</ul>'
                 '<p class="note"><b>Next step:</b> confirm whether an IPU was actually attempted. If yes, collect a fresh TSS SetupReport '
                 '<i>after</i> the upgrade runs (so <code>~bt_Panther</code> exists); if the IPU has not started, kick it off and capture logs when it stalls/fails.</p>' + Z)
    parts.append(A + '<h2>Which logs to check (IPU cheat-sheet)</h2>' + LOGS_CARD + Z)
    parts.append(A + f'<div class="small muted">Generated {datetime.now():%Y-%m-%d %H:%M} local by ipu_analyze.py.</div>' + Z)
    return HTML_SHELL.replace('{{BODY}}', '\n'.join(parts))

def render_html(model):
    if model.get('no_ipu'):
        return render_no_ipu(model)
    m = model
    parts = []
    A = '<div class="card">'; Z = '</div>'
    attempts = m['attempts']
    sel = m['sel_indices']            # list of attempt indices to render in detail
    primary = attempts[sel[0]]        # headline attempt

    # hero (headline = primary attempt)
    if m['final_code']:
        kpi_res, kpi_lbl = esc(m['final_code']), 'final result'
    elif primary.get('hang'):
        kpi_res, kpi_lbl = 'HUNG', 'no terminal code'
    elif m.get('incomplete'):
        kpi_res, kpi_lbl = 'INCOMPLETE', 'no clean exit'
    else:
        kpi_res, kpi_lbl = 'n/a', 'final result'
    dur_lbl = 'attempt duration'
    sub_extra = ''
    if primary.get('trailing', 0) > 300:
        dur_lbl = 'upgrade window (to cancel)'
        sub_extra = (f' &mdash; plus <b>{fmt_dur(primary["trailing"])}</b> of dead time after the operator confirmed '
                     f'the cancel at {primary["cancel_ts"]:%H:%M:%S}, until the log ends at '
                     f'{primary["log_end"]:%m-%d %H:%M:%S} (not counted as upgrade time)')
    parts.append(f'''<div class="hero">
      <h1>IPU Timeline Analysis</h1>
      <div class="sub">{esc(m['source_label'])} &mdash; {len(attempts)} attempt(s) detected{sub_extra}</div>
      <div class="kpis">
        <div class="kpi"><div class="n">{fmt_dur(primary['dur'])}</div><div class="l">{dur_lbl}</div></div>
        <div class="kpi"><div class="n">{esc(len(primary['phase_rows']))}</div><div class="l">phases</div></div>
        <div class="kpi"><div class="n">{primary['mig_total']:,}</div><div class="l">files migrated (MIG)</div></div>
        <div class="kpi"><div class="n">{kpi_res}</div><div class="l">{kpi_lbl}</div></div>
      </div>
      <div class="verdict">{m['verdict']}</div>
    </div>''')

    # RECOMMENDED NEXT STEPS (prominent, right after hero)
    recs = m.get('recommendations') or []
    if recs:
        lis = []
        for r in recs:
            pcls = {1: 'p1', 2: 'p2', 3: 'p3'}.get(r['prio'], 'p3')
            plbl = {1: 'DO FIRST', 2: 'NEXT', 3: 'HYGIENE'}.get(r['prio'], '')
            lis.append(f'<li><span class="pr {pcls}">{plbl}</span> {r["text"]}</li>')
        parts.append('<div class="card recs"><h2>Recommended next steps</h2><ol class="reclist">' +
                     ''.join(lis) + '</ol></div>')

    # attempts overview table (only if >1)
    if len(attempts) > 1:
        rows = ['<tr><th>#</th><th>Window (UTC)</th><th>Duration</th><th>Max %</th><th>Longest stall</th><th>Top migrated folder</th></tr>']
        for i, a in enumerate(attempts):
            stall = f"{a['stall'][0]}% / {fmt_dur(a['stall'][1])}" if a['stall'] else '-'
            top = sorted(a['mig_folder'].items(), key=lambda kv: -kv[1])[:1]
            topf = f"{esc(top[0][0])} ({top[0][1]:,})" if top else '-'
            star = ' &starf;' if i in sel else ''
            rows.append(f"<tr><td>{i+1}{star}</td><td class='mono small'>{a['start']:%m-%d %H:%M} &rarr; {a['end']:%m-%d %H:%M}</td>"
                        f"<td>{fmt_dur(a['dur'])}</td><td>{a['max_pct']}%</td><td>{stall}</td><td class='small'>{topf}</td></tr>")
        parts.append(A + '<h2>Attempts overview</h2><table class="ref">' + ''.join(rows) + '</table>'
                     '<p class="note">&starf; = shown in detail below. Re-run with <code>--attempt N</code> or <code>--all</code> to change which attempt is detailed.</p>' + Z)

    # per-attempt detail
    for i in sel:
        parts.append(render_attempt_detail(attempts[i], i, len(attempts)))

    # MigLog: USMT migration breakdown (only when --miglog was parsed)
    mig = m.get('miglog')
    if mig:
        gitems = [(k, v, f"{v:,}") for k, v in sorted(mig['groups'].items(), key=lambda kv: -kv[1])[:10]]
        aitems = [(k, v, f"{v:,}") for k, v in sorted(mig['agents'].items(), key=lambda kv: -kv[1])[:8]]
        plug_rows = sorted(mig['plugins'].items(), key=lambda kv: -kv[1])[:20]
        prows = ''.join(f"<tr><td class='mono small'>{esc(k)}</td><td>{v:,}</td></tr>" for k, v in plug_rows)
        sess = ' &rarr; '.join(f"{esc(n)} ({esc(t)})" for n, t in (mig.get('sessions') or [])[:10])
        parts.append(A + '<h2>USMT migration breakdown (MigLog.xml)</h2>'
                     + (f'<div class="small muted" style="margin-bottom:8px">Sessions: {sess}</div>' if sess else '')
                     + f'<div class="small" style="margin-bottom:6px">Total migration units: <b>{mig["total_units"]:,}</b></div>'
                     + '<h2 style="margin-top:10px">Units by group</h2>' + svg_hbars(gitems, color='bar3')
                     + '<h2 style="margin-top:14px">Units by agent</h2>' + svg_hbars(aitems, color='bar2')
                     + '<h2 style="margin-top:14px">Migration plugins invoked (action count)</h2>'
                     + '<table class="ref"><tr><th>Plugin</th><th>Actions</th></tr>' + prows + '</table>'
                     + '<p class="note">MigUnits are the things USMT migrates (settings, app data, documents) grouped by category/agent; '
                     'the plugin list shows which migration DLLs ran (e.g. <code>iismig.dll</code> for IIS, <code>SxsMigPlugin.dll</code> for WinSxS). '
                     'A plugin with a huge action count or a group dominating hints at what the migration spent effort on.</p>' + Z)

    # Online / post-reboot phase
    online = m.get('online')
    if online and online.get('meaningful'):
        oa = online['model']
        items = [(r['phase'].replace('SetupPhase', ''), r['dur'], fmt_dur(r['dur'])) for r in oa['phase_rows']]
        if online.get('booted'):
            note = (f'From <code>win_Panther\\NewOs\\Panther\\setupact.log</code>. The IPU rebooted into the new OS and reached '
                    f'{oa["max_pct"]}% - this is the real first/second-boot (online) work.')
        else:
            note = ('From <code>win_Panther\\NewOs\\Panther\\setupact.log</code>. These are the new-OS setup phases Setup staged '
                    '<b>during the offline apply</b> (offline specialize), not a true post-reboot boot - this run failed/cancelled '
                    'in the downlevel phase and never rebooted. A real first-boot timeline (FirstBoot/SecondBoot/OOBE) appears here '
                    'when the IPU gets past the reboot.')
        parts.append(A + '<h2>Online / NewOS phase</h2>'
                     + (svg_hbars(items, unit='dur', color='bar') if items else '')
                     + f'<p class="note">{note}</p>' + Z)
    elif online is not None:
        parts.append(A + '<h2>Online / NewOS phase</h2>'
                     '<p class="note">This capture did not reach a meaningful online/NewOS phase - the IPU failed or was '
                     'cancelled during the downlevel/offline-apply portion. (This section fills in with the post-reboot '
                     'first-boot timeline for a TSS from an IPU that rebooted past FirstBoot.)</p>' + Z)

    # outcome (file-level)
    fc = m['final_code']
    if fc:
        fdetail = f'<b>{esc(fc)}</b> {esc(code_note(fc))}'
        if m.get('incomplete'):
            inc = m['incomplete']
            fdetail += (f'<br><span class="small">Note: this setupact.log is also <b>truncated</b> '
                        f'({inc["null_bytes"]:,} bytes of null padding at the end), so anything after the capture '
                        'was cut off is unknown.</span>')
    elif primary.get('hang'):
        h = primary['hang']
        fdetail = ('<b>No terminal result code</b> - setup never got far enough to fail. It froze at '
                   f'{h["start"]:%Y-%m-%d %H:%M:%S} UTC and logged nothing for '
                   f'{fmt_dur(h.get("total_secs", h["secs"]))}.')
        sc = m.get('stale_code')
        if sc:
            fdetail += (f'<br><span class="small">The last <code>Result = </code> line in setuperr.log is '
                        f'<b>{esc(sc["code"])}</b> at {sc["ts"]:%H:%M:%S}, which is <i>before</i> the freeze - it is '
                        f'an earlier non-fatal error, not the cause of the hang.</span>')
    elif m.get('incomplete'):
        inc = m['incomplete']
        fdetail = ('<b>No clean exit code</b> &mdash; this log capture is <b>incomplete/truncated</b>. '
                   f'<code>setupact.log</code> cuts off abruptly after the last real line'
                   + (f' at {inc["last_real_ts"]:%Y-%m-%d %H:%M:%S} UTC' if inc.get('last_real_ts') else '')
                   + f', followed by <b>{inc["null_bytes"]:,} bytes</b> of blank/null padding to end of file. '
                   'This is <i>not</i> evidence of a hang, cancellation, or clean completion - the file was simply cut '
                   'off mid-capture. Collect a fresh, complete TSS capture to see how this run actually ended.')
        sc = m.get('stale_code')
        if sc:
            fdetail += (f'<br><span class="small">The last <code>Result = </code> line in setuperr.log is '
                        f'<b>{esc(sc["code"])}</b> at {sc["ts"]:%H:%M:%S} - since the capture is truncated, this is '
                        'not reliable as the terminal result and is shown for reference only.</span>')
    else:
        fdetail = 'n/a'
    scan = m.get('scan') or {}
    block_html = ''
    for b in scan.get('hard_blocks', []):
        block_html += (f'<div class="panel bad"><b>Compatibility HARD BLOCK ({esc(b["id"])}):</b> '
                       + esc(b['message'] or '(no message text)')
                       + (f'<br><span class="small">{b["guidance"]}</span>' if b.get('guidance') else '')
                       + '</div>')
    for d in scan.get('driver_blocks', []):
        block_html += (f'<div class="panel warn"><b>Driver blocks migration:</b> <code>{esc(d["inf"])}</code>'
                       + (' (unsigned)' if not d.get('signed') else '') + '</div>')
    err = m.get('err') or {}
    gf = err.get('gather_fail')
    if gf:
        rep = f' &mdash; failed identically <b>{gf["count"]}x</b> (deterministic, not transient).' if gf.get('count', 1) > 1 else ''
        block_html += (f'<div class="panel bad"><b>Migration plugin Gather failure (the real blocker):</b> '
                       f'<code>{esc(gf["plugin"])}</code> failed with <b>{esc(gf["code"])}</b> '
                       f'{esc(code_note(gf["code"]))} at {gf["ts"]:%H:%M:%S}.{rep} '
                       'This plugin is a critical action, so its failure - not the generic wrapper code above - is '
                       'what actually ended the run.</div>')
    diag_an = err.get('diag_analysis')
    if diag_an:
        block_html += (f'<div class="panel warn"><b>Post-failure diagnostic pass also failed:</b> '
                       f'<code>CSetupHost::ExecuteDiagnosticAnalysis</code> returned <b>{esc(diag_an["code"])}</b> '
                       f'{esc(code_note(diag_an["code"]))}'
                       + (f' at {diag_an["ts"]:%H:%M:%S}' if diag_an.get('ts') else '')
                       + '. This runs after the real install result is already decided - it is SetupHost collecting '
                         'extra telemetry about the failure, not a second root cause, but its own failure/timeout here '
                         'is usually why setupact.log goes silent afterward.</div>')
    diag = m.get('setupdiag') or {}
    diag_line = ''
    if diag:
        parts_d = []
        if diag.get('profile'): parts_d.append('profile ' + esc(diag['profile']))
        if diag.get('ext_code'): parts_d.append('ext ' + esc(diag['ext_code']) + ' ' + esc(code_note(diag['ext_code'])))
        if diag.get('failing_op'): parts_d.append('failing op: ' + esc(diag['failing_op']))
        if diag.get('failing_phase'): parts_d.append('phase: ' + esc(diag['failing_phase']))
        if parts_d:
            diag_line = '<div class="mono small">SetupDiag: ' + ' | '.join(parts_d) + '</div>'
    corr = m.get('corruption') or {}
    corr_html = ''
    if corr:
        badge = 'bad' if (corr.get('detected') and not corr.get('repaired')) else 'warn'
        corr_html = (f'<div class="panel {badge}"><b>Component-store corruption (CBS.log):</b> '
                     f'detected {corr.get("detected")}, repaired {corr.get("repaired")}'
                     + (f', {esc(corr.get("hr"))} {esc(code_note(corr.get("hr")))}' if corr.get('hr') else '')
                     + (f'<br><span class="small">breakdown: {corr.get("binaries",0)} system binaries, {corr.get("defender",0)} Defender files</span>' if (corr.get("binaries") or corr.get("defender")) else '')
                     + '</div>')
        # blocker-vs-noise assessment
        ca = m.get('corr_assess')
        if ca:
            level, reason = ca
            lbl = {'blocker': 'LIKELY BLOCKER', 'relevant': 'LIKELY RELEVANT',
                   'noise': 'LIKELY BENIGN NOISE', 'none': ''}.get(level, '')
            lcls = {'blocker': 'bad', 'relevant': 'warn', 'noise': 'ok'}.get(level, 'warn')
            corr_html += (f'<div class="panel {lcls}"><b>Corruption assessment: {lbl}.</b> ' + esc(reason) + '</div>')
        if corr.get('samples'):
            corr_html += '<div class="mono small">corrupt files: ' + esc(', '.join(corr['samples'][:10])) + '</div>'
    tail_html = ''
    if m.get('err_tail'):
        tail_html = '<details><summary>setuperr.log tail</summary><pre class="log">' + \
                    esc('\n'.join(m['err_tail'])) + '</pre></details>'
    parts.append(A + '<h2>Outcome</h2>' +
                 f'<div class="panel">Final result: {fdetail}</div>' + block_html + diag_line + corr_html + tail_html + Z)

    # which logs card
    parts.append(A + '<h2>Which logs to check (IPU cheat-sheet)</h2>' + LOGS_CARD + Z)

    # sources
    fu = '<br>'.join(f'{esc(k)}: <span class="mono small">{esc(v)}</span>' for k, v in m['logs_found'].items())
    parts.append(A + '<h2>Sources parsed</h2><div class="small">' + fu + '</div>' +
                 f'<div class="small muted" style="margin-top:8px">Generated {datetime.now():%Y-%m-%d %H:%M} local by ipu_analyze.py. Times shown are raw log timestamps (Azure IPU logs are UTC).</div>' + Z)

    return HTML_SHELL.replace('{{BODY}}', '\n'.join(parts))

LOGS_CARD = '''<table class="ref">
<tr><th>Log</th><th>Path (under Setup_Report)</th><th>What it tells you</th></tr>
<tr><td>Downlevel setupact</td><td class="mono">UpgradeSetup\\~bt_Panther\\setupact.log</td><td>Main timeline: phases, progress %, MIG file migration, finalize telemetry. Biggest/most useful log.</td></tr>
<tr><td>Downlevel setuperr</td><td class="mono">UpgradeSetup\\~bt_Panther\\setuperr.log</td><td>Error chain + final result code (0x800704C7 cancel, 0x8007007f plugin, etc.).</td></tr>
<tr><td>Online setupact</td><td class="mono">UpgradeSetup\\win_Panther\\NewOs\\Panther\\setupact.log</td><td>First/second-boot (online) phase - only present if the IPU rebooted into the new OS.</td></tr>
<tr><td>SetupDiag</td><td class="mono">logs\\SetupDiag\\setupdiagresults.xml</td><td>Microsoft's own verdict: failure profile, error + extended code, failing operation.</td></tr>
<tr><td>BlueBox</td><td class="mono">logs\\MoSetup\\BlueBox.log</td><td>MoSetup host result + cleanup; terminal wWinMain error code.</td></tr>
<tr><td>CBS</td><td class="mono">logs\\CBS\\CBS.log</td><td>Component-store corruption (CSI Payload Corrupt, Total Detected/Repaired, 0x800f0906).</td></tr>
<tr><td>MigLog</td><td class="mono">UpgradeSetup\\~bt_Panther\\MigLog.xml</td><td>Full USMT migration inventory (large) - what got gathered/applied.</td></tr>
<tr><td>ScanResult</td><td class="mono">UpgradeSetup\\~bt_Panther\\ScanResult.xml</td><td>Pre-flight compat scan verdict per hardware/plugin/program (BlockingType=Hard/None + Message) - e.g. a domain controller missing ADPREP /DOMAINPREP.</td></tr>
</table>
<p class="note"><b>Reading the phases:</b> Downlevel (running OS) &rarr; SafeOS/WinPE (offline apply) &rarr; FirstBoot &rarr; SecondBoot &rarr; OOBE. Progress 0-~90% is downlevel+offline apply; a stall at ~88-90% is almost always the offline apply / USMT migration.</p>'''

HTML_SHELL = '''<!doctype html><html><head><meta charset="utf-8">
<title>IPU Timeline Analysis</title>
<style>
:root{--bg:#0f1420;--card:#171e2e;--ink:#e7ecf5;--mut:#8a97ad;--acc:#4f7cff;--acc2:#28c2a0;--acc3:#f5a623;--bad:#ff5c6c;--warn:#f5a623;--grid:#273349}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 'Segoe UI',system-ui,sans-serif;padding:24px}
.hero{background:linear-gradient(135deg,#1b2740,#141b2b);border:1px solid #26314a;border-radius:14px;padding:22px 24px;margin-bottom:18px}
h1{margin:0 0 2px;font-size:22px}
h2{font-size:15px;margin:0 0 12px;color:#cdd7ea}
.sub{color:var(--mut);font-size:13px;margin-bottom:14px}
.kpis{display:flex;gap:26px;flex-wrap:wrap;margin:8px 0 12px}
.kpi .n{font-size:24px;font-weight:700;color:#fff}
.kpi .l{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
.verdict{background:#0e1626;border-left:3px solid var(--acc);padding:10px 14px;border-radius:6px;color:#dfe7f5}
.card{background:var(--card);border:1px solid #232d44;border-radius:12px;padding:18px 20px;margin-bottom:16px}
.chart{width:100%;height:auto;display:block;margin:4px 0}
.grid{stroke:var(--grid);stroke-width:1}
.axl,.axl2{fill:var(--mut);font-size:11px}
.axl2{font-size:12px}
.cap{fill:var(--mut);font-size:11px}
.progline{fill:none;stroke:var(--acc);stroke-width:2.2}
.stall{fill:rgba(255,92,108,.12)}
.stalllbl{fill:var(--bad);font-size:11px;font-weight:600}
.bar{fill:var(--acc)} .bar2{fill:var(--acc2)} .bar3{fill:var(--acc3)} .badbar{fill:var(--bad)}
.note{color:var(--mut);font-size:12.5px;margin:10px 0 0}
.small{font-size:12px}.muted{color:var(--mut)}
.mono{font-family:Consolas,monospace}
.panel{background:#0e1626;border:1px solid #263149;border-radius:8px;padding:10px 14px;margin:8px 0}
.panel.bad{border-color:var(--bad);background:#26141a}
.panel.warn{border-color:var(--warn);background:#241f12}
.panel.ok{border-color:var(--acc2);background:#122420}
.recs{border-color:#2f57b8;background:linear-gradient(135deg,#141d33,#131a2b)}
.reclist{margin:6px 0 0;padding-left:20px}
.reclist li{margin:9px 0;color:#dfe7f5;font-size:13px}
.pr{display:inline-block;font-size:10px;font-weight:700;letter-spacing:.04em;padding:2px 7px;border-radius:10px;margin-right:8px;vertical-align:middle}
.pr.p1{background:#3a1620;color:#ff8a97;border:1px solid #ff5c6c}
.pr.p2{background:#2a2410;color:#ffcf7a;border:1px solid #f5a623}
.pr.p3{background:#16233a;color:#9db4e6;border:1px solid #3a5488}
.atag{display:inline-block;background:#0e1626;border:1px solid #2b3a58;color:#9fb2d6;font-size:12px;padding:3px 10px;border-radius:20px;margin-bottom:10px}
pre.log{background:#0b101b;border:1px solid #222c42;border-radius:8px;padding:12px;overflow:auto;font:12px/1.45 Consolas,monospace;color:#c7d2e6}
details summary{cursor:pointer;color:var(--acc);margin-top:8px}
table.ref{width:100%;border-collapse:collapse;font-size:12.5px}
table.ref th,table.ref td{border:1px solid #263149;padding:6px 9px;text-align:left;vertical-align:top}
table.ref th{background:#0e1626;color:#cdd7ea}
code{background:#0b101b;padding:1px 5px;border-radius:4px;font-family:Consolas,monospace;color:#a9c1ff}
</style></head><body>{{BODY}}</body></html>'''

# --------------------------------------------------------------------------
def build_attempt_model(att):
    log_end = att['last_ts']
    astart = att['begin'] or att['first_ts']
    # The run stops being an upgrade when the operator confirms the cancel. Anything
    # logged after that (often just a logoff/EndSession hours later) is dead time and
    # must not be counted as upgrade duration, stall, or operation elapsed.
    aend = att['cancel_ts'] or log_end
    trailing = (log_end - aend).total_seconds() if (log_end and aend and log_end > aend) else 0
    phase_rows = build_phase_timeline(att['phase_changes'], aend)
    stall = detect_stall(att['progress'], aend)
    ops = build_operations(att, aend)
    max_pct = max((p for _, p in att['progress']), default=0)
    # A stall is only a real HANG when the log itself went silent through it.
    # A flat % with continued logging = busy (e.g. USMT grinding files).
    # Report the ONSET (first long silence) - that is where the freeze started - plus
    # the total silent time across the attempt.
    hang = None
    gaps = [g for g in att['gaps'] if not aend or g['start'] < aend]
    if stall:
        s_start = stall[2]
        s_end = s_start + timedelta(seconds=stall[1])
        gaps = [g for g in gaps if not (g['end'] < s_start or g['start'] > s_end)]
    if gaps:
        onset = min(gaps, key=lambda g: g['start'])
        total = sum(g['secs'] for g in gaps)
        hang = dict(secs=onset['secs'], total_secs=total, count=len(gaps),
                    start=onset['start'], end=onset['end'], last_line=onset['last_line'])
    return dict(start=astart, end=aend, log_end=log_end, trailing=trailing,
                cancel_ts=att['cancel_ts'], session_end_ts=att['session_end_ts'],
                dur=(aend - astart).total_seconds() if astart and aend else 0,
                progress=att['progress'], phase_rows=phase_rows, stall=stall,
                hang=hang, gaps=att['gaps'],
                telemetry=att['telemetry'], operations=ops,
                mig_total=att['mig_total'], mig_folder=att['mig_folder'],
                max_pct=max_pct)

SR_DATE_RE = re.compile(r'Setup_Report-(\d{4})-(\d{2})-(\d{2})\.(\d{2})(\d{2})')

def report_date(label):
    m = SR_DATE_RE.search(label)
    if m:
        y, mo, d, hh, mm = map(int, m.groups())
        try:
            return datetime(y, mo, d, hh, mm)
        except ValueError:
            pass
    return None

def find_setup_reports(root):
    dirs = []
    for dp, dns, fns in os.walk(root):
        base = os.path.basename(dp)
        if base.startswith('Setup_Report'):
            # confirm it actually holds a Panther setupact somewhere beneath
            for dp2, _, fns2 in os.walk(dp):
                if 'setupact.log' in fns2 and 'Panther' in dp2:
                    dirs.append(dp); break
    return sorted(set(dirs))

def collect_reports(inp, workdir, want_miglog=False, local=False):
    """Return list of (label, found_logs_dict), one per Setup_Report / zip / log."""
    reps = []
    if local:
        found, bt = discover_local_system(want_miglog)
        host = os.environ.get('COMPUTERNAME', 'this-computer')
        label = f'{host} (live capture, {datetime.now():%Y-%m-%d %H:%M})'
        if not found:
            winp = os.path.join(_sysdrive(), 'Windows', 'Panther')
            print(f'[!] No IPU logs found under {bt} or {winp}.', file=sys.stderr)
            print('    These are removed automatically roughly 10 days after the upgrade '
                  'finishes or rolls back (sooner via Disk Cleanup\'s "Previous Windows '
                  'installation(s)"). Run --local again right after the next stuck/failed '
                  'attempt, or point the tool at a saved TSS export / log folder instead.',
                  file=sys.stderr)
        reps.append((label, found))
        return reps
    if os.path.isfile(inp) and inp.lower().endswith('.zip'):
        sub = os.path.join(workdir, 'z0'); os.makedirs(sub, exist_ok=True)
        reps.append((os.path.basename(inp), extract_from_zip(inp, sub, want_miglog)))
    elif os.path.isfile(inp) and inp.lower().endswith('.log'):
        found = {'downlevel_act': inp}
        sib = os.path.join(os.path.dirname(inp), 'setuperr.log')
        if os.path.exists(sib): found['downlevel_err'] = sib
        reps.append((os.path.basename(os.path.dirname(inp)) or inp, found))
    elif os.path.isdir(inp):
        srdirs = find_setup_reports(inp)
        if len(srdirs) <= 1:
            found = discover_from_folder(srdirs[0] if srdirs else inp)
            if found:
                lbl = os.path.basename(srdirs[0]) if srdirs else os.path.basename(os.path.normpath(inp))
                reps.append((lbl, found))
        else:
            for d in srdirs:
                found = discover_from_folder(d)
                if found:
                    reps.append((os.path.basename(d), found))
    return reps

def probe_setupact_meta(path, max_lines=4000):
    """Cheap scan of a setupact log: date span, build, and whether it has IPU markers.
    Used to explain a SetupReport that contains no actual in-place upgrade run."""
    if not path or not os.path.exists(path):
        return None
    first = last = build = None
    has_prog = has_phase = False
    n = 0
    try:
        with open_text(path) as fh:
            for line in fh:
                ts = parse_ts(line)
                if ts:
                    if first is None: first = ts
                    last = ts
                if build is None:
                    mb = re.search(r'Build version is ([\d.]+)', line)
                    if mb: build = mb.group(1)
                if not has_prog and 'Mapped Global progress' in line: has_prog = True
                if not has_phase and 'Setup phase change' in line: has_phase = True
                n += 1
                if n >= max_lines and build is not None:
                    break
    except Exception:
        pass
    # for the tail timestamp, cheaply read the end
    try:
        tail = ''
        with open(path, 'rb') as fh:
            fh.seek(max(0, os.path.getsize(path) - 8192)); tail = fh.read().decode('utf-8', 'replace')
        for line in reversed(tail.splitlines()):
            t = parse_ts(line)
            if t: last = t; break
    except Exception:
        pass
    return dict(path=path, first=first, last=last, build=build,
                has_progress=has_prog, has_phase=has_phase,
                size=os.path.getsize(path))

def parse_online_phase(found):
    """Light online/post-reboot summary from win_Panther\\NewOs setupact. Distinguishes
    the offline-applied NewOS specialize (present even for downlevel-cancelled runs) from a
    true post-reboot first boot (phases FirstBoot/SecondBoot/OOBE)."""
    op = found.get('online_act')
    if not op or not os.path.exists(op):
        return None
    atts = parse_setupact(op)
    if not atts:
        return None
    a = build_attempt_model(atts[-1])
    phase_names = ' '.join(r['phase'].lower() for r in a['phase_rows'])
    booted = any(k in phase_names for k in ('firstboot', 'secondboot', 'oobe'))
    meaningful = bool(a['phase_rows']) or a['max_pct'] > 0
    return dict(meaningful=meaningful, booted=booted, model=a)

def _no_ipu_model(found, label, is_local=False):
    """Build an explanatory model when a SetupReport has no in-place upgrade run."""
    probes = []
    for key in ('winpanther_act', 'winre_act', 'dpx_act', 'online_act'):
        if found.get(key):
            pm = probe_setupact_meta(found[key])
            if pm: probes.append((key, pm))
    reasons = ['No <code>~bt_Panther</code> downlevel setup logs (the working directory setup.exe creates when an IPU starts).',
               'No <code>Mapped Global progress</code> or <code>Setup phase change</code> markers in any setupact log.']
    if is_local:
        reasons.append('Running with <code>--local</code>: these logs are deleted automatically roughly 10 days '
                        'after the upgrade finishes or rolls back (sooner via Disk Cleanup\'s "Previous Windows '
                        'installation(s)"). If the stuck/failed attempt on this machine was more than a few days '
                        'ago, they may simply be gone already - run <code>--local</code> again right after the '
                        '<em>next</em> attempt, or analyze a saved TSS export / log folder instead.')
    return dict(source_label=label, logs_found=found, no_ipu=True, reasons=reasons,
                probes=probes, report_date=report_date(label))

def analyze_report(found, label, attempt_sel=None, show_all=False, want_miglog=False, is_local=False):
    """Parse one report's logs and return a full render model (no IO)."""
    act_path = found.get('downlevel_act') or found.get('online_act')
    raw_attempts = parse_setupact(act_path) if act_path else []
    attempts = [build_attempt_model(a) for a in raw_attempts]
    # Detect "no IPU run": no primary downlevel/online log, or logs have no IPU markers.
    has_ipu = any(a['progress'] or a['phase_rows'] or a['mig_total'] for a in attempts)
    if not has_ipu:
        return _no_ipu_model(found, label, is_local)
    if show_all:
        sel = list(range(len(attempts)))
    elif attempt_sel is not None and 1 <= attempt_sel <= len(attempts):
        sel = [attempt_sel - 1]
    else:
        sel = [len(attempts) - 1]
    err = parse_setuperr_final(found.get('downlevel_err') or found.get('online_err'))
    diag = parse_setupdiag(found.get('setupdiag'))
    corr = parse_cbs_corruption(found.get('cbs'))
    scan = parse_scan_result(found.get('scanresult'))
    primary = attempts[sel[0]]
    # A setupact.log that was exported/copied mid-write ends with a run of NUL-byte
    # padding instead of a clean final line. That means the CAPTURE is incomplete - the
    # run may still have been going when the snapshot was taken - so no Result= code
    # found in this capture can be trusted as the terminal outcome, hang or not.
    trunc = detect_truncation(act_path)
    incomplete = None
    if trunc:
        incomplete = dict(null_bytes=trunc['null_bytes'], size=trunc['size'],
                          last_real_ts=primary.get('log_end') or primary.get('end'))
    # A setuperr Result= code is only the TERMINAL result if (a) the capture is complete
    # and (b) it was logged at/after the point the run froze. An early code (e.g. a
    # Dynamic Update payload 404) that predates a multi-hour hang - or ANY code pulled
    # from a truncated capture - is not reliably what killed the run; do not present it
    # as the final result.
    stale_code = None
    if err.get('final_code') and not (diag or {}).get('error_code'):
        if incomplete:
            stale_code = dict(code=err['final_code'], ts=err.get('final_ts'), reason='truncated')
            err = dict(err, final_code=None)
        else:
            ets = err.get('final_ts')
            cutoff = None
            if primary.get('hang'):
                cutoff = primary['hang']['start']
            elif primary.get('stall') and primary['stall'][1] > 3600:
                cutoff = primary['stall'][2]
            if ets and cutoff and ets < cutoff:
                # Don't suppress a code that is actually the trigger for the freeze: if
                # SetupHost's own post-failure diagnostic-analysis pass logged its result
                # between this code and the hang, the hang IS that diagnostic pass getting
                # stuck right after the real failure - same cascade, not an early/unrelated
                # code. Likewise, a code within a few minutes of the freeze is far more
                # likely its direct cause than a true stale/predates-the-freeze code (which,
                # per the original Dynamic-Update case this guard was built for, sits hours
                # before an unrelated later hang).
                diag_an = err.get('diag_analysis')
                cascade = bool(diag_an and diag_an.get('ts') and ets <= diag_an['ts'] <= cutoff)
                if not cascade and (cutoff - ets).total_seconds() > 300:
                    stale_code = dict(code=err['final_code'], ts=ets, reason='hang')
                    err = dict(err, final_code=None)
    final_code = err.get('final_code') or (diag or {}).get('error_code')
    corr_assess = assess_corruption(corr, err, diag, final_code)
    recs = build_recommendations(primary, err, corr, corr_assess, diag, scan, incomplete)
    verdict = build_verdict(primary, err, corr, diag, stale_code, scan, incomplete)
    online = parse_online_phase(found)
    miglog = None
    if want_miglog and found.get('miglog'):
        print(f'    [*] parsing MigLog.xml ({os.path.getsize(found["miglog"])//(1024*1024)} MB)...')
        miglog = parse_miglog(found['miglog'])
    return dict(source_label=label, logs_found=found, attempts=attempts, sel_indices=sel,
                final_code=final_code, err=err, err_tail=err['tail'], stale_code=stale_code,
                incomplete=incomplete, scan=scan,
                setupdiag=diag, corruption=corr, corr_assess=corr_assess,
                recommendations=recs, verdict=verdict, report_date=report_date(label),
                online=online, miglog=miglog)

def _print_summary(model):
    if model.get('no_ipu'):
        print(f"\n=== {model['source_label']} ===")
        print('   NO IPU RUN FOUND: no ~bt_Panther downlevel logs, no progress/phase markers.')
        for key, pm in model.get('probes', []):
            span = f"{pm['first']:%Y-%m-%d} -> {pm['last']:%Y-%m-%d}" if pm['first'] and pm['last'] else '-'
            print(f"   present: {key} build={pm['build']} {span} markers={'yes' if (pm['has_progress'] or pm['has_phase']) else 'none'}")
        print('   -> likely an image/OOBE machine or the IPU was never started; collect a fresh TSS after the upgrade runs.')
        return
    attempts = model['attempts']; sel = model['sel_indices']; primary = attempts[sel[0]]
    err = model['err']; corr = model['corruption']
    print(f"\n=== {model['source_label']} ({len(attempts)} attempt(s), detailing #{sel[0]+1}) ===")
    for i, a in enumerate(attempts):
        mark = '*' if i in sel else ' '
        top = sorted(a['mig_folder'].items(), key=lambda x:-x[1])[:1]
        topf = f'{top[0][0]}={top[0][1]:,}' if top else '-'
        stall = f'{a["stall"][0]}%/{fmt_dur(a["stall"][1])}' if a['stall'] else '-'
        print(f' {mark}#{i+1}: {a["start"]:%m-%d %H:%M}->{a["end"]:%H:%M} {fmt_dur(a["dur"]):>7} max{a["max_pct"]}% stall {stall} | {topf}')
    if primary['operations']:
        print('   top ops: ' + ', '.join(f'{o["name"][:28]}={fmt_dur(o["elapsed"])}' for o in primary['operations'][:3]))
    if primary.get('hang'):
        h = primary['hang']
        print(f'   HUNG   : setupact silent {fmt_dur(h["secs"])} from {h["start"]:%m-%d %H:%M:%S}'
              + (f' ({fmt_dur(h["total_secs"])} total over {h["count"]} gaps)' if h.get('count', 1) > 1 else ''))
        if h.get('last_line'):
            print(f'   last   : {h["last_line"][:150]}')
    if primary.get('trailing', 0) > 300:
        print(f'   dead   : {fmt_dur(primary["trailing"])} after cancel confirmed '
              f'{primary["cancel_ts"]:%H:%M:%S} -> log end {primary["log_end"]:%m-%d %H:%M:%S} (excluded)')
    inc = model.get('incomplete')
    if inc:
        print(f'   WARN   : setupact.log is TRUNCATED/INCOMPLETE - {inc["null_bytes"]:,} bytes of null padding after '
              'the last real line. No clean exit code can be trusted from this capture.')
    for b in (model.get('scan') or {}).get('hard_blocks', []):
        print(f'   BLOCK  : compat hard block ({b["id"]}): {(b["message"] or "")[:160]}')
    gf = (model.get('err') or {}).get('gather_fail')
    if gf:
        rep = f' x{gf["count"]}' if gf.get('count', 1) > 1 else ''
        print(f'   GATHER : plugin {gf["plugin"]} failed with {gf["code"]}{rep} at {gf["ts"]:%H:%M:%S} - real blocker')
    if model['final_code']:
        print(f'   final  : {model["final_code"]} {code_note(model["final_code"])}')
    else:
        sc = model.get('stale_code')
        if sc and sc.get('reason') == 'truncated':
            extra = f' (last setuperr code {sc["code"]} at {sc["ts"]:%H:%M:%S} - unreliable, capture is truncated)'
        elif sc:
            extra = f' (last setuperr code {sc["code"]} at {sc["ts"]:%H:%M:%S} predates the freeze)'
        else:
            extra = ''
        print(f'   final  : none - no terminal result code{extra}')
    if corr: print(f'   CBS    : det {corr.get("detected")}, rep {corr.get("repaired")}, {corr.get("hr")} -> {model["corr_assess"][0] if model["corr_assess"] else "n/a"}')
    if model['recommendations']:
        print('   next   : ' + re.sub('<[^>]+>', '', model['recommendations'][0]['text'])[:120])

def analyze(inp, out_html, out_json=None, attempt_sel=None, show_all=False, want_miglog=False, local=False):
    workdir = None
    try:
        workdir = tempfile.mkdtemp(prefix='ipu_')
        reps = collect_reports(inp, workdir, want_miglog, local=local)
        if not reps:
            print('ERROR: no setupact.log / Setup_Report found under the given path.', file=sys.stderr)
            return 3
        models = []
        for label, found in reps:
            print(f'[*] report: {label}')
            m = analyze_report(found, label, attempt_sel, show_all, want_miglog, is_local=local)
            if m:
                models.append(m)
        if not models:
            print('ERROR: no parsable setup logs.', file=sys.stderr)
            return 4

        if len(models) == 1:
            with open(out_html, 'w', encoding='utf-8') as f:
                f.write(render_html(models[0]))
            print(f'[+] report: {out_html}')
            _print_summary(models[0])
        else:
            # multi-capture: sort by date, write per-report files + a comparison page
            models.sort(key=lambda m: m['report_date'] or datetime.min)
            outdir = os.path.dirname(os.path.abspath(out_html))
            base = os.path.splitext(os.path.basename(out_html))[0]
            links = []
            for i, m in enumerate(models):
                fn = f'{base}_{i+1}_{re.sub(r"[^0-9A-Za-z._-]","_", m["source_label"])[:40]}.html'
                with open(os.path.join(outdir, fn), 'w', encoding='utf-8') as f:
                    f.write(render_html(m))
                m['_link'] = fn
                links.append(fn)
                _print_summary(m)
            with open(out_html, 'w', encoding='utf-8') as f:
                f.write(render_compare(models, inp))
            print(f'\n[+] comparison: {out_html}')
            print(f'[+] {len(models)} per-capture reports: ' + ', '.join(links))

        if out_json:
            jm = [dict(label=m['source_label'], date=str(m['report_date']), final=m.get('final_code'),
                       incomplete=m.get('incomplete'), hard_blocks=(m.get('scan') or {}).get('hard_blocks'),
                       gather_fail=(m.get('err') or {}).get('gather_fail'), corr=m.get('corruption'),
                       recs=[r['text'] for r in m.get('recommendations', [])]) for m in models]
            with open(out_json, 'w', encoding='utf-8') as f:
                json.dump(jm, f, indent=2, default=str)
            print(f'[+] json:   {out_json}')
        return 0
    finally:
        if workdir and os.path.isdir(workdir):
            shutil.rmtree(workdir, ignore_errors=True)

def build_verdict(am, err, corr, diag=None, stale_code=None, scan=None, incomplete=None):
    bits = []
    hang = am.get('hang')
    hard_blocks = (scan or {}).get('hard_blocks') or []
    if hard_blocks:
        b = hard_blocks[0]
        bits.append(f'the pre-flight compatibility scan found a <b>HARD BLOCK</b> ({esc(b["id"])}): '
                    + esc(b['message'] or '(no message text)'))
    gf = err.get('gather_fail')
    if gf:
        rep = f' ({gf["count"]}x, deterministic)' if gf.get('count', 1) > 1 else ''
        bits.append(f'the migration plugin <b>{esc(gf["plugin"])}</b> failed its USMT Gather callback with '
                    f'<b>{esc(gf["code"])}</b>{rep} - this is the real blocker, not just the wrapper code below')
    if hang:
        extra_total = ''
        if hang.get('count', 1) > 1:
            extra_total = (f' (in total it logged nothing for <b>{fmt_dur(hang["total_secs"])}</b> '
                           f'across {hang["count"]} silent stretches)')
        bits.append(f'setupact.log went <b>completely silent for {fmt_dur(hang["secs"])}</b> '
                    f'from {hang["start"]:%Y-%m-%d %H:%M:%S} UTC{extra_total}')
    if am['stall'] and am['stall'][1] > 1800:
        bits.append(f'progress sat at <b>{am["stall"][0]}%</b> for <b>{fmt_dur(am["stall"][1])}</b>')
    top = sorted(am['mig_folder'].items(), key=lambda x:-x[1])[:1]
    if top and am['mig_total']:
        k, v = top[0]
        pct = v*100//(am['mig_total'] or 1)
        if pct >= 40:
            bits.append(f'migration was looping <b>{v:,}</b> files ({pct}%) under <b>{esc(k)}</b>')
    if am['operations'] and not hang:
        o = am['operations'][0]
        if o['elapsed'] > 3600:
            bits.append(f'longest operation <b>{esc(o["name"][:44])} = {fmt_dur(o["elapsed"])}</b>')
    fc = err.get('final_code') or (diag or {}).get('error_code')
    fop = (diag or {}).get('failing_op')
    if fc:
        note = code_note(fc)
        if fc.upper() in ('0X800704C7', '0X800704D3') and hard_blocks:
            bits.append(f'ended with <b>{fc}</b> {esc(note)} - the operator/engineer backed out after hitting the hard block above')
        elif fc.upper() == '0X800704C7':
            bits.append('ended in <b>ERROR_CANCELLED</b> (cancelled while migration was still running - a symptom of cancellation, not a hard block)')
        elif note:
            bits.append(f'failed with <b>{fc}</b> {esc(note)}' + (f' at <b>{esc(fop)}</b>' if fop else ''))
    elif stale_code and stale_code.get('reason') == 'hang':
        bits.append(f'never produced a terminal error code (the last setuperr entry, <b>{esc(stale_code["code"])}</b> '
                    f'at {stale_code["ts"]:%H:%M:%S}, predates the freeze and is not the cause)')
    elif incomplete:
        bits.append('ended with <b>no clean exit code</b> because the log capture itself is <b>incomplete/truncated</b> '
                    f'({incomplete["null_bytes"]:,} bytes of blank/null padding after the last real line'
                    + (f' at {incomplete["last_real_ts"]:%H:%M:%S}' if incomplete.get('last_real_ts') else '')
                    + '), so the terminal outcome cannot be reliably determined from this file')
    if incomplete and fc:
        bits.append(f'(note: this setupact.log is also truncated - {incomplete["null_bytes"]:,} bytes of null padding at '
                    'the end - so anything that happened after the capture was cut off is unknown)')
    if corr and corr.get('detected') and not corr.get('repaired'):
        bits.append(f'with unrepaired store corruption ({corr.get("detected")} files, {esc(corr.get("hr") or "")})')
    if not bits:
        return 'Parsed the IPU timeline. See charts below.'
    if incomplete and not hang and not fc:
        lead = 'This capture has <b>no clean exit</b> - '
    elif hang:
        lead = 'This IPU <b>genuinely hung</b> - '
    else:
        lead = 'This IPU was <b>not hung</b> - it was '
    if hang:
        tail = '; '.join(bits) + '.'
        if hang.get('last_line'):
            tail += f'<br><span class="small">Last thing setup logged before the freeze: <code>{esc(hang["last_line"][:190])}</code></span>'
        return lead + tail
    return lead + ('; '.join(bits)) + '.'

def main():
    ap = argparse.ArgumentParser(description='Find the blocker in a Windows in-place upgrade (IPU): analyze a TSS/log export, or read this machine directly with --local.')
    ap.add_argument('input', nargs='?', default=None,
                     help='TSS folder, .zip, Setup_Report folder, or a setupact.log. Omit this when using --local.')
    ap.add_argument('--local', action='store_true',
                     help="Skip log collection entirely: read the IPU logs straight off THIS machine's "
                          "well-known locations ($WINDOWS.~BT\\Sources\\Panther, C:\\Windows\\Panther, "
                          "C:\\Windows\\Logs). Run it on the server that had the stuck/failed upgrade, ideally "
                          "right after it happens -- Windows deletes these logs ~10 days later, or sooner via "
                          "Disk Cleanup. May need an elevated (Administrator) prompt to read some of them.")
    ap.add_argument('-o', '--out', default='ipu_report.html', help='output HTML path')
    ap.add_argument('--json', dest='json_out', default=None, help='also write the parsed model as JSON')
    ap.add_argument('--attempt', type=int, default=None, help='detail this attempt number (1-based); default = last')
    ap.add_argument('--all', action='store_true', help='render detail for every attempt')
    ap.add_argument('--miglog', action='store_true', help='also parse MigLog.xml (USMT migration breakdown; can be 300 MB+, adds time)')
    a = ap.parse_args()
    if not a.local and not a.input:
        ap.error('provide INPUT (a TSS zip/folder/log), or pass --local to analyze this machine directly')
    if a.local and a.input:
        ap.error('pass either INPUT or --local, not both')
    sys.exit(analyze(a.input, a.out, a.json_out, attempt_sel=a.attempt, show_all=a.all,
                      want_miglog=a.miglog, local=a.local))

if __name__ == '__main__':
    main()

