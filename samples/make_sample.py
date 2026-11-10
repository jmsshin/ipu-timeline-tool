#!/usr/bin/env python3
"""
make_sample.py - generates a small, fully synthetic TSS-style SetupReport folder so
you can try ipu_analyze.py immediately without a real capture.

Scenario modeled: a Server 2016 -> Server 2022 upgrade that stalls at 91% doing USMT
file migration (C:\\Windows\\SystemTemp dominates), then fails with 0x80070070
ERROR_DISK_FULL. No real hostnames, timestamps, or customer data - everything here is
made up for demonstration only.

Usage:
    python samples/make_sample.py
    python ipu_analyze.py samples/Setup_Report_sample -o samples/sample_report.html
"""
import os
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, 'Setup_Report_sample')
PANTHER = os.path.join(ROOT, '~bt_Panther')


def ts(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def build():
    os.makedirs(PANTHER, exist_ok=True)
    t0 = datetime(2026, 1, 15, 2, 0, 0)
    lines = [f'{ts(t0)}, Info                   SetupHost Logging Begin']

    # climb to 91% over ~70 minutes
    t = t0
    for pct in range(0, 92, 7):
        t = t0 + timedelta(minutes=pct)
        lines.append(f'{ts(t)}, Info            SP     Mapped Global progress: [{pct}%]')
    lines.append(f'{ts(t)}, Info            SP     Setup phase change: [Down] -> [Finalize]')

    # stall at 91%: ~2.5 hours of real, busy USMT migration work (not a hang) -
    # thousands of tiny SystemTemp files is the classic multi-hour cause
    stall_start = t
    cur = stall_start
    for i in range(500):
        cur = stall_start + timedelta(seconds=i * 2)
        lines.append(f'{ts(cur)}, Info [0x0802c6] MIG    Processing File: '
                      f'C:\\Windows\\SystemTemp\\tmp{i:05d}.tmp')
    stall_end = cur

    # final failure: ran out of disk space finishing the migration
    err_ts = stall_end + timedelta(seconds=30)
    lines.append(f'{ts(err_ts)}, Error           SP     Operation execution failed: '
                 f'13. hr = 0x80070070[gle=0x00000070]')

    with open(os.path.join(PANTHER, 'setupact.log'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    with open(os.path.join(PANTHER, 'setuperr.log'), 'w', encoding='utf-8') as f:
        f.write(f'{ts(err_ts)}, Error           SP     Result = 0x80070070\n')

    print(f'[+] wrote synthetic SetupReport to {ROOT}')
    print('    try it: python ipu_analyze.py samples/Setup_Report_sample -o samples/sample_report.html')


if __name__ == '__main__':
    build()
