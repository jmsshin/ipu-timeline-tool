<#
.SYNOPSIS
    Collects Windows In-Place Upgrade (IPU) setup logs for manual upload to a support
    case, for use when TSS is unavailable or a TSS collection came back incomplete.

.DESCRIPTION
    Reusable reference version of the manual IPU log collection script. Captures
    hostname + collection timestamp in both the output name and an embedded manifest
    so a batch of zips from multiple VMs is never ambiguous about which machine/run
    each one came from.

    Copies, if present, the ENTIRE contents of (not just specific files, so nothing
    relevant is filtered out):
      - $WINDOWS.~BT\Sources\Panther           (downlevel/pre-reboot setup logs)
      - $WINDOWS.~BT\Sources\Rollback          (rollback logs, if the upgrade rolled back)
      - %WinDir%\Panther                       (post-reboot/online setup logs, named
                                                 "win_Panther" to match the same
                                                 convention TSS and ipu_analyze.py use)
      - %WinDir%\Logs\SetupDiag                (Microsoft's own automated verdict, if it ran)
      - %WinDir%\Logs\CBS                      (component-store servicing/corruption history)
      - %WinDir%\Logs\DISM                     (DISM engine log - driver/package migration failures)
      - %WinDir%\Logs\Mosetup                  (BlueBox.log - host/WU communication, cleanup result)

    Also writes:
      - CollectionInfo.txt  - hostname, FQDN/domain, collection timestamp (local + UTC),
                               OS version/build, case number (if provided), run-as user.
      - DiskSpace.txt       - free/total space on every local volume, plus the total size
                               of $WINDOWS.~BT (cheap, bounded - NOT a full WinSxS walk).
                               A disk-space shortfall during Pre-Finalize is one of the
                               most common IPU failure causes and is otherwise invisible
                               until someone reads thousands of setupact.log lines.
      - CollectionWarnings.txt - populated ONLY if a copy encountered errors or the
                               destination ended up with fewer files than the source
                               (e.g. a security product intercepting/quarantining files
                               mid-copy) - makes a partial/incomplete collection visible
                               up front instead of silently uploading a short zip.

    Then compresses everything into a single zip in Downloads, ready to upload.

.PARAMETER CaseNumber
    Optional support case number. Included in the output folder/zip name and the
    manifest if provided; omit it to run this ad hoc without a case.

.NOTES
    Run this in an elevated ("Run as Administrator") PowerShell window.
    Because this copies whole folders rather than a hand-picked file list, it may take
    a few minutes and produce a larger zip depending on how much is in Panther/Rollback/CBS.
#>

#Requires -RunAsAdministrator

param(
    [string]$CaseNumber = ''
)

$Hostname = $env:COMPUTERNAME
$StampLocal = Get-Date
$Stamp      = $StampLocal.ToString('yyyyMMdd-HHmmss')
$NameParts  = @('IPU_Logs', $Hostname)
if ($CaseNumber) { $NameParts += $CaseNumber }
$NameParts += $Stamp
$DestRoot   = Join-Path $env:USERPROFILE ("Downloads\" + ($NameParts -join '_'))
$ZipPath    = "$DestRoot.zip"
$Warnings   = New-Object System.Collections.Generic.List[string]

New-Item -Path $DestRoot -ItemType Directory -Force | Out-Null

function Copy-FolderWithAudit {
    <#
    Copies a folder recursively and reports (not silently swallows) any shortfall
    between what was there before the copy and what actually landed afterward - a
    security product intercepting/quarantining newly-created files mid-copy is a
    real, previously-observed failure mode, and a silent Copy-Item would hide it.
    #>
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$Label
    )
    if (-not (Test-Path -LiteralPath $Source)) { return $false }

    $srcCount = (Get-ChildItem -LiteralPath $Source -Recurse -File -ErrorAction SilentlyContinue |
        Measure-Object).Count

    $copyErrors = $null
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force `
        -ErrorAction SilentlyContinue -ErrorVariable copyErrors

    $destCount = if (Test-Path -LiteralPath $Destination) {
        (Get-ChildItem -LiteralPath $Destination -Recurse -File -ErrorAction SilentlyContinue |
            Measure-Object).Count
    } else { 0 }

    if ($copyErrors -and $copyErrors.Count -gt 0) {
        $msg = "$Label : $($copyErrors.Count) copy error(s) reported (see below). Source=$srcCount file(s), copied=$destCount file(s)."
        Write-Warning $msg
        $Warnings.Add($msg)
        foreach ($e in $copyErrors) { $Warnings.Add("  - $($e.Exception.Message)") }
    }
    elseif ($destCount -lt $srcCount) {
        $msg = "$Label : copied $destCount of $srcCount file(s) - $($srcCount - $destCount) file(s) missing with NO reported error. " +
               "This is consistent with a security product (AV/EDR) silently dropping files during the copy - " +
               "check endpoint-protection quarantine/exclusion logs for this path."
        Write-Warning $msg
        $Warnings.Add($msg)
    }
    else {
        Write-Host "  OK  : $Label ($destCount file(s))" -ForegroundColor DarkGray
    }
    return $true
}

Write-Host ""
Write-Host "Host: $Hostname   Collecting: $($StampLocal.ToString('yyyy-MM-dd HH:mm:ss zzz'))" -ForegroundColor Cyan
if ($CaseNumber) { Write-Host "Case: $CaseNumber" -ForegroundColor Cyan }
Write-Host ""

# ---- $WINDOWS.~BT normally lives at the root of the OS volume, but check every local
# drive in case it was moved or the OS disk isn't C:. ----
$BtRoots = Get-Volume |
    Where-Object { $_.DriveLetter } |
    ForEach-Object { "$($_.DriveLetter):\`$WINDOWS.~BT" } |
    Where-Object { Test-Path -LiteralPath $_ }

if (-not $BtRoots) {
    $msg = "No `$WINDOWS.~BT folder found on any drive. If it has already been cleaned up, the upgrade may need to be re-run to recapture these logs."
    Write-Warning $msg
    $Warnings.Add($msg)
}

foreach ($BtRoot in $BtRoots) {
    $DriveLetter = (Split-Path -Qualifier $BtRoot).TrimEnd(':')

    Copy-FolderWithAudit -Source (Join-Path $BtRoot 'Sources\Panther') `
        -Destination (Join-Path $DestRoot "${DriveLetter}_Panther") `
        -Label "${DriveLetter}: downlevel Panther (pre-reboot setup logs)" | Out-Null

    Copy-FolderWithAudit -Source (Join-Path $BtRoot 'Sources\Rollback') `
        -Destination (Join-Path $DestRoot "${DriveLetter}_Rollback") `
        -Label "${DriveLetter}: Rollback logs" | Out-Null
}

# ---- Post-reboot / online setup logs (only present if the IPU got far enough to
# reboot into the new OS). Named "win_Panther" to match the convention TSS and
# ipu_analyze.py already recognize for this location. ----
Copy-FolderWithAudit -Source (Join-Path $env:WinDir 'Panther') `
    -Destination (Join-Path $DestRoot 'win_Panther') `
    -Label 'Post-reboot (online) Panther' | Out-Null

# ---- SetupDiag may already have run automatically when the upgrade failed. ----
Copy-FolderWithAudit -Source (Join-Path $env:WinDir 'Logs\SetupDiag') `
    -Destination (Join-Path $DestRoot 'SetupDiag') `
    -Label 'SetupDiag' | Out-Null

# ---- Component-store servicing/corruption history - needed to assess whether CBS
# corruption is a contributing factor. Can occasionally be large on a heavily
# serviced box (persisted CbsPersist_*.log archives); still collected whole per the
# "don't cherry-pick, nothing relevant gets filtered out" policy, but flagged if big. ----
$CbsSrc = Join-Path $env:WinDir 'Logs\CBS'
if (Test-Path -LiteralPath $CbsSrc) {
    $cbsSizeMB = [math]::Round(((Get-ChildItem -LiteralPath $CbsSrc -Recurse -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum) / 1MB, 0)
    if ($cbsSizeMB -gt 500) {
        $msg = "CBS logs folder is ${cbsSizeMB} MB - collecting anyway, but this is larger than typical and may take a while to upload."
        Write-Warning $msg
        $Warnings.Add($msg)
    }
}
Copy-FolderWithAudit -Source $CbsSrc -Destination (Join-Path $DestRoot 'CBS') -Label 'CBS (component store)' | Out-Null

# ---- DISM engine log - needed for driver/package migration failures (e.g. the
# 0x80070003 "Process Drivers for Migration" failure class). ----
Copy-FolderWithAudit -Source (Join-Path $env:WinDir 'Logs\DISM') `
    -Destination (Join-Path $DestRoot 'DISM') `
    -Label 'DISM' | Out-Null

# ---- BlueBox.log - MoSetup host <-> Windows Update communication / cleanup result.
# Most relevant for a WU-driven upgrade; cheap to grab regardless. ----
Copy-FolderWithAudit -Source (Join-Path $env:WinDir 'Logs\Mosetup') `
    -Destination (Join-Path $DestRoot 'Mosetup') `
    -Label 'Mosetup (BlueBox.log)' | Out-Null

# ---- Disk space snapshot. A free-space shortfall during Pre-Finalize is one of the
# most common IPU failure causes and is otherwise invisible until someone reads
# thousands of setupact.log lines - this makes it visible in seconds. ----
$DiskSpaceLines = New-Object System.Collections.Generic.List[string]
$DiskSpaceLines.Add("Disk space snapshot - $($StampLocal.ToString('yyyy-MM-dd HH:mm:ss zzz'))")
$DiskSpaceLines.Add('')
Get-Volume | Where-Object { $_.DriveLetter } | Sort-Object DriveLetter | ForEach-Object {
    $sizeGB = [math]::Round($_.Size / 1GB, 1)
    $freeGB = [math]::Round($_.SizeRemaining / 1GB, 1)
    $DiskSpaceLines.Add("  $($_.DriveLetter): $freeGB GB free of $sizeGB GB total  ($($_.FileSystemLabel))")
}
$DiskSpaceLines.Add('')
foreach ($BtRoot in $BtRoots) {
    $btSizeGB = [math]::Round(((Get-ChildItem -LiteralPath $BtRoot -Recurse -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum) / 1GB, 2)
    $DiskSpaceLines.Add("  $BtRoot size: $btSizeGB GB")
}
$DiskSpaceLines -join "`r`n" | Out-File -LiteralPath (Join-Path $DestRoot 'DiskSpace.txt') -Encoding utf8

# ---- Collection manifest - hostname, timestamp, OS build, case number, who ran it. ----
$OsInfo = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
$InfoLines = @(
    "Hostname        : $Hostname"
    "FQDN            : $([System.Net.Dns]::GetHostEntry($Hostname).HostName)"
    "Case number     : $(if ($CaseNumber) { $CaseNumber } else { '(not provided)' })"
    "Collected (local): $($StampLocal.ToString('yyyy-MM-dd HH:mm:ss zzz'))"
    "Collected (UTC) : $($StampLocal.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
    "Run as          : $env:USERDOMAIN\$env:USERNAME"
    "OS version      : $($OsInfo.ProductName) (build $($OsInfo.CurrentBuildNumber).$($OsInfo.UBR))"
)
$InfoLines -join "`r`n" | Out-File -LiteralPath (Join-Path $DestRoot 'CollectionInfo.txt') -Encoding utf8

if ($Warnings.Count -gt 0) {
    $Warnings -join "`r`n" | Out-File -LiteralPath (Join-Path $DestRoot 'CollectionWarnings.txt') -Encoding utf8
}

$CollectedFiles = Get-ChildItem -Path $DestRoot -Recurse -File
if (-not $CollectedFiles) {
    Write-Warning "No log files were found to collect. Please contact your support engineer before proceeding."
    return
}

if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
Compress-Archive -Path (Join-Path $DestRoot '*') -DestinationPath $ZipPath -Force

Write-Host ""
Write-Host "Collected $($CollectedFiles.Count) file(s) from:" -ForegroundColor Cyan
$CollectedFiles | Select-Object -ExpandProperty DirectoryName -Unique | ForEach-Object { Write-Host "  $_" }
if ($Warnings.Count -gt 0) {
    Write-Host ""
    Write-Host "$($Warnings.Count) warning(s) were recorded in CollectionWarnings.txt inside the zip - review before closing out a 'logs are complete' assumption." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "Done. Please upload this single zip file to the support case:" -ForegroundColor Green
Write-Host "  $ZipPath" -ForegroundColor Green
