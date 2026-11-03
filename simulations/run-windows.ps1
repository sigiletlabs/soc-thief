<#
Soc Thief detection measurement: fixed, benign attack simulations for a DISPOSABLE Windows test host.

Run in an elevated PowerShell, ON the test host only, after the operator has approved the run
(docs/DETECTION.md):
    .\run-windows.ps1 --i-am-on-the-disposable-test-host $env:COMPUTERNAME [--run-log FILE]

Built-in tools only (net, schtasks, reg, wevtutil, Windows PowerShell). Nothing is downloaded and
no address other than 127.0.0.1 is contacted. Wazuh is never touched. Every artefact is named
`soc-thief-sim` and removed in the finally block, including after a failure.

Equivalent Atomic Red Team tests (named only; the framework is not used or downloaded):
  brute_force_success          T1110.001 / T1078.003 (local account password guessing then logon)
  account_created              T1136.001-3 (net user /add), T1098 (add to Administrators)
  log_cleared                  T1070.001-1/-2 (wevtutil cl) - see the note on that scenario
  persistence                  T1547.001-1 (Run key), T1053.005-1 (scheduled task)
  suspicious_powershell_child  T1059.001 / T1059.003 (PowerShell spawning cmd.exe recon)
  eicar                        T1204.002 / AV test file (EICAR test string)

What the operator should know before approving:
  - log_cleared clears a REAL event channel. Event 104 (log cleared, written to the System log)
    is what fires rule 60117; clearing the Security log (event 1102) would destroy audit evidence
    and is not done. The default channel is Microsoft-Windows-WinRM/Operational (low value);
    override with -LogName. On a disposable host this loses that channel's history.
  - eicar: Defender will usually quarantine the file or block the write. Either is recorded as
    ok, because the attempt is the stimulus; a blocked write is still a detection test.
  - persistence touches HKLM Run and a scheduled task. Wazuh syscheck may report registry changes
    only on its next scan; run the measurement after that delay.
  - Remote management agents (RMM tools) may run PowerShell on the host: if this host is managed
    by one, its own PowerShell activity will blur the suspicious_powershell_child result.
#>
# Arguments are parsed by hand so the spelling matches run-linux.sh exactly.
$IAmOnTheDisposableTestHost = ''
$RunLog = ''
$LogName = 'Microsoft-Windows-WinRM/Operational'
for ($i = 0; $i -lt $args.Count; $i += 2) {
    $value = if ($i + 1 -lt $args.Count) { [string]$args[$i + 1] } else { '' }
    switch ([string]$args[$i]) {
        '--i-am-on-the-disposable-test-host' { $IAmOnTheDisposableTestHost = $value }
        '--run-log' { $RunLog = $value }
        '--log-name' { $LogName = $value }
        default { [Console]::Error.WriteLine('unknown argument'); exit 2 }
    }
}
function Stop-Refused($Message) { [Console]::Error.WriteLine("refusing: $Message"); exit 2 }

# Hostname guard: refuse unless the operator typed this machine's own hostname.
if ([string]::IsNullOrEmpty($IAmOnTheDisposableTestHost) -or $IAmOnTheDisposableTestHost -ne $env:COMPUTERNAME) {
    Stop-Refused "pass --i-am-on-the-disposable-test-host <this host's hostname>"
}
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Refused 'run elevated on the test host'
}
$ErrorActionPreference = 'Stop'

$Name = 'soc-thief-sim'
$BfUser = 'soc-thief-sim-bf'
$RunId = 'sim-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
if (-not $RunLog) { $RunLog = Join-Path (Get-Location) "soc-thief-sim-run-$RunId.jsonl" }
if (Test-Path $RunLog) { Stop-Refused 'run log already exists' }
foreach ($u in @($Name, $BfUser)) {
    if (Get-LocalUser -Name $u -ErrorAction SilentlyContinue) {
        Stop-Refused "a $u account already exists; the cleanup would delete it"
    }
}
$Pause = 45   # seconds between scenarios so alert windows do not overlap
$RunKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
$EicarFile = Join-Path $env:TEMP "$Name-eicar.com"
New-Item -ItemType File -Path $RunLog -Force | Out-Null

function Get-Now { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

function Write-Entry($Id, $Start, $End, $Status) {
    $line = '{{"run":"{0}","platform":"windows","scenario":"{1}","start":"{2}","end":"{3}","status":"{4}"}}' -f $RunId, $Id, $Start, $End, $Status
    Add-Content -Path $RunLog -Value $line -Encoding ascii
}

function Invoke-Scenario($Id, [scriptblock]$Body) {
    $start = Get-Now
    $status = 'ok'
    try { & $Body } catch { $status = 'failed'; Write-Warning "scenario $Id failed" }
    Write-Entry $Id $start (Get-Now) $status
    Start-Sleep -Seconds $Pause
}

function New-RandomPassword { 'Aa1!' + ([guid]::NewGuid().ToString('N')) }

function Remove-Artefacts {
    foreach ($u in @($Name, $BfUser)) {
        try { net user $u /delete 2>$null | Out-Null } catch { }
    }
    try { Remove-ItemProperty -Path $RunKey -Name $Name -ErrorAction SilentlyContinue } catch { }
    try { schtasks /delete /tn $Name /f 2>$null | Out-Null } catch { }
    try { net use "\\127.0.0.1\IPC$" /delete /y 2>$null | Out-Null } catch { }
    Remove-Item -Force -ErrorAction SilentlyContinue $EicarFile
}

try {
    # Setup before the first window, so its alerts do not read as the account_created scenario.
    $bfPassword = New-RandomPassword
    $setupOk = $true
    try { net user $BfUser $bfPassword /add | Out-Null } catch { $setupOk = $false }
    if ($LASTEXITCODE -ne 0) { $setupOk = $false }
    Start-Sleep -Seconds $Pause

    # brute_force_success: wrong network logons to 127.0.0.1 (logon type 3, so Windows records a
    # source address), then one correct logon.
    if ($setupOk) {
        Invoke-Scenario 'brute_force_success' {
            for ($i = 0; $i -lt 10; $i++) {
                net use "\\127.0.0.1\IPC$" /user:$BfUser 'wrong-password-sim' 2>$null | Out-Null
            }
            net use "\\127.0.0.1\IPC$" /user:$BfUser $bfPassword 2>$null | Out-Null
            net use "\\127.0.0.1\IPC$" /delete /y 2>$null | Out-Null
        }
    } else {
        $t = Get-Now; Write-Entry 'brute_force_success' $t $t 'skipped'
    }

    # account_created: a local admin account, then deleted.
    Invoke-Scenario 'account_created' {
        $pw = New-RandomPassword
        net user $Name $pw /add | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'net user failed' }
        net localgroup Administrators $Name /add | Out-Null
        Start-Sleep -Seconds 5
        net localgroup Administrators $Name /delete | Out-Null
        net user $Name /delete | Out-Null
    }

    # log_cleared: event 104 in System, from clearing a low-value channel (see header).
    Invoke-Scenario 'log_cleared' {
        wevtutil cl $LogName
        if ($LASTEXITCODE -ne 0) { throw 'wevtutil failed' }
    }

    # persistence: HKLM Run value and a scheduled task, both harmless and both removed.
    Invoke-Scenario 'persistence' {
        New-ItemProperty -Path $RunKey -Name $Name -Value 'cmd.exe /c exit' -PropertyType String -Force | Out-Null
        schtasks /create /tn $Name /tr 'cmd.exe /c exit' /sc onlogon /f | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'schtasks failed' }
        Start-Sleep -Seconds 30
        Remove-ItemProperty -Path $RunKey -Name $Name
        schtasks /delete /tn $Name /f | Out-Null
    }

    # suspicious_powershell_child: PowerShell starts cmd.exe, which runs discovery commands.
    Invoke-Scenario 'suspicious_powershell_child' {
        powershell.exe -NoProfile -Command "Start-Process -Wait -WindowStyle Hidden cmd.exe -ArgumentList '/c whoami /priv & net user & ipconfig /all'" | Out-Null
    }

    # eicar: the standard AV test string, built from pieces so this file is not itself flagged.
    Invoke-Scenario 'eicar' {
        $a = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$'
        $b = 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        try { Set-Content -Path $EicarFile -Value ($a + $b) -NoNewline -Encoding ascii } catch { }
        Start-Sleep -Seconds 30
    }
}
finally {
    Remove-Artefacts
}
Write-Output "run log: $RunLog"
