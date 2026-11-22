#Requires -Version 7.2
# #1764: hosted Windows acceptance for the acknowledged upgrade flush owner.
#
# Runs on a GitHub-hosted windows-latest runner (Windows Server, admin
# rights). It starts the real x0xd under the real `x0x autostart` v2 wrapper
# with an isolated config (no seeds, no mDNS, no port mapping, no update
# check, loopback only), then checks the flush owner from outside the
# process. It does NOT run a supervised apply: there is no signed test
# release for it to download, so #1764 items 2 and 3 stay open beyond the
# wrapper restart rule checked here with a stub child.
#
# Every check is written to <Evidence>\summary.json. The script exits 1 when
# any check fails. <Work> holds the instance data root (API token, keys) and
# is never uploaded.
param(
    [Parameter(Mandatory)] [string]$X0xd,
    [Parameter(Mandatory)] [string]$X0x,
    [Parameter(Mandatory)] [string]$Evidence,
    [Parameter(Mandatory)] [string]$Work
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Instance = 'accept1764'
$PeerUser = 'x0x1764peer'
$PeerDir = 'C:\x0x-1764-peer'
$PipePrefix = 'x0x-upgrade-flush-'

Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
New-Item -ItemType Directory -Force -Path $Evidence, $Work | Out-Null
# Backslash-only absolute paths: the pipe name hashes the canonical root.
$Evidence = [System.IO.Path]::GetFullPath($Evidence)
$Work = [System.IO.Path]::GetFullPath($Work)
# NamedPipeServerStreamAcl and PipesAclExtensions live in this assembly.
try { Add-Type -AssemblyName System.IO.Pipes.AccessControl } catch { Write-Host "pipe ACL assembly: $($_.Exception.Message)" }
$X0xd = (Resolve-Path $X0xd).ProviderPath
$X0x = (Resolve-Path $X0x).ProviderPath
$checks = [System.Collections.Generic.List[object]]::new()
$facts = [ordered]@{}

function Add-Check([string]$Item, [string]$Name, [bool]$Pass, $Detail) {
    $checks.Add([pscustomobject]@{ item = $Item; check = $Name; pass = $Pass; detail = "$Detail" })
    $mark = if ($Pass) { 'PASS' } else { 'FAIL' }
    Write-Host "[$mark] item $Item - $Name - $Detail"
}

# Native commands write progress to stderr; do not let that throw.
function Invoke-Native([scriptblock]$Command) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Command } finally { $ErrorActionPreference = $saved }
}

function Get-PipeNames {
    [System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { $_.Substring('\\.\pipe\'.Length) }
}

function Wait-Until([scriptblock]$Condition, [int]$Seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 250
    }
    return [bool](& $Condition)
}

function Get-Health([string]$Address) {
    try {
        (Invoke-WebRequest -Uri "http://$Address/health" -TimeoutSec 5 -SkipHttpErrorCheck).StatusCode
    } catch { 0 }
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class X0xPipeServer {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint processId);
}
'@

# Same-user client. It checks the pipe server process before it sends the
# token, as docs/upgrade-system.md requires of an arm client.
function Invoke-PipeRequest([string]$PipeName, [int]$ExpectedServer, [string]$Line) {
    $client = [System.IO.Pipes.NamedPipeClientStream]::new('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $client.Connect(10000)
        [uint32]$server = 0
        if (-not [X0xPipeServer]::GetNamedPipeServerProcessId($client.SafePipeHandle.DangerousGetHandle(), [ref]$server)) {
            throw "GetNamedPipeServerProcessId failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        $sddl = $(try {
                [System.IO.Pipes.PipesAclExtensions]::GetAccessControl($client).GetSecurityDescriptorSddlForm('All')
            } catch { "unavailable: $($_.Exception.Message)" })
        if ($server -ne $ExpectedServer) {
            return [pscustomobject]@{ server_pid = $server; sddl = $sddl; reply = $null }
        }
        $encoding = [System.Text.UTF8Encoding]::new($false)
        $writer = [System.IO.StreamWriter]::new($client, $encoding, 4096, $true)
        $writer.Write($Line + "`n")
        $writer.Flush()
        $reader = [System.IO.StreamReader]::new($client, $encoding, $false, 4096, $true)
        $read = $reader.ReadLineAsync()
        if (-not $read.Wait(20000)) { throw 'no reply on the pipe within 20 s' }
        [pscustomobject]@{ server_pid = $server; sddl = $sddl; reply = $read.Result }
    } catch {
        [pscustomobject]@{ server_pid = 0; sddl = $null; reply = $null; error = $_.Exception.Message }
    } finally {
        $client.Dispose()
    }
}

function Get-ReplyError([string]$Reply) {
    if (-not $Reply) { return $null }
    $property = ($Reply | ConvertFrom-Json).PSObject.Properties['error']
    if ($property) { $property.Value } else { $null }
}

function New-ArmRequest([string]$Token, [string]$Root) {
    $digest = { param($b) @(1..32 | ForEach-Object { $b }) }
    $artifact = [ordered]@{
        target_path = "$Root\x0xd.exe"; staged_path = "$Root\x0xd.staged"; backup_path = "$Root\x0xd.backup"
        previous_sha256 = (& $digest 1); candidate_sha256 = (& $digest 2)
    }
    [ordered]@{
        token = $Token; transaction_id = 'acceptance-1764'; generation = 1; instance_id = $Instance
        plan = [ordered]@{
            previous_version = '1.0.0'; candidate_version = '2.0.0'; manifest_sha256 = (& $digest 3)
            daemon = $artifact; cli = $artifact; participants = @()
        }
    } | ConvertTo-Json -Depth 10 -Compress
}

# ---- Host facts -----------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$facts.os = "$($os.Caption) $($os.Version)"
$facts.user = $identity.Name
$facts.elevated = ([System.Security.Principal.WindowsPrincipal]$identity).IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator)
$facts.token_owner_sid = $identity.Owner.Value
$facts.x0xd = $X0xd
$facts.x0xd_sha256 = (Get-FileHash -Algorithm SHA256 $X0xd).Hash.ToLowerInvariant()

# ---- Item 1: clock identity -------------------------------------------------
$bootKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
$bootId = $(try { Get-ItemPropertyValue -Path $bootKey -Name BootId } catch { $null })
$facts.boot_identity = if ($null -ne $bootId) { "windows-boot-$bootId" } else { 'missing' }
Add-Check '1' 'kernel BootId is readable (clock identity windows-boot-<n>)' ($null -ne $bootId) $facts.boot_identity

# ---- Wrapper: generated by the real `x0x autostart` -------------------------
$autostartLog = Join-Path $Evidence 'autostart.log'
Invoke-Native { & $X0x autostart --name $Instance *> $autostartLog }
$autostartExit = $LASTEXITCODE
# Only the wrapper file is needed. Drop the logon task it registered.
Invoke-Native { schtasks /Delete /TN x0xd /F *> $null }
$wrapper = Join-Path $env:APPDATA 'x0x\x0xd-wrapper.ps1'
Add-Check '1' 'x0x autostart writes the wrapper' ($autostartExit -eq 0 -and (Test-Path $wrapper)) "exit $autostartExit, $wrapper"
if (-not (Test-Path $wrapper)) { throw 'no wrapper; cannot continue' }
Copy-Item $wrapper (Join-Path $Evidence 'x0xd-wrapper.ps1')
$wrapperText = Get-Content -Raw $wrapper
$escaped = $X0xd.Replace("'", "''")
$wrapperOk = $wrapperText.Contains('$x0xWrapperVersion = 2') -and
    $wrapperText.Contains("`$x0xExecutable = '$escaped'") -and
    $wrapperText.Contains("`$x0xArguments = @('--name','$Instance')") -and
    $wrapperText.Contains('$x0xRestartOnExit100 = $true') -and
    $wrapperText.Contains('$x0xRestartOnExit75 = $true')
Add-Check '1' 'wrapper is template v2 for this x0xd and instance' $wrapperOk 'version, executable, arguments, restart flags'

# ---- Isolated instance config ----------------------------------------------
$root = Join-Path $Work 'instance'
$dataDir = Join-Path $root 'data'
New-Item -ItemType Directory -Force -Path $dataDir, (Join-Path $root 'identity') | Out-Null
$configDir = Join-Path $env:APPDATA "x0x-$Instance"
New-Item -ItemType Directory -Force -Path $configDir | Out-Null
@"
network_id = "x0x.acceptance.issue1764"
data_dir = '$dataDir'
identity_dir = '$root\identity'
bind_address = "127.0.0.1:0"
api_address = "127.0.0.1:0"
bootstrap_peers = []
mdns_enabled = false
port_mapping_enabled = false
rendezvous_enabled = false
log_level = "info"

[update]
enabled = false

[history]
enabled = false
"@ | Set-Content -Encoding ascii -Path (Join-Path $configDir 'config.toml')
Copy-Item (Join-Path $configDir 'config.toml') (Join-Path $Evidence 'config.toml')

# ---- Start x0xd under the unmodified wrapper ---------------------------------
$stdout = Join-Path $Evidence 'x0xd-stdout.log'
$stderr = Join-Path $Evidence 'x0xd-stderr.log'
$wrapperProcess = Start-Process -FilePath powershell.exe -PassThru `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $wrapper) `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr
# Hold the handle now; without it ExitCode can read back empty after exit.
$null = $wrapperProcess.Handle
$portFile = Join-Path $dataDir 'api.port'
$started = Wait-Until { (Test-Path $portFile) -or $wrapperProcess.HasExited } 240
$daemon = $null
$address = $null
if ($started -and (Test-Path $portFile)) {
    $address = (Get-Content -Raw $portFile).Trim()
    $daemon = Get-CimInstance Win32_Process -Filter "Name = 'x0xd.exe'" |
        Where-Object { $_.ParentProcessId -eq $wrapperProcess.Id } | Select-Object -First 1
}
$health = if ($address) { Get-Health $address } else { 0 }
Add-Check '1' 'x0xd starts under the wrapper and serves /health' ($null -ne $daemon -and $health -eq 200) `
    "api $address, health $health, x0xd pid $(if ($daemon) { $daemon.ProcessId } else { 'none' })"
if ($null -eq $daemon -or $health -ne 200) {
    $checks | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $Evidence 'summary.json')
    throw 'x0xd did not start; see x0xd-stdout.log and x0xd-stderr.log'
}
$facts.x0xd_pid = $daemon.ProcessId
$facts.x0xd_command_line = $daemon.CommandLine

# The pipe name is sha256(lowercased canonical data root)[..16] in hex.
$canonical = ('\\?\' + (Get-Item $dataDir).FullName).ToLowerInvariant()
$hash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($canonical))
$expectedPipe = $PipePrefix + (($hash[0..15] | ForEach-Object { $_.ToString('x2') }) -join '')
$flushPipes = @(Get-PipeNames | Where-Object { $_.StartsWith($PipePrefix) })
$facts.flush_pipes = $flushPipes
Add-Check '1' 'the flush owner serves its named pipe at the derived name' `
    ($flushPipes.Count -eq 1 -and $flushPipes[0] -eq $expectedPipe) "expected $expectedPipe, found $($flushPipes -join ',')"

# ---- Item 4: same-user client --------------------------------------------------
$token = (Get-Content -Raw (Join-Path $dataDir 'api-token')).Trim()
Write-Host "::add-mask::$token"
$canonicalRoot = (Get-Item $dataDir).FullName
$right = Invoke-PipeRequest $expectedPipe $daemon.ProcessId (New-ArmRequest $token $canonicalRoot)
$facts.pipe_sddl = $right.sddl
$facts.pipe_server_pid = $right.server_pid
Add-Check '4' 'the pipe server process is x0xd' ($right.server_pid -eq $daemon.ProcessId) "server pid $($right.server_pid)"
$rightError = Get-ReplyError $right.reply
Add-Check '4' 'same user + API token: authenticated, then refused at admission (no prepared transaction)' `
    ($rightError -eq 'no prepared host transaction') ($right | ConvertTo-Json -Compress)
$wrong = Invoke-PipeRequest $expectedPipe $daemon.ProcessId (New-ArmRequest 'wrong credential' $canonicalRoot)
$wrongError = Get-ReplyError $wrong.reply
Add-Check '4' 'same user + wrong token: refused' ($wrongError -eq 'invalid control credential') ($wrong | ConvertTo-Json -Compress)
$stillServing = (Get-Health $address) -eq 200 -and $null -ne (Get-Process -Id $daemon.ProcessId -ErrorAction SilentlyContinue)
Add-Check '4' 'x0xd keeps serving after both refusals, no flush record' `
    ($stillServing -and -not (Test-Path (Join-Path $dataDir 'upgrade-flush.json'))) 'health 200, same pid'

# ---- Item 4: another local user ------------------------------------------------
$peerResult = $null
$controlName = "x0x-1764-control-$([guid]::NewGuid().ToString('n'))"
try {
    $secret = [byte[]]::new(8)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($secret)
    # net user prompts for passwords over 14 characters, so keep it at 14.
    $password = 'Xa9!' + (($secret[0..4] | ForEach-Object { $_.ToString('x2') }) -join '')
    Write-Host "::add-mask::$password"
    Invoke-Native { net user $PeerUser $password /add *> $null }
    if ($LASTEXITCODE -ne 0) { throw "net user /add exited $LASTEXITCODE" }
    New-Item -ItemType Directory -Force -Path $PeerDir | Out-Null
    Invoke-Native { icacls $PeerDir /grant "${PeerUser}:(OI)(CI)M" *> $null }
    Copy-Item (Join-Path $PSScriptRoot 'windows-flush-acceptance-peer.ps1') (Join-Path $PeerDir 'peer.ps1')

    # Positive control: a pipe whose DACL admits Everyone. The peer must
    # reach it, so a denial on the x0xd pipe is that pipe's DACL.
    $control = Start-ThreadJob -ArgumentList $controlName -ScriptBlock {
        param($Name)
        $security = [System.IO.Pipes.PipeSecurity]::new()
        $everyone = [System.Security.Principal.SecurityIdentifier]::new(
            [System.Security.Principal.WellKnownSidType]::WorldSid, $null)
        $security.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new(
                $everyone, [System.IO.Pipes.PipeAccessRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow))
        $server = [System.IO.Pipes.NamedPipeServerStreamAcl]::Create($Name,
            [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte,
            [System.IO.Pipes.PipeOptions]::Asynchronous, 0, 0, $security)
        try {
            if ($server.WaitForConnectionAsync().Wait(120000)) { 'connected' } else { 'timeout' }
        } finally { $server.Dispose() }
    }
    if (-not (Wait-Until { (Get-PipeNames) -contains $controlName } 15)) { throw 'control pipe did not appear' }

    $credential = [pscredential]::new("$env:COMPUTERNAME\$PeerUser",
        (ConvertTo-SecureString $password -AsPlainText -Force))
    $peerOut = Join-Path $PeerDir 'peer-result.json'
    $peer = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "$PeerDir\peer.ps1",
            '-X0xPipe', $expectedPipe, '-ControlPipe', $controlName, '-Out', $peerOut) `
        -Credential $credential -WorkingDirectory $PeerDir -LoadUserProfile -PassThru -Wait
    $facts.peer_exit = $peer.ExitCode
    if (Test-Path $peerOut) {
        Copy-Item $peerOut (Join-Path $Evidence 'peer-result.json')
        $peerResult = Get-Content -Raw $peerOut | ConvertFrom-Json
    }
    $facts.control_server = (Receive-Job -Job $control -Wait -AutoRemoveJob) -join ','
} catch {
    $facts.peer_error = $_.Exception.Message
}
$peerIsOther = $null -ne $peerResult -and $peerResult.identity -like "*\$PeerUser" -and -not $peerResult.is_admin
Add-Check '4' 'a process runs as a second, non-admin local user' $peerIsOther `
    "$(if ($peerResult) { "$($peerResult.identity) admin=$($peerResult.is_admin)" } else { "no result: $($facts['peer_error'])" })"
Add-Check '4' 'that user reaches an Everyone pipe (positive control)' `
    ($peerIsOther -and $peerResult.control_pipe -eq 'connected') "$(if ($peerResult) { $peerResult.control_pipe })"
Add-Check '4' 'that user is refused by the flush pipe DACL' `
    ($peerIsOther -and $peerResult.x0x_pipe -eq 'access-denied') "$(if ($peerResult) { $peerResult.x0x_pipe })"
Invoke-Native { net user $PeerUser /delete *> $null }

# ---- Ordinary stop propagates through the real wrapper ------------------------
$stop = $(try {
    (Invoke-WebRequest -Method Post -Uri "http://$address/shutdown" -Headers @{ Authorization = "Bearer $token" } `
        -TimeoutSec 10 -SkipHttpErrorCheck).StatusCode
    } catch { 0 })
$wrapperEnded = Wait-Until { $wrapperProcess.HasExited } 90
$restarted = @(Get-CimInstance Win32_Process -Filter "Name = 'x0xd.exe'" |
        Where-Object { $_.ParentProcessId -eq $wrapperProcess.Id }).Count -gt 0
$wrapperExit = if ($wrapperEnded) { $wrapperProcess.ExitCode } else { 'running' }
Add-Check '2/3' 'ordinary stop: x0xd exits 0 and the wrapper exits 0 without a restart' `
    ($stop -ge 200 -and $stop -lt 300 -and $wrapperEnded -and $wrapperExit -eq 0 -and -not $restarted) "shutdown HTTP $stop, wrapper exit $wrapperExit"
if (-not $wrapperEnded) { Stop-Process -Id $wrapperProcess.Id -Force -ErrorAction SilentlyContinue }
Get-Process -Name x0xd -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Read after the stop, so the wrapper has written every line it relayed.
$logText = "$(Get-Content -Raw $stdout -ErrorAction SilentlyContinue)$(Get-Content -Raw $stderr -ErrorAction SilentlyContinue)"
Add-Check '1' 'no "Acknowledged flush unavailable" warning in the x0xd log' `
    (-not $logText.Contains('Acknowledged flush unavailable')) "$($logText.Length) log characters"

# ---- Items 2/3, wrapper half: restart on 100 and 75 only ----------------------
# The generated wrapper with ONLY its executable line pointed at a stub that
# exits 100, then 75, then 3. This is the wrapper rule, not an apply.
$stubDir = Join-Path $Work 'stub'
New-Item -ItemType Directory -Force -Path $stubDir | Out-Null
'0' | Set-Content -Encoding ascii (Join-Path $stubDir 'count.txt')
@(
    '@echo off'
    'setlocal'
    'set /p n=<"%~dp0count.txt"'
    'set /a n=n+1'
    '>"%~dp0count.txt" echo %n%'
    '>>"%~dp0runs.txt" echo run=%n% supervised=%X0X_SUPERVISED% wrapper=%X0X_WRAPPER%'
    'if %n%==1 exit /b 100'
    'if %n%==2 exit /b 75'
    'exit /b 3'
) | Set-Content -Encoding ascii (Join-Path $stubDir 'stub.cmd')
$stubWrapper = Join-Path $stubDir 'x0xd-wrapper.ps1'
$executableLine = "`$x0xExecutable = '$escaped'"
$stubLine = "`$x0xExecutable = '$((Join-Path $stubDir 'stub.cmd').Replace("'", "''"))'"
$stubText = $wrapperText.Replace($executableLine, $stubLine)
$onlyOneLine = ($wrapperText -split "`n").Count -eq ($stubText -split "`n").Count -and $stubText -ne $wrapperText
Set-Content -NoNewline -Encoding ascii -Path $stubWrapper -Value $stubText
$clock = [System.Diagnostics.Stopwatch]::StartNew()
$stubRun = Start-Process -FilePath powershell.exe -PassThru -Wait `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $stubWrapper)
$clock.Stop()
$runsFile = Join-Path $stubDir 'runs.txt'
$runs = if (Test-Path $runsFile) { @(Get-Content $runsFile) } else { @() }
Copy-Item $runsFile (Join-Path $Evidence 'stub-runs.txt') -ErrorAction SilentlyContinue
$sawSupervision = $runs.Count -eq 3 -and @($runs | Where-Object { $_ -like "*supervised=1 wrapper=$stubWrapper" }).Count -eq 3
Add-Check '2/3' 'wrapper restarts after exit 100 and 75, then propagates exit 3' `
    ($onlyOneLine -and $stubRun.ExitCode -eq 3 -and $sawSupervision -and $clock.Elapsed.TotalSeconds -ge 10) `
    "exit $($stubRun.ExitCode), $($runs.Count) runs, $([int]$clock.Elapsed.TotalSeconds) s, X0X_SUPERVISED/X0X_WRAPPER seen: $sawSupervision"

# ---- Item 5: record directory barrier on NTFS ---------------------------------
$barrierTmp = Join-Path $Work 'barrier-tmp'
New-Item -ItemType Directory -Force -Path $barrierTmp | Out-Null
$format = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($barrierTmp)).DriveFormat
$facts.barrier_volume = "$([System.IO.Path]::GetPathRoot($barrierTmp)) $format"
$barrierLog = Join-Path $Evidence 'barrier-tests.log'
$savedTmp = $env:TMP, $env:TEMP
$env:TMP = $barrierTmp
$env:TEMP = $barrierTmp
Invoke-Native { cargo test --lib windows_exec_regressions -- --test-threads=1 --color never *> $barrierLog }
$barrierExit = $LASTEXITCODE
$env:TMP, $env:TEMP = $savedTmp
$barrierText = Get-Content -Raw $barrierLog
$barrierOk = $barrierExit -eq 0 -and $format -eq 'NTFS' -and
    $barrierText.Contains('windows_open_for_sync_flushes_a_file_and_a_directory ... ok') -and
    $barrierText.Contains('windows_record_barrier_support_is_available ... ok')
Add-Check '5' 'FlushFileBuffers on a directory handle succeeds on NTFS' $barrierOk "$($facts.barrier_volume), cargo exit $barrierExit"

# ---- Summary --------------------------------------------------------------------
$failed = @($checks | Where-Object { -not $_.pass }).Count
[ordered]@{ issue = 1764; failed = $failed; facts = $facts; checks = $checks } |
    ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Evidence 'summary.json')
if ($env:GITHUB_STEP_SUMMARY) {
    $lines = @('### Windows flush-owner acceptance (#1764)', '', '| Item | Check | Result | Detail |', '|---|---|---|---|')
    foreach ($check in $checks) {
        $result = if ($check.pass) { 'PASS' } else { 'FAIL' }
        $lines += "| $($check.item) | $($check.check) | $result | $($check.detail.Replace('|', '/')) |"
    }
    $lines | Add-Content $env:GITHUB_STEP_SUMMARY
}
if ($failed -gt 0) {
    Write-Host "$failed check(s) failed"
    exit 1
}
Write-Host 'all checks passed'
