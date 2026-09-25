# x0x installer for Windows (PowerShell 5.1+). Non-interactive; never needs admin.
#
# Usage:
#   irm https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.ps1 | iex
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.ps1))) -Start
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Version v0.45.0 -Start
#
# What it does:
#   1. Resolves the latest release (or -Version)
#   2. Downloads x0x-windows-x64.zip and verifies its SHA-256 checksum and its
#      GPG signature against the pinned Saorsa Labs release key
#   3. Stops any running x0xd, installs x0xd.exe + x0x.exe to
#      %LOCALAPPDATA%\x0x\bin (or -InstallDir)
#   4. Adds that directory to the user PATH (idempotent)
#   5. Optionally starts x0xd (-Start)
#
# Signature verification needs gpg.exe (Gpg4win, or the copy bundled with Git
# for Windows). Without it the installer stops unless -SkipSignature is given;
# the SHA-256 checksum is always verified.

param(
    [string]$Version = "latest",
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "x0x\bin"),
    [switch]$Start,
    [switch]$SkipSignature,
    # Accepted for compatibility; the installer never prompts.
    [switch]$Yes
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
# Windows PowerShell 5.1 does not enable TLS 1.2 by default.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Repo = "saorsa-labs/x0x"
$Asset = "x0x-windows-x64.zip"
# Saorsa Labs release signing key (primary fingerprint). Rotate only with a
# reviewed installer change.
$TrustedFingerprint = "CEB3506E7DCB8A2DD2D679E8EDDA4827D89C0F29"

function Get-Download([string]$Url, [string]$OutFile) {
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
}

function Find-Gpg {
    $cmd = Get-Command gpg -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "GnuPG\bin\gpg.exe"),
        (Join-Path $env:ProgramFiles "GnuPG\bin\gpg.exe"),
        (Join-Path $env:ProgramFiles "Git\usr\bin\gpg.exe")
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
    return $null
}

function Test-ReleaseSignature([string]$Gpg, [string]$Artifact, [string]$Signature, [string]$KeyFile, [string]$WorkDir) {
    # gpg writes progress to stderr; under "Stop", Windows PowerShell 5.1 turns
    # redirected native stderr into a terminating error. Exit codes and the
    # status-fd lines are checked explicitly instead.
    $ErrorActionPreference = "Continue"
    # Check the downloaded key is the pinned one before trusting anything it signs.
    $keyInfo = & $Gpg --batch --with-colons --show-keys --fingerprint $KeyFile 2>$null
    $keyFprs = @($keyInfo | Where-Object { $_ -like "fpr:*" } | ForEach-Object { ($_ -split ":")[9].ToUpperInvariant() })
    if ($keyFprs -notcontains $TrustedFingerprint) {
        throw "Downloaded SAORSA_PUBLIC_KEY.asc is not the pinned release key ($TrustedFingerprint)."
    }

    # Isolated keyring so the user's own GnuPG state is untouched.
    $gnupgHome = Join-Path $WorkDir "gnupg"
    New-Item -ItemType Directory -Force -Path $gnupgHome | Out-Null
    & $Gpg --homedir $gnupgHome --batch --import $KeyFile 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "gpg failed to import the release key." }

    $status = & $Gpg --homedir $gnupgHome --batch --status-fd 1 --verify $Signature $Artifact 2>$null
    $verifyExit = $LASTEXITCODE
    $signers = @()
    foreach ($line in $status) {
        $parts = $line -split "\s+"
        if ($parts.Length -ge 3 -and $parts[0] -eq "[GNUPG:]" -and $parts[1] -eq "VALIDSIG") {
            $signers += $parts[2].ToUpperInvariant()
            if ($parts.Length -ge 12) { $signers += $parts[11].ToUpperInvariant() }
        }
    }
    if ($verifyExit -ne 0 -or ($signers -notcontains $TrustedFingerprint)) {
        throw "GPG signature verification FAILED for $Asset. The download may have been tampered with."
    }
}

Write-Host "x0x installer (Windows)" -ForegroundColor Blue

# ── Resolve release ─────────────────────────────────────────────────────────

if ($Version -eq "latest") {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing -Headers @{ "User-Agent" = "x0x-install.ps1" }
    $Tag = $release.tag_name
    if (-not $Tag) { throw "Could not resolve the latest x0x release." }
} elseif ($Version.StartsWith("v")) {
    $Tag = $Version
} else {
    $Tag = "v$Version"
}
$BaseUrl = "https://github.com/$Repo/releases/download/$Tag"

Write-Host "  Release: $Tag"
Write-Host "  Install: $InstallDir"

$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("x0x-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $Tmp | Out-Null

try {
    # ── Download and verify ─────────────────────────────────────────────────

    $zip = Join-Path $Tmp $Asset
    Write-Host "Downloading $Asset..."
    Get-Download "$BaseUrl/$Asset" $zip
    Get-Download "$BaseUrl/$Asset.sha256" "$zip.sha256"

    # Checksum file format: "<hex>  <name>" or "<hex> *<name>".
    $expected = ((Get-Content -LiteralPath "$zip.sha256" -Raw).Trim() -split "\s+")[0].ToLowerInvariant()
    $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -notmatch "^[0-9a-f]{64}$" -or $expected -ne $actual) {
        throw "SHA-256 mismatch for $Asset (expected $expected, got $actual)."
    }
    Write-Host "  SHA-256 verified" -ForegroundColor Green

    $gpg = Find-Gpg
    if ($gpg) {
        Get-Download "$BaseUrl/$Asset.asc" "$zip.asc"
        Get-Download "$BaseUrl/SAORSA_PUBLIC_KEY.asc" (Join-Path $Tmp "SAORSA_PUBLIC_KEY.asc")
        Test-ReleaseSignature $gpg $zip "$zip.asc" (Join-Path $Tmp "SAORSA_PUBLIC_KEY.asc") $Tmp
        Write-Host "  GPG signature verified ($TrustedFingerprint)" -ForegroundColor Green
    } elseif ($SkipSignature) {
        Write-Warning "gpg not found and -SkipSignature given: installing with checksum verification only."
    } else {
        throw ("gpg.exe not found, so the release signature cannot be verified. " +
            "Install Gpg4win (https://gpg4win.org) or Git for Windows, or re-run with -SkipSignature " +
            "to accept checksum-only verification.")
    }

    # ── Extract ─────────────────────────────────────────────────────────────

    # The Windows zip is flat: x0xd.exe and x0x.exe sit at the archive root.
    $extract = Join-Path $Tmp "extract"
    Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
    foreach ($bin in @("x0xd.exe", "x0x.exe")) {
        if (-not (Test-Path -LiteralPath (Join-Path $extract $bin) -PathType Leaf)) {
            throw "Release archive is missing $bin at its root; the release layout may have changed."
        }
    }

    # ── Stop any running instance ───────────────────────────────────────────

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $existingCli = Join-Path $InstallDir "x0x.exe"
    if (Test-Path -LiteralPath $existingCli) {
        Write-Host "Stopping running instance..."
        $ErrorActionPreference = "Continue"
        & $existingCli stop *> $null
        $ErrorActionPreference = "Stop"
        Start-Sleep -Seconds 1
    }

    # ── Install ─────────────────────────────────────────────────────────────

    # A running .exe cannot be overwritten on Windows but can be renamed, so
    # move the old binary aside first, then move the new one into place.
    Get-ChildItem -LiteralPath $InstallDir -Filter "*.old-*" -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
    foreach ($bin in @("x0xd.exe", "x0x.exe")) {
        $dest = Join-Path $InstallDir $bin
        $staged = "$dest.new"
        Copy-Item -LiteralPath (Join-Path $extract $bin) -Destination $staged -Force
        if (Test-Path -LiteralPath $dest) {
            Move-Item -LiteralPath $dest -Destination ("$dest.old-" + [Guid]::NewGuid().ToString("N")) -Force
        }
        Move-Item -LiteralPath $staged -Destination $dest -Force
    }
    Write-Host "Installed: x0xd.exe x0x.exe" -ForegroundColor Green
} finally {
    Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# ── PATH (user scope, idempotent) ───────────────────────────────────────────

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$entries = @()
if ($userPath) { $entries = $userPath -split ";" | Where-Object { $_ -ne "" } }
$normalized = $InstallDir.TrimEnd("\")
$onPath = $entries | Where-Object { $_.TrimEnd("\") -ieq $normalized }
if (-not $onPath) {
    [Environment]::SetEnvironmentVariable("Path", (($entries + $normalized) -join ";"), "User")
    Write-Host "Added $normalized to your user PATH (new terminals pick it up)."
}
if (-not (($env:Path -split ";") | Where-Object { $_.TrimEnd("\") -ieq $normalized })) {
    $env:Path = "$env:Path;$normalized"
}

# ── Start daemon (optional) ─────────────────────────────────────────────────

if ($Start) {
    # x0xd's default data dir on Windows is %APPDATA%\x0x (dirs::data_dir()).
    $dataDir = Join-Path $env:APPDATA "x0x"
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
    $portFile = Join-Path $dataDir "api.port"
    Write-Host ""
    Write-Host "Starting: $(Join-Path $InstallDir 'x0xd.exe')"
    $proc = Start-Process -FilePath (Join-Path $InstallDir "x0xd.exe") -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $dataDir "x0xd.log") `
        -RedirectStandardError (Join-Path $dataDir "x0xd.err.log")

    $tries = 0
    while (-not (Test-Path -LiteralPath $portFile) -and $tries -lt 30) {
        Start-Sleep -Seconds 1
        $tries++
    }
    if (-not (Test-Path -LiteralPath $portFile)) {
        throw "Timeout waiting for x0xd. Check: $(Join-Path $dataDir 'x0xd.err.log')"
    }
    $api = (Get-Content -LiteralPath $portFile -Raw).Trim()

    $health = $null
    for ($i = 0; $i -lt 15 -and -not $health; $i++) {
        try { $health = Invoke-RestMethod -Uri "http://$api/health" -UseBasicParsing } catch { Start-Sleep -Seconds 1 }
    }
    if (-not $health) {
        throw "Timeout waiting for a healthy x0xd. Check: $(Join-Path $dataDir 'x0xd.err.log')"
    }

    $agentId = ""
    $tokenFile = Join-Path $dataDir "api-token"
    if (Test-Path -LiteralPath $tokenFile) {
        $token = (Get-Content -LiteralPath $tokenFile -Raw).Trim()
        try {
            $agent = Invoke-RestMethod -Uri "http://$api/agent" -UseBasicParsing -Headers @{ Authorization = "Bearer $token" }
            $agentId = $agent.agent_id
        } catch { }
    }

    Write-Host ""
    Write-Host "x0x is running" -ForegroundColor Green
    Write-Host "  API:    http://$api"
    Write-Host "  Agent:  $agentId"
    Write-Host "  Log:    $(Join-Path $dataDir 'x0xd.log')"
    Write-Host "  PID:    $($proc.Id)"
}

# ── Next steps ──────────────────────────────────────────────────────────────

Write-Host ""
if (-not $Start) {
    Write-Host "Start:  x0xd                      Run the daemon (creates your identity on first run)"
}
Write-Host "Try:    x0x health                Check the daemon"
Write-Host "        x0x gui                   Open the web GUI"
Write-Host "        x0x agent                 Show your agent id"
Write-Host "Invited? Import the inviter's card, then message them:"
Write-Host "        x0x agent import `"<card-link>`" --trust known"
Write-Host "        x0x direct send <agent-id> `"hello`""
Write-Host ""
Write-Host "Docs: https://github.com/$Repo"
