# x0x installer for Windows (PowerShell 5.1+). Non-interactive; never needs admin.
#
# Usage:
#   irm https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.ps1 | iex
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.ps1))) -Start
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Version v0.48.0 -Start
#
# Versions before v0.46.5 predate the --verify-release-manifest probe in the
# release binaries and no longer install.
#
# What it does:
#   1. Resolves the latest release (or -Version)
#   2. Downloads x0x-windows-x64.zip and verifies its SHA-256 checksum, the
#      signed ML-DSA-65 release manifest, whose version and channel must
#      match the resolved release tag (through an installed x0x.exe when
#      available, else the release's own binary — the updater's verify
#      path — before the zip is extracted), and, when gpg is present, the
#      GPG signature against the pinned Saorsa Labs release key
#   3. Stops any running x0xd, installs x0xd.exe + x0x.exe to
#      %LOCALAPPDATA%\x0x\bin (or -InstallDir)
#   4. Adds that directory to the user PATH (idempotent)
#   5. Optionally starts x0xd (-Start)
#
# Signature verification needs gpg.exe (Gpg4win, or the copy bundled with Git
# for Windows). As in install.sh, the SHA-256 checksum and the signed ML-DSA
# manifest are always verified; if gpg is absent the installer prints a loud
# warning and continues without the independent GPG signature.

param(
    [string]$Version = "latest",
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "x0x\bin"),
    [switch]$Start,
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

function Expand-ReleaseZip([string]$Zip, [string]$Destination) {
    # Extract into a fresh subfolder, never next to the downloaded
    # manifest: a crafted zip carrying its own release-manifest.json and
    # .sig must not be able to replace the files the binding and the
    # signature check read. The Windows zip is flat: x0xd.exe and x0x.exe
    # sit at the archive root.
    Expand-Archive -LiteralPath $Zip -DestinationPath $Destination -Force
    foreach ($bin in @("x0xd.exe", "x0x.exe")) {
        if (-not (Test-Path -LiteralPath (Join-Path $Destination $bin) -PathType Leaf)) {
            throw "Release archive is missing $bin at its root; the release layout may have changed."
        }
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
    } else {
        # Same policy and wording as install.sh: warn loudly, and say
        # plainly that without gpg, when no post-v0.46.5 x0x is
        # installed, the manifest check is self-attested by the
        # downloaded binary.
        Write-Host ""
        Write-Host "################################################################" -ForegroundColor Yellow
        Write-Host "# WARNING: gpg NOT FOUND - the GPG signature was NOT verified. #" -ForegroundColor Yellow
        Write-Host "# The checksum and the ML-DSA manifest were checked. With      #" -ForegroundColor Yellow
        Write-Host "# no installed post-v0.46.5 x0x, the manifest is checked by    #" -ForegroundColor Yellow
        Write-Host "# the downloaded binary itself, not by an independent key.     #" -ForegroundColor Yellow
        Write-Host "# Install gpg and re-run for a check that does not depend      #" -ForegroundColor Yellow
        Write-Host "# on this download.                                            #" -ForegroundColor Yellow
        Write-Host "################################################################" -ForegroundColor Yellow
        Write-Host ""
    }

    # ── Signed release manifest (ML-DSA-65, as the updater checks it) ──────
    #
    # The updater refuses a release whose manifest signature fails against
    # the release key compiled into the binary (src/upgrade/signature.rs).
    # This installer reuses that verify path instead of adding a second
    # implementation. Four steps, in this order:
    #
    #   1. Bind: the manifest's version and channel must match the resolved
    #      release tag (stable, non-prerelease, same version), before any
    #      of the archive's bytes run. A genuinely-signed manifest for a
    #      different release is refused. The stable, non-prerelease shape
    #      is the updater's rule (src/upgrade/monitor.rs); matching the
    #      tag is this installer's addition.
    #   2. Bind: the manifest's archive_sha256 entry for this platform
    #      must name the downloaded zip, still before extraction.
    #   3. Sign: an already-installed x0x.exe — its key was trusted by an
    #      earlier install — runs the inert --verify-release-manifest
    #      probe (src/upgrade/verification_probe.rs), which reads only
    #      the two downloaded files, and this runs before the zip is
    #      extracted at all. The bound hash and the verified signature
    #      therefore always apply to the same bytes.
    #   4. Only then is the zip extracted, into a fresh subfolder, so its
    #      entries can never replace the manifest and signature that were
    #      bound and checked. On a first install, or when the installed
    #      x0x.exe predates v0.46.5 (exit 2 on the probe argument), the
    #      release's own x0x.exe from that subfolder does the check
    #      instead — a stated self-attest limit; the pinned GPG signature
    #      stays the independent anchor there.
    #
    # A missing manifest or signature, a bad signature, a version or
    # channel that differs from the release tag, or a hash that differs
    # from the manifest entry stops the install.

    $manifest = Join-Path $Tmp "release-manifest.json"
    $manifestSig = Join-Path $Tmp "release-manifest.json.sig"
    Get-Download "$BaseUrl/release-manifest.json" $manifest
    Get-Download "$BaseUrl/release-manifest.json.sig" $manifestSig

    # The version and channel must match the resolved tag: a manifest
    # from one release cannot be served for another. The stable,
    # non-prerelease shape is the updater's rule (src/upgrade/monitor.rs);
    # matching the tag is this installer's addition, and the tag itself
    # comes from the unauthenticated latest-release API, so this is not
    # downgrade protection. Strip exactly one leading "v", as the
    # updater's version_from_tag does.
    $releaseManifest = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
    $manifestVersion = [string]$releaseManifest.version
    $manifestChannel = [string]$releaseManifest.channel
    if (-not $manifestVersion -or -not $manifestChannel) {
        throw "The signed manifest is missing its version or channel."
    }
    if ($manifestVersion -like "*-*" -or $manifestChannel -cne "stable") {
        throw "The signed manifest names $manifestVersion ($manifestChannel); the updater rule accepts stable, non-prerelease releases only."
    }
    $tagVersion = if ($Tag.StartsWith("v")) { $Tag.Substring(1) } else { $Tag }
    if ($manifestVersion -cne $tagVersion) {
        throw "The signed manifest names version $manifestVersion ($manifestChannel), but release $Tag was requested. Nothing was installed."
    }
    Write-Host "  Manifest version $manifestVersion ($manifestChannel) matches $Tag"

    # The manifest's archive_sha256 must name this zip before extraction:
    # this refuses a swapped archive without executing any of its content.
    $assetEntry = @($releaseManifest.assets | Where-Object { $_.target -ceq "x86_64-pc-windows-msvc" })
    if ($assetEntry.Count -ne 1 -or -not $assetEntry[0].archive_sha256) {
        throw "The signed manifest has no archive_sha256 entry for x86_64-pc-windows-msvc."
    }
    $manifestSha = ([string]$assetEntry[0].archive_sha256).ToLowerInvariant()
    if ($manifestSha -notmatch "^[0-9a-f]{64}$" -or $manifestSha -ne $actual) {
        throw "SHA-256 mismatch between $Asset and the manifest (expected $manifestSha, got $actual)."
    }
    Write-Host "  Archive hash matches the manifest entry" -ForegroundColor Green

    # ── Manifest signature: installed verifier first, extraction after ────
    #
    # Like Test-ReleaseSignature: the probe may write to stderr, and
    # Windows PowerShell 5.1 turns redirected native stderr into a
    # terminating error under "Stop", so relax around the invocations and
    # catch, so a launch failure becomes the repair message instead of a
    # raw OS error. $LASTEXITCODE is cleared before each: if the exe fails
    # to launch at all, a stale success from an earlier native call must
    # not read as "verified". The verifier's own error output is kept, so
    # a refusal says what the verifier actually objected to.
    #
    # Prefer an already-installed x0x.exe as the verifier: its key was
    # trusted by an earlier install, so the check does not depend on this
    # download. The probe runs before the zip is extracted, and the
    # manifest and signature it reads are the downloaded files, which no
    # archive byte has touched. Installed binaries from v0.46.5 know
    # --verify-release-manifest and exit 0 (valid) or 1 (invalid); a
    # pre-probe installed binary rejects the unknown argument with exit
    # code 2, and first installs have no binary yet, so both fall back to
    # the release's own x0x.exe from a fresh extraction subfolder. An
    # installed x0x.exe that exists but cannot launch at all (corrupt,
    # wrong architecture, quarantined) stops the install instead: falling
    # back to the downloaded binary would let an unverified download
    # decide its own install. Limit, stated plainly: on those fallback
    # paths the manifest is checked by the downloaded binary itself, so
    # an attacker controlling the whole origin could self-attest; the
    # pinned GPG signature stays the independent check there.
    $ErrorActionPreference = "Continue"
    $extract = $null
    $verifyBin = $null
    $probeExit = $null
    $probeOutput = @()
    $installedCli = Join-Path $InstallDir "x0x.exe"
    if (Test-Path -LiteralPath $installedCli -PathType Leaf) {
        $global:LASTEXITCODE = $null
        try {
            $probeOutput = & $installedCli --verify-release-manifest $manifest $manifestSig 2>&1
        } catch {
            $probeOutput = @($_)
        }
        $installedExit = $LASTEXITCODE
        if ($null -eq $installedExit) {
            $ErrorActionPreference = "Stop"
            throw "$installedCli exists but could not be launched to verify the manifest. Repair or remove it, then re-run; nothing was installed."
        }
        if ($installedExit -ne 2) {
            $verifyBin = $installedCli
            $probeExit = $installedExit
        } else {
            Write-Warning ("The installed x0x.exe predates v0.46.5 and cannot check the manifest, " +
                "so the downloaded x0x.exe verifies its own release. " +
                "The pinned GPG signature stays the independent check for this install.")
        }
    }
    if ($null -eq $probeExit) {
        $extract = Join-Path $Tmp "extract"
        Expand-ReleaseZip $zip $extract
        $verifyBin = Join-Path $extract "x0x.exe"
        $global:LASTEXITCODE = $null
        try {
            $probeOutput = & $verifyBin --verify-release-manifest $manifest $manifestSig 2>&1
        } catch {
            $probeOutput = @($_)
        }
        $probeExit = $LASTEXITCODE
    }
    $ErrorActionPreference = "Stop"
    if ($null -eq $probeExit -or $probeExit -ne 0) {
        $detail = (@($probeOutput) | Where-Object { "$_" }) -join " "
        throw "ML-DSA manifest signature FAILED for release-manifest.json. The download may have been tampered with. Verifier said: $detail"
    }
    if ($verifyBin -eq $installedCli) {
        Write-Host "  ML-DSA-65 manifest signature verified (by the installed x0x.exe)" -ForegroundColor Green
    } else {
        Write-Host "  ML-DSA-65 manifest signature verified" -ForegroundColor Green
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

    # The installed-verifier path skipped the earlier extraction; extract now.
    if (-not $extract) {
        $extract = Join-Path $Tmp "extract"
        Expand-ReleaseZip $zip $extract
    }

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

    # Never report another daemon as the one we started: if any x0xd is
    # already running (e.g. from another install dir), say so and do not start.
    $running = @(Get-Process -Name x0xd -ErrorAction SilentlyContinue)
    if ($running.Count -gt 0) {
        $pids = ($running | ForEach-Object { $_.Id }) -join ", "
        Write-Warning ("x0xd is already running (PID $pids), so -Start did not start another. " +
            "To run the version just installed: x0x stop, then x0xd.")
    } else {
        # No x0xd is running, so any api.port left behind is stale.
        Remove-Item -LiteralPath $portFile -Force -ErrorAction SilentlyContinue
        Write-Host "Starting: $(Join-Path $InstallDir 'x0xd.exe')"
        $proc = Start-Process -FilePath (Join-Path $InstallDir "x0xd.exe") -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Join-Path $dataDir "x0xd.log") `
            -RedirectStandardError (Join-Path $dataDir "x0xd.err.log")
        $exitedMsg = "x0xd (PID $($proc.Id)) exited during startup. Check: $(Join-Path $dataDir 'x0xd.err.log')"

        $tries = 0
        while (-not (Test-Path -LiteralPath $portFile) -and -not $proc.HasExited -and $tries -lt 30) {
            Start-Sleep -Seconds 1
            $tries++
        }
        if ($proc.HasExited) { throw $exitedMsg }
        if (-not (Test-Path -LiteralPath $portFile)) {
            throw "Timeout waiting for x0xd. Check: $(Join-Path $dataDir 'x0xd.err.log')"
        }
        $api = (Get-Content -LiteralPath $portFile -Raw).Trim()

        $health = $null
        for ($i = 0; $i -lt 15 -and -not $health -and -not $proc.HasExited; $i++) {
            try { $health = Invoke-RestMethod -Uri "http://$api/health" -UseBasicParsing } catch { Start-Sleep -Seconds 1 }
        }
        # Health must come from a daemon while our child is still alive.
        if ($proc.HasExited) { throw $exitedMsg }
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
