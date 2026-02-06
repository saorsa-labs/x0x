# x0x SKILL.md Installation Script (Windows PowerShell)

$ErrorActionPreference = "Stop"

$Repo = "saorsa-labs/x0x"
$ReleaseUrl = "https://github.com/$Repo/releases/latest/download"
$InstallDir = "$env:LOCALAPPDATA\x0x"

Write-Host "x0x Installation Script" -ForegroundColor Blue
Write-Host "========================" -ForegroundColor Blue
Write-Host ""

# Check if GPG is installed
$GpgAvailable = Get-Command gpg -ErrorAction SilentlyContinue
if (-not $GpgAvailable) {
    Write-Host "Warning: GPG not found. Signature verification will be skipped." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To enable signature verification, install GPG:"
    Write-Host "  https://gnupg.org/download/"
    Write-Host ""
    $response = Read-Host "Continue without verification? (y/N)"
    if ($response -ne "y" -and $response -ne "Y") {
        exit 1
    }
}

# Create install directory
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Set-Location $InstallDir

Write-Host "Downloading SKILL.md..."
Invoke-WebRequest -Uri "$ReleaseUrl/SKILL.md" -OutFile "SKILL.md"

if ($GpgAvailable) {
    Write-Host "Downloading signature..."
    Invoke-WebRequest -Uri "$ReleaseUrl/SKILL.md.sig" -OutFile "SKILL.md.sig"
    Invoke-WebRequest -Uri "$ReleaseUrl/SAORSA_PUBLIC_KEY.asc" -OutFile "SAORSA_PUBLIC_KEY.asc"
    
    Write-Host "Importing Saorsa Labs public key..."
    gpg --import SAORSA_PUBLIC_KEY.asc 2>&1 | Out-Null
    
    Write-Host "Verifying signature..."
    $verification = gpg --verify SKILL.md.sig SKILL.md 2>&1 | Out-String
    if ($verification -match "Good signature") {
        Write-Host "Signature verified" -ForegroundColor Green
    } else {
        Write-Host "Signature verification failed" -ForegroundColor Red
        Write-Host ""
        Write-Host "This file may have been tampered with."
        $response = Read-Host "Install anyway? (y/N)"
        if ($response -ne "y" -and $response -ne "Y") {
            exit 1
        }
    }
}

Write-Host ""
Write-Host "Installation complete" -ForegroundColor Green
Write-Host ""
Write-Host "SKILL.md installed to: $InstallDir\SKILL.md"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Review SKILL.md: cat $InstallDir\SKILL.md"
Write-Host "  2. Install SDK:"
Write-Host "     - Rust:       cargo add x0x"
Write-Host "     - TypeScript: npm install x0x"
Write-Host "     - Python:     pip install agent-x0x"
Write-Host ""
Write-Host "Learn more: https://github.com/$Repo"
