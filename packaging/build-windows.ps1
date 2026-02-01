<#
.SYNOPSIS
    Build OpenLabels Windows installer

.DESCRIPTION
    This script builds the OpenLabels Windows installer using PyInstaller and Inno Setup.

.EXAMPLE
    .\packaging\build-windows.ps1

.NOTES
    Prerequisites:
    - Python 3.9+ with pip
    - Inno Setup 6+ (https://jrsoftware.org/isdl.php)
#>

param(
    [switch]$SkipInstaller,  # Skip Inno Setup, just build with PyInstaller
    [switch]$Clean           # Clean build directories first
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

Write-Host "OpenLabels Windows Build" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host ""

# Clean if requested
if ($Clean) {
    Write-Host "Cleaning build directories..." -ForegroundColor Yellow
    Remove-Item -Path "$ProjectRoot\build\__pycache__" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$ProjectRoot\dist" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Done." -ForegroundColor Green
}

# Check Python
Write-Host "Checking Python..." -ForegroundColor Yellow
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Error "Python not found. Please install Python 3.9 or later."
    exit 1
}
$pythonVersion = python --version
Write-Host "  Found: $pythonVersion" -ForegroundColor Green

# Install dependencies
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pip install pyinstaller --quiet
pip install -e "$ProjectRoot[gui,pdf,office,images,ocr,auth]" --quiet
Write-Host "  Done." -ForegroundColor Green

# Run PyInstaller
Write-Host "Building with PyInstaller..." -ForegroundColor Yellow
Push-Location $ProjectRoot
try {
    pyinstaller --clean --noconfirm packaging/openlabels.spec
    if ($LASTEXITCODE -ne 0) {
        Write-Error "PyInstaller failed with exit code $LASTEXITCODE"
        exit 1
    }
} finally {
    Pop-Location
}
Write-Host "  Done. Output: dist/OpenLabels/" -ForegroundColor Green

# Check if we should build installer
if ($SkipInstaller) {
    Write-Host ""
    Write-Host "Skipping installer build (use without -SkipInstaller to build .exe installer)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Build complete!" -ForegroundColor Green
    Write-Host "  GUI:  dist\OpenLabels\OpenLabels.exe" -ForegroundColor Cyan
    Write-Host "  CLI:  dist\OpenLabels\openlabels-cli.exe" -ForegroundColor Cyan
    exit 0
}

# Check for Inno Setup
Write-Host "Checking Inno Setup..." -ForegroundColor Yellow
$innoPath = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $innoPath) {
    Write-Host "  Inno Setup not found. Skipping installer build." -ForegroundColor Yellow
    Write-Host "  Install from: https://jrsoftware.org/isdl.php" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Build complete (without installer)!" -ForegroundColor Green
    Write-Host "  GUI:  dist\OpenLabels\OpenLabels.exe" -ForegroundColor Cyan
    Write-Host "  CLI:  dist\OpenLabels\openlabels-cli.exe" -ForegroundColor Cyan
    exit 0
}
Write-Host "  Found: $innoPath" -ForegroundColor Green

# Build installer
Write-Host "Building installer with Inno Setup..." -ForegroundColor Yellow
& $innoPath "$ProjectRoot\packaging\installer.iss"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Inno Setup failed with exit code $LASTEXITCODE"
    exit 1
}
Write-Host "  Done." -ForegroundColor Green

Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green
Write-Host "  Installer: dist\OpenLabels-0.1.0-Setup.exe" -ForegroundColor Cyan
Write-Host "  GUI:       dist\OpenLabels\OpenLabels.exe" -ForegroundColor Cyan
Write-Host "  CLI:       dist\OpenLabels\openlabels-cli.exe" -ForegroundColor Cyan
