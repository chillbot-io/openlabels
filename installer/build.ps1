# OpenLabels Windows Installer Build Script
# Requires: Python 3.11+, PyInstaller, Inno Setup 6

param(
    [switch]$SkipPyInstaller,
    [switch]$SkipInnoSetup,
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

Write-Host "OpenLabels Installer Build" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host "Version: $Version"
Write-Host ""

# Check prerequisites
function Test-Command($Command) {
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

if (-not (Test-Command "python")) {
    Write-Error "Python is not installed or not in PATH"
    exit 1
}

if (-not $SkipPyInstaller -and -not (Test-Command "pyinstaller")) {
    Write-Host "Installing PyInstaller..." -ForegroundColor Yellow
    pip install pyinstaller
}

# Create dist directory
$DistDir = Join-Path $ScriptDir "dist"
if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir | Out-Null
}

# Step 1: Build Python executables with PyInstaller
if (-not $SkipPyInstaller) {
    Write-Host ""
    Write-Host "Step 1: Building Python executables..." -ForegroundColor Green

    Push-Location $RootDir

    # Build tray application
    Write-Host "  Building OpenLabelsTray.exe..."
    pyinstaller --noconfirm --onedir --windowed `
        --name "OpenLabelsTray" `
        --icon "$ScriptDir\icons\openlabels.ico" `
        --add-data "docker-compose.yml;." `
        --hidden-import "PySide6" `
        --hidden-import "httpx" `
        src/openlabels/windows/tray.py

    # Build service executable
    Write-Host "  Building OpenLabelsService.exe..."
    pyinstaller --noconfirm --onedir --console `
        --name "OpenLabelsService" `
        --hidden-import "win32serviceutil" `
        --hidden-import "win32service" `
        --hidden-import "win32event" `
        --hidden-import "servicemanager" `
        src/openlabels/windows/service.py

    # Move to installer dist
    Copy-Item -Recurse -Force "dist\OpenLabelsTray" "$DistDir\OpenLabels"
    Copy-Item -Recurse -Force "dist\OpenLabelsService\*" "$DistDir\OpenLabels\"

    Pop-Location

    Write-Host "  Done!" -ForegroundColor Green
}

# Step 2: Build installer with Inno Setup
if (-not $SkipInnoSetup) {
    Write-Host ""
    Write-Host "Step 2: Building Windows installer..." -ForegroundColor Green

    # Find Inno Setup
    $InnoSetup = @(
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        "C:\Program Files\Inno Setup 6\ISCC.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $InnoSetup) {
        Write-Warning "Inno Setup not found. Download from: https://jrsoftware.org/isdl.php"
        Write-Warning "Skipping installer creation."
    } else {
        # Update version in ISS file
        $IssFile = Join-Path $ScriptDir "openlabels.iss"
        $IssContent = Get-Content $IssFile -Raw
        $IssContent = $IssContent -replace '#define MyAppVersion ".*"', "#define MyAppVersion `"$Version`""
        Set-Content -Path $IssFile -Value $IssContent

        # Build installer
        & $InnoSetup $IssFile

        Write-Host "  Installer created: $DistDir\OpenLabels-Setup-$Version.exe" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Build complete!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output files:" -ForegroundColor Yellow
Get-ChildItem $DistDir -Recurse -File | ForEach-Object {
    Write-Host "  $($_.FullName)"
}
