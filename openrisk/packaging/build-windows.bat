@echo off
REM OpenLabels Windows Build Script
REM
REM Prerequisites:
REM   - Python 3.9+ with pip
REM   - Inno Setup 6+ (optional, for installer)
REM
REM Usage:
REM   build-windows.bat          Build everything
REM   build-windows.bat --help   Show help

setlocal enabledelayedexpansion

echo.
echo OpenLabels Windows Build
echo ========================
echo.

REM Get script directory and project root
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.9 or later.
    exit /b 1
)
echo [OK] Python found

REM Install dependencies
echo Installing dependencies...
pip install pyinstaller --quiet
pip install -e "%PROJECT_ROOT%[gui,pdf,office,images,ocr,auth]" --quiet
echo [OK] Dependencies installed

REM Build with PyInstaller
echo Building with PyInstaller...
cd /d "%PROJECT_ROOT%"
pyinstaller --clean --noconfirm packaging\openlabels.spec
if errorlevel 1 (
    echo ERROR: PyInstaller failed
    exit /b 1
)
echo [OK] PyInstaller complete

REM Check for Inno Setup
set "ISCC="
if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" (
    set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
)
if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" (
    set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
)

if "%ISCC%"=="" (
    echo.
    echo [SKIP] Inno Setup not found - installer not built
    echo        Install from: https://jrsoftware.org/isdl.php
    echo.
    echo Build complete!
    echo   GUI: dist\OpenLabels\OpenLabels.exe
    echo   CLI: dist\OpenLabels\openlabels-cli.exe
    exit /b 0
)

REM Build installer
echo Building installer...
"%ISCC%" "%PROJECT_ROOT%\packaging\installer.iss"
if errorlevel 1 (
    echo ERROR: Inno Setup failed
    exit /b 1
)

echo.
echo Build complete!
echo   Installer: dist\OpenLabels-0.1.0-Setup.exe
echo   GUI:       dist\OpenLabels\OpenLabels.exe
echo   CLI:       dist\OpenLabels\openlabels-cli.exe
