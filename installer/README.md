# OpenLabels Windows Installer

Build scripts for creating the Windows installer.

## Prerequisites

- Windows 10/11 or Windows Server 2019+
- Python 3.11+
- [Inno Setup 6](https://jrsoftware.org/isdl.php)
- Docker Desktop (for testing)

## Building the Installer

```powershell
# Install build dependencies
pip install pyinstaller pywin32 PySide6

# Run the build script
.\build.ps1

# Or with version
.\build.ps1 -Version "1.0.1"
```

## Output

The build creates:
- `dist/OpenLabels/` - Application files
- `dist/OpenLabels-Setup-X.X.X.exe` - Windows installer

## What Gets Installed

| Component | Location |
|-----------|----------|
| Application | `C:\Program Files\OpenLabels\` |
| Configuration | `C:\ProgramData\OpenLabels\config.yaml` |
| Docker Compose | `C:\ProgramData\OpenLabels\docker-compose.yml` |
| Data | `C:\ProgramData\OpenLabels\data\` |
| Logs | `C:\ProgramData\OpenLabels\logs\` |

## Installation Options

The installer offers:
- **Desktop icon** - Shortcut on desktop
- **Start with Windows** - Launch tray app on login
- **Install as Windows Service** - Run backend automatically

## Manual Service Management

```powershell
# Install service
OpenLabelsService.exe install

# Start/stop service
OpenLabelsService.exe start
OpenLabelsService.exe stop

# Remove service
OpenLabelsService.exe remove
```

## Docker Requirements

The installer will prompt to install Docker Desktop if not found.
Docker Desktop must be running for the backend services to work.
