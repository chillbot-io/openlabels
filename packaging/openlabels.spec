# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for OpenLabels Windows GUI.

Build with:
    pip install pyinstaller
    pyinstaller packaging/openlabels.spec

This creates:
    dist/OpenLabels/OpenLabels.exe  (GUI application)
"""

import sys
from pathlib import Path

# Get the project root
project_root = Path(SPECPATH).parent

block_cipher = None

# Main GUI application
gui_a = Analysis(
    [str(project_root / 'openlabels' / 'gui' / 'app.py')],
    pathex=[str(project_root)],
    binaries=[],
    datas=[
        # Include any data files needed
        # (str(project_root / 'openlabels' / 'data'), 'openlabels/data'),
    ],
    hiddenimports=[
        # PySide6 imports
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        # OpenLabels modules
        'openlabels',
        'openlabels.client',
        'openlabels.core',
        'openlabels.core.scorer',
        'openlabels.core.registry',
        'openlabels.adapters.scanner',
        'openlabels.auth',
        'openlabels.vault',
        # Dependencies
        'regex',
        'rich',
        'argon2',
        'cryptography',
        'jwt',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude unnecessary modules to reduce size
        'tkinter',
        'matplotlib',
        'scipy',
        'pandas',
        'notebook',
        'IPython',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

gui_pyz = PYZ(gui_a.pure, gui_a.zipped_data, cipher=block_cipher)

gui_exe = EXE(
    gui_pyz,
    gui_a.scripts,
    [],
    exclude_binaries=True,
    name='OpenLabels',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # GUI app, no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(project_root / 'packaging' / 'icon.ico') if (project_root / 'packaging' / 'icon.ico').exists() else None,
)

# CLI application (separate exe for command-line users)
cli_a = Analysis(
    [str(project_root / 'openlabels' / 'cli' / 'main.py')],
    pathex=[str(project_root)],
    binaries=[],
    datas=[],
    hiddenimports=[
        'openlabels',
        'openlabels.client',
        'openlabels.core',
        'openlabels.core.scorer',
        'openlabels.adapters.scanner',
        'regex',
        'rich',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'PySide6',  # CLI doesn't need Qt
        'tkinter',
        'matplotlib',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

cli_pyz = PYZ(cli_a.pure, cli_a.zipped_data, cipher=block_cipher)

cli_exe = EXE(
    cli_pyz,
    cli_a.scripts,
    [],
    exclude_binaries=True,
    name='openlabels-cli',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,  # CLI needs console
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# Collect all into one directory
coll = COLLECT(
    gui_exe,
    gui_a.binaries,
    gui_a.zipfiles,
    gui_a.datas,
    cli_exe,
    cli_a.binaries,
    cli_a.zipfiles,
    cli_a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='OpenLabels',
)
