"""
Main entry point for the OpenLabels GUI.
"""

import sys


def run_gui(server_url: str = "http://localhost:8000") -> None:
    """
    Launch the OpenLabels GUI application.

    Args:
        server_url: URL of the OpenLabels server to connect to
    """
    try:
        from PySide6.QtWidgets import QApplication
        from openlabels.gui.main_window import MainWindow
    except ImportError:
        print("Error: PySide6 is required for the GUI.")
        print("Install it with: pip install openlabels[gui]")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName("OpenLabels")
    app.setOrganizationName("Chillbot.io")

    window = MainWindow(server_url=server_url)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    run_gui()
