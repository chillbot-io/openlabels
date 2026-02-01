"""
OpenLabels GUI Style.

Professional dark theme designed for security operations.
Inspired by tools like Splunk, Elastic Security, and CrowdStrike.
"""

# Professional security tool color palette
COLORS = {
    # Background hierarchy (darkest to lightest)
    "bg_base": "#0d1117",           # Main background
    "bg_surface": "#161b22",        # Cards, panels
    "bg_elevated": "#21262d",       # Elevated surfaces, inputs
    "bg_hover": "#30363d",          # Hover states

    # Borders
    "border": "#30363d",            # Standard border
    "border_subtle": "#21262d",     # Subtle border
    "border_emphasis": "#484f58",   # Emphasized border

    # Text hierarchy
    "text_primary": "#e6edf3",      # Primary text
    "text_secondary": "#8b949e",    # Secondary text
    "text_muted": "#6e7681",        # Muted text
    "text_link": "#58a6ff",         # Links

    # Accent colors - Blue/Grey theme
    "accent_blue": "#58a6ff",       # Primary accent
    "accent_blue_muted": "#388bfd", # Muted blue for selections
    "accent_green": "#3fb950",      # Success
    "accent_yellow": "#d29922",     # Warning
    "accent_orange": "#db6d28",     # Caution
    "accent_red": "#f85149",        # Danger/Critical
    "accent_purple": "#a371f7",     # Info

    # Risk tier colors (calibrated for dark backgrounds)
    "tier_critical": "#f85149",     # Red - immediate action
    "tier_high": "#db6d28",         # Orange - high priority
    "tier_medium": "#d29922",       # Yellow - moderate
    "tier_low": "#3fb950",          # Green - acceptable
    "tier_minimal": "#6e7681",      # Gray - negligible

    # Legacy compatibility aliases
    "accent": "#58a6ff",
    "primary": "#58a6ff",
    "primary_dark": "#388bfd",
    "primary_light": "#58a6ff",
    "success": "#3fb950",
    "warning": "#d29922",
    "danger": "#f85149",
    "bg": "#0d1117",
    "bg_secondary": "#161b22",
    "bg_tertiary": "#21262d",
    "text": "#e6edf3",
    "border_focus": "#58a6ff",
}

# Monospace font stack for technical data (hashes, IDs, code)
MONO_FONT = '"IBM Plex Mono", "JetBrains Mono", "Fira Code", Consolas, monospace'

# UI font - IBM Plex Sans for solid, technical look (falls back to system fonts)
UI_FONT = '"IBM Plex Sans", "SF Pro Display", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'

# Font weights
FONT_WEIGHT_NORMAL = 500  # Medium as base for solid look
FONT_WEIGHT_MEDIUM = 550
FONT_WEIGHT_SEMIBOLD = 600


def get_stylesheet() -> str:
    """Return the complete Qt stylesheet for professional dark theme."""
    return f"""
/* ============================================
   GLOBAL STYLES
   ============================================ */
QWidget {{
    font-family: {UI_FONT};
    font-size: 13px;
    font-weight: {FONT_WEIGHT_NORMAL};
    color: {COLORS["text_primary"]};
    background-color: {COLORS["bg_base"]};
}}

QMainWindow {{
    background-color: {COLORS["bg_base"]};
}}

/* ============================================
   FRAMES AND CONTAINERS
   ============================================ */
QFrame {{
    background-color: transparent;
    border: none;
}}

QFrame[frameShape="4"], QFrame[frameShape="5"] {{
    background-color: {COLORS["border"]};
}}

QGroupBox {{
    font-weight: {FONT_WEIGHT_SEMIBOLD};
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: {COLORS["text_secondary"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 4px;
    margin-top: 14px;
    padding: 14px 10px 10px 10px;
    background-color: {COLORS["bg_surface"]};
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 6px;
    background-color: {COLORS["bg_surface"]};
}}

/* ============================================
   BUTTONS
   ============================================ */
QPushButton {{
    background-color: {COLORS["bg_elevated"]};
    color: {COLORS["text_primary"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 4px;
    padding: 5px 12px;
    font-weight: {FONT_WEIGHT_SEMIBOLD};
    font-size: 13px;
    min-height: 22px;
}}

QPushButton:hover {{
    background-color: {COLORS["bg_hover"]};
    border-color: {COLORS["border_emphasis"]};
}}

QPushButton:pressed {{
    background-color: {COLORS["border"]};
}}

QPushButton:disabled {{
    background-color: {COLORS["bg_elevated"]};
    color: {COLORS["text_muted"]};
    border-color: {COLORS["border_subtle"]};
}}

QPushButton[primary="true"], QPushButton#primaryButton {{
    background-color: {COLORS["accent_blue_muted"]};
    border-color: {COLORS["accent_blue_muted"]};
    color: white;
}}

QPushButton[primary="true"]:hover, QPushButton#primaryButton:hover {{
    background-color: {COLORS["accent_blue"]};
    border-color: {COLORS["accent_blue"]};
}}

QPushButton[secondary="true"], QPushButton#secondaryButton {{
    background-color: transparent;
    border-color: {COLORS["border"]};
    color: {COLORS["text_secondary"]};
}}

QPushButton[secondary="true"]:hover, QPushButton#secondaryButton:hover {{
    background-color: {COLORS["bg_hover"]};
    color: {COLORS["text_primary"]};
}}

QPushButton[danger="true"], QPushButton#dangerButton {{
    background-color: transparent;
    border-color: {COLORS["accent_red"]};
    color: {COLORS["accent_red"]};
}}

QPushButton[danger="true"]:hover, QPushButton#dangerButton:hover {{
    background-color: {COLORS["accent_red"]};
    color: white;
}}

/* ============================================
   INPUT FIELDS
   ============================================ */
QLineEdit, QTextEdit, QPlainTextEdit {{
    background-color: {COLORS["bg_elevated"]};
    color: {COLORS["text_primary"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 4px;
    padding: 5px 8px;
    selection-background-color: {COLORS["accent_blue_muted"]};
    selection-color: white;
}}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
    border-color: {COLORS["accent_blue"]};
}}

QLineEdit:disabled {{
    background-color: {COLORS["bg_surface"]};
    color: {COLORS["text_muted"]};
}}

QLineEdit[monospace="true"] {{
    font-family: {MONO_FONT};
    font-size: 12px;
}}

/* ============================================
   COMBO BOXES
   ============================================ */
QComboBox {{
    background-color: {COLORS["bg_elevated"]};
    color: {COLORS["text_primary"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 4px;
    padding: 5px 8px;
    min-width: 80px;
}}

QComboBox:focus {{
    border-color: {COLORS["accent_blue"]};
}}

QComboBox::drop-down {{
    border: none;
    width: 18px;
    padding-right: 4px;
}}

QComboBox QAbstractItemView {{
    background-color: {COLORS["bg_elevated"]};
    border: 1px solid {COLORS["border"]};
    selection-background-color: {COLORS["accent_blue_muted"]};
    selection-color: white;
    outline: none;
}}

QComboBox QAbstractItemView::item {{
    padding: 5px 8px;
}}

QComboBox QAbstractItemView::item:hover {{
    background-color: {COLORS["bg_hover"]};
}}

/* ============================================
   SPIN BOXES
   ============================================ */
QSpinBox, QDoubleSpinBox {{
    background-color: {COLORS["bg_elevated"]};
    color: {COLORS["text_primary"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 4px;
    padding: 5px 8px;
}}

QSpinBox:focus, QDoubleSpinBox:focus {{
    border-color: {COLORS["accent_blue"]};
}}

QSpinBox::up-button, QSpinBox::down-button,
QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {{
    background-color: {COLORS["bg_hover"]};
    border: none;
    width: 16px;
}}

/* ============================================
   TABLES
   ============================================ */
QTableWidget, QTableView {{
    background-color: {COLORS["bg_surface"]};
    alternate-background-color: {COLORS["bg_base"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 4px;
    gridline-color: {COLORS["border_subtle"]};
    selection-background-color: {COLORS["accent_blue_muted"]};
    selection-color: white;
    outline: none;
}}

QTableWidget::item, QTableView::item {{
    padding: 4px 6px;
    border-bottom: 1px solid {COLORS["border_subtle"]};
}}

QTableWidget::item:selected, QTableView::item:selected {{
    background-color: {COLORS["accent_blue_muted"]};
}}

QHeaderView::section {{
    background-color: {COLORS["bg_elevated"]};
    color: {COLORS["text_secondary"]};
    font-weight: {FONT_WEIGHT_SEMIBOLD};
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    padding: 6px 8px;
    border: none;
    border-bottom: 1px solid {COLORS["border"]};
    border-right: 1px solid {COLORS["border_subtle"]};
}}

QHeaderView::section:last {{
    border-right: none;
}}

QHeaderView::section:hover {{
    background-color: {COLORS["bg_hover"]};
}}

/* ============================================
   TAB WIDGET
   ============================================ */
QTabWidget::pane {{
    border: none;
    background-color: transparent;
    top: -1px;
}}

QTabBar::tab {{
    background-color: {COLORS["bg_elevated"]};
    color: {COLORS["text_secondary"]};
    border: 1px solid {COLORS["border"]};
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    padding: 6px 14px;
    margin-right: 2px;
    font-weight: {FONT_WEIGHT_SEMIBOLD};
    font-size: 13px;
}}

QTabBar::tab:selected {{
    background-color: {COLORS["bg_surface"]};
    color: {COLORS["text_primary"]};
    border-bottom: 2px solid {COLORS["accent_blue"]};
}}

QTabBar::tab:hover:!selected {{
    background-color: {COLORS["bg_hover"]};
    color: {COLORS["text_primary"]};
}}

/* ============================================
   PROGRESS BAR
   ============================================ */
QProgressBar {{
    background-color: {COLORS["bg_elevated"]};
    border: none;
    border-radius: 2px;
    height: 4px;
    text-align: center;
}}

QProgressBar::chunk {{
    background-color: {COLORS["accent_blue"]};
    border-radius: 2px;
}}

/* ============================================
   SCROLL BARS
   ============================================ */
QScrollBar:vertical {{
    background-color: {COLORS["bg_surface"]};
    width: 8px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background-color: {COLORS["border"]};
    border-radius: 4px;
    min-height: 24px;
    margin: 2px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {COLORS["border_emphasis"]};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}

QScrollBar:horizontal {{
    background-color: {COLORS["bg_surface"]};
    height: 8px;
    margin: 0;
}}

QScrollBar::handle:horizontal {{
    background-color: {COLORS["border"]};
    border-radius: 4px;
    min-width: 24px;
    margin: 2px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {COLORS["border_emphasis"]};
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
}}

/* ============================================
   TREE VIEW
   ============================================ */
QTreeView, QTreeWidget {{
    background-color: {COLORS["bg_surface"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 4px;
    alternate-background-color: {COLORS["bg_base"]};
    outline: none;
}}

QTreeView::item {{
    padding: 3px 4px;
}}

QTreeView::item:selected {{
    background-color: {COLORS["accent_blue_muted"]};
    color: white;
}}

QTreeView::item:hover:!selected {{
    background-color: {COLORS["bg_hover"]};
}}

/* ============================================
   SPLITTER
   ============================================ */
QSplitter::handle {{
    background-color: transparent;
}}

QSplitter::handle:horizontal {{
    width: 8px;
}}

QSplitter::handle:vertical {{
    height: 8px;
}}

/* ============================================
   STATUS BAR
   ============================================ */
QStatusBar {{
    background-color: {COLORS["bg_surface"]};
    border-top: 1px solid {COLORS["border"]};
    padding: 2px 6px;
    color: {COLORS["text_secondary"]};
    font-size: 11px;
}}

QStatusBar::item {{
    border: none;
}}

/* ============================================
   MENU BAR
   ============================================ */
QMenuBar {{
    background-color: {COLORS["bg_surface"]};
    border-bottom: 1px solid {COLORS["border"]};
    padding: 2px 4px;
}}

QMenuBar::item {{
    padding: 4px 8px;
    border-radius: 3px;
    color: {COLORS["text_secondary"]};
    font-size: 13px;
    font-weight: {FONT_WEIGHT_MEDIUM};
}}

QMenuBar::item:selected {{
    background-color: {COLORS["bg_hover"]};
    color: {COLORS["text_primary"]};
}}

QMenu {{
    background-color: {COLORS["bg_elevated"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 4px;
    padding: 4px;
}}

QMenu::item {{
    padding: 5px 20px 5px 10px;
    border-radius: 3px;
    font-size: 13px;
}}

QMenu::item:selected {{
    background-color: {COLORS["accent_blue_muted"]};
    color: white;
}}

QMenu::separator {{
    height: 1px;
    background-color: {COLORS["border"]};
    margin: 4px 8px;
}}

/* ============================================
   LABELS
   ============================================ */
QLabel {{
    color: {COLORS["text_primary"]};
    background-color: transparent;
}}

QLabel[heading="true"] {{
    font-size: 15px;
    font-weight: {FONT_WEIGHT_SEMIBOLD};
}}

QLabel[subheading="true"] {{
    font-size: 12px;
    font-weight: {FONT_WEIGHT_MEDIUM};
    color: {COLORS["text_secondary"]};
}}

QLabel[muted="true"] {{
    color: {COLORS["text_muted"]};
    font-size: 11px;
}}

QLabel[monospace="true"] {{
    font-family: {MONO_FONT};
    font-size: 12px;
}}

/* ============================================
   CHECK BOXES
   ============================================ */
QCheckBox {{
    spacing: 6px;
    color: {COLORS["text_primary"]};
}}

QCheckBox::indicator {{
    width: 14px;
    height: 14px;
    border: 1px solid {COLORS["border"]};
    border-radius: 3px;
    background-color: {COLORS["bg_elevated"]};
}}

QCheckBox::indicator:checked {{
    background-color: {COLORS["accent_blue"]};
    border-color: {COLORS["accent_blue"]};
}}

QCheckBox::indicator:hover {{
    border-color: {COLORS["accent_blue"]};
}}

QCheckBox:disabled {{
    color: {COLORS["text_muted"]};
}}

/* ============================================
   DIALOGS
   ============================================ */
QDialog {{
    background-color: {COLORS["bg_base"]};
}}

QMessageBox {{
    background-color: {COLORS["bg_base"]};
}}

QMessageBox QLabel {{
    color: {COLORS["text_primary"]};
}}

/* ============================================
   TOOL TIPS
   ============================================ */
QToolTip {{
    background-color: {COLORS["bg_elevated"]};
    color: {COLORS["text_primary"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 11px;
}}

/* ============================================
   TOOL BAR
   ============================================ */
QToolBar {{
    background-color: {COLORS["bg_surface"]};
    border: none;
    border-bottom: 1px solid {COLORS["border"]};
    padding: 2px;
    spacing: 2px;
}}

QToolBar::separator {{
    width: 1px;
    background-color: {COLORS["border"]};
    margin: 4px 6px;
}}

QToolButton {{
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: 3px;
    padding: 4px;
    color: {COLORS["text_secondary"]};
}}

QToolButton:hover {{
    background-color: {COLORS["bg_hover"]};
    border-color: {COLORS["border"]};
    color: {COLORS["text_primary"]};
}}
"""


def get_tier_color(tier: str) -> str:
    """Get the color for a risk tier."""
    tier_colors = {
        "CRITICAL": COLORS["tier_critical"],
        "HIGH": COLORS["tier_high"],
        "MEDIUM": COLORS["tier_medium"],
        "LOW": COLORS["tier_low"],
        "MINIMAL": COLORS["tier_minimal"],
        "UNKNOWN": COLORS["text_muted"],
    }
    return tier_colors.get(tier.upper(), COLORS["text_muted"])


def get_mono_font() -> str:
    """Get the monospace font family string."""
    return MONO_FONT


def create_font(family: str, size: int, weight: int = 500, monospace: bool = False) -> "QFont":
    """Create a QFont with proper antialiasing for crisp rendering.

    This configures the font with the same quality settings as web browsers,
    including proper antialiasing and hinting for sharp, full-bodied text.

    Args:
        family: Font family name (e.g., "IBM Plex Sans")
        size: Font size in points
        weight: Font weight (400=normal, 500=medium, 600=semibold, 700=bold)
        monospace: If True, use monospace font stack

    Returns:
        QFont configured with high-quality rendering
    """
    from PySide6.QtGui import QFont

    # Map common weight values to QFont.Weight enum
    weight_map = {
        400: QFont.Weight.Normal,
        500: QFont.Weight.Medium,
        550: QFont.Weight.Medium,  # Qt doesn't have 550, use Medium
        600: QFont.Weight.DemiBold,
        700: QFont.Weight.Bold,
    }
    qt_weight = weight_map.get(weight, QFont.Weight.Medium)

    font = QFont(family, size)
    font.setWeight(qt_weight)

    # Enable high-quality antialiasing (like browser ClearType/FreeType rendering)
    font.setStyleStrategy(
        QFont.StyleStrategy.PreferAntialias | QFont.StyleStrategy.PreferQuality
    )
    # Full hinting for sharp pixel alignment
    font.setHintingPreference(QFont.HintingPreference.PreferFullHinting)

    return font
