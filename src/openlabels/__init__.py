"""
OpenLabels - Open Source Data Classification & Auto-Labeling Platform

This package provides:
- Server: FastAPI-based classification and labeling server
- CLI: Command-line administration tools
"""

# Security: Monkey-patch stdlib XML parsers to block XXE attacks globally.
# This must happen before any other import that might use xml.etree, xml.sax, etc.
import defusedxml
defusedxml.defuse_stdlib()

__version__ = "1.0.0"
__author__ = "Chillbot.io"
