# Dependency Documentation

This document tracks direct and known transitive dependencies for supply chain security awareness.

## Security Fix (MED-012)

This file addresses the security audit finding that transitive dependencies were unmanaged.
Knowing what's in your dependency tree helps identify when CVEs affect your project.

## Direct Dependencies

### Required (always installed)
| Package | Version | Purpose |
|---------|---------|---------|
| regex | >=2023.0.0,<2025.0.0 | ReDoS timeout protection |

### Optional Dependencies

#### PDF Processing (`pip install openlabels[pdf]`)
| Package | Version | Purpose |
|---------|---------|---------|
| pymupdf | >=1.23.11,<1.25.0 | PDF text extraction |

**Known Transitive Dependencies:**
- `pymupdfb` - PyMuPDF binary libraries

#### Office Documents (`pip install openlabels[office]`)
| Package | Version | Purpose |
|---------|---------|---------|
| python-docx | >=1.0.0,<2.0.0 | DOCX extraction |
| openpyxl | >=3.1.0,<4.0.0 | XLSX extraction |
| xlrd | >=2.0.0,<3.0.0 | XLS extraction |
| striprtf | >=0.0.26,<1.0.0 | RTF extraction |

**Known Transitive Dependencies:**
- `lxml` - XML parsing (via python-docx, openpyxl)
- `et_xmlfile` - XML file handling (via openpyxl)

#### Image Processing (`pip install openlabels[images]`)
| Package | Version | Purpose |
|---------|---------|---------|
| pillow | >=10.3.0,<11.0.0 | Image handling |

**Known Transitive Dependencies:**
- None (Pillow is self-contained with C extensions)

#### OCR (`pip install openlabels[ocr]`)
| Package | Version | Purpose |
|---------|---------|---------|
| numpy | >=1.24.0,<2.0.0 | Array operations |
| onnxruntime | >=1.16.0,<2.0.0 | ML inference |
| rapidocr-onnxruntime | >=1.3.0,<2.0.0 | OCR engine |
| intervaltree | >=3.1.0,<4.0.0 | Interval operations |

**Known Transitive Dependencies:**
- `protobuf` - Protocol buffers (via onnxruntime)
- `flatbuffers` - Serialization (via onnxruntime)
- `sympy` - Symbolic math (via onnxruntime)
- `coloredlogs` - Logging (via onnxruntime)
- `packaging` - Version parsing (via onnxruntime)
- `opencv-python` or `opencv-python-headless` - Image processing (via rapidocr)
- `pyclipper` - Polygon clipping (via rapidocr)
- `shapely` - Geometric operations (via rapidocr)
- `sortedcontainers` - Sorted collections (via intervaltree)

#### Performance (`pip install openlabels[performance]`)
| Package | Version | Purpose |
|---------|---------|---------|
| pyahocorasick | >=2.0.0,<3.0.0 | Fast string matching |

**Known Transitive Dependencies:**
- None (C extension only)

## Security Recommendations

1. **Run `pip-audit` regularly** to check for CVEs in all dependencies:
   ```bash
   pip install pip-audit
   pip-audit
   ```

2. **Generate a lockfile** for reproducible builds:
   ```bash
   pip install pip-tools
   pip-compile pyproject.toml -o requirements.lock
   ```

3. **Monitor for updates** to these high-risk transitive dependencies:
   - `protobuf` - Frequently has security updates
   - `lxml` - XML parsing can have vulnerabilities
   - `numpy` - Occasionally has buffer overflow fixes

## CVE History

### Fixed in Current Minimum Versions
- **CVE-2024-28219** (Pillow <10.3.0): Buffer overflow in _imagingcms.c
- **CVE-2023-51105** (MuPDF <1.23.11): Security vulnerability
- **CVE-2023-51104** (MuPDF <1.23.11): Security vulnerability

### Monitoring
The security audit report (SECURITY_AUDIT_REPORT.md) mentioned CVE-2024-29054 for PyMuPDF,
but this CVE is actually for Microsoft Defender for IoT, not PyMuPDF. The MuPDF/PyMuPDF
vulnerabilities are tracked separately.

## Updating This Document

When adding new dependencies:
1. Add to the appropriate section above
2. Run `pip show <package>` to identify transitive dependencies
3. Update the "Known Transitive Dependencies" list
4. Run `pip-audit` to check for known CVEs
