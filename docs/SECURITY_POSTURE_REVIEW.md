# OpenLabels Security Posture Review

**Date:** 2026-03-03
**Scope:** Architecture-level security analysis — file processing pipeline trust boundaries, defense-in-depth posture, and comparison with commercial DLP platforms (Varonis)
**Complements:** `AUDIT_REPORT.md` (code-level findings), `docs/SECURITY_AUDIT_*.md` (prior audits)

---

## 1. Executive Summary

OpenLabels has strong code-level security (parameterized queries, RLS, CSRF, rate limiting, defusedxml, non-root containers). However, this review identifies **architectural gaps in the file processing pipeline** — the highest-risk attack surface — and areas where the security posture could be hardened with minimal effort.

The platform processes untrusted files from arbitrary sources (network shares, SharePoint, S3, Azure Blob) through format-specific extractors (PyMuPDF, python-docx, openpyxl, python-pptx, extract-msg, Pillow, BeautifulSoup). Each of these libraries has had CVEs. The current approach relies entirely on library-level safety with no pre-processing validation layer.

### How Varonis Handles This

Varonis **does not run antivirus** in its classification pipeline. Their philosophy:
- AV belongs at the endpoint (Windows Defender, CrowdStrike, etc.)
- At the data layer, detect malicious behavior through **User Behavior Analytics** — file access patterns, mass encryption (ransomware), directory crawling, exfiltration
- One exception: DatAlert rules scan for **malicious payloads in Office document metadata** and can auto-quarantine

OpenLabels is not Varonis. Varonis is a managed SaaS with behavioral analytics; OpenLabels is self-hosted open-source software processing files on the operator's infrastructure. This difference matters for the threat model.

---

## 2. File Processing Pipeline — Trust Boundary Analysis

### 2.1 Current Defenses (What's Good)

| Defense | Location | Assessment |
|---------|----------|------------|
| **Decompression bomb protection** | `extractors.py:19-26, 263-300` | Pillow pixel limit (25M), per-format size tracking, `MAX_DECOMPRESSED_SIZE` (200MB), `MAX_EXTRACTION_RATIO` (100x) |
| **Page/row limits** | `constants.py:105-106` | `MAX_DOCUMENT_PAGES=50`, `MAX_SPREADSHEET_ROWS=100,000` |
| **Magic byte validation** | `processor.py:38-122` | Blocks PE/ELF/shebang executables, validates extension vs content-type |
| **File size limit** | `constants.py:108` | `MAX_FILE_SIZE_BYTES=50MB` (enforced at adapter level) |
| **Request body size limit** | `middleware/stack.py:111-160` | 50MB max, chunked encoding restrictions |
| **XXE protection** | `__init__.py:11-12` | Global `defusedxml.defuse_stdlib()` monkey-patch |
| **Container hardening** | `Dockerfile`, `docker-compose.yml` | Non-root user (UID 1000), `cap_drop: ALL`, `security_opt: no-new-privileges`, pinned base image digest |
| **Model integrity** | `detectors/model_integrity.py` | SHA-256 TOFU verification of ML model files |

### 2.2 Gaps in the Pipeline

#### G1. No Content Sanitization Before Extraction (HIGH)

Files from untrusted sources go directly to format-specific parsing libraries:

```
adapter.read_file() → raw bytes → extractors.extract() → fitz.open() / Document() / load_workbook() / ...
```

There is no sanitization, re-encoding, or content disarming step. A crafted PDF exploiting a PyMuPDF vulnerability would be parsed directly.

**Recommendation:** Consider optional ClamAV pre-scan integration (clamd socket) for operators who want it. Not mandatory — follows Varonis's philosophy that AV is the endpoint's job — but valuable for self-hosted deployments where the operator may not have endpoint protection on the scanning server.

#### G2. No Resource Isolation for Extractors (MEDIUM)

All file extraction runs in-process in the worker. A memory-corruption vulnerability in PyMuPDF or Pillow would compromise the entire worker process (which has database credentials, API tokens, etc.).

**Current mitigation:** Docker `cap_drop: ALL` + `no-new-privileges` limits post-exploitation impact.

**Recommendation:** Consider running extractors in a subprocess with `resource.setrlimit()` for memory/CPU caps, or use `seccomp` profiles to restrict syscalls during extraction. The worker agent pool (`core/agents/pool.py`) already provides subprocess infrastructure — extraction could be routed through it.

#### G3. HTML Parsing Without Sanitization (MEDIUM)

`EmailExtractor._html_to_text()` and `HTMLExtractor.extract()` use BeautifulSoup with `html.parser`:

```python
soup = BeautifulSoup(html, "html.parser")  # extractors.py:1009, 1065
```

While the extracted text is used for PII detection (not rendered in a browser), the parsing itself processes untrusted HTML. The `html.parser` is Python's stdlib parser and doesn't handle all malformed HTML edge cases. The code does strip `<script>` and `<style>` tags, which is good.

**Note:** This is low risk since extracted text is never rendered as HTML — it feeds into the detection pipeline as plain text.

#### G4. Legacy Format Extractors Lack Bounds Checking (LOW)

`_extract_legacy_doc()` and `_extract_legacy_ppt()` decode entire binary files as `latin-1`:

```python
text = content.decode("latin-1", errors="ignore")  # extractors.py:318, 799
```

No `MAX_DECOMPRESSED_SIZE` check is applied to these legacy format paths. A 50MB .doc file would produce up to 50MB of decoded text. The 50MB file size limit at the adapter level provides some protection, but the ratio check (`MAX_EXTRACTION_RATIO`) is not applied here.

#### G5. MSG Extraction Uses Broad Exception Catch (LOW)

```python
except Exception as e:  # extractors.py:901
```

`extract_msg.Message()` can raise arbitrary exceptions from the OLE2 parser. The broad catch prevents crashes but also silences potential security-relevant errors (e.g., buffer overflows that happen to raise Python exceptions).

---

## 3. Authentication & Session Security

### 3.1 Strengths

| Control | Details |
|---------|---------|
| **Multi-provider OIDC** | Full OpenID Connect with JWKS validation, RS256-only, 1-hour cache with auto-refresh |
| **Session encryption** | Fernet (AES-128-CBC + HMAC-SHA256), HKDF key derivation, key rotation support |
| **Cookie security** | `HttpOnly`, `SameSite=lax`, `Secure` (via X-Forwarded-Proto detection) |
| **CSRF protection** | Double-submit cookie + origin/referer validation, constant-time comparison |
| **Credential encryption** | Fernet at rest for all stored credentials (API keys, passwords, tokens) |
| **SSRF protection** | `url_validation.py` blocks RFC1918, link-local, loopback for all outbound URLs |

### 3.2 Architecture Notes

- **Auth defaults to `none`** — The `auth.provider` setting defaults to `"none"`, meaning an unconfigured deployment has no authentication. The `validate_production_secret_key` validator catches missing secret keys in production/staging, but `auth.provider` itself is not validated. Prior audit (S20) covers this.

- **Database SSL enforced in production** — The `validate_production_db_ssl` model validator on `Settings` prevents `require_ssl=False` in production/staging. Good.

- **Wildcard CORS + credentials blocked** — The `validate_cors_security` validator raises `ValueError` if wildcard origins are combined with `allow_credentials=True`. Good.

---

## 4. Infrastructure Security

### 4.1 Container Security (Strong)

The Docker Compose production configuration is well-hardened:

- Non-root user (UID 1000)
- `cap_drop: ALL` on all containers
- `security_opt: no-new-privileges`
- Database and Redis on internal network only (no host port bindings)
- API bound to `127.0.0.1:8000` (expects reverse proxy)
- Required secrets via `${VAR:?}` syntax (fails if unset)
- Pinned base image digest for reproducible builds
- Multi-stage build (build deps not in production image)

### 4.2 Dependency Pinning

`pyproject.toml` pins minimum versions with CVE-specific comments:
- `authlib>=1.6.6` — CVE-2025-68158
- `cryptography>=46.0.5` — CVE-2026-26007
- `pillow>=12.1.1` — CVE-2026-25990

The `uv.lock` provides full dependency locking. Good practice.

### 4.3 Error Handling (Strong)

The global exception handler (`error_handlers.py:251-276`) **never leaks internals**:

```python
body = {"error": "INTERNAL_ERROR", "message": "An unexpected error occurred"}
```

Full tracebacks are logged server-side only. SQLAlchemy errors return a generic "database error" message. Validation errors truncate input values >100 chars. OpenAPI docs are disabled in production/staging unless `debug=True`.

### 4.4 Observability Security

Sentry integration (`sentry.py`) scrubs sensitive fields from:
- Request headers, cookies, query strings, body
- Exception values (regex-based scrub of `field=value` patterns)
- Stack frame local variables
- Breadcrumb data

`send_default_pii=False` is set. Good.

---

## 5. Comparison with Varonis Architecture

| Capability | Varonis | OpenLabels | Gap |
|-----------|---------|------------|-----|
| **Malware scanning** | No AV — behavioral detection via DatAlert UBA | No AV — no behavioral detection | OpenLabels has neither. Optional ClamAV integration would provide parity with "neither" position. |
| **File content validation** | Collectors extract metadata + classify in customer boundary | Magic byte validation + format-specific extraction | OpenLabels's magic byte check is solid. |
| **Decompression bomb protection** | Not publicly documented | Explicit limits (200MB decompressed, 100x ratio, 50-page PDF, 100K-row spreadsheet) | OpenLabels is more transparent about this. |
| **XXE protection** | Not publicly documented | Global `defusedxml.defuse_stdlib()` | Explicitly handled. |
| **Credential isolation** | SaaS — customer data never leaves customer boundary | Self-hosted — operator controls boundary, Fernet encryption at rest | Different model, appropriate for each. |
| **Ransomware detection** | DatAlert auto-lockout on mass encryption patterns | None | Not in scope for a classification tool. |
| **RLS / tenant isolation** | Multi-tenant SaaS with strict isolation | PostgreSQL RLS on 23 tables + restricted app role | Strong for self-hosted. |
| **Data residency** | Customer-local collectors, metadata-only in cloud | Fully self-hosted | Advantage for compliance-sensitive orgs. |

---

## 6. Recommendations (Priority Order)

### P0 — Address Immediately

These are net-new findings not covered by `AUDIT_REPORT.md`:

1. **Add extraction timeout** — If PyMuPDF or openpyxl hangs on a crafted file, the worker thread blocks indefinitely. Wrap `extractor.extract()` in a timeout (e.g., `asyncio.wait_for()` or `signal.alarm()` in the agent subprocess).

2. **Apply `MAX_DECOMPRESSED_SIZE` to legacy .doc/.ppt extractors** — Currently these paths (`_extract_legacy_doc`, `_extract_legacy_ppt`) have no size limit on the decoded output.

### P1 — Next Sprint

3. **Consider subprocess isolation for extractors** — Route file extraction through the existing agent pool (`core/agents/pool.py`) so that a library vulnerability doesn't compromise the worker's database credentials. The pool infrastructure already exists.

4. **Optional ClamAV integration** — Add a `clamd` socket scan before extraction for operators who want it. Make it opt-in via config:
   ```yaml
   security:
     clamav_enabled: false
     clamav_socket: /var/run/clamav/clamd.ctl
   ```

### P2 — Backlog

5. **Narrow the `except Exception` in MSG extraction** — Replace with specific `extract_msg` exception types.

6. **Add extraction metrics** — Track extraction duration, file sizes, and failure rates in Prometheus. Anomalous spikes could indicate adversarial input.

7. **Document the trust model** — Add a `docs/SECURITY_MODEL.md` explaining:
   - What files OpenLabels trusts vs. treats as untrusted
   - Where AV scanning fits (answer: at the endpoint, not in OpenLabels)
   - Container isolation as the primary defense boundary
   - What an operator should configure for a hardened deployment
