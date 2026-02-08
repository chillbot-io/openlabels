"""System diagnostic checks."""

from __future__ import annotations

import shutil
import sys
from typing import Any

import click

from openlabels.cli.base import common_options, format_option, server_options
from openlabels.cli.output import OutputFormatter


@click.command("doctor")
@common_options
@server_options
@format_option(["table", "json"])
def doctor(
    output_format: str,
    quiet: bool,
    server: str,
    token: str | None,
) -> None:
    """Run diagnostic checks on the OpenLabels installation."""
    fmt = OutputFormatter(output_format, quiet)
    checks: list[dict[str, Any]] = []

    checks.append(_check_python())
    checks.append(_check_server(server, token))
    checks.append(_check_database(server, token))
    checks.append(_check_ml())
    checks.append(_check_ocr())
    checks.append(_check_rust())
    checks.append(_check_mip())

    fmt.print_table(checks, columns=["check", "status", "detail"])

    failed = [c for c in checks if c["status"] == "FAIL"]
    if failed:
        fmt.print_error(f"{len(failed)} check(s) failed")
        raise SystemExit(1)
    else:
        fmt.print_success("All checks passed")


def _check_python() -> dict[str, str]:
    v = sys.version_info
    status = "OK" if v >= (3, 10) else "FAIL"
    return {
        "check": "Python",
        "status": status,
        "detail": f"{v.major}.{v.minor}.{v.micro}",
    }


def _check_server(server: str, token: str | None) -> dict[str, str]:
    try:
        import httpx

        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        r = httpx.get(f"{server}/health", timeout=5, headers=headers)
        if r.status_code == 200:
            return {
                "check": "API Server",
                "status": "OK",
                "detail": f"Connected to {server}",
            }
        return {
            "check": "API Server",
            "status": "FAIL",
            "detail": f"HTTP {r.status_code}",
        }
    except Exception as e:
        return {"check": "API Server", "status": "FAIL", "detail": str(e)}


def _check_database(server: str, token: str | None) -> dict[str, str]:
    try:
        import httpx

        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        r = httpx.get(
            f"{server}/api/v1/health/status",
            timeout=5,
            headers=headers,
        )
        if r.status_code == 200:
            data = r.json()
            db_status = data.get("db", "unknown")
            return {
                "check": "Database",
                "status": "OK" if db_status == "healthy" else "FAIL",
                "detail": data.get("db_text", str(db_status)),
            }
        return {
            "check": "Database",
            "status": "WARN",
            "detail": f"Health endpoint returned {r.status_code}",
        }
    except Exception as e:
        return {"check": "Database", "status": "FAIL", "detail": str(e)}


def _check_ml() -> dict[str, str]:
    try:
        import onnxruntime

        providers = onnxruntime.get_available_providers()
        return {
            "check": "ONNX Runtime",
            "status": "OK",
            "detail": f"Providers: {providers}",
        }
    except ImportError:
        return {
            "check": "ONNX Runtime",
            "status": "WARN",
            "detail": "Not installed (ML detection disabled)",
        }


def _check_ocr() -> dict[str, str]:
    if shutil.which("tesseract"):
        return {
            "check": "OCR (Tesseract)",
            "status": "OK",
            "detail": "tesseract found in PATH",
        }
    try:
        from rapidocr_onnxruntime import RapidOCR  # noqa: F401

        return {
            "check": "OCR (RapidOCR)",
            "status": "OK",
            "detail": "RapidOCR available",
        }
    except ImportError:
        return {
            "check": "OCR",
            "status": "WARN",
            "detail": "No OCR engine available",
        }


def _check_rust() -> dict[str, str]:
    try:
        from openlabels_matcher import FileFilter  # noqa: F401

        return {
            "check": "Rust Extensions",
            "status": "OK",
            "detail": "openlabels_matcher loaded",
        }
    except ImportError:
        return {
            "check": "Rust Extensions",
            "status": "WARN",
            "detail": "Using Python fallback",
        }


def _check_mip() -> dict[str, str]:
    try:
        import clr  # noqa: F401

        return {
            "check": "MIP SDK",
            "status": "OK",
            "detail": "pythonnet available",
        }
    except ImportError:
        return {
            "check": "MIP SDK",
            "status": "WARN",
            "detail": "pythonnet not installed (labeling disabled)",
        }
