"""PDF export module for SentinelX."""

from __future__ import annotations

import logging
import re
from pathlib import Path

LOGGER = logging.getLogger(__name__)

CSS_VAR_MAP: dict[str, str] = {
    "--ink": "#1c2530",
    "--ink-soft": "#55606d",
    "--ink-faint": "#8993a0",
    "--line": "#d6dbe0",
    "--paper": "#f4f5f3",
    "--card": "#ffffff",
    "--accent": "#8a3b1f",
    "--accent-soft": "#f4e5db",
    "--critical": "#9c2b2b",
    "--critical-bg": "#f8e6e2",
    "--high": "#b5551f",
    "--high-bg": "#fbeee1",
    "--medium": "#a9781f",
    "--medium-bg": "#f8f0d9",
    "--low": "#2f7a4f",
    "--low-bg": "#e7f3ea",
}

CSS_STRIPLIST: list[str] = [
    r"--[\w-]+\s*:[^;]+;",
    r'@import\s+url\(["\']https://fonts\.googleapis[^)]+\)[^;]*;',
    r"-webkit-font-smoothing\s*:[^;]+;",
    r"transition\s*:[^;]+;",
    r"scroll-behavior\s*:[^;]+;",
    r"letter-spacing\s*:[^;]+;",
]

LINK_STRIPLIST: list[str] = [
    r'<link[^>]+fonts\.googleapis\.com[^>]*>',
    r'<link[^>]+fonts\.gstatic\.com[^>]*>',
]


def _resolve_css_vars(html: str) -> str:
    def replacer(match: re.Match[str]) -> str:
        var_name = match.group(1).strip()
        fallback = match.group(2)
        literal = CSS_VAR_MAP.get(var_name)
        if literal:
            return literal
        if fallback:
            return fallback.strip()
        return "#cccccc"

    return re.sub(r"var\(\s*(--[\w-]+)(?:\s*,\s*([^)]+))?\s*\)", replacer, html)


def _strip_incompatible_css(html: str) -> str:
    for pattern in CSS_STRIPLIST:
        html = re.sub(pattern, "", html, flags=re.IGNORECASE | re.DOTALL)
    for pattern in LINK_STRIPLIST:
        html = re.sub(pattern, "", html, flags=re.IGNORECASE | re.DOTALL)
    return html


def _add_pdf_base_styles(html: str) -> str:
    pdf_styles = (
        "<style>"
        "body { font-family: Helvetica, Arial, sans-serif; font-size: 11pt; color: #0f172a; background: #f8fafc; }"
        "h1,h2,h3,h4,h5,h6 { font-family: Helvetica, Arial, sans-serif; }"
        "code, pre, .mono { font-family: Courier, 'Courier New', monospace; }"
        "</style>"
    )
    return html.replace("<head>", "<head>\n" + pdf_styles, 1)


def _preprocess_html_for_xhtml2pdf(html_path: str) -> str:
    with open(html_path, "r", encoding="utf-8") as handle:
        html = handle.read()
    html = _strip_incompatible_css(html)
    html = _resolve_css_vars(html)
    html = _add_pdf_base_styles(html)
    return html


def _export_with_xhtml2pdf(html_path: str, pdf_path: str) -> bool:
    try:
        from xhtml2pdf import pisa  # noqa: PLC0415
    except ImportError:
        LOGGER.debug("xhtml2pdf not installed.")
        return False

    try:
        preprocessed = _preprocess_html_for_xhtml2pdf(html_path)
        html_file = Path(html_path).resolve()
        with open(pdf_path, "wb") as dest:
            result = pisa.CreatePDF(
                preprocessed,
                dest=dest,
                encoding="utf-8",
                base_dir=str(html_file.parent),
            )
        if result.err:
            LOGGER.debug("xhtml2pdf reported %d non-fatal warning(s).", result.err)
        return Path(pdf_path).exists() and Path(pdf_path).stat().st_size > 1000
    except Exception as exc:
        LOGGER.warning("xhtml2pdf export failed: %s", exc)
        return False


def _export_with_weasyprint(html_path: str, pdf_path: str) -> bool:
    try:
        from weasyprint import HTML as WeasyHTML  # noqa: PLC0415
    except (ImportError, Exception):
        LOGGER.debug("WeasyPrint not available.")
        return False

    try:
        html_file = Path(html_path).resolve()
        WeasyHTML(filename=str(html_file)).write_pdf(pdf_path)
        return Path(pdf_path).exists() and Path(pdf_path).stat().st_size > 1000
    except Exception as exc:
        LOGGER.warning("WeasyPrint export failed: %s", exc)
        return False


def _export_with_minimal_placeholder(pdf_path: str) -> bool:
    try:
        content = b"%PDF-1.4\n"
        objects = []
        offsets = []

        def add_obj(obj_bytes: bytes) -> None:
            offsets.append(len(content) + sum(len(item) for item in objects))
            objects.append(obj_bytes)

        add_obj(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
        add_obj(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
        add_obj(
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
        )
        stream = b"BT /F1 14 Tf 72 740 Td (SentinelX PDF fallback report generated.) Tj ET"
        add_obj(
            b"4 0 obj\n<< /Length "
            + str(len(stream)).encode("ascii")
            + b" >>\nstream\n"
            + stream
            + b"\nendstream\nendobj\n"
        )
        add_obj(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

        body = b"".join(objects)
        xref_start = len(content) + len(body)
        xref = [b"xref\n0 6\n0000000000 65535 f \n"]
        for offset in offsets:
            xref.append(f"{offset:010d} 00000 n \n".encode("ascii"))
        trailer = (
            b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n"
            + str(xref_start).encode("ascii")
            + b"\n%%EOF\n"
        )
        with open(pdf_path, "wb") as handle:
            handle.write(content + body + b"".join(xref) + trailer)
        return Path(pdf_path).exists() and Path(pdf_path).stat().st_size > 200
    except Exception as exc:
        LOGGER.warning("Minimal PDF placeholder generation failed: %s", exc)
        return False


def export_pdf(html_path: str, pdf_path: str = "final_report.pdf") -> dict[str, str | None]:
    """Convert an HTML report file to PDF and return structured export metadata."""
    html_file = Path(html_path).resolve()
    if not html_file.exists():
        LOGGER.error("HTML report not found at %s - cannot generate PDF.", html_path)
        return {"path": None, "status": "skipped", "engine": "missing_html"}

    LOGGER.info("Exporting PDF: %s -> %s", html_path, pdf_path)

    if _export_with_xhtml2pdf(html_path, pdf_path):
        LOGGER.info("PDF export successful via xhtml2pdf: %s", pdf_path)
        return {"path": pdf_path, "status": "full_pdf", "engine": "xhtml2pdf"}

    LOGGER.info("Trying WeasyPrint as fallback...")
    if _export_with_weasyprint(html_path, pdf_path):
        LOGGER.info("PDF export successful via WeasyPrint: %s", pdf_path)
        return {"path": pdf_path, "status": "full_pdf", "engine": "weasyprint"}

    LOGGER.info("Trying minimal PDF placeholder fallback...")
    if _export_with_minimal_placeholder(pdf_path):
        LOGGER.info("PDF placeholder generated: %s", pdf_path)
        return {"path": pdf_path, "status": "placeholder_pdf", "engine": "placeholder"}

    LOGGER.warning("PDF export failed. Install xhtml2pdf or WeasyPrint for a full export.")
    return {"path": None, "status": "skipped", "engine": "unavailable"}
