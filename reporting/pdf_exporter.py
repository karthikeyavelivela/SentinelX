"""PDF export module — converts the HTML report to a PDF audit document.

Strategy (in priority order):
1. xhtml2pdf — pure Python, no system dependencies (preferred on Windows).
   Pre-processes HTML to resolve CSS custom properties, which xhtml2pdf cannot handle.
2. WeasyPrint — high-fidelity but requires GTK3 on Windows (fallback).
3. Skip gracefully with a warning if neither is available.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

LOGGER = logging.getLogger(__name__)

# Map of CSS custom property names → literal hex/rgb values used in the template
CSS_VAR_MAP: dict[str, str] = {
    "--brand": "#0f172a",
    "--brand-light": "#1e293b",
    "--accent": "#3b82f6",
    "--accent-muted": "#dbeafe",
    "--bg": "#f8fafc",
    "--card": "#ffffff",
    "--text": "#0f172a",
    "--text-muted": "#64748b",
    "--border": "#e2e8f0",
    "--high": "#dc2626",
    "--high-bg": "#fef2f2",
    "--high-border": "#fecaca",
    "--medium": "#d97706",
    "--medium-bg": "#fffbeb",
    "--medium-border": "#fde68a",
    "--low": "#16a34a",
    "--low-bg": "#f0fdf4",
    "--low-border": "#bbf7d0",
    "--score-low": "#16a34a",
    "--score-medium": "#d97706",
    "--score-high": "#dc2626",
    "--purple": "#7c3aed",
    "--purple-bg": "#f5f3ff",
    "--purple-border": "#ddd6fe",
}

# xhtml2pdf-incompatible CSS patterns to strip entirely
CSS_STRIPLIST: list[str] = [
    # CSS custom property declarations
    r"--[\w-]+\s*:[^;]+;",
    # @font-face blocks referencing Google Fonts (causes CSS parse warnings)
    r'@import\s+url\(["\']https://fonts\.googleapis[^)]+\)[^;]*;',
    # -webkit-font-smoothing
    r"-webkit-font-smoothing\s*:[^;]+;",
    # transition properties (not supported)
    r"transition\s*:[^;]+;",
    # scroll-behavior
    r"scroll-behavior\s*:[^;]+;",
    # letter-spacing (can cause issues in some ReportLab builds)
    # Keep it — most builds handle it fine
]

# Google Fonts link tags to remove from <head>
LINK_STRIPLIST: list[str] = [
    r'<link[^>]+fonts\.googleapis\.com[^>]*>',
    r'<link[^>]+fonts\.gstatic\.com[^>]*>',
]


def _resolve_css_vars(html: str) -> str:
    """Replace var(--token) usage with literal values throughout the HTML."""
    def replacer(match: re.Match) -> str:
        var_name = match.group(1).strip()
        fallback = match.group(2)  # group 2 = fallback value after comma, if any
        literal = CSS_VAR_MAP.get(var_name)
        if literal:
            return literal
        if fallback:
            return fallback.strip()
        return "#cccccc"  # safe grey for any unknown var

    # var(--name) or var(--name, fallback)  — 2 capture groups only
    return re.sub(r"var\(\s*(--[\w-]+)(?:\s*,\s*([^)]+))?\s*\)", replacer, html)


def _strip_incompatible_css(html: str) -> str:
    """Remove / simplify CSS that xhtml2pdf cannot parse."""
    for pattern in CSS_STRIPLIST:
        html = re.sub(pattern, "", html, flags=re.IGNORECASE | re.DOTALL)
    for pattern in LINK_STRIPLIST:
        html = re.sub(pattern, "", html, flags=re.IGNORECASE | re.DOTALL)
    return html


def _add_pdf_base_styles(html: str) -> str:
    """Inject xhtml2pdf-friendly base font stack after the opening <head> tag."""
    pdf_styles = (
        "<style>"
        "body { font-family: Helvetica, Arial, sans-serif; font-size: 11pt; color: #0f172a; background: #f8fafc; }"
        "h1,h2,h3,h4,h5,h6 { font-family: Helvetica, Arial, sans-serif; }"
        "code, pre, .mono { font-family: Courier, 'Courier New', monospace; }"
        "</style>"
    )
    return html.replace("<head>", "<head>\n" + pdf_styles, 1)


def _preprocess_html_for_xhtml2pdf(html_path: str) -> str:
    """Read HTML and pre-process it to be xhtml2pdf-compatible."""
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    html = _strip_incompatible_css(html)
    html = _resolve_css_vars(html)
    html = _add_pdf_base_styles(html)
    return html


def _export_with_xhtml2pdf(html_path: str, pdf_path: str) -> bool:
    """Attempt PDF generation via xhtml2pdf (pure Python, no GTK needed)."""
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

        if Path(pdf_path).exists() and Path(pdf_path).stat().st_size > 1000:
            return True

        LOGGER.debug("xhtml2pdf produced an empty/tiny file — skipping.")
        return False

    except Exception as exc:
        LOGGER.warning("xhtml2pdf export failed: %s", exc)
        return False


def _export_with_weasyprint(html_path: str, pdf_path: str) -> bool:
    """Attempt PDF generation via WeasyPrint (requires GTK3 on Windows)."""
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


def export_pdf(html_path: str, pdf_path: str = "final_report.pdf") -> str | None:
    """
    Convert an HTML report file to PDF.

    Tries xhtml2pdf first (pure Python, Windows-compatible),
    then falls back to WeasyPrint. Returns the pdf_path on success, None if both fail.
    """
    html_file = Path(html_path).resolve()

    if not html_file.exists():
        LOGGER.error("HTML report not found at %s — cannot generate PDF.", html_path)
        return None

    LOGGER.info("Exporting PDF: %s → %s", html_path, pdf_path)

    if _export_with_xhtml2pdf(html_path, pdf_path):
        LOGGER.info("PDF export successful via xhtml2pdf: %s", pdf_path)
        return pdf_path

    LOGGER.info("Trying WeasyPrint as fallback...")
    if _export_with_weasyprint(html_path, pdf_path):
        LOGGER.info("PDF export successful via WeasyPrint: %s", pdf_path)
        return pdf_path

    LOGGER.warning(
        "PDF export failed. Install xhtml2pdf: pip install xhtml2pdf"
    )
    return None
