"""Authorization acknowledgment gate for SentinelX scans.

SentinelX performs active network interactions against the target (HTTP
fetches, TCP port probes), not purely passive lookups. This module blocks a
scan from starting until the operator has acknowledged the authorization
requirement in LEGAL.md, once per domain.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

AUTHORIZATION_NOTICE = (
    "SentinelX performs active checks (HTTP fetches, TCP port probes) against\n"
    "  the target, not only passive lookups. You must own this domain or hold\n"
    "  explicit written authorization to assess it. See LEGAL.md for the full\n"
    "  authorization and legal-compliance requirements."
)


class AuthorizationDeclined(Exception):
    """Raised when the operator declines the authorization prompt."""


def _consent_path(consent_root: str) -> Path:
    return Path(consent_root) / "consent.json"


def _load_consent(consent_root: str) -> dict[str, Any]:
    path = _consent_path(consent_root)
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
            return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _record_consent(consent_root: str, domain: str, email: str | None) -> None:
    path = _consent_path(consent_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    store = _load_consent(consent_root)
    store[domain] = {
        "acknowledged_at": datetime.now(timezone.utc).isoformat(),
        "analyst_email": email or None,
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(store, handle, indent=2)


def has_acknowledged(consent_root: str, domain: str) -> bool:
    key = (domain or "").strip().lower()
    return key in _load_consent(consent_root)


def record_acknowledgment(consent_root: str, domain: str, email: str | None = None) -> None:
    """Record acknowledgment without prompting. Used by --i-have-authorization and the GUI."""
    key = (domain or "").strip().lower()
    if key:
        _record_consent(consent_root, key, email)


def ensure_authorization(
    *,
    domain: str,
    consent_root: str,
    email: str | None = None,
    non_interactive: bool = False,
) -> None:
    """Block until authorization is acknowledged for *domain*.

    Acknowledgment is cached per-domain in ``consent_root/consent.json`` so a
    repeat scan of the same domain does not reprompt. Pass
    ``non_interactive=True`` (CLI ``--i-have-authorization``, or any run
    launched from the GUI, which collects the same confirmation itself) to
    record acknowledgment without a terminal prompt.
    """
    key = (domain or "").strip().lower()
    if not key:
        return
    if has_acknowledged(consent_root, key):
        return

    if non_interactive:
        record_acknowledgment(consent_root, key, email)
        LOGGER.info("Authorization acknowledged (non-interactive) for %s", key)
        return

    print("\n" + "=" * 60)
    print("  SentinelX - Authorization Required")
    print("=" * 60)
    print(f"  Target: {key}")
    print()
    print(" ", AUTHORIZATION_NOTICE)
    print()
    try:
        answer = input('  Type "yes" to confirm authorization and continue: ').strip().lower()
    except EOFError:
        answer = ""

    if answer != "yes":
        print("\n  Authorization not confirmed. Scan cancelled.\n")
        raise AuthorizationDeclined(f"Authorization not confirmed for {key}.")

    record_acknowledgment(consent_root, key, email)
    LOGGER.info("Authorization acknowledged (interactive) for %s", key)
    print()
