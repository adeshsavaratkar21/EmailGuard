"""
Authentication Analyzer - EmailGuard
======================================
Orchestrates SPF, DKIM, DMARC, S/MIME, and PGP checks and combines results
into the structured authentication report.

This module is the entry point called by service.py.  It:
  1. Runs independent SPF evaluation (or reports CONTEXT_UNAVAILABLE).
  2. Independently verifies DKIM signatures from raw bytes + DNS.
  3. Computes DMARC alignment from verified SPF/DKIM outcomes + DNS policy.
  4. Verifies S/MIME signatures via OpenSSL CMS.
  5. Verifies PGP/OpenPGP signatures via GnuPG.

Each method exposes reported_status (from receiver headers) and verified_status
(from EmailGuard's own check) separately.  The distinction is never elided.

Receiver-reported Authentication-Results values inside an uploaded .eml file
can be forged by an attacker.  They are labelled as receiver_reported and must
not be presented as EmailGuard's own verification.
"""

from __future__ import annotations

import os
import re

from ..config import ENABLE_DKIM_DNS_LOOKUPS
from .dkim_verifier import verify_dkim
from .dmarc_evaluator import evaluate_dmarc
from .pgp_verifier import verify_pgp
from .smime_verifier import verify_smime
from .spf_checker import check_spf

# operator_context may be injected by the API for local testing (see main.py).
# These are never treated as independently trusted receiver data.


def _extract_reported_dmarc(auth_headers: list[str]) -> tuple[str | None, str | None]:
    for h in auth_headers:
        m = re.search(
            r"\bdmarc\s*=\s*(pass|fail|none|quarantine|reject|unknown|policy)",
            h, re.IGNORECASE,
        )
        if m:
            status = m.group(1).upper()
            policy_m = re.search(r"\bpolicy\s*=\s*([a-z]+)", h, re.IGNORECASE)
            policy = policy_m.group(1).lower() if policy_m else None
            return status, policy
    return None, None


def analyze_authentication(
    raw: bytes,
    parsed: dict,
    operator_context: dict | None = None,
) -> dict:
    """
    Run all authentication checks and return a unified report.

    Parameters
    ----------
    raw             : original .eml bytes
    parsed          : output of parse_eml()
    operator_context: optional dict with keys client_ip, smtp_mailfrom, helo
                      for local SPF testing (labelled operator_supplied)

    Returns
    -------
    dict with keys: spf, dkim, dmarc, smime, pgp, dns_records, caveat
    """
    auth_headers: list[str] = parsed.get("headers", {}).get("authentication_results", [])

    # ─── SPF ─────────────────────────────────────────────────────────────────
    spf_result = check_spf(parsed, operator_context=operator_context)

    # ─── DKIM ────────────────────────────────────────────────────────────────
    dkim_result = verify_dkim(raw, parsed)

    # ─── DMARC ───────────────────────────────────────────────────────────────
    from_header = parsed.get("sender", "")
    visible_domain: str | None = None
    if "@" in from_header:
        visible_domain = from_header.rsplit("@", 1)[1].lower().strip("> ")
    # Provide receiver-reported dmarc to evaluator via side-channel in spf_result
    reported_dmarc_status, reported_dmarc_policy = _extract_reported_dmarc(auth_headers)
    spf_result["_dmarc_reported_status"] = reported_dmarc_status
    spf_result["_dmarc_reported_policy"] = reported_dmarc_policy

    # Envelope sender domain for SPF alignment
    spf_env_domain: str | None = None
    mf = (spf_result.get("evidence") or {}).get("smtp_mailfrom", "")
    if mf and "@" in mf:
        spf_env_domain = mf.rsplit("@", 1)[1].lower()

    dmarc_result = evaluate_dmarc(
        from_domain=visible_domain,
        spf_result=spf_result,
        dkim_result=dkim_result,
        spf_envelope_domain=spf_env_domain,
    )

    # ─── S/MIME ──────────────────────────────────────────────────────────────
    smime_result = verify_smime(raw, parsed)

    # ─── PGP ─────────────────────────────────────────────────────────────────
    pgp_result = verify_pgp(raw, parsed)

    # ─── DNS records (informational) ─────────────────────────────────────────
    dns_enabled = os.getenv("EMAILGUARD_DNS_LOOKUPS", "false").lower() in {"1", "true", "yes"}
    from .dns_records import lookup_sender_domain_records
    dns_records = lookup_sender_domain_records(visible_domain, dns_enabled)

    # Strip internal side-channel keys
    spf_result.pop("_dmarc_reported_status", None)
    spf_result.pop("_dmarc_reported_policy", None)

    return {
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result,
        "smime": smime_result,
        "pgp": pgp_result,
        "dns_records": dns_records,
        "caveat": (
            "Authentication-Results headers inside an uploaded .eml file can be forged. "
            "Values labelled 'receiver_reported' are claims from the message itself, not "
            "EmailGuard's independent verification. 'independent' means EmailGuard itself "
            "performed the check. 'unavailable' means required evidence was not present."
        ),
    }
