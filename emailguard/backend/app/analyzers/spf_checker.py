"""
SPF Checker - EmailGuard
========================
Performs a real SPF evaluation using pyspf when trustworthy SMTP context is
available, or returns CONTEXT_UNAVAILABLE when it is not.

DESIGN PRINCIPLES
-----------------
* A fresh SPF evaluation needs the actual connecting SMTP peer IP, the SMTP
  envelope-sender (MAIL FROM), and optionally the HELO identity.
* These can only come from a trusted source: a configured trusted receiving
  system's Authentication-Results header identified by a known authserv-id, or
  operator-supplied transport context (labelled as such).
* An uploaded .eml never reliably contains the trusted connecting IP.
* Unknown / absent / DNS-error / SPF result codes are distinct statuses.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

TRUSTED_AUTHSERV_IDS: frozenset[str] = frozenset(
    s.strip().lower()
    for s in os.getenv("EMAILGUARD_TRUSTED_AUTHSERV_IDS", "").split(",")
    if s.strip()
)

SPF_DNS_TIMEOUT: float = float(os.getenv("EMAILGUARD_SPF_DNS_TIMEOUT", "3.0"))
SPF_DNS_LIMIT: int = int(os.getenv("EMAILGUARD_SPF_DNS_LIMIT", "10"))

_CLIENT_IP_RE = re.compile(r"\bclient-ip\s*=\s*([0-9a-fA-F:.]+)", re.IGNORECASE)
_MAILFROM_RE = re.compile(r"\bsmtp\.mailfrom\s*=\s*([^\s;]+)", re.IGNORECASE)
_HELO_RE = re.compile(r"\bsmtp\.helo\s*=\s*([^\s;]+)", re.IGNORECASE)
_AUTHSERV_RE = re.compile(r"^([^\s;]+)", re.IGNORECASE)


def _is_public_ip(addr_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(addr_str)
        return not (
            addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified
        )
    except ValueError:
        return False


def _extract_from_auth_results(
    auth_headers: list[str],
    trusted_ids: frozenset[str],
) -> tuple[dict[str, str | None], str | None]:
    fields: dict[str, str | None] = {"client_ip": None, "smtp_mailfrom": None, "helo": None}
    provenance: str | None = None
    for header in auth_headers:
        m = _AUTHSERV_RE.match(header.strip())
        authserv_id = m.group(1).lower() if m else None
        is_trusted = authserv_id in trusted_ids if (authserv_id and trusted_ids) else False
        if not is_trusted:
            continue
        ip_m = _CLIENT_IP_RE.search(header)
        mf_m = _MAILFROM_RE.search(header)
        helo_m = _HELO_RE.search(header)
        if ip_m or mf_m:
            if ip_m:
                fields["client_ip"] = ip_m.group(1)
            if mf_m:
                fields["smtp_mailfrom"] = mf_m.group(1).strip("<>")
            if helo_m:
                fields["helo"] = helo_m.group(1).strip()
            provenance = authserv_id
            break
    return fields, provenance


def check_spf(
    parsed: dict,
    operator_context: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Attempt a real SPF evaluation.

    Returns dict with keys:
        status               - PASS|FAIL|SOFTFAIL|NEUTRAL|NONE|TEMPERROR|PERMERROR|
                               CONTEXT_UNAVAILABLE|SPF_LIBRARY_UNAVAILABLE|DNS_ERROR
        verification_type    - independent|receiver_reported|
                               operator_supplied_context|unavailable
        reported_status      - value from Authentication-Results if any
        verified_status      - result of EmailGuard own evaluation, or None
        evidence             - summary of inputs used (no private data)
        missing_prerequisites - list of missing fields if not runnable
        explanation          - human-readable reason
        authserv_id_used     - which trusted authserv-id was used, or None
    """
    auth_headers: list[str] = parsed.get("headers", {}).get("authentication_results", [])

    reported_status: str | None = None
    for h in auth_headers:
        m = re.search(
            r"\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy)",
            h, re.IGNORECASE,
        )
        if m:
            reported_status = m.group(1).upper()
            break

    fields, provenance = _extract_from_auth_results(auth_headers, TRUSTED_AUTHSERV_IDS)
    using_operator_context = False

    if operator_context and not (fields["client_ip"] and fields["smtp_mailfrom"]):
        fields["client_ip"] = operator_context.get("client_ip") or fields["client_ip"]
        fields["smtp_mailfrom"] = operator_context.get("smtp_mailfrom") or fields["smtp_mailfrom"]
        fields["helo"] = operator_context.get("helo") or fields["helo"]
        using_operator_context = True

    client_ip = fields["client_ip"]
    smtp_mailfrom = fields["smtp_mailfrom"]
    helo = fields["helo"] or ""
    
    using_fallback = False
    
    # FALLBACK: Extract from Received and Return-Path headers if not provided
    if not client_ip or not smtp_mailfrom:
        if not smtp_mailfrom:
            rp = parsed.get("headers", {}).get("return_path", "")
            if rp:
                smtp_mailfrom = rp.strip("<>")
        
        if not client_ip:
            received_headers = parsed.get("headers", {}).get("received", [])
            for r_header in received_headers:
                # Look for an IP address in brackets, e.g. [192.168.1.1] or (10.0.0.1)
                match = re.search(r"[\[\(]([0-9a-fA-F:\.]+)[\]\)]", r_header)
                if match:
                    ip_candidate = match.group(1)
                    if _is_public_ip(ip_candidate):
                        client_ip = ip_candidate
                        # Optional: extract helo from "from <helo> ("
                        helo_match = re.search(r"^from\s+([^\s]+)", r_header, re.IGNORECASE)
                        if not helo and helo_match:
                            helo = helo_match.group(1)
                        break
        
        if client_ip and smtp_mailfrom:
            using_fallback = True

    missing: list[str] = []
    if not client_ip:
        missing.append("client_ip (actual connecting SMTP peer IP)")
    if not smtp_mailfrom:
        missing.append("smtp_mailfrom (SMTP envelope sender)")

    if missing:
        if reported_status:
            return {
                "status": reported_status,
                "verification_type": "receiver_reported",
                "reported_status": reported_status,
                "verified_status": None,
                "evidence": {
                    "source": "Authentication-Results header in uploaded .eml",
                    "warning": "Header inside an uploaded file can be forged; treat as untrusted claim.",
                },
                "missing_prerequisites": missing,
                "explanation": (
                    f"EmailGuard cannot independently evaluate SPF (missing: {', '.join(missing)}). "
                    f"Receiver reported spf={reported_status} but EmailGuard cannot verify this claim."
                ),
                "authserv_id_used": None,
            }
        return {
            "status": "CONTEXT_UNAVAILABLE",
            "verification_type": "unavailable",
            "reported_status": None,
            "verified_status": None,
            "evidence": None,
            "missing_prerequisites": missing,
            "explanation": (
                "SPF evaluation requires a connecting IP and envelope sender. "
                "These are not available in the uploaded .eml file."
            ),
            "authserv_id_used": None,
        }

    if not _is_public_ip(client_ip):
        return {
            "status": "CONTEXT_UNAVAILABLE",
            "verification_type": "operator_supplied_context" if using_operator_context else "unavailable",
            "reported_status": reported_status,
            "verified_status": None,
            "evidence": {"client_ip_rejected": client_ip},
            "missing_prerequisites": ["client_ip is a private/reserved address"],
            "explanation": (
                f"The client IP {client_ip!r} is private/reserved. "
                "SPF requires the actual public SMTP peer IP from the receiving server."
            ),
            "authserv_id_used": provenance,
        }

    try:
        import spf  # type: ignore  # pyspf
    except ImportError:
        if reported_status:
            return {
                "status": reported_status,
                "verification_type": "receiver_reported",
                "reported_status": reported_status,
                "verified_status": None,
                "evidence": {"source": "Authentication-Results (untrusted)"},
                "missing_prerequisites": ["pyspf library unavailable"],
                "explanation": "pyspf not installed; cannot perform independent SPF evaluation.",
                "authserv_id_used": None,
            }
        return {
            "status": "SPF_LIBRARY_UNAVAILABLE",
            "verification_type": "unavailable",
            "reported_status": reported_status,
            "verified_status": None,
            "evidence": None,
            "missing_prerequisites": ["pyspf library unavailable"],
            "explanation": "pyspf not installed; cannot perform independent SPF evaluation.",
            "authserv_id_used": None,
        }

    try:
        result_code, spf_explanation = spf.check2(
            i=client_ip,
            s=smtp_mailfrom,
            h=helo,
            timeout=int(SPF_DNS_TIMEOUT),
        )
        result_upper = (result_code or "NONE").upper()
        
        if using_operator_context:
            vtype = "operator_supplied_context"
        elif using_fallback:
            vtype = "extracted_from_headers"
        else:
            vtype = "independent"
            
        explanation = (
            f"EmailGuard independently evaluated SPF using pyspf. "
            f"Result: {result_upper}. {spf_explanation}"
        )
        if using_operator_context:
            explanation = "[OPERATOR-SUPPLIED CONTEXT - not independently trusted receiver data] " + explanation
        elif using_fallback:
            explanation = "[EXTRACTED FROM HEADERS - untrusted, can be forged] " + explanation

        provenance = "operator_supplied" if using_operator_context else (
            "extracted_from_headers" if using_fallback else f"trusted_receiver:{provenance}"
        )
        
        return {
            "status": result_upper,
            "verification_type": vtype,
            "reported_status": reported_status,
            "verified_status": result_upper,
            "evidence": {
                "client_ip": client_ip,
                "smtp_mailfrom": smtp_mailfrom,
                "helo": helo or "(empty)",
                "provenance": provenance,
            },
            "missing_prerequisites": [],
            "explanation": explanation,
            "authserv_id_used": provenance,
        }
    except Exception as exc:
        logger.warning("SPF evaluation error: %s", exc)
        return {
            "status": "DNS_ERROR",
            "verification_type": "unavailable",
            "reported_status": reported_status,
            "verified_status": None,
            "evidence": {"error": str(exc)[:200]},
            "missing_prerequisites": [],
            "explanation": f"SPF evaluation raised an error: {str(exc)[:200]}",
            "authserv_id_used": provenance,
        }
