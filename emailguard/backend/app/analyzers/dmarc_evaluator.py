"""
DMARC Evaluator - EmailGuard
============================
Calculates DMARC alignment from real SPF and DKIM outcomes and the DNS policy.

DESIGN PRINCIPLES
-----------------
* DMARC policy (p=reject etc.) describes what receivers SHOULD do; it is NOT
  itself a verdict on whether this particular message failed.
* DMARC passes if either:
  - a passing SPF identity is aligned with the RFC5322 From domain, or
  - a passing DKIM d= identity is aligned with it.
* Alignment is strict (exact match) or relaxed (organizational domain match).
* Organizational domain is computed using the Public Suffix List (publicsuffix2).
* If SPF/DKIM results are unavailable, DMARC must be CONTEXT_UNAVAILABLE.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

DMARC_DNS_TIMEOUT: float = float(os.getenv("EMAILGUARD_DMARC_DNS_TIMEOUT", "5.0"))

# Import from central config so the default (now True) is consistent everywhere
from app.config import ENABLE_DNS_LOOKUPS


def _get_org_domain(domain: str | None) -> str | None:
    """Return the organizational domain using Public Suffix List."""
    if not domain:
        return None
    try:
        import publicsuffix2  # type: ignore
        return publicsuffix2.get_sld(domain) or domain
    except ImportError:
        # Naive fallback: last two labels (not PSL-aware, documented limitation)
        parts = domain.rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _aligned(from_domain: str, auth_domain: str | None, mode: str) -> bool:
    """Check DMARC alignment."""
    if not auth_domain or not from_domain:
        return False
    from_d = from_domain.lower()
    auth_d = auth_domain.lower()
    if mode == "s":  # strict
        return from_d == auth_d
    else:  # relaxed
        from_org = _get_org_domain(from_d)
        auth_org = _get_org_domain(auth_d)
        return bool(from_org and auth_org and from_org == auth_org)


def _fetch_dmarc_record(domain: str) -> tuple[str | None, str]:
    """Fetch _dmarc.domain TXT record. Returns (record_text, status)."""
    if not ENABLE_DNS_LOOKUPS:
        return None, "DNS_LOOKUPS_DISABLED"
    try:
        import dns.resolver  # type: ignore
        resolver = dns.resolver.Resolver()
        resolver.timeout = DMARC_DNS_TIMEOUT
        resolver.lifetime = DMARC_DNS_TIMEOUT
        try:
            answers = resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=DMARC_DNS_TIMEOUT)
            records = []
            for a in answers:
                txt = b"".join(a.strings).decode("utf-8", errors="replace") if hasattr(a, "strings") else a.to_text().strip('"')
                if txt.lower().startswith("v=dmarc1"):
                    records.append(txt)
            if len(records) == 0:
                return None, "NO_RECORD"
            if len(records) > 1:
                return records[0], "MULTIPLE_RECORDS_FIRST_USED"
            return records[0], "FOUND"
        except Exception as exc:
            msg = str(exc).lower()
            if "nxdomain" in msg or "no answer" in msg:
                return None, "NO_RECORD"
            if "timeout" in msg:
                return None, "DNS_TIMEOUT"
            return None, f"DNS_ERROR:{str(exc)[:100]}"
    except ImportError:
        return None, "DNS_LIB_UNAVAILABLE"


def _parse_dmarc_record(record: str) -> dict[str, str | None]:
    """Parse a DMARC TXT record into a dict of tag -> value."""
    tags: dict[str, str | None] = {}
    for m in re.finditer(r"(?:^|;)\s*([a-z]+)\s*=\s*([^;]+)", record, re.IGNORECASE):
        tags[m.group(1).lower()] = m.group(2).strip().lower()
    return tags


def evaluate_dmarc(
    from_domain: str | None,
    spf_result: dict[str, Any],
    dkim_result: dict[str, Any],
    spf_envelope_domain: str | None = None,
) -> dict[str, Any]:
    """
    Calculate DMARC alignment and result.

    Parameters
    ----------
    from_domain       : RFC5322 visible From domain.
    spf_result        : output of check_spf().
    dkim_result       : output of verify_dkim().
    spf_envelope_domain: the domain in the SMTP MAIL FROM (envelope sender domain).

    Returns dict with keys:
        status               - PASS|FAIL|CONTEXT_UNAVAILABLE|NO_POLICY|DNS_ERROR|...
        verification_type    - independent|receiver_reported|unavailable
        reported_status      - receiver-reported dmarc= value, if any
        verified_status      - EmailGuard computed DMARC result, or None
        from_domain          - the visible From domain tested
        policy               - p= value from DNS
        sub_policy           - sp= value from DNS
        adkim                - adkim= alignment mode
        aspf                 - aspf= alignment mode
        spf_aligned          - True/False/None
        dkim_aligned         - True/False/None
        dns_record           - raw DMARC TXT, or None
        dns_lookup_status    - FOUND|NO_RECORD|DISABLED|DNS_ERROR|...
        org_domain           - organizational domain used
        explanation          - human-readable summary
    """
    auth_headers: list[str] = []  # passed via spf/dkim results; we don't have parsed here

    # Receiver-reported DMARC (from Authentication-Results) - extracted by caller
    reported_status: str | None = spf_result.get("_dmarc_reported_status")
    reported_policy: str | None = spf_result.get("_dmarc_reported_policy")

    if not from_domain:
        return {
            "status": "CONTEXT_UNAVAILABLE",
            "verification_type": "unavailable",
            "reported_status": reported_status,
            "verified_status": None,
            "from_domain": None,
            "policy": None,
            "sub_policy": None,
            "adkim": None,
            "aspf": None,
            "spf_aligned": None,
            "dkim_aligned": None,
            "dns_record": None,
            "dns_lookup_status": "NO_FROM_DOMAIN",
            "org_domain": None,
            "explanation": "No RFC5322 From domain is available; DMARC cannot be evaluated.",
        }

    # Fetch DMARC record
    record, dns_status = _fetch_dmarc_record(from_domain)
    if record is None:
        # Try organizational domain
        org = _get_org_domain(from_domain)
        if org and org != from_domain:
            record, dns_status2 = _fetch_dmarc_record(org)
            if record:
                dns_status = f"FOUND_AT_ORG_DOMAIN:{org}"
            else:
                dns_status = dns_status  # keep original subdomain status
    else:
        dns_status = dns_status

    tags: dict[str, str | None] = {}
    if record:
        tags = _parse_dmarc_record(record)

    policy = tags.get("p")
    sub_policy = tags.get("sp")
    adkim = (tags.get("adkim") or "r")[0].lower()  # r=relaxed, s=strict
    aspf = (tags.get("aspf") or "r")[0].lower()

    if not record and dns_status in ("NO_RECORD", "DNS_LOOKUPS_DISABLED"):
        return {
            "status": "NO_POLICY" if dns_status == "NO_RECORD" else "CONTEXT_UNAVAILABLE",
            "verification_type": "unavailable",
            "reported_status": reported_status,
            "verified_status": None,
            "from_domain": from_domain,
            "policy": None,
            "sub_policy": None,
            "adkim": None,
            "aspf": None,
            "spf_aligned": None,
            "dkim_aligned": None,
            "dns_record": None,
            "dns_lookup_status": dns_status,
            "org_domain": _get_org_domain(from_domain),
            "explanation": (
                "No DMARC record found for this domain." if dns_status == "NO_RECORD"
                else "DNS lookups are disabled; DMARC policy was not retrieved."
            ),
        }

    # Determine SPF domain and pass status
    spf_status = spf_result.get("verified_status") or spf_result.get("status")
    spf_pass = spf_status == "PASS"
    # Use envelope sender domain for SPF alignment
    env_domain: str | None = spf_envelope_domain
    if not env_domain:
        mf = (spf_result.get("evidence") or {}).get("smtp_mailfrom", "")
        if mf and "@" in mf:
            env_domain = mf.rsplit("@", 1)[1].lower()
        elif mf:
            env_domain = mf.lower()

    spf_aligned: bool | None = None
    if spf_pass and env_domain:
        spf_aligned = _aligned(from_domain, env_domain, aspf)
    elif spf_result.get("verified_status") is None and spf_result.get("status") not in (
        "PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "TEMPERROR", "PERMERROR"
    ):
        spf_aligned = None  # unavailable
    else:
        spf_aligned = False

    # DKIM aligned signatures
    dkim_aligned: bool | None = None
    dkim_pass_sigs = [
        sig for sig in dkim_result.get("signatures", [])
        if sig.get("verified_status") == "PASS"
    ]
    if dkim_pass_sigs:
        for sig in dkim_pass_sigs:
            if _aligned(from_domain, sig.get("domain"), adkim):
                dkim_aligned = True
                break
        if dkim_aligned is None:
            dkim_aligned = False
    elif dkim_result.get("verified_status") in (
        "DKIM_LIB_UNAVAILABLE", "DNS_LOOKUPS_DISABLED", "KEY_UNAVAILABLE", "VERIFICATION_ERROR"
    ):
        dkim_aligned = None  # unavailable
    else:
        dkim_aligned = False

    # DMARC result
    spf_provides = spf_aligned is True
    dkim_provides = dkim_aligned is True

    if spf_provides or dkim_provides:
        verified_status = "PASS"
    elif spf_aligned is None and dkim_aligned is None:
        verified_status = "CONTEXT_UNAVAILABLE"
    else:
        verified_status = "FAIL"

    if verified_status == "CONTEXT_UNAVAILABLE":
        vtype = "unavailable"
        explanation = (
            "DMARC result is CONTEXT_UNAVAILABLE because SPF and/or DKIM results "
            "were not independently verifiable. EmailGuard cannot compute a reliable alignment."
        )
    elif verified_status == "PASS":
        vtype = "independent"
        passing = []
        if spf_provides:
            passing.append(f"SPF (aspf={adkim})")
        if dkim_provides:
            passing.append(f"DKIM (adkim={adkim})")
        explanation = (
            f"DMARC PASS: alignment passed via {' and '.join(passing)}. "
            f"Policy from DNS: p={policy or 'none'}."
        )
    else:
        vtype = "independent"
        explanation = (
            f"DMARC FAIL: no passing and aligned SPF or DKIM mechanism found. "
            f"SPF aligned={spf_aligned}, DKIM aligned={dkim_aligned}. "
            f"Policy from DNS: p={policy or 'none'}."
        )

    return {
        "status": verified_status,
        "verification_type": vtype,
        "reported_status": reported_status,
        "verified_status": verified_status,
        "from_domain": from_domain,
        "policy": policy,
        "sub_policy": sub_policy,
        "adkim": adkim,
        "aspf": aspf,
        "spf_aligned": spf_aligned,
        "dkim_aligned": dkim_aligned,
        "dns_record": record,
        "dns_lookup_status": dns_status,
        "org_domain": _get_org_domain(from_domain),
        "explanation": explanation,
    }
