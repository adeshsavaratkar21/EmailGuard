"""
DKIM Verifier - EmailGuard
==========================
Independently verifies DKIM signatures using dkimpy against the original raw
message bytes and live DNS lookups.

DESIGN PRINCIPLES
-----------------
* Verification runs against the original raw bytes - never re-serialized text.
* Each DKIM-Signature is reported separately.
* receiver-reported dkim=... from Authentication-Results stays separate from
  EmailGuard verified_status.
* DNS timeout / key missing is NOT the same as a bad signature.
* A forwarded or modified message may legitimately fail DKIM.
* The sender private key is never needed for verification.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

DKIM_DNS_TIMEOUT: float = float(os.getenv("EMAILGUARD_DKIM_DNS_TIMEOUT", "5.0"))

# Import from central config so the default (now True) is consistent everywhere
from app.config import ENABLE_DKIM_DNS_LOOKUPS as ENABLE_DKIM_VERIFICATION

_SIG_FIELD_RE = re.compile(r"(?:^|;)\s*([a-z]+)\s*=\s*([^;]+)", re.IGNORECASE)


class _DkimKeyUnavailable(Exception):
    """The DKIM public key could not be retrieved from DNS.

    dkimpy reports a missing key and a wrong signature with the same ``False``
    return value, so the key lookup is performed here instead and a failed lookup
    raises this exception.  "Key could not be fetched" is NOT "signature is bad"
    and must never be scored as a forgery.
    """


def _fetch_dkim_key_record(name: str | bytes, timeout: float | None = None) -> bytes:
    """Fetch the TXT record for ``<selector>._domainkey.<domain>`` from DNS.

    dkimpy calls its DNS hook with a *bytes* name, so both bytes and str are
    accepted.  Returns the raw record bytes; raises :class:`_DkimKeyUnavailable`
    when the record does not exist or DNS cannot be reached.
    """
    if isinstance(name, bytes):
        name = name.decode("ascii", errors="replace")
    try:
        import dns.resolver  # type: ignore  # dnspython
    except ImportError as exc:  # pragma: no cover - dependency is in requirements.txt
        raise _DkimKeyUnavailable("dnspython is not installed; cannot fetch the DKIM public key") from exc

    timeout = DKIM_DNS_TIMEOUT if timeout is None else timeout
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(name, "TXT", lifetime=timeout)
    except Exception as exc:
        message = str(exc)
        lowered = message.lower()
        if "timeout" in lowered or "timed out" in lowered:
            reason = f"DNS lookup for {name} timed out"
        elif "nxdomain" in lowered or "does not exist" in lowered or "no answer" in lowered:
            reason = f"no DKIM public key is published at {name}"
        else:
            reason = f"DNS lookup for {name} failed ({message[:120]})"
        raise _DkimKeyUnavailable(reason) from exc

    for answer in answers:
        try:
            value = b"".join(answer.strings) if hasattr(answer, "strings") else answer.to_text().strip('"').encode("utf-8")
        except Exception:
            continue
        if b"p=" in value or value.lower().startswith(b"v=dkim1"):
            return value
    raise _DkimKeyUnavailable(f"no DKIM public key is published at {name}")


def _parse_dkim_sig_fields(sig_header: str) -> dict[str, str]:
    """Extract tag=value pairs from a DKIM-Signature header."""
    return {
        m.group(1).lower(): m.group(2).strip()
        for m in _SIG_FIELD_RE.finditer(sig_header)
    }


def _reported_dkim(auth_headers: list[str]) -> tuple[str | None, str | None]:
    """Extract receiver-reported dkim= result and signing domain."""
    for h in auth_headers:
        m = re.search(
            r"\bdkim\s*=\s*(pass|fail|neutral|none|temperror|permerror|policy|unknown)",
            h, re.IGNORECASE,
        )
        if m:
            status = m.group(1).upper()
            d_m = re.search(r"\bheader\.d\s*=\s*([^\s;]+)", h, re.IGNORECASE)
            domain = d_m.group(1).strip("<>") if d_m else None
            return status, domain
    return None, None


def verify_dkim(raw: bytes, parsed: dict) -> dict[str, Any]:
    """
    Independently verify all DKIM-Signature headers in raw using dkimpy.

    Returns dict with keys:
        verification_type    - independent|receiver_reported|unavailable
        reported_status      - receiver-reported dkim= value
        reported_domain      - receiver-reported header.d= value
        verified_status      - overall: PASS|FAIL|NONE|KEY_UNAVAILABLE|
                               VERIFICATION_ERROR|DKIM_LIB_UNAVAILABLE|
                               NOT_PRESENT|MULTIPLE_MIXED
        signatures           - list of per-signature result dicts
        signature_present    - bool
        explanation          - human-readable summary
    """
    auth_headers: list[str] = parsed.get("headers", {}).get("authentication_results", [])
    reported_status, reported_domain = _reported_dkim(auth_headers)

    # Collect all DKIM-Signature header values from raw
    from email import message_from_bytes
    from email.policy import compat32
    msg = message_from_bytes(raw, policy=compat32)
    sig_headers: list[str] = msg.get_all("DKIM-Signature") or []

    if not sig_headers:
        return {
            "verification_type": "unavailable" if reported_status else "unavailable",
            "reported_status": reported_status,
            "reported_domain": reported_domain,
            "verified_status": "NOT_PRESENT",
            "signatures": [],
            "signature_present": False,
            "explanation": "No DKIM-Signature header found in this message.",
        }

    if not ENABLE_DKIM_VERIFICATION:
        # Parse metadata only, no DNS
        sigs_meta = []
        for sig in sig_headers:
            fields = _parse_dkim_sig_fields(sig)
            sigs_meta.append({
                "domain": fields.get("d"),
                "selector": fields.get("s"),
                "algorithm": fields.get("a"),
                "canonicalization": fields.get("c"),
                "verified_status": "DNS_LOOKUPS_DISABLED",
                "explanation": "DKIM DNS lookups are disabled. Set EMAILGUARD_DKIM_DNS_LOOKUPS=true to enable independent verification.",
            })
        return {
            "verification_type": "receiver_reported" if reported_status else "unavailable",
            "reported_status": reported_status,
            "reported_domain": reported_domain,
            "verified_status": "DNS_LOOKUPS_DISABLED",
            "signatures": sigs_meta,
            "signature_present": True,
            "explanation": (
                "DKIM DNS lookups are disabled; independent verification was not performed. "
                + (f"Receiver reported dkim={reported_status}." if reported_status else "No receiver report available either.")
            ),
        }

    try:
        import dkim  # type: ignore  # dkimpy
    except ImportError:
        return {
            "verification_type": "receiver_reported" if reported_status else "unavailable",
            "reported_status": reported_status,
            "reported_domain": reported_domain,
            "verified_status": "DKIM_LIB_UNAVAILABLE",
            "signatures": [],
            "signature_present": True,
            "explanation": "dkimpy is not installed; cannot perform independent DKIM verification.",
        }

    per_sig_results = []
    for i, sig_val in enumerate(sig_headers):
        fields = _parse_dkim_sig_fields(sig_val)
        d = fields.get("d", "")
        s = fields.get("s", "")
        a = fields.get("a", "")
        c = fields.get("c", "")
        result_entry: dict[str, Any] = {
            "index": i,
            "domain": d or None,
            "selector": s or None,
            "algorithm": a or None,
            "canonicalization": c or None,
            "verified_status": "VERIFICATION_ERROR",
            "explanation": "",
        }
        try:
            # dkimpy: verify() tests ALL signatures; for per-sig we use the index
            # The DNS hook is our own so a missing/unreachable key is distinguishable
            # from a signature that simply does not verify.
            d_obj = dkim.DKIM(raw, logger=None)
            dns_cache: dict[str, bytes] = {}

            def _dnsfunc(name: bytes, timeout: float = DKIM_DNS_TIMEOUT) -> bytes:
                cache_key = name.decode("ascii", errors="replace") if isinstance(name, bytes) else str(name)
                if cache_key not in dns_cache:
                    dns_cache[cache_key] = _fetch_dkim_key_record(name, timeout)
                return dns_cache[cache_key]

            # try verify with signature index if supported
            try:
                ok = d_obj.verify(idx=i, dnsfunc=_dnsfunc)
            except TypeError:
                # Older dkimpy doesn't have idx; fall back to verify() for first sig
                ok = bool(dkim.verify(raw, dnsfunc=_dnsfunc)) if i == 0 else None

            if ok is None:
                result_entry["verified_status"] = "VERIFICATION_ERROR"
                result_entry["explanation"] = "Cannot verify per-signature with this dkimpy version."
            elif ok:
                result_entry["verified_status"] = "PASS"
                result_entry["explanation"] = f"Signature {i} for d={d} s={s} independently verified by EmailGuard via DNS."
            else:
                result_entry["verified_status"] = "FAIL"
                result_entry["explanation"] = (
                    f"Signature {i} for d={d} s={s} failed DKIM verification. "
                    "The message body or headers may have been modified after signing, "
                    "or the DNS key does not match the signature."
                )
        except _DkimKeyUnavailable as exc:
            result_entry["verified_status"] = "KEY_UNAVAILABLE"
            result_entry["explanation"] = (
                f"The DKIM public key for d={d} s={s} could not be retrieved: {exc}. "
                "The signature could not be checked at all, so this is reported as "
                "key-unavailable and is NOT treated as an invalid signature."
            )
        except dkim.ValidationError as exc:
            result_entry["verified_status"] = "FAIL"
            result_entry["explanation"] = f"DKIM validation error for d={d} s={s}: {str(exc)[:200]}"
        except Exception as exc:
            msg_str = str(exc).lower()
            if "timeout" in msg_str or "dns" in msg_str or "nxdomain" in msg_str or "no record" in msg_str:
                result_entry["verified_status"] = "KEY_UNAVAILABLE"
                result_entry["explanation"] = f"DNS error fetching key for d={d} s={s}: {str(exc)[:200]}"
            else:
                result_entry["verified_status"] = "VERIFICATION_ERROR"
                result_entry["explanation"] = f"Verifier error for d={d} s={s}: {str(exc)[:200]}"
        per_sig_results.append(result_entry)

    statuses = [r["verified_status"] for r in per_sig_results]
    if all(s == "PASS" for s in statuses):
        overall = "PASS"
    elif any(s == "FAIL" for s in statuses):
        overall = "FAIL"
    elif any(s == "KEY_UNAVAILABLE" for s in statuses):
        overall = "KEY_UNAVAILABLE"
    elif all(s == "DNS_LOOKUPS_DISABLED" for s in statuses):
        overall = "DNS_LOOKUPS_DISABLED"
    elif len(set(statuses)) > 1:
        overall = "MULTIPLE_MIXED"
    else:
        overall = statuses[0] if statuses else "VERIFICATION_ERROR"

    return {
        "verification_type": "independent",
        "reported_status": reported_status,
        "reported_domain": reported_domain,
        "verified_status": overall,
        "signatures": per_sig_results,
        "signature_present": True,
        "explanation": (
            f"EmailGuard independently verified {len(per_sig_results)} DKIM signature(s) "
            f"using dkimpy + live DNS. Overall: {overall}."
        ),
    }
