from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import uuid4

from .analyzers.authentication import analyze_authentication
from .analyzers.crypto import analyze_crypto
from .analyzers.email_parser import parse_eml
from .analyzers.url_analyzer import analyze_url
from .config import ALLOW_ACTIVE_URL_CHECKS, MAX_ACTIVE_URLS_PER_EMAIL, MAX_URLS_PER_EMAIL
from .risk.engine import assess_email, assess_url


def analyze_email_bytes(
    raw: bytes,
    filename: str,
    network_checks: bool = False,
    operator_context: dict | None = None,
) -> dict:
    """
    Analyze a raw .eml file.

    Parameters
    ----------
    raw              : raw .eml bytes
    filename         : original filename (safe, no path)
    network_checks   : whether to probe URLs actively
    operator_context : optional SMTP transport context for SPF evaluation.
                       Keys: client_ip, smtp_mailfrom, helo.
                       Labelled as operator_supplied — not trusted receiver data.
    """
    parsed = parse_eml(raw)
    authentication = analyze_authentication(raw, parsed, operator_context=operator_context)
    cryptography = analyze_crypto(raw, parsed, authentication)
    source_urls = parsed["urls"][:MAX_URLS_PER_EMAIL]
    url_reports = [
        analyze_url(url, network_checks=network_checks and index < MAX_ACTIVE_URLS_PER_EMAIL)
        for index, url in enumerate(source_urls)
    ]
    assessment = assess_email(authentication, parsed, url_reports, cryptography)
    safe_name = filename.replace("\\", "/").split("/")[-1][:255] or "uploaded.eml"
    reply_to = parsed.get("headers", {}).get("reply_to", "")
    # SHA-256 of the raw bytes as a non-sensitive audit identifier
    message_sha256 = hashlib.sha256(raw).hexdigest()
    limitations = [
        "An .eml file does not reliably contain the trusted connecting IP needed for a fresh SPF check. Receiver authentication headers are reported, not assumed trustworthy.",
        "Attachments are identified by metadata only. They are never opened, extracted, or executed.",
        "Risk scores are explainable prototype assessments, not proof of safety or a calibrated probability.",
    ]
    if network_checks and ALLOW_ACTIVE_URL_CHECKS and len(source_urls) > MAX_ACTIVE_URLS_PER_EMAIL:
        limitations.append(f"Active network checks are capped at the first {MAX_ACTIVE_URLS_PER_EMAIL} URLs in one email; remaining links were assessed passively.")
    if operator_context:
        limitations.append(
            "Operator-supplied SMTP transport context was used for SPF evaluation. "
            "This is labelled operator_supplied_context and is NOT independently trusted receiver data."
        )
    report = {
        "analysis_id": str(uuid4()),
        "kind": "email",
        "filename": safe_name,
        "message_sha256": message_sha256,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "email": {
            "from": parsed.get("headers", {}).get("from", ""),
            "sender": parsed.get("sender", ""),
            "to": parsed.get("headers", {}).get("to", ""),
            "reply_to": reply_to,
            "return_path": parsed.get("headers", {}).get("return_path", ""),
            "subject": parsed.get("subject", ""),
            "date": parsed.get("headers", {}).get("date", ""),
            "message_id": parsed.get("headers", {}).get("message_id", ""),
            "received": parsed.get("headers", {}).get("received", []),
            "body_character_count": parsed.get("body_character_count", 0),
            "raw_message_size": parsed.get("raw_message_size", len(raw)),
            "mime_types": parsed.get("mime_types", []),
            "attachments": parsed.get("attachments", []),
            "urls_found": len(parsed.get("urls", [])),
            "urls_analyzed": len(url_reports),
            "urls_truncated": len(parsed.get("urls", [])) > len(url_reports),
        },
        "authentication": authentication,
        "cryptography": cryptography,
        "urls": url_reports,
        **assessment,
        "limitations": limitations,
    }
    return report


def analyze_single_url(url: str, network_checks: bool = False) -> dict:
    details = analyze_url(url, network_checks=network_checks)
    assessment = assess_url(details)
    return {
        "analysis_id": str(uuid4()),
        "kind": "url",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "url_analysis": details,
        **assessment,
        "limitations": details.get("limitations", []),
    }
