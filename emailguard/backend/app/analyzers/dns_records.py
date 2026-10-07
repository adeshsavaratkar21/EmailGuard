from __future__ import annotations

import re


def lookup_sender_domain_records(domain: str | None, enabled: bool) -> dict:
    """Optionally retrieve SPF and DMARC policy text without treating policy as a check result."""
    if not enabled:
        return {"lookup_status": "DISABLED", "spf_record": None, "dmarc_record": None, "dmarc_policy": None}
    if not domain:
        return {"lookup_status": "NO_SENDER_DOMAIN", "spf_record": None, "dmarc_record": None, "dmarc_policy": None}
    try:
        import dns.resolver  # type: ignore
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.0
        resolver.lifetime = 2.5
        records: dict[str, str | None] = {"spf_record": None, "dmarc_record": None, "dmarc_policy": None}
        for record_type, query_name, key, prefix in (
            ("TXT", domain, "spf_record", "v=spf1"),
            ("TXT", f"_dmarc.{domain}", "dmarc_record", "v=dmarc1"),
        ):
            try:
                answers = resolver.resolve(query_name, record_type, lifetime=2.5)
                for answer in answers:
                    value = b"".join(answer.strings).decode("utf-8", errors="replace") if hasattr(answer, "strings") else answer.to_text().strip('"')
                    if value.lower().startswith(prefix):
                        records[key] = value
                        break
            except Exception:
                continue
        if records["dmarc_record"]:
            match = re.search(r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\b", records["dmarc_record"], re.IGNORECASE)
            records["dmarc_policy"] = match.group(1).lower() if match else None
        records["lookup_status"] = "COMPLETED"
        records["note"] = "DNS policy text is not an authentication verdict; SPF still needs a trusted sending IP and DMARC needs receiver evaluation."
        return records
    except ImportError:
        return {"lookup_status": "DEPENDENCY_MISSING", "spf_record": None, "dmarc_record": None, "dmarc_policy": None}
