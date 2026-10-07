from __future__ import annotations

from collections import Counter

from ..config import DEFAULT_WEIGHTS, SAFE_SAFETY_THRESHOLD, SUSPICIOUS_SAFETY_THRESHOLD


def _decision(risk_score: int) -> dict:
    risk = max(0, min(100, int(risk_score)))
    safety = 100 - risk
    if safety >= SAFE_SAFETY_THRESHOLD:
        classification, recommendation, label = "SAFE", "ALLOW", "LOW RISK"
    elif safety >= SUSPICIOUS_SAFETY_THRESHOLD:
        classification, recommendation, label = "SUSPICIOUS", "WARN", "REVIEW"
    else:
        classification, recommendation, label = "MALICIOUS", "QUARANTINE", "HIGH RISK"
    return {
        "risk_score": risk,
        "safety_score": safety,
        "classification": classification,
        "recommendation": recommendation,
        "risk_label": label,
    }


def _factor(code: str, title: str, description: str, severity: str, weight_key: str | None = None, count: int = 1) -> dict:
    weight = DEFAULT_WEIGHTS.get(weight_key or code, 0)
    contribution = weight * count
    return {
        "code": code,
        "title": title,
        "description": description,
        "severity": severity,
        "contribution": contribution,
        "direction": "reduces risk" if contribution < 0 else "increases risk" if contribution > 0 else "informational",
    }


def assess_email(auth: dict, email: dict, urls: list[dict], crypto: dict) -> dict:
    factors: list[dict] = []

    # Use verified_status where available (independently checked), fall back to status
    # for receiver_reported results.  Never silently score untrusted header claims as verified.
    def _effective_status(check_name: str) -> str:
        item = auth.get(check_name, {})
        vtype = item.get("verification_type", "unavailable")
        if vtype == "independent":
            return item.get("verified_status") or item.get("status", "UNVERIFIED")
        elif vtype in ("receiver_reported", "operator_supplied_context"):
            # Use but label separately — the factor titles distinguish them
            return item.get("status", "UNVERIFIED")
        return item.get("status", "UNVERIFIED")

    def _is_independently_checked(check_name: str) -> bool:
        return auth.get(check_name, {}).get("verification_type") == "independent"

    spf_status = _effective_status("spf")
    dkim_status = _effective_status("dkim")
    dmarc_status = _effective_status("dmarc")

    spf_ind = _is_independently_checked("spf")
    dkim_ind = _is_independently_checked("dkim")
    dmarc_ind = _is_independently_checked("dmarc")

    label_prefix_spf = "" if spf_ind else "Receiver-reported: "
    label_prefix_dkim = "" if dkim_ind else "Receiver-reported: "
    label_prefix_dmarc = "" if dmarc_ind else "Receiver-reported: "

    auth_by_name = {"spf": spf_status, "dkim": dkim_status, "dmarc": dmarc_status}
    status_map = {
        ("spf", "PASS"): ("spf_pass", f"{label_prefix_spf}SPF passed", f"{label_prefix_spf}SPF result passed; this speaks to sender authorization.", "positive"),
        ("spf", "FAIL"): ("spf_fail", f"{label_prefix_spf}SPF failed", f"{label_prefix_spf}SPF result failed.", "high"),
        ("spf", "SOFTFAIL"): ("spf_softfail", f"{label_prefix_spf}SPF softfail", f"{label_prefix_spf}SPF policy discouraged this sending host.", "medium"),
        ("dkim", "PASS"): ("dkim_pass", f"{label_prefix_dkim}DKIM passed", f"{label_prefix_dkim}DKIM signature was valid; valid signing does not prove benign content.", "positive"),
        ("dkim", "FAIL"): ("dkim_fail", f"{label_prefix_dkim}DKIM failed", f"{label_prefix_dkim}DKIM signature was invalid.", "high"),
        ("dmarc", "PASS"): ("dmarc_pass", f"{label_prefix_dmarc}DMARC passed", f"{label_prefix_dmarc}DMARC alignment checks passed.", "positive"),
        ("dmarc", "FAIL"): ("dmarc_fail", f"{label_prefix_dmarc}DMARC failed", f"{label_prefix_dmarc}DMARC alignment checks failed.", "high"),
    }
    for mechanism, status in auth_by_name.items():
        spec = status_map.get((mechanism, status))
        if spec:
            code, title, desc, severity = spec
            factors.append(_factor(code, title, desc, severity))

    # S/MIME and PGP: only penalize cryptographically INVALID signatures.
    # Absence of S/MIME/PGP is NOT a risk factor.
    smime_info = auth.get("smime", {})
    smime_status = smime_info.get("status", "NOT_PRESENT")
    if smime_status == "SIGNATURE_INVALID":
        factors.append(_factor("invalid_signature", "S/MIME signature invalid",
            "The S/MIME cryptographic signature verification failed; the message may have been modified.", "high"))
    elif smime_status in ("PASS", "PASS_SIG_ONLY"):
        factors.append(_factor("valid_signature", "S/MIME signature valid",
            "An S/MIME cryptographic signature was independently verified.", "positive"))

    pgp_info = auth.get("pgp", {})
    pgp_status = pgp_info.get("status", "NOT_PRESENT")
    if pgp_status == "SIGNATURE_INVALID":
        factors.append(_factor("invalid_signature", "PGP signature invalid",
            "The PGP cryptographic signature verification failed; the message may have been modified.", "high"))
    elif pgp_status == "PASS":
        factors.append(_factor("valid_signature", "PGP signature valid and trusted",
            "A PGP cryptographic signature was verified and the signing key is trusted.", "positive"))

    sender = email.get("sender", "")
    reply = email.get("reply_to_address", "")
    sender_domain = sender.rsplit("@", 1)[1].lower() if "@" in sender else ""
    reply_domain = reply.rsplit("@", 1)[1].lower() if "@" in reply else ""
    if sender_domain and reply_domain and sender_domain != reply_domain:
        factors.append(_factor("reply_to_mismatch", "Reply-To domain differs", f"Visible sender uses {sender_domain}, while Reply-To uses {reply_domain}.", "medium"))

    # Limited evidence: only applies when NO independently verified check succeeded
    has_meaningful_result = any(
        status in {"PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "TEMPERROR", "PERMERROR"}
        for status in auth_by_name.values()
    )
    if not has_meaningful_result:
        factors.append(_factor("limited_evidence", "Authentication evidence is limited", "No trusted receiving-system authentication result was available; uploaded Authentication-Results headers can be forged.", "info"))

    counts: Counter[str] = Counter()
    for report in urls:
        flags = report.get("flags", {})
        if report.get("lookalike_detected"):
            counts["lookalike_domain"] += 1
        if report.get("suspicious"):
            counts["suspicious_url"] += 1
        if flags.get("ip_based_url"):
            counts["ip_based_url"] += 1
        if flags.get("private_network_url"):
            counts["private_network_url"] += 1
        if flags.get("suspicious_keyword"): 
            counts["suspicious_keyword"] += 1
        if flags.get("insecure_http") and (flags.get("suspicious_keyword") or report.get("lookalike_detected")):
            counts["insecure_http"] += 1
        if flags.get("excessive_subdomains"):
            counts["excessive_subdomains"] += 1
        if flags.get("encoded_url"):
            counts["encoded_url"] += 1
        if flags.get("unusual_port"):
            counts["unusual_port"] += 1
        if flags.get("suspicious_redirect"):
            counts["suspicious_redirect"] += 1
        if flags.get("tls_invalid"):
            detail = report.get("tls", {}).get("detail", "TLS certificate validation failed.")
            lowered = detail.lower()
            code = "expired_tls" if "expired" in lowered else "hostname_mismatch" if any(term in lowered for term in ("hostname", "doesn't match", "not valid for")) else "tls_invalid"
            title = "TLS certificate expired" if code == "expired_tls" else "TLS hostname mismatch" if code == "hostname_mismatch" else "TLS certificate could not be verified"
            factors.append(_factor(code, title, detail, "high"))
        elif flags.get("tls_valid"):
            factors.append(_factor("valid_tls", "TLS certificate validated", "The certificate and hostname validated during a bounded public-endpoint probe; this is not a trust verdict.", "positive"))

    descriptions = {
        "lookalike_domain": ("Look-alike domain detected", "A URL domain resembles a known brand but is not its registered domain.", "high"),
        "suspicious_url": ("Suspicious URL pattern", "A URL contains one or more phishing indicators; no single pattern proves malicious intent.", "high"),
        "ip_based_url": ("IP-based URL", "A URL points directly to an IP address rather than a named domain.", "medium"),
        "private_network_url": ("Private-network target", "The URL names a loopback or private-network destination; active probing is blocked.", "high"),
        "suspicious_keyword": ("Sensitive URL terms", "The URL contains login, verification, payment, or similar sensitive-looking terms.", "low"),
        "insecure_http": ("Unencrypted HTTP link", "A sensitive-looking link does not use HTTPS.", "medium"),
        "excessive_subdomains": ("Deep subdomain chain", "The hostname contains an unusually large number of subdomain labels.", "medium"),
        "encoded_url": ("Encoded URL content", "Percent-encoded URL content can obscure the destination or behavior.", "low"),
        "unusual_port": ("Non-standard URL port", "The URL uses a port other than 80 or 443.", "medium"),
        "suspicious_redirect": ("Suspicious redirect", "A redirect changes hostname, downgrades HTTPS, or lands on a look-alike domain.", "high"),
    }
    caps = {"suspicious_url": 2, "lookalike_domain": 2, "ip_based_url": 2, "private_network_url": 1, "suspicious_keyword": 2, "insecure_http": 1, "excessive_subdomains": 1, "encoded_url": 1, "unusual_port": 1, "suspicious_redirect": 1}
    for code, count in counts.items():
        title, description, severity = descriptions[code]
        factors.append(_factor(code, title, description, severity, count=min(count, caps.get(code, count))))

    raw_risk = sum(item["contribution"] for item in factors)
    decision = _decision(raw_risk)
    high_priority = sorted((f for f in factors if f["contribution"] > 0), key=lambda f: f["contribution"], reverse=True)
    reasons = [factor["description"] for factor in high_priority[:5]]
    if not reasons:
        reasons = ["No high-confidence malicious indicator was detected in the checks that were available."]
    confidence = "Limited" if any(f["code"] == "limited_evidence" for f in factors) or any(not item.get("network_checks_performed") for item in urls) else "Moderate"
    return {
        **decision,
        "factors": factors,
        "reasons": reasons,
        "confidence": confidence,
        "model_note": "Prototype rules and weights are configurable starting points, not statistically validated probabilities.",
    }


def assess_url(report: dict) -> dict:
    flags = report.get("flags", {})
    factors: list[dict] = []
    if report.get("lookalike_detected"):
        factors.append(_factor("lookalike_domain", "Look-alike domain detected", f"This domain resembles {report.get('lookalike_brand') or 'a known brand'} but is not its registered domain.", "high"))
    if report.get("suspicious"):
        factors.append(_factor("suspicious_url", "Suspicious URL pattern", "One or more URL characteristics deserve caution; the pattern alone is not proof of maliciousness.", "high"))
    if flags.get("ip_based_url"):
        factors.append(_factor("ip_based_url", "IP-based URL", "The URL uses a raw IP address instead of a registered domain.", "medium"))
    if flags.get("private_network_url"):
        factors.append(_factor("private_network_url", "Private-network target", "The URL names a loopback or private-network destination; active probing is blocked.", "high"))
    if flags.get("suspicious_keyword"):
        factors.append(_factor("suspicious_keyword", "Sensitive-looking URL terms", "Login, verification, payment, or similar terms appear in the URL.", "low"))
    if flags.get("insecure_http"):
        factors.append(_factor("insecure_http", "HTTP connection", "The URL does not use HTTPS; encryption status alone does not determine site legitimacy.", "medium"))
    if flags.get("excessive_subdomains"):
        factors.append(_factor("excessive_subdomains", "Deep subdomain chain", "The hostname has an unusually deep subdomain structure.", "medium"))
    if flags.get("encoded_url"):
        factors.append(_factor("encoded_url", "Encoded URL content", "The path or query includes percent encoding.", "low"))
    if flags.get("unusual_port"):
        factors.append(_factor("unusual_port", "Non-standard port", f"The URL uses port {report.get('port')}.", "medium"))
    if flags.get("suspicious_redirect"):
        factors.append(_factor("suspicious_redirect", "Suspicious redirect", "A redirect changed domains, downgraded HTTPS, or reached a look-alike domain.", "high"))
    if flags.get("tls_invalid"):
        detail = report.get("tls", {}).get("detail", "The certificate could not be validated.")
        lowered = detail.lower()
        code = "expired_tls" if "expired" in lowered else "hostname_mismatch" if any(term in lowered for term in ("hostname", "doesn't match", "not valid for")) else "tls_invalid"
        title = "TLS certificate expired" if code == "expired_tls" else "TLS hostname mismatch" if code == "hostname_mismatch" else "TLS certificate could not be verified"
        factors.append(_factor(code, title, detail, "high"))
    elif flags.get("tls_valid"): 
        factors.append(_factor("valid_tls", "TLS certificate validated", "A public endpoint returned a valid hostname-matched certificate. HTTPS is not a trust guarantee.", "positive"))
    if not report.get("network_checks_performed"):
        factors.append(_factor("limited_evidence", "Passive checks only", "This assessment did not contact the site; redirect and live certificate status were not checked.", "info"))
    decision = _decision(sum(f["contribution"] for f in factors))
    return {
        **decision,
        "factors": factors,
        "reasons": [f["description"] for f in factors if f["contribution"] > 0][:5] or ["No high-confidence phishing indicator was detected in the passive URL checks."],
        "confidence": "Moderate" if report.get("network_checks_performed") else "Limited",
        "model_note": "Prototype rules and weights are configurable starting points, not statistically validated probabilities.",
    }
