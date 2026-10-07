from pathlib import Path

import pytest

from app.analyzers.email_parser import parse_eml
from app.analyzers.url_analyzer import _safe_resolve, analyze_url
from app.risk.engine import _decision, assess_url
from app.service import analyze_email_bytes, analyze_single_url

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"


def test_eml_parser_extracts_headers_and_html_anchor():
    raw = (FIXTURES / "lookalike_phishing.eml").read_bytes()
    parsed = parse_eml(raw)
    assert parsed["sender"] == "billing@paypa1-security.com"
    assert parsed["subject"] == "Urgent: verify your account"
    assert "https://paypa1-security.com/login/verify" in parsed["urls"]
    assert parsed["body_character_count"] > 0


def test_attachment_is_metadata_only():
    raw = (FIXTURES / "attachment_metadata.eml").read_bytes()
    parsed = parse_eml(raw)
    assert parsed["attachments"][0]["filename"] == "report.pdf"
    assert parsed["attachments"][0]["inspection"].startswith("metadata only")


def test_lookalike_domain_is_a_signal():
    report = analyze_url("https://paypa1-security.com/login")
    assert report["lookalike_detected"] is True
    assert report["lookalike_brand"] == "paypal"
    assert report["suspicious"] is True


def test_sensitive_keyword_alone_is_not_a_malicious_verdict():
    details = analyze_url("https://example.com/login")
    assessment = assess_url(details)
    assert details["suspicious_keywords"] == ["login"]
    assert details["suspicious"] is False
    assert assessment["classification"] == "SAFE"
    assert assessment["safety_score"] >= 80


def test_active_probe_refuses_loopback_addresses():
    with pytest.raises(ValueError, match="private|non-public"):
        _safe_resolve("127.0.0.1", 443)


def test_cross_domain_redirect_to_private_target_is_recorded_and_blocked(monkeypatch):
    from app.analyzers import url_analyzer

    monkeypatch.setattr(url_analyzer, "ALLOW_ACTIVE_URL_CHECKS", True)
    calls = []

    def fake_head(url):
        calls.append(url)
        if len(calls) == 1:
            return {"status": 302, "location": "http://127.0.0.1/admin", "tls": {"status": "VALID"}}
        raise ValueError("The hostname resolves to a private, reserved, or non-public address")

    monkeypatch.setattr(url_analyzer, "_one_safe_head", fake_head)
    report = url_analyzer.analyze_url("https://example.com", network_checks=True)
    assert len(calls) == 2
    assert report["redirects"]["redirect_count"] == 1
    assert report["redirects"]["domain_changed"] is True
    assert report["flags"]["suspicious_redirect"] is True
    assert report["redirects"]["chain"][-1]["blocked"] is True


def test_private_targets_are_flagged_passively_without_network_access(): 
    details = analyze_url("http://127.0.0.1/admin")
    assessment = assess_url(details)
    assert details["flags"]["private_network_url"] is True
    assert details["network_checks_performed"] is False
    assert assessment["classification"] == "MALICIOUS"


def test_non_http_schemes_are_rejected():
    with pytest.raises(ValueError, match="HTTP and HTTPS"):
        analyze_url("javascript:alert(1)")


def test_scoring_thresholds_are_explainable():
    assert _decision(5)["classification"] == "SAFE"
    assert _decision(35)["classification"] == "SUSPICIOUS"
    assert _decision(65)["classification"] == "MALICIOUS"
    assert _decision(65)["recommendation"] == "QUARANTINE"


def test_synthetic_uncertain_email_scores_as_suspicious():
    raw = (FIXTURES / "suspicious_but_uncertain.eml").read_bytes()
    report = analyze_email_bytes(raw, "suspicious_but_uncertain.eml")
    assert report["classification"] == "SUSPICIOUS"
    assert report["safety_score"] == 56


def test_email_report_omits_body_and_includes_digest():
    raw = (FIXTURES / "safe_newsletter.eml").read_bytes()
    report = analyze_email_bytes(raw, "safe_newsletter.eml")
    assert "body_text" not in report
    assert len(report["cryptography"]["hashes"]["sha256"]) == 64
    assert report["email"]["urls_found"] == 1
    assert "not statistically validated" in report["model_note"].lower()


def test_url_report_has_passive_limitations():
    report = analyze_single_url("https://example.com/about")
    assert report["url_analysis"]["network_checks_performed"] is False
    assert report["url_analysis"]["tls"]["status"] == "NOT_CHECKED"
    assert report["safety_score"] == 92
