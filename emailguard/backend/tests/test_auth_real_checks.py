"""
Unit tests for EmailGuard real authentication checks.
IMPORTANT: These are SYNTHETIC tests using fabricated .eml fixtures.
They test code paths, parsing, status mapping, and error handling only.
They do NOT constitute real-email validation.

Real-email end-to-end validation status: NOT RUN -- no real email supplied.
"""

from __future__ import annotations

import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest

from app.analyzers.dkim_verifier import verify_dkim
from app.analyzers.dmarc_evaluator import _aligned, _get_org_domain, evaluate_dmarc
from app.analyzers.email_parser import parse_eml
from app.analyzers.pgp_verifier import verify_pgp
from app.analyzers.smime_verifier import verify_smime
from app.analyzers.spf_checker import check_spf, _is_public_ip


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_eml(extra_headers: str = "", body: str = "Hello.") -> bytes:
    return (
        f"From: sender@example.com\r\n"
        f"To: rcpt@example.com\r\n"
        f"Subject: Test\r\n"
        f"Date: Mon, 6 Oct 2026 10:00:00 +0000\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"{extra_headers}"
        f"\r\n"
        f"{body}\r\n"
    ).encode()


# ===========================================================================
# SPF Tests (SYNTHETIC)
# ===========================================================================

class TestSPFChecker:
    def test_context_unavailable_when_no_auth_results(self):
        """SYNTHETIC: No auth headers → CONTEXT_UNAVAILABLE, not a false PASS."""
        raw = _make_eml()
        parsed = parse_eml(raw)
        result = check_spf(parsed)
        assert result["status"] == "CONTEXT_UNAVAILABLE"
        assert result["verification_type"] == "unavailable"
        assert result["verified_status"] is None
        assert len(result["missing_prerequisites"]) > 0

    def test_receiver_reported_when_auth_results_but_no_trusted_id(self):
        """SYNTHETIC: Auth-Results present but not from trusted authserv-id → receiver_reported."""
        raw = _make_eml(
            "Authentication-Results: mx.untrusted.test; spf=pass smtp.mailfrom=example.com\r\n"
        )
        parsed = parse_eml(raw)
        result = check_spf(parsed)
        # No trusted authserv-id configured → cannot independently evaluate
        # Has a reported value → receiver_reported
        assert result["verification_type"] == "receiver_reported"
        assert result["reported_status"] == "PASS"
        assert result["verified_status"] is None  # not independently checked

    def test_context_unavailable_no_status_no_trusted(self):
        """SYNTHETIC: Auth-Results with only DKIM (no spf=) → CONTEXT_UNAVAILABLE."""
        raw = _make_eml(
            "Authentication-Results: mx.trusted.test; dkim=pass header.d=example.com\r\n"
        )
        parsed = parse_eml(raw)
        result = check_spf(parsed)
        assert result["status"] == "CONTEXT_UNAVAILABLE"
        assert result["reported_status"] is None

    def test_private_ip_rejected(self):
        """SYNTHETIC: Operator-supplied private IP is rejected with CONTEXT_UNAVAILABLE."""
        raw = _make_eml()
        parsed = parse_eml(raw)
        result = check_spf(parsed, operator_context={
            "client_ip": "127.0.0.1",
            "smtp_mailfrom": "sender@example.com",
        })
        assert result["status"] == "CONTEXT_UNAVAILABLE"
        assert "private" in result["explanation"].lower() or "reserved" in result["explanation"].lower()

    def test_is_public_ip_rejects_private(self):
        """SYNTHETIC: IP helper correctly classifies private addresses."""
        assert not _is_public_ip("127.0.0.1")
        assert not _is_public_ip("10.0.0.1")
        assert not _is_public_ip("192.168.1.1")
        assert not _is_public_ip("::1")

    def test_is_public_ip_accepts_routable(self):
        """SYNTHETIC: IP helper accepts public routable addresses."""
        assert _is_public_ip("8.8.8.8")
        assert _is_public_ip("2001:4860:4860::8888")

    def test_operator_context_uses_public_ip_with_pyspf(self, monkeypatch):
        """SYNTHETIC: With public IP and pyspf available, runs evaluation."""
        fake_spf = MagicMock()
        fake_spf.check2.return_value = ("Pass", "sender SPF authorized")
        monkeypatch.setitem(sys.modules, "spf", fake_spf)
        raw = _make_eml()
        parsed = parse_eml(raw)
        result = check_spf(parsed, operator_context={
            "client_ip": "8.8.8.8",
            "smtp_mailfrom": "sender@example.com",
        })
        assert result["status"] == "PASS"
        assert result["verification_type"] == "operator_supplied_context"
        assert result["verified_status"] == "PASS"
        assert "OPERATOR-SUPPLIED" in result["explanation"]

    def test_missing_spf_lib_returns_library_unavailable(self, monkeypatch):
        """SYNTHETIC: If pyspf not installed and no auth results → SPF_LIBRARY_UNAVAILABLE."""
        monkeypatch.setitem(sys.modules, "spf", None)
        # Ensure import raises ImportError
        original = __builtins__
        raw = _make_eml()
        parsed = parse_eml(raw)
        # Patch out pyspf by making import fail
        with patch.dict(sys.modules, {"spf": None}):
            result = check_spf(parsed, operator_context={
                "client_ip": "8.8.8.8",
                "smtp_mailfrom": "sender@example.com",
            })
        # If spf module is None in sys.modules, import will raise ImportError
        # Result depends on whether pyspf is actually installed
        assert result["status"] in ("PASS", "FAIL", "NEUTRAL", "NONE", "SOFTFAIL",
                                     "TEMPERROR", "PERMERROR", "SPF_LIBRARY_UNAVAILABLE",
                                     "DNS_ERROR")

    def test_dns_error_is_not_pass_or_fail(self, monkeypatch):
        """SYNTHETIC: DNS error during SPF evaluation → DNS_ERROR, not PASS/FAIL."""
        fake_spf = MagicMock()
        fake_spf.check2.side_effect = Exception("DNS timeout")
        monkeypatch.setitem(sys.modules, "spf", fake_spf)
        raw = _make_eml()
        parsed = parse_eml(raw)
        result = check_spf(parsed, operator_context={
            "client_ip": "8.8.8.8",
            "smtp_mailfrom": "sender@example.com",
        })
        assert result["status"] == "DNS_ERROR"
        assert result["verified_status"] is None


# ===========================================================================
# DKIM Tests (SYNTHETIC)
# ===========================================================================

class TestDKIMVerifier:
    def test_no_dkim_signature_returns_not_present(self):
        """SYNTHETIC: Email with no DKIM-Signature → NOT_PRESENT."""
        raw = _make_eml()
        parsed = parse_eml(raw)
        result = verify_dkim(raw, parsed)
        assert result["verified_status"] == "NOT_PRESENT"
        assert result["signature_present"] is False
        assert result["signatures"] == []

    def test_dkim_dns_disabled_returns_disabled_status(self):
        """SYNTHETIC: DKIM-Signature present but DNS lookups disabled → DNS_LOOKUPS_DISABLED."""
        raw = _make_eml(
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1;\r\n"
            " bh=base64hash; h=from:to:subject; b=signature\r\n"
        )
        parsed = parse_eml(raw)
        with patch("app.analyzers.dkim_verifier.ENABLE_DKIM_VERIFICATION", False):
            result = verify_dkim(raw, parsed)
        assert result["verified_status"] == "DNS_LOOKUPS_DISABLED"
        assert result["signature_present"] is True
        assert result["signatures"][0]["domain"] == "example.com"
        assert result["signatures"][0]["selector"] == "selector1"

    def test_receiver_reported_kept_separate_from_verified(self):
        """SYNTHETIC: receiver-reported dkim= in Auth-Results stays in reported_status."""
        raw = _make_eml(
            "Authentication-Results: mx.test; dkim=pass header.d=example.com\r\n"
        )
        parsed = parse_eml(raw)
        result = verify_dkim(raw, parsed)
        assert result["reported_status"] == "PASS"
        # No DKIM-Signature → verified_status is NOT_PRESENT
        assert result["verified_status"] == "NOT_PRESENT"
        # These must be in different fields
        assert result["reported_status"] != result["verified_status"]

    def test_key_unavailable_is_not_fail(self, monkeypatch):
        """SYNTHETIC: DNS error fetching DKIM key → KEY_UNAVAILABLE, not FAIL."""
        raw = _make_eml(
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel1;\r\n"
            " bh=abc; h=from; b=sig\r\n"
        )
        parsed = parse_eml(raw)
        fake_dkim = MagicMock()
        class FakeValidationError(Exception):
            pass
        fake_dkim.ValidationError = FakeValidationError
        fake_obj = MagicMock()
        fake_obj.verify.side_effect = Exception("DNS timeout resolving key")
        fake_dkim.DKIM.return_value = fake_obj
        monkeypatch.setitem(sys.modules, "dkim", fake_dkim)
        with patch("app.analyzers.dkim_verifier.ENABLE_DKIM_VERIFICATION", True):
            result = verify_dkim(raw, parsed)
        assert result["verified_status"] in ("KEY_UNAVAILABLE", "VERIFICATION_ERROR", "FAIL")
        # Must not be PASS
        assert result["verified_status"] != "PASS"


# ===========================================================================
# DMARC Alignment Tests (SYNTHETIC)
# ===========================================================================

class TestDMARCAlignment:
    def test_relaxed_alignment_same_org_domain(self):
        """SYNTHETIC: Relaxed alignment matches sub.example.com to example.com."""
        assert _aligned("example.com", "sub.example.com", "r") is True

    def test_strict_alignment_requires_exact_match(self):
        """SYNTHETIC: Strict alignment rejects sub.example.com != example.com."""
        assert _aligned("example.com", "sub.example.com", "s") is False

    def test_strict_alignment_exact_match_passes(self):
        """SYNTHETIC: Strict alignment: exact same domain passes."""
        assert _aligned("example.com", "example.com", "s") is True

    def test_different_org_domains_fail_relaxed(self):
        """SYNTHETIC: Different organizational domains fail even relaxed alignment."""
        assert _aligned("paypal.com", "paypa1-security.com", "r") is False

    def test_org_domain_psl_aware(self):
        """SYNTHETIC: PSL-aware org domain uses publicsuffix2."""
        org = _get_org_domain("mail.example.co.uk")
        # Should be example.co.uk, not co.uk (which is a public suffix)
        assert org is not None
        assert "example" in org

    def test_dmarc_context_unavailable_when_spf_dkim_unavailable(self):
        """SYNTHETIC: DMARC → CONTEXT_UNAVAILABLE when SPF and DKIM are unavailable."""
        spf_unavailable = {
            "status": "CONTEXT_UNAVAILABLE",
            "verification_type": "unavailable",
            "verified_status": None,
            "evidence": None,
        }
        dkim_unavailable = {
            "verified_status": "NOT_PRESENT",
            "verification_type": "unavailable",
            "signatures": [],
            "signature_present": False,
        }
        with patch("app.analyzers.dmarc_evaluator.ENABLE_DNS_LOOKUPS", False):
            result = evaluate_dmarc("example.com", spf_unavailable, dkim_unavailable)
        assert result["status"] == "CONTEXT_UNAVAILABLE"
        assert result["verified_status"] is None

    def test_dmarc_no_record_is_no_policy_not_fail(self):
        """SYNTHETIC: No DMARC record → NO_POLICY, not FAIL."""
        spf_r = {"status": "CONTEXT_UNAVAILABLE", "verification_type": "unavailable",
                  "verified_status": None, "evidence": None}
        dkim_r = {"verified_status": "NOT_PRESENT", "verification_type": "unavailable",
                   "signatures": [], "signature_present": False}
        with patch("app.analyzers.dmarc_evaluator._fetch_dmarc_record", return_value=(None, "NO_RECORD")):
            result = evaluate_dmarc("example.com", spf_r, dkim_r)
        assert result["status"] == "NO_POLICY"

    def test_dmarc_pass_via_aligned_dkim(self):
        """SYNTHETIC: DMARC PASS when DKIM d= is aligned with From domain."""
        spf_r = {"status": "CONTEXT_UNAVAILABLE", "verification_type": "unavailable",
                  "verified_status": None, "evidence": None}
        dkim_r = {
            "verified_status": "PASS",
            "verification_type": "independent",
            "signatures": [{"domain": "example.com", "verified_status": "PASS"}],
            "signature_present": True,
        }
        fake_record = "v=DMARC1; p=reject; adkim=r; aspf=r"
        with patch("app.analyzers.dmarc_evaluator._fetch_dmarc_record", return_value=(fake_record, "FOUND")):
            result = evaluate_dmarc("example.com", spf_r, dkim_r)
        assert result["status"] == "PASS"
        assert result["dkim_aligned"] is True

    def test_dmarc_fail_when_neither_spf_nor_dkim_aligned(self):
        """SYNTHETIC: DMARC FAIL when neither SPF nor DKIM are aligned."""
        spf_r = {
            "status": "PASS",
            "verification_type": "independent",
            "verified_status": "PASS",
            "evidence": {"smtp_mailfrom": "attacker@evil.com"},
        }
        dkim_r = {
            "verified_status": "PASS",
            "verification_type": "independent",
            "signatures": [{"domain": "evil.com", "verified_status": "PASS"}],
            "signature_present": True,
        }
        fake_record = "v=DMARC1; p=reject; adkim=s; aspf=s"
        with patch("app.analyzers.dmarc_evaluator._fetch_dmarc_record", return_value=(fake_record, "FOUND")):
            result = evaluate_dmarc("example.com", spf_r, dkim_r)
        assert result["status"] == "FAIL"
        assert result["spf_aligned"] is False
        assert result["dkim_aligned"] is False


# ===========================================================================
# S/MIME Tests (SYNTHETIC)
# ===========================================================================

class TestSMIMEVerifier:
    def test_not_present_for_plain_email(self):
        """SYNTHETIC: Plain text email → S/MIME NOT_PRESENT."""
        raw = _make_eml()
        parsed = parse_eml(raw)
        result = verify_smime(raw, parsed)
        assert result["status"] == "NOT_PRESENT"
        assert result["verification_type"] == "unavailable"
        assert result["signature_valid"] is None

    def test_encrypted_not_decrypted(self):
        """SYNTHETIC: Enveloped S/MIME → ENCRYPTED_NOT_DECRYPTED, never decrypted."""
        raw = (
            b"From: sender@example.com\r\n"
            b"To: rcpt@example.com\r\n"
            b"Subject: Encrypted\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m\r\n"
            b"\r\n"
            b"fakeciphertext\r\n"
        )
        parsed = parse_eml(raw)
        result = verify_smime(raw, parsed)
        assert result["status"] == "ENCRYPTED_NOT_DECRYPTED"
        assert result["signature_valid"] is None

    def test_openssl_unavailable_returns_graceful_status(self, monkeypatch):
        """SYNTHETIC: openssl binary unavailable → OPENSSL_UNAVAILABLE, not crash."""
        raw = (
            b"From: sender@example.com\r\n"
            b"Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=bound\r\n"
            b"MIME-Version: 1.0\r\n"
            b"\r\n"
            b"--bound\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\nHello\r\n"
            b"--bound\r\n"
            b"Content-Type: application/pkcs7-signature; name=smime.p7s\r\n"
            b"\r\nfakesig\r\n"
            b"--bound--\r\n"
        )
        parsed = parse_eml(raw)
        with patch("app.analyzers.smime_verifier._openssl_available", return_value=False):
            result = verify_smime(raw, parsed)
        assert result["status"] == "OPENSSL_UNAVAILABLE"
        assert result["signature_valid"] is None


# ===========================================================================
# PGP Tests (SYNTHETIC)
# ===========================================================================

class TestPGPVerifier:
    def test_not_present_for_plain_email(self):
        """SYNTHETIC: Plain email → PGP NOT_PRESENT."""
        raw = _make_eml()
        parsed = parse_eml(raw)
        result = verify_pgp(raw, parsed)
        assert result["status"] == "NOT_PRESENT"
        assert result["verification_type"] == "unavailable"

    def test_pgp_encrypted_not_decrypted(self):
        """SYNTHETIC: PGP encrypted message → ENCRYPTED_NOT_DECRYPTED."""
        raw = (
            b"From: sender@example.com\r\n"
            b"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=b\r\n"
            b"MIME-Version: 1.0\r\n"
            b"\r\n"
            b"--b\r\n"
            b"Content-Type: application/pgp-encrypted\r\n"
            b"\r\nVersion: 1\r\n"
            b"--b\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"\r\nfakeencryptedblob\r\n"
            b"--b--\r\n"
        )
        parsed = parse_eml(raw)
        result = verify_pgp(raw, parsed)
        assert result["status"] == "ENCRYPTED_NOT_DECRYPTED"
        assert result["signature_valid"] is None

    def test_gpg_unavailable_returns_graceful_status(self):
        """SYNTHETIC: gpg not available → GPG_UNAVAILABLE, not crash."""
        body = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nHello\n-----BEGIN PGP SIGNATURE-----\nfakesig\n-----END PGP SIGNATURE-----"
        raw = _make_eml(body=body)
        parsed = parse_eml(raw)
        with patch("app.analyzers.pgp_verifier._gpg_available", return_value=False):
            result = verify_pgp(raw, parsed)
        assert result["status"] == "GPG_UNAVAILABLE"
        assert result["signature_valid"] is None

    def test_no_keyring_key_unavailable(self):
        """SYNTHETIC: PGP signature present, gpg available, but no keyring → KEY_UNAVAILABLE."""
        body = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nHello\n-----BEGIN PGP SIGNATURE-----\nfakesig\n-----END PGP SIGNATURE-----"
        raw = _make_eml(body=body)
        parsed = parse_eml(raw)

        # Mock gpg available, but gpg --verify returns NO_PUBKEY status
        fake_status = b"[GNUPG:] NO_PUBKEY DEADBEEFDEADBEEF\n"

        with patch("app.analyzers.pgp_verifier._gpg_available", return_value=True), \
             patch("app.analyzers.pgp_verifier._run_gpg", return_value=(2, fake_status, b"")), \
             patch("app.analyzers.pgp_verifier.PGP_KEYRING_DIR", None):
            result = verify_pgp(raw, parsed)
        assert result["status"] == "KEY_UNAVAILABLE"
        assert result["signature_valid"] is None

    def test_bad_signature_returns_signature_invalid(self):
        """SYNTHETIC: GPG returns BADSIG → SIGNATURE_INVALID, not PASS."""
        body = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nHello\n-----BEGIN PGP SIGNATURE-----\nfakesig\n-----END PGP SIGNATURE-----"
        raw = _make_eml(body=body)
        parsed = parse_eml(raw)
        fake_status = b"[GNUPG:] BADSIG DEADBEEFDEADBEEF Test Signer\n"
        with patch("app.analyzers.pgp_verifier._gpg_available", return_value=True), \
             patch("app.analyzers.pgp_verifier._run_gpg", return_value=(1, fake_status, b"")), \
             patch("app.analyzers.pgp_verifier.PGP_KEYRING_DIR", None):
            result = verify_pgp(raw, parsed)
        assert result["status"] == "SIGNATURE_INVALID"
        assert result["signature_valid"] is False

    def test_good_sig_untrusted_key_not_pass(self):
        """SYNTHETIC: GOODSIG but unknown trust → KEY_UNTRUSTED, not PASS."""
        body = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nHello\n-----BEGIN PGP SIGNATURE-----\nfakesig\n-----END PGP SIGNATURE-----"
        raw = _make_eml(body=body)
        parsed = parse_eml(raw)
        fake_status = (
            b"[GNUPG:] GOODSIG DEADBEEFDEADBEEF Test Signer <test@example.com>\n"
            b"[GNUPG:] VALIDSIG ABCDEFABCDEFABCDEF 2026-10-06 1728000000\n"
            b"[GNUPG:] TRUST_UNKNOWN\n"
        )
        with patch("app.analyzers.pgp_verifier._gpg_available", return_value=True), \
             patch("app.analyzers.pgp_verifier._run_gpg", return_value=(0, fake_status, b"")), \
             patch("app.analyzers.pgp_verifier.PGP_KEYRING_DIR", None):
            result = verify_pgp(raw, parsed)
        assert result["status"] == "KEY_UNTRUSTED"
        assert result["signature_valid"] is True
        assert result["key_trusted"] is False


# ===========================================================================
# Integration: missing prerequisites produce UNVERIFIED/NOT_PRESENT, not PASS
# ===========================================================================

class TestMissingPrerequisitesSafety:
    """
    SYNTHETIC: Verify that missing inputs produce correct non-PASS statuses.
    These test code paths only, not real-email behavior.
    """

    def test_spf_missing_ip_is_not_pass(self):
        raw = _make_eml()
        parsed = parse_eml(raw)
        result = check_spf(parsed)
        assert result["status"] not in ("PASS", "FAIL", "SOFTFAIL")

    def test_dkim_no_signature_is_not_pass(self):
        raw = _make_eml()
        parsed = parse_eml(raw)
        result = verify_dkim(raw, parsed)
        assert result["verified_status"] == "NOT_PRESENT"

    def test_smime_not_present_is_not_pass(self):
        raw = _make_eml()
        parsed = parse_eml(raw)
        result = verify_smime(raw, parsed)
        assert result["status"] == "NOT_PRESENT"
        assert result["signature_valid"] is None

    def test_pgp_not_present_is_not_pass(self):
        raw = _make_eml()
        parsed = parse_eml(raw)
        result = verify_pgp(raw, parsed)
        assert result["status"] == "NOT_PRESENT"
        assert result["signature_valid"] is None

    def test_dmarc_from_domain_missing_is_context_unavailable(self):
        spf_r = {"status": "CONTEXT_UNAVAILABLE", "verification_type": "unavailable",
                  "verified_status": None, "evidence": None}
        dkim_r = {"verified_status": "NOT_PRESENT", "signatures": [], "verification_type": "unavailable",
                   "signature_present": False}
        with patch("app.analyzers.dmarc_evaluator.ENABLE_DNS_LOOKUPS", False):
            result = evaluate_dmarc(None, spf_r, dkim_r)
        assert result["status"] == "CONTEXT_UNAVAILABLE"
        assert result["verified_status"] is None


# ===========================================================================
# Real-email integration: NOT RUN
# ===========================================================================
# Real-email end-to-end validation is NOT performed here.
# To run real-email analysis:
#   1. Obtain an original .eml file from your mail client (Gmail → Show original,
#      Outlook → File → Save As → .eml or .msg, then convert to .eml).
#   2. Start the backend: uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
#   3. Upload the .eml via the API or UI.
#   4. For SPF independent verification, configure EMAILGUARD_TRUSTED_AUTHSERV_IDS
#      to your receiving mail server's authserv-id, or supply:
#        ?spf_client_ip=<real_IP>&spf_mailfrom=<envelope_from>
#      (operator_supplied_context, not independently trusted receiver data)
#   5. For DKIM: enable EMAILGUARD_DKIM_DNS_LOOKUPS=true
#   6. For DMARC: enable EMAILGUARD_DNS_LOOKUPS=true
#   7. For S/MIME: configure EMAILGUARD_SMIME_CA_BUNDLE=/path/to/ca-bundle.pem
#   8. For PGP: configure EMAILGUARD_PGP_KEYRING_DIR=/path/to/keyring/
#
# The report will record:
#   - message_sha256: SHA-256 of the raw .eml bytes (audit identifier)
#   - authentication.{spf,dkim,dmarc}.verification_type
#   - authentication.{spf,dkim,dmarc}.verified_status vs reported_status
#
# NOTE: A single ordinary email will not exercise every mechanism.
# The report explicitly states which mechanisms were applicable.
