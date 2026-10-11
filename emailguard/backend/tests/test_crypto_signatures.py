"""End-to-end tests for the S/MIME signed-data path.

These tests generate a throw-away key pair and a real CMS signature with the
``openssl`` binary, embed it in a ``multipart/signed`` message and run the real
verifier.  They are skipped when ``openssl`` is unavailable.

The signed-data path previously returned VERIFIER_ERROR for every signed message
(IndexError from an over-eager list.pop while removing the CA bundle path), so
these tests guard that a genuine signature verifies and that tampering is caught.
"""

from __future__ import annotations

import base64
import shutil
import subprocess
import textwrap
from email import message_from_bytes
from email.policy import compat32
from pathlib import Path

import pytest

from app.analyzers.email_parser import parse_eml
from app.analyzers.smime_verifier import verify_smime

OPENSSL = shutil.which("openssl")
requires_openssl = pytest.mark.skipif(OPENSSL is None, reason="openssl binary is required")


def _openssl(args: list[str], cwd: Path) -> None:
    proc = subprocess.run([OPENSSL, *args], cwd=cwd, capture_output=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)} failed: {proc.stderr.decode(errors='replace')[:300]}")


def _signer_credentials(tmp_path: Path) -> tuple[Path, Path]:
    key_file = tmp_path / "signer.key"
    cert_file = tmp_path / "signer.pem"
    if not key_file.exists():
        _openssl(
            [
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                "-subj", "/CN=EmailGuard Test Signer/O=EmailGuard Demo",
                "-keyout", str(key_file), "-out", str(cert_file),
            ],
            cwd=tmp_path,
        )
    return key_file, cert_file


def _build_signed_message(tmp_path: Path, body: bytes, tamper: bool = False) -> bytes:
    """Return a multipart/signed .eml whose detached CMS signature is real."""
    key_file, cert_file = _signer_credentials(tmp_path)
    placeholder = (
        b"From: signer@example.test\r\n"
        b"To: rcpt@example.test\r\n"
        b"Subject: Signed test message\r\n"
        b"Date: Mon, 6 Oct 2026 10:00:00 +0000\r\n"
        b"Message-ID: <smime-e2e@example.test>\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\";"
        b" micalg=sha-256; boundary=\"sig-bound\"\r\n"
        b"\r\n"
        b"--sig-bound\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: 7bit\r\n"
        b"\r\n" + body + b"\r\n"
        b"--sig-bound\r\n"
        b"Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"Content-Disposition: attachment; filename=\"smime.p7s\"\r\n"
        b"\r\nPLACEHOLDER\r\n"
        b"--sig-bound--\r\n"
    )

    # Sign exactly the bytes the verifier will feed to openssl (the content part,
    # including its own MIME headers, canonicalised by the email package).
    content_bytes = message_from_bytes(placeholder, policy=compat32).get_payload()[0].as_bytes()
    content_file = tmp_path / "content.bin"
    content_file.write_bytes(content_bytes)
    signature_file = tmp_path / "signature.der"
    # NOTE: no "-binary" here. The verifier runs "openssl cms -verify" without it,
    # and SMIME canonicalisation of the content must match on both sides.
    _openssl(
        [
            "cms", "-sign", "-in", str(content_file),
            "-signer", str(cert_file), "-inkey", str(key_file),
            "-outform", "DER", "-out", str(signature_file),
        ],
        cwd=tmp_path,
    )
    wrapped = base64.b64encode(signature_file.read_bytes()).decode("ascii")
    signature_block = "\r\n".join(textwrap.wrap(wrapped, 64)).encode("ascii")

    signed = placeholder.replace(b"PLACEHOLDER", signature_block)
    if tamper:
        # Modify the signed content after signing: the signature must no longer match.
        signed = signed.replace(body, body + b" (modified after signing)")
    return signed


@requires_openssl
def test_real_signed_smime_message_verifies(tmp_path):
    raw = _build_signed_message(tmp_path, b"This paragraph is the signed content.")
    result = verify_smime(raw, parse_eml(raw))

    assert result["status"] != "VERIFIER_ERROR", result["explanation"]
    assert result["signature_valid"] is True
    # The certificate is self-signed, so the signature is valid but the chain is not
    # trusted.  That distinction must be preserved rather than reported as a pass.
    assert result["status"] in {"CERT_UNTRUSTED", "PASS_SIG_ONLY", "PASS"}
    if result["cert_trusted"] is False:
        assert result["status"] == "CERT_UNTRUSTED"
    # The signer certificate must be reported, not silently dropped.
    assert "EmailGuard Test Signer" in (result["cert_details"] or {}).get("subject", "")


@requires_openssl
def test_tampered_smime_signature_is_detected(tmp_path):
    raw = _build_signed_message(tmp_path, b"This paragraph is the signed content.", tamper=True)
    result = verify_smime(raw, parse_eml(raw))

    assert result["status"] == "SIGNATURE_INVALID"
    assert result["signature_valid"] is False
    assert "FAILED" in result["explanation"]


@requires_openssl
def test_tampered_smime_signature_is_scored_as_a_risk_factor(tmp_path):
    from app.service import analyze_email_bytes

    raw = _build_signed_message(tmp_path, b"Please confirm your account details.", tamper=True)
    report = analyze_email_bytes(raw, "tampered-smime.eml")

    factor = next((f for f in report["factors"] if f["code"] == "invalid_signature"), None)
    assert factor is not None, [f["code"] for f in report["factors"]]
    assert factor["contribution"] == 25
