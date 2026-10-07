"""
S/MIME Verifier - EmailGuard
=============================
Verifies signed S/MIME messages using OpenSSL CMS via safe subprocess calls.

SUPPORTED FORMS
---------------
* multipart/signed with protocol="application/pkcs7-signature" (detached sig)
* application/pkcs7-mime with smime-type=signed-data (opaque signed)
* Legacy x-pkcs7 MIME types

DESIGN PRINCIPLES
-----------------
* Signature cryptographic validity is reported separately from certificate trust.
* A valid signature from an untrusted certificate is NOT called a trusted sender.
* No decryption is performed; decryption requires recipient private key.
* OpenSSL is called via argument list (no shell=True).
* Temporary dirs are used with restrictive permissions and cleaned up.
* Expired certificate, unknown issuer, missing CA, and bad signature are distinct.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
from typing import Any

logger = logging.getLogger(__name__)

# Import from central config so certifi CA auto-detection works out of the box
from app.config import SMIME_CA_BUNDLE as CA_BUNDLE
OPENSSL_TIMEOUT: int = int(os.getenv("EMAILGUARD_OPENSSL_TIMEOUT", "10"))


def _run_openssl(args: list[str], input_data: bytes | None = None, timeout: int = OPENSSL_TIMEOUT) -> tuple[int, bytes, bytes]:
    """Run openssl safely (no shell=True). Returns (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            ["openssl"] + args,
            input=input_data,
            capture_output=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, b"", b"openssl not found"
    except subprocess.TimeoutExpired:
        return -2, b"", b"openssl timeout"
    except Exception as exc:
        return -3, b"", str(exc).encode()


def _openssl_available() -> bool:
    rc, _, _ = _run_openssl(["version"], timeout=5)
    return rc == 0


def _extract_smime_parts(raw: bytes, parsed: dict) -> tuple[str, bytes | None, bytes | None]:
    """
    Detect S/MIME form and extract relevant parts.

    Returns (form, content_bytes, sig_bytes).
    form: 'multipart_signed' | 'opaque_signed' | 'not_present' | 'unknown'
    """
    from email import message_from_bytes
    from email.policy import compat32

    msg = message_from_bytes(raw, policy=compat32)
    ct = msg.get_content_type().lower()
    smime_type = (msg.get_param("smime-type") or "").lower()
    protocol = (msg.get_param("protocol") or "").lower()

    # Multipart/signed with pkcs7-signature
    if ct == "multipart/signed" and "pkcs7" in protocol:
        parts = msg.get_payload()
        if isinstance(parts, list) and len(parts) >= 2:
            # Part 0 is content, part 1 is signature
            content_part = parts[0]
            sig_part = parts[1]
            try:
                sig_bytes = sig_part.get_payload(decode=True)
                # We need the raw content bytes in canonical form
                content_bytes = content_part.as_bytes()
                return "multipart_signed", content_bytes, sig_bytes
            except Exception:
                return "multipart_signed", None, None

    # Opaque signed or encrypted
    if ct in ("application/pkcs7-mime", "application/x-pkcs7-mime"):
        if "signed" in smime_type:
            try:
                payload = msg.get_payload(decode=True)
                return "opaque_signed", None, payload
            except Exception:
                return "opaque_signed", None, None
        elif "enveloped" in smime_type or "encrypted" in smime_type:
            return "encrypted_not_decrypted", None, None
        else:
            try:
                payload = msg.get_payload(decode=True)
                return "opaque_unknown", None, payload
            except Exception:
                return "opaque_unknown", None, None

    # Check attachments for .p7s or .p7m
    mime_types_present = parsed.get("mime_types", [])
    attachments = parsed.get("attachments", [])
    has_smime = any(
        v in {"application/pkcs7-signature", "application/x-pkcs7-signature",
              "application/pkcs7-mime", "application/x-pkcs7-mime"}
        for v in mime_types_present
    ) or any("smime.p7" in (a.get("filename") or "").lower() for a in attachments)

    if has_smime:
        return "unknown", None, None

    return "not_present", None, None


def _parse_openssl_cert_info(output: str) -> dict[str, Any]:
    """Extract basic certificate details from openssl output text."""
    info: dict[str, Any] = {}
    subject_m = re.search(r"subject=(.+)", output)
    issuer_m = re.search(r"issuer=(.+)", output)
    not_before = re.search(r"Not Before\s*:\s*(.+)", output)
    not_after = re.search(r"Not After\s*:\s*(.+)", output)
    if subject_m:
        info["subject"] = subject_m.group(1).strip()
    if issuer_m:
        info["issuer"] = issuer_m.group(1).strip()
    if not_before:
        info["valid_from"] = not_before.group(1).strip()
    if not_after:
        info["valid_until"] = not_after.group(1).strip()
    return info


def verify_smime(raw: bytes, parsed: dict) -> dict[str, Any]:
    """
    Verify S/MIME signature if present.

    Returns dict with keys:
        status               - PASS|FAIL|NOT_PRESENT|ENCRYPTED_NOT_DECRYPTED|
                               SIGNATURE_INVALID|CERT_UNTRUSTED|CERT_EXPIRED|
                               KEY_UNAVAILABLE|VERIFIER_ERROR|OPENSSL_UNAVAILABLE|
                               UNSUPPORTED_FORM
        verification_type    - independent|unavailable
        signature_valid      - True|False|None (cryptographic only)
        cert_trusted         - True|False|None (chain trust)
        cert_details         - dict of signer cert fields
        smime_form           - detected S/MIME form
        explanation          - human-readable summary
    """
    form, content_bytes, sig_bytes = _extract_smime_parts(raw, parsed)

    if form == "not_present":
        return {
            "status": "NOT_PRESENT",
            "verification_type": "unavailable",
            "signature_valid": None,
            "cert_trusted": None,
            "cert_details": None,
            "smime_form": "not_present",
            "explanation": "No S/MIME signature or encryption structure detected in this message.",
        }

    if form == "encrypted_not_decrypted":
        return {
            "status": "ENCRYPTED_NOT_DECRYPTED",
            "verification_type": "unavailable",
            "signature_valid": None,
            "cert_trusted": None,
            "cert_details": None,
            "smime_form": "encrypted",
            "explanation": (
                "This message appears to be encrypted S/MIME (enveloped data). "
                "EmailGuard does not decrypt messages. Decryption requires the "
                "authorized recipient's private key."
            ),
        }

    if not _openssl_available():
        return {
            "status": "OPENSSL_UNAVAILABLE",
            "verification_type": "unavailable",
            "signature_valid": None,
            "cert_trusted": None,
            "cert_details": None,
            "smime_form": form,
            "explanation": "openssl command is not available; cannot verify S/MIME signature.",
        }

    if form == "unknown" or (sig_bytes is None and form != "opaque_signed"):
        return {
            "status": "UNSUPPORTED_FORM",
            "verification_type": "unavailable",
            "signature_valid": None,
            "cert_trusted": None,
            "cert_details": None,
            "smime_form": form,
            "explanation": (
                f"S/MIME structure detected (form={form}) but signature bytes could not be "
                "extracted for verification. This S/MIME form may not be supported."
            ),
        }

    tmpdir = tempfile.mkdtemp(prefix="emailguard_smime_")
    try:
        sig_file = os.path.join(tmpdir, "sig.p7s")
        content_file = os.path.join(tmpdir, "content.bin")
        out_file = os.path.join(tmpdir, "verified.out")
        cert_file = os.path.join(tmpdir, "signer.pem")

        if sig_bytes:
            with open(sig_file, "wb") as f:
                f.write(sig_bytes)
        if content_bytes:
            with open(content_file, "wb") as f:
                f.write(content_bytes)

        # Build openssl cms verify command
        if form == "multipart_signed" and sig_bytes and content_bytes:
            # Detached signature
            cmd = ["cms", "-verify", "-in", sig_file, "-inform", "DER",
                   "-content", content_file, "-out", out_file,
                   "-signer", cert_file, "-noverify"]
            if CA_BUNDLE:
                cmd = ["cms", "-verify", "-in", sig_file, "-inform", "DER",
                       "-content", content_file, "-out", out_file,
                       "-signer", cert_file, "-CAfile", CA_BUNDLE]
        else:
            # Opaque signed - sig_bytes contains full CMS
            if sig_bytes:
                with open(sig_file, "wb") as f:
                    f.write(sig_bytes)
            cmd = ["cms", "-verify", "-in", sig_file, "-inform", "DER",
                   "-out", out_file, "-signer", cert_file, "-noverify"]
            if CA_BUNDLE:
                cmd = ["cms", "-verify", "-in", sig_file, "-inform", "DER",
                       "-out", out_file, "-signer", cert_file, "-CAfile", CA_BUNDLE]

        # Step 1: Verify signature WITHOUT trust chain (cryptographic only)
        crypto_cmd = [a for a in cmd if a != CA_BUNDLE]
        if "-CAfile" in crypto_cmd:
            i = crypto_cmd.index("-CAfile")
            crypto_cmd.pop(i); crypto_cmd.pop(i)
        if "-noverify" not in crypto_cmd:
            crypto_cmd.append("-noverify")
        rc_crypto, out_crypto, err_crypto = _run_openssl(crypto_cmd)
        signature_valid = rc_crypto == 0

        # Extract signer cert details
        cert_details: dict[str, Any] = {}
        if os.path.exists(cert_file) and os.path.getsize(cert_file) > 0:
            rc_cert, out_cert, _ = _run_openssl(
                ["x509", "-in", cert_file, "-noout", "-text", "-nameopt", "RFC2253"]
            )
            if rc_cert == 0:
                cert_details = _parse_openssl_cert_info(out_cert.decode("utf-8", errors="replace"))

        # Step 2: Verify chain trust if CA bundle configured
        cert_trusted: bool | None = None
        trust_explanation = "Certificate chain trust was not checked (no CA bundle configured)."
        if CA_BUNDLE and os.path.exists(CA_BUNDLE):
            trusted_cmd = [a for a in cmd]
            if "-noverify" in trusted_cmd:
                trusted_cmd.remove("-noverify")
            rc_trust, out_trust, err_trust = _run_openssl(trusted_cmd)
            cert_trusted = rc_trust == 0
            if cert_trusted:
                trust_explanation = "Certificate chain validated against configured CA bundle."
            else:
                err_str = err_trust.decode("utf-8", errors="replace")
                if "expired" in err_str.lower():
                    trust_explanation = f"Certificate has expired: {err_str[:200]}"
                elif "unable to get local issuer" in err_str.lower() or "verify error" in err_str.lower():
                    trust_explanation = f"Certificate chain could not be verified: {err_str[:200]}"
                else:
                    trust_explanation = f"Trust check failed: {err_str[:200]}"

        # Determine overall status
        if not signature_valid:
            err_str = err_crypto.decode("utf-8", errors="replace")
            status = "SIGNATURE_INVALID"
            explanation = f"S/MIME cryptographic signature verification FAILED. {err_str[:200]}"
        elif cert_trusted is False:
            status = "CERT_UNTRUSTED"
            explanation = f"S/MIME signature is cryptographically valid but {trust_explanation}"
        elif cert_trusted is True:
            status = "PASS"
            explanation = f"S/MIME signature is cryptographically valid and certificate chain is trusted. {trust_explanation}"
        else:
            status = "PASS_SIG_ONLY"
            explanation = (
                "S/MIME cryptographic signature is VALID. "
                "Certificate chain trust was not checked (configure EMAILGUARD_SMIME_CA_BUNDLE). "
                "A valid signature from an untrusted certificate does not prove the sender's identity."
            )

        return {
            "status": status,
            "verification_type": "independent",
            "signature_valid": signature_valid,
            "cert_trusted": cert_trusted,
            "cert_details": cert_details,
            "smime_form": form,
            "explanation": explanation,
        }
    except Exception as exc:
        logger.warning("S/MIME verifier error: %s", exc)
        return {
            "status": "VERIFIER_ERROR",
            "verification_type": "unavailable",
            "signature_valid": None,
            "cert_trusted": None,
            "cert_details": None,
            "smime_form": form,
            "explanation": f"S/MIME verifier raised an error: {str(exc)[:200]}",
        }
    finally:
        import shutil
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass
