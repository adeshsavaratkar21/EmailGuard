"""
PGP/OpenPGP Verifier - EmailGuard
===================================
Verifies PGP signatures using GnuPG in an isolated temporary keyring.

SUPPORTED FORMS
---------------
* Inline clear-signed PGP (-----BEGIN PGP SIGNED MESSAGE-----)
* PGP/MIME detached signature (multipart/signed; protocol="application/pgp-signature")

DESIGN PRINCIPLES
-----------------
* Signature cryptographic validity is reported separately from key/identity trust.
* We do NOT automatically import keys. A key embedded in a message is not trusted.
* Keys must come from a configured keyring (EMAILGUARD_PGP_KEYRING_DIR) or be
  explicitly operator-supplied.
* GnuPG runs in an isolated temp home with --batch, --no-auto-check-trustdb and
  no network keyserver access by default.
* A valid signature from an unknown/untrusted fingerprint is NOT proof of identity.
* We do NOT decrypt messages (requires recipient private key).
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any

logger = logging.getLogger(__name__)

# Import from central config for consistency
from app.config import PGP_KEYRING_DIR
GPG_TIMEOUT: int = int(os.getenv("EMAILGUARD_GPG_TIMEOUT", "10"))

_PGP_SIGNED_MARKER = "-----BEGIN PGP SIGNED MESSAGE-----"
_PGP_MSG_MARKER = "-----BEGIN PGP MESSAGE-----"
_PGP_SIG_MARKER = "-----BEGIN PGP SIGNATURE-----"


def _gpg_available() -> bool:
    try:
        proc = subprocess.run(
            ["gpg", "--version"], capture_output=True, timeout=5
        )
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _run_gpg(args: list[str], input_data: bytes | None, home: str) -> tuple[int, bytes, bytes]:
    """Run gpg safely in isolated home, no shell=True."""
    base_args = [
        "gpg",
        "--homedir", ".",
        "--batch",
        "--no-auto-check-trustdb",
        "--no-default-keyring",
        "--keyid-format", "long",
        "--status-fd", "1",
    ]
    try:
        proc = subprocess.run(
            base_args + args,
            input=input_data,
            cwd=home,
            capture_output=True,
            timeout=GPG_TIMEOUT,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -2, b"", b"gpg timeout"
    except Exception as exc:
        return -3, b"", str(exc).encode()


def _import_keyring(home: str) -> bool:
    """Import keys from configured keyring directory into temp home."""
    if not PGP_KEYRING_DIR or not os.path.isdir(PGP_KEYRING_DIR):
        return False
    imported = False
    for fname in os.listdir(PGP_KEYRING_DIR):
        fpath = os.path.join(PGP_KEYRING_DIR, fname)
        if os.path.isfile(fpath) and fname.lower().endswith((".asc", ".gpg", ".pub")):
            try:
                with open(fpath, "rb") as f:
                    key_data = f.read()
                rc, _, _ = _run_gpg(["--import"], key_data, home)
                if rc == 0:
                    imported = True
            except Exception:
                continue
    return imported


def _detect_pgp_form(raw: bytes, parsed: dict) -> tuple[str, bytes | None, bytes | None]:
    """
    Detect PGP form and extract parts.
    Returns (form, content_bytes, sig_bytes).
    form: 'inline_clear_signed'|'pgp_mime_detached'|'pgp_encrypted'|'not_present'
    """
    from email import message_from_bytes
    from email.policy import compat32

    msg = message_from_bytes(raw, policy=compat32)
    ct = msg.get_content_type().lower()
    protocol = (msg.get_param("protocol") or "").lower()

    # PGP/MIME detached signature
    if ct == "multipart/signed" and "pgp-signature" in protocol:
        parts = msg.get_payload()
        if isinstance(parts, list) and len(parts) >= 2:
            content_part = parts[0]
            sig_part = parts[1]
            try:
                sig_bytes = sig_part.get_payload(decode=True) or sig_part.get_payload().encode()
                content_bytes = content_part.as_bytes()
                return "pgp_mime_detached", content_bytes, sig_bytes
            except Exception:
                return "pgp_mime_detached", None, None

    # PGP/MIME encrypted
    if ct == "multipart/encrypted" and "pgp-encrypted" in protocol:
        return "pgp_encrypted", None, None

    # Inline clear-signed
    body = parsed.get("body_text", "")
    if _PGP_SIGNED_MARKER in body:
        return "inline_clear_signed", body.encode("utf-8", errors="replace"), None

    if _PGP_MSG_MARKER in body:
        return "pgp_encrypted_inline", None, None

    return "not_present", None, None


def _parse_gpg_status(status_output: bytes) -> dict[str, Any]:
    """Parse GPG --status-fd output."""
    text = status_output.decode("utf-8", errors="replace")
    info: dict[str, Any] = {
        "good_sig": False,
        "bad_sig": False,
        "no_pubkey": False,
        "key_expired": False,
        "fingerprint": None,
        "signer_uid": None,
        "trust_level": None,
    }
    for line in text.splitlines():
        if "[GNUPG:] GOODSIG" in line:
            info["good_sig"] = True
            parts = line.split(None, 3)
            if len(parts) >= 4:
                info["signer_uid"] = parts[3]
        elif "[GNUPG:] BADSIG" in line:
            info["bad_sig"] = True
        elif "[GNUPG:] NO_PUBKEY" in line or "NO_PUBKEY" in line:
            info["no_pubkey"] = True
        elif "[GNUPG:] KEY_EXPIRED" in line:
            info["key_expired"] = True
        elif "[GNUPG:] VALIDSIG" in line:
            parts = line.split()
            if len(parts) >= 3:
                info["fingerprint"] = parts[2]
        elif "[GNUPG:] TRUST_" in line:
            trust = re.search(r"TRUST_(\w+)", line)
            if trust:
                info["trust_level"] = trust.group(1).lower()
    return info


def verify_pgp(raw: bytes, parsed: dict) -> dict[str, Any]:
    """
    Verify PGP signature if present.

    Returns dict with keys:
        status               - PASS|FAIL|NOT_PRESENT|KEY_UNAVAILABLE|
                               KEY_UNTRUSTED|SIGNATURE_INVALID|
                               ENCRYPTED_NOT_DECRYPTED|VERIFIER_ERROR|
                               GPG_UNAVAILABLE|NO_KEYRING|UNSUPPORTED_FORM
        verification_type    - independent|unavailable
        signature_valid      - True|False|None (cryptographic)
        key_trusted          - True|False|None (gpg trust model)
        fingerprint          - hex fingerprint or None
        signer_uid           - uid string or None
        trust_level          - marginal|full|ultimate|unknown|None
        pgp_form             - detected form
        keyring_source       - where keys came from
        explanation          - human-readable summary
    """
    form, content_bytes, sig_bytes = _detect_pgp_form(raw, parsed)

    if form == "not_present":
        return {
            "status": "NOT_PRESENT",
            "verification_type": "unavailable",
            "signature_valid": None,
            "key_trusted": None,
            "fingerprint": None,
            "signer_uid": None,
            "trust_level": None,
            "pgp_form": "not_present",
            "keyring_source": None,
            "explanation": "No PGP/OpenPGP signature or encrypted content detected in this message.",
        }

    if form in ("pgp_encrypted", "pgp_encrypted_inline"):
        return {
            "status": "ENCRYPTED_NOT_DECRYPTED",
            "verification_type": "unavailable",
            "signature_valid": None,
            "key_trusted": None,
            "fingerprint": None,
            "signer_uid": None,
            "trust_level": None,
            "pgp_form": form,
            "keyring_source": None,
            "explanation": (
                "This message is PGP-encrypted. EmailGuard does not decrypt messages. "
                "Decryption requires the recipient's private key and explicit authorization."
            ),
        }

    if not _gpg_available():
        return {
            "status": "GPG_UNAVAILABLE",
            "verification_type": "unavailable",
            "signature_valid": None,
            "key_trusted": None,
            "fingerprint": None,
            "signer_uid": None,
            "trust_level": None,
            "pgp_form": form,
            "keyring_source": None,
            "explanation": "gpg command is not available; cannot verify PGP signature.",
        }

    home = tempfile.mkdtemp(prefix="emailguard_gpg_")
    try:
        # Restrictive permissions on temp home
        os.chmod(home, 0o700)

        # Import keys from configured keyring
        keyring_source: str | None = None
        if PGP_KEYRING_DIR:
            imported = _import_keyring(home)
            keyring_source = f"configured keyring: {PGP_KEYRING_DIR}" if imported else f"configured keyring (no keys imported from {PGP_KEYRING_DIR})"
        else:
            keyring_source = "none (EMAILGUARD_PGP_KEYRING_DIR not configured)"

        # Perform verification
        if form == "inline_clear_signed" and content_bytes:
            # For inline clear-signed, gpg reads from stdin
            tmpf = os.path.join(home, "msg.txt")
            with open(tmpf, "wb") as f:
                f.write(content_bytes)
            rc, status_out, stderr_out = _run_gpg(
                ["--verify", "msg.txt"], None, home
            )
        elif form == "pgp_mime_detached" and sig_bytes is not None and content_bytes:
            sig_file = os.path.join(home, "sig.asc")
            content_file = os.path.join(home, "content.bin")
            with open(sig_file, "wb") as f:
                f.write(sig_bytes)
            with open(content_file, "wb") as f:
                f.write(content_bytes)
            rc, status_out, stderr_out = _run_gpg(
                ["--verify", "sig.asc", "content.bin"], None, home
            )
        else:
            return {
                "status": "UNSUPPORTED_FORM",
                "verification_type": "unavailable",
                "signature_valid": None,
                "key_trusted": None,
                "fingerprint": None,
                "signer_uid": None,
                "trust_level": None,
                "pgp_form": form,
                "keyring_source": keyring_source,
                "explanation": (
                    f"PGP form {form!r} detected but required parts unavailable for verification."
                ),
            }

        gpg_info = _parse_gpg_status(status_out)
        stderr_text = stderr_out.decode("utf-8", errors="replace")

        if gpg_info["no_pubkey"]:
            return {
                "status": "KEY_UNAVAILABLE",
                "verification_type": "unavailable",
                "signature_valid": None,
                "key_trusted": None,
                "fingerprint": gpg_info["fingerprint"],
                "signer_uid": gpg_info["signer_uid"],
                "trust_level": None,
                "pgp_form": form,
                "keyring_source": keyring_source,
                "explanation": (
                    "PGP signature present but the signer's public key is not in the "
                    "configured keyring. Cannot verify the signature without the key. "
                    "Provide the key in EMAILGUARD_PGP_KEYRING_DIR to enable verification."
                ),
            }

        if gpg_info["bad_sig"]:
            return {
                "status": "SIGNATURE_INVALID",
                "verification_type": "independent",
                "signature_valid": False,
                "key_trusted": None,
                "fingerprint": gpg_info["fingerprint"],
                "signer_uid": gpg_info["signer_uid"],
                "trust_level": None,
                "pgp_form": form,
                "keyring_source": keyring_source,
                "explanation": (
                    "PGP signature verification FAILED (BAD signature). "
                    "The message may have been modified after signing."
                ),
            }

        if gpg_info["good_sig"]:
            trust = gpg_info["trust_level"] or "unknown"
            key_trusted = trust in ("full", "ultimate")
            if trust == "unknown" or not key_trusted:
                status = "KEY_UNTRUSTED"
                explanation = (
                    f"PGP signature is cryptographically VALID (GOODSIG). "
                    f"However, the signing key is not in the trusted keyring or has "
                    f"trust level {trust!r}. A valid signature from an untrusted key "
                    f"does not prove the sender's identity. "
                    f"Fingerprint: {gpg_info['fingerprint'] or 'unknown'}."
                )
            else:
                status = "PASS"
                explanation = (
                    f"PGP signature is VALID and the signing key has trust level {trust!r}. "
                    f"Signer UID: {gpg_info['signer_uid'] or 'unknown'}. "
                    f"Fingerprint: {gpg_info['fingerprint'] or 'unknown'}."
                )
            return {
                "status": status,
                "verification_type": "independent",
                "signature_valid": True,
                "key_trusted": key_trusted,
                "fingerprint": gpg_info["fingerprint"],
                "signer_uid": gpg_info["signer_uid"],
                "trust_level": trust,
                "pgp_form": form,
                "keyring_source": keyring_source,
                "explanation": explanation,
            }

        # rc != 0 and none of the known status flags
        return {
            "status": "VERIFIER_ERROR",
            "verification_type": "unavailable",
            "signature_valid": None,
            "key_trusted": None,
            "fingerprint": None,
            "signer_uid": None,
            "trust_level": None,
            "pgp_form": form,
            "keyring_source": keyring_source,
            "explanation": f"GPG returned an unexpected error (rc={rc}): {stderr_text[:200]}",
        }

    except Exception as exc:
        logger.warning("PGP verifier error: %s", exc)
        return {
            "status": "VERIFIER_ERROR",
            "verification_type": "unavailable",
            "signature_valid": None,
            "key_trusted": None,
            "fingerprint": None,
            "signer_uid": None,
            "trust_level": None,
            "pgp_form": "unknown",
            "keyring_source": None,
            "explanation": f"PGP verifier raised an error: {str(exc)[:200]}",
        }
    finally:
        try:
            shutil.rmtree(home, ignore_errors=True)
        except Exception:
            pass
