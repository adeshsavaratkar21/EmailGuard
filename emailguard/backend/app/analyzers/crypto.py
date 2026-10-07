"""
Cryptographic Integrity Module - EmailGuard
============================================
Provides body hashes and aggregates digital signature status from the
authentication check results.  The SHA-256/512 digests are integrity
identifiers only - they do NOT authenticate the sender.

S/MIME and PGP status come from the real verifiers (smime_verifier,
pgp_verifier) called by authentication.py.  This module does not re-verify
them; it only assembles the crypto section of the report.
"""

from __future__ import annotations

import hashlib


def analyze_crypto(raw: bytes, parsed: dict, authentication: dict) -> dict:
    """
    Assemble cryptographic section of the email analysis report.

    Parameters
    ----------
    raw            : original .eml bytes
    parsed         : output of parse_eml()
    authentication : output of analyze_authentication()

    Returns
    -------
    dict with keys: hashes, digital_signature, certificate, smime, pgp
    """
    body = parsed.get("body_text", "").encode("utf-8", errors="replace")

    digest256 = hashlib.sha256(body).hexdigest()
    digest512 = hashlib.sha512(body).hexdigest()

    dkim_info = authentication.get("dkim", {})
    smime_info = authentication.get("smime", {})
    pgp_info = authentication.get("pgp", {})

    dkim_status = dkim_info.get("verified_status") or dkim_info.get("status", "UNVERIFIED")
    dkim_present = dkim_info.get("signature_present", False)
    smime_status = smime_info.get("status", "NOT_PRESENT")
    smime_present = smime_status not in ("NOT_PRESENT", "OPENSSL_UNAVAILABLE")
    pgp_status = pgp_info.get("status", "NOT_PRESENT")
    pgp_present = pgp_status not in ("NOT_PRESENT", "GPG_UNAVAILABLE")

    # Certificate details from S/MIME result
    smime_cert = smime_info.get("cert_details") or {}
    cert_section: dict = {
        "status": smime_status if smime_present else "NOT_PRESENT",
        "note": smime_info.get("explanation", ""),
        "smime_signature_valid": smime_info.get("signature_valid"),
        "cert_trusted": smime_info.get("cert_trusted"),
    }
    if smime_cert:
        cert_section.update({
            "subject": smime_cert.get("subject"),
            "issuer": smime_cert.get("issuer"),
            "valid_from": smime_cert.get("valid_from"),
            "valid_until": smime_cert.get("valid_until"),
        })

    return {
        "hashes": {
            "algorithm": "SHA-256 / SHA-512",
            "sha256": digest256,
            "sha512": digest512,
            "scope": "Decoded text body only; digest is useful for integrity comparison and does not authenticate the sender.",
            "body_bytes": len(body),
        },
        "digital_signature": {
            "dkim_present": dkim_present,
            "dkim_status": dkim_status,
            "dkim_verified_status": dkim_info.get("verified_status"),
            "dkim_reported_status": dkim_info.get("reported_status"),
            "smime_present": smime_present,
            "smime_status": smime_status,
            "smime_verification_type": smime_info.get("verification_type", "unavailable"),
            "pgp_present": pgp_present,
            "pgp_status": pgp_status,
            "pgp_verification_type": pgp_info.get("verification_type", "unavailable"),
            "rsa_ecc": "Algorithm/key type is reported per-signature from verifier output when available.",
        },
        "certificate": cert_section,
        "smime": {
            "status": smime_status,
            "verification_type": smime_info.get("verification_type", "unavailable"),
            "signature_valid": smime_info.get("signature_valid"),
            "cert_trusted": smime_info.get("cert_trusted"),
            "smime_form": smime_info.get("smime_form"),
            "cert_details": smime_cert or None,
            "explanation": smime_info.get("explanation", ""),
        },
        "pgp": {
            "status": pgp_status,
            "verification_type": pgp_info.get("verification_type", "unavailable"),
            "signature_valid": pgp_info.get("signature_valid"),
            "key_trusted": pgp_info.get("key_trusted"),
            "fingerprint": pgp_info.get("fingerprint"),
            "signer_uid": pgp_info.get("signer_uid"),
            "trust_level": pgp_info.get("trust_level"),
            "pgp_form": pgp_info.get("pgp_form"),
            "keyring_source": pgp_info.get("keyring_source"),
            "explanation": pgp_info.get("explanation", ""),
        },
    }
