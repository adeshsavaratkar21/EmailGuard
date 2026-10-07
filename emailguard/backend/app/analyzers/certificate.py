"""X.509 certificate parsing helpers for a successfully negotiated TLS peer.

The URL analyzer invokes these helpers only after it has constrained DNS results
and negotiated TLS with hostname validation enabled. This module never turns a
certificate into a site-trust verdict.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.serialization import Encoding


def summarize_der_certificate(der: bytes, tls_version: str | None, hostname: str) -> dict:
    cert = x509.load_der_x509_certificate(der)
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_info = {"algorithm": "RSA", "key_size_bits": public_key.key_size}
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_info = {"algorithm": "ECC", "curve": public_key.curve.name, "key_size_bits": public_key.key_size}
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key_info = {"algorithm": public_key.__class__.__name__.replace("PublicKey", ""), "key_size_bits": None}
    else:
        key_info = {"algorithm": public_key.__class__.__name__, "key_size_bits": None}

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    try:
        signature_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    except Exception:
        signature_hash = "unknown"
    return {
        "status": "VALID",
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "valid_from": not_before.isoformat(),
        "valid_until": not_after.isoformat(),
        "expired": now > not_after,
        "not_yet_valid": now < not_before,
        "hostname": hostname,
        "hostname_match": True,
        "chain_validated": True,
        "subject_alt_names": names[:32],
        "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
        "signature_hash": signature_hash,
        "public_key": key_info,
        "tls_version": tls_version,
        "sha256_fingerprint": hashlib.sha256(der).hexdigest(),
        "certificate_bytes": len(der),
        "trust_note": "TLS chain and hostname validation succeeded. A valid certificate encrypts the connection; it does not establish that the site is legitimate.",
    }


def summarize_certificate(certificate: dict, tls_version: str | None) -> dict:
    """Normalize the limited certificate fields provided by Python's ssl module."""
    issuer = ", ".join(value for group in certificate.get("issuer", []) for _, value in group)
    subject = ", ".join(value for group in certificate.get("subject", []) for _, value in group)
    return {
        "subject": subject,
        "issuer": issuer,
        "valid_from": certificate.get("notBefore"),
        "valid_until": certificate.get("notAfter"),
        "subject_alt_names": [value for kind, value in certificate.get("subjectAltName", []) if kind == "DNS"],
        "tls_version": tls_version,
        "note": "Chain and hostname validation must be assessed by the TLS verifier, not inferred from certificate metadata alone.",
    }
