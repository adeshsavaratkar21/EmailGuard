from __future__ import annotations

import json
import os

APP_NAME = "EmailGuard API"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./emailguard.db")
MAX_EMAIL_BYTES = int(os.getenv("EMAILGUARD_MAX_EMAIL_BYTES", str(10 * 1024 * 1024)))
ALLOW_ACTIVE_URL_CHECKS = os.getenv("EMAILGUARD_ALLOW_ACTIVE_URL_CHECKS", "false").lower() in {"1", "true", "yes"}

# Enable DNS lookups by default to allow real DKIM and DMARC verification out of the box
ENABLE_DKIM_DNS_LOOKUPS = os.getenv("EMAILGUARD_DKIM_DNS_LOOKUPS", "true").lower() in {"1", "true", "yes"}
ENABLE_DNS_LOOKUPS = os.getenv("EMAILGUARD_DNS_LOOKUPS", "true").lower() in {"1", "true", "yes"}

SAFE_SAFETY_THRESHOLD = int(os.getenv("EMAILGUARD_SAFE_THRESHOLD", "80"))
SUSPICIOUS_SAFETY_THRESHOLD = int(os.getenv("EMAILGUARD_SUSPICIOUS_THRESHOLD", "50"))
MAX_URLS_PER_EMAIL = int(os.getenv("EMAILGUARD_MAX_URLS_PER_EMAIL", "50"))
MAX_ACTIVE_URLS_PER_EMAIL = int(os.getenv("EMAILGUARD_MAX_ACTIVE_URLS_PER_EMAIL", "3"))
ACTIVE_URL_TIMEOUT_SECONDS = float(os.getenv("EMAILGUARD_URL_TIMEOUT_SECONDS", "2.5"))
MAX_URL_REDIRECTS = int(os.getenv("EMAILGUARD_MAX_URL_REDIRECTS", "3"))
# SPF: comma-separated list of trusted authserv-id values.
# Example: EMAILGUARD_TRUSTED_AUTHSERV_IDS=mx.myorg.com,mail.myorg.com
# Default: empty (no trusted receiver configured; SPF will not be independently evaluated)
TRUSTED_AUTHSERV_IDS = os.getenv("EMAILGUARD_TRUSTED_AUTHSERV_IDS", "")
# S/MIME: path to PEM CA bundle for certificate chain validation
# Default: Uses certifi CA bundle if available
try:
    import certifi
    default_ca = certifi.where()
except ImportError:
    default_ca = ""
SMIME_CA_BUNDLE = os.getenv("EMAILGUARD_SMIME_CA_BUNDLE", default_ca)
# PGP: path to directory containing trusted public key files (.asc/.gpg/.pub)
# Default: empty (PGP signatures present but keys unavailable → KEY_UNAVAILABLE)
PGP_KEYRING_DIR = os.getenv("EMAILGUARD_PGP_KEYRING_DIR", "")
# DNS timeouts
SPF_DNS_TIMEOUT = float(os.getenv("EMAILGUARD_SPF_DNS_TIMEOUT", "3.0"))
DKIM_DNS_TIMEOUT = float(os.getenv("EMAILGUARD_DKIM_DNS_TIMEOUT", "5.0"))
DMARC_DNS_TIMEOUT = float(os.getenv("EMAILGUARD_DMARC_DNS_TIMEOUT", "5.0"))

DEFAULT_WEIGHTS: dict[str, int] = {
    "spf_fail": 15,
    "spf_softfail": 7,
    "dkim_fail": 15,
    "dmarc_fail": 20,
    # The visible From domain has no MX/A/AAAA/NS records at all. Distinct from
    # "no DMARC policy published", which is informational and carries no weight.
    "sender_domain_unresolvable": 10,
    "invalid_signature": 25,
    "suspicious_url": 20,
    "lookalike_domain": 25,
    "suspicious_redirect": 20,
    "expired_tls": 15,
    "hostname_mismatch": 25,
    "tls_invalid": 15,
    "ip_based_url": 10,
    "private_network_url": 15,
    "suspicious_keyword": 6,
    "insecure_http": 5,
    "reply_to_mismatch": 8,
    "excessive_subdomains": 6,
    "encoded_url": 5,
    "unusual_port": 8,
    "spf_pass": -5,
    "dkim_pass": -5,
    "dmarc_pass": -10,
    "valid_signature": -10,
    "valid_tls": -2,
    "limited_evidence": 8,
}

try:
    _overrides = json.loads(os.getenv("EMAILGUARD_SCORING_WEIGHTS", "{}"))
    if isinstance(_overrides, dict):
        DEFAULT_WEIGHTS.update({str(k): int(v) for k, v in _overrides.items()})
except (ValueError, TypeError):
    pass

TRUSTED_BRANDS = {
    "paypal.com": "paypal",
    "google.com": "google",
    "microsoft.com": "microsoft",
    "apple.com": "apple",
    "amazon.com": "amazon",
    "amazon.in": "amazon",
    "netflix.com": "netflix",
    "facebook.com": "facebook",
    "instagram.com": "instagram",
    "linkedin.com": "linkedin",
    "dropbox.com": "dropbox",
    "adobe.com": "adobe",
    "icicibank.com": "icici",
    "sbi.co.in": "sbi",
    "hdfcbank.com": "hdfc",
}

SUSPICIOUS_TERMS = {
    "login", "log-in", "signin", "sign-in", "verify", "verification", "password",
    "account", "update", "secure", "security", "payment", "invoice", "wallet",
    "authenticate", "auth", "reset", "recover", "suspended", "billing", "confirm",
}
