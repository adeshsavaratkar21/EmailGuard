from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from difflib import SequenceMatcher
from urllib.parse import urljoin, urlsplit, urlunsplit

from ..config import ACTIVE_URL_TIMEOUT_SECONDS, ALLOW_ACTIVE_URL_CHECKS, MAX_URL_REDIRECTS, SUSPICIOUS_TERMS, TRUSTED_BRANDS

_MULTI_PART_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.in", "firm.in", "com.br", "co.jp", "co.nz"}
_TRANSLATE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s"})


def _registrable_domain(host: str) -> tuple[str, str]:
    labels = host.strip(".").lower().split(".")
    if len(labels) <= 1:
        return host.lower(), ""
    suffix2 = ".".join(labels[-2:])
    count = 3 if suffix2 in _MULTI_PART_SUFFIXES and len(labels) >= 3 else 2
    registered = ".".join(labels[-count:])
    subdomain = ".".join(labels[:-count])
    return registered, subdomain


def _domain_similarity(host: str) -> dict:
    registered, _ = _registrable_domain(host)
    labels = registered.split(".")
    candidate = labels[0] if labels else registered
    compared: list[tuple[float, str]] = []
    candidates = [candidate, candidate.replace("-", ""), *[chunk for chunk in candidate.split("-") if chunk]]
    for brand_domain, brand_name in TRUSTED_BRANDS.items():
        if host == brand_domain or host.endswith("." + brand_domain):
            continue
        trusted_root, _ = _registrable_domain(brand_domain)
        expected = trusted_root.split(".")[0]
        try:
            from rapidfuzz.fuzz import ratio
            score = max(ratio(value.translate(_TRANSLATE), expected) / 100 for value in candidates if value)
        except ImportError:
            score = max(SequenceMatcher(None, value.translate(_TRANSLATE), expected).ratio() for value in candidates if value)
        brand_mentioned = any(label == expected or label.startswith(expected + "-") for label in host.split("."))
        if score >= 0.77 or brand_mentioned:
            compared.append((score, brand_name))
    if not compared:
        return {"detected": False, "brand": None, "similarity": None}
    similarity, brand = max(compared, key=lambda item: item[0])
    return {"detected": True, "brand": brand, "similarity": round(similarity, 3)}


def _safe_resolve(host: str, port: int) -> list[str]:
    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        try:
            import dns.resolver  # type: ignore
            resolver = dns.resolver.Resolver()
            resolver.timeout = min(1.2, ACTIVE_URL_TIMEOUT_SECONDS)
            resolver.lifetime = min(2.4, ACTIVE_URL_TIMEOUT_SECONDS)
            addresses = []
            for record_type in ("A", "AAAA"):
                try:
                    answers = resolver.resolve(host, record_type, lifetime=min(1.2, ACTIVE_URL_TIMEOUT_SECONDS), search=False)
                    addresses.extend(str(answer) for answer in answers)
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue
                except dns.resolver.LifetimeTimeout as exc:
                    raise ValueError("DNS lookup timed out; network probing was stopped") from exc
            addresses = list(dict.fromkeys(addresses))
        except ImportError as exc:
            raise ValueError("Safe DNS resolver is unavailable; network probing was stopped") from exc
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError("DNS lookup failed; network probing was stopped") from exc
    if not addresses:
        raise ValueError("No address records found")
    parsed = [ipaddress.ip_address(address) for address in addresses]
    if any(not address.is_global for address in parsed):
        raise ValueError("The hostname resolves to a private, reserved, or non-public address; network probing was blocked")
    return addresses


def _one_safe_head(url: str, timeout: float = ACTIVE_URL_TIMEOUT_SECONDS) -> dict:
    parts = urlsplit(url)
    host = parts.hostname or ""
    scheme = parts.scheme.lower()
    port = parts.port if parts.port is not None else (443 if scheme == "https" else 80)
    if scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS can be probed")
    expected_port = 443 if scheme == "https" else 80
    if port != expected_port:
        raise ValueError("Active checks are limited to the standard port for the URL scheme")
    if not host or parts.username or parts.password:
        raise ValueError("Host is missing or URL credentials are not allowed")
    addresses = _safe_resolve(host, port)
    sock = socket.create_connection((addresses[0], port), timeout=timeout)
    tls_info: dict = {"status": "NOT_APPLICABLE"}
    if scheme == "https":
        context = ssl.create_default_context()
        try:
            sock = context.wrap_socket(sock, server_hostname=host)
            der_certificate = sock.getpeercert(binary_form=True)
            from .certificate import summarize_der_certificate
            certificate_summary = summarize_der_certificate(der_certificate, sock.version(), host)
            tls_info = {
                "status": "VALID",
                "version": sock.version(),
                "issuer": certificate_summary.get("issuer", "Verified issuer"),
                "not_after": certificate_summary.get("valid_until"),
                "subject_alt_names": certificate_summary.get("subject_alt_names", [])[:12],
                "hostname_match": True,
                "chain_validated": True,
                "certificate": certificate_summary,
            }
        except ssl.SSLCertVerificationError as exc:
            try:
                sock.close()
            except OSError:
                pass
            return {"status": "TLS_INVALID", "tls": {"status": "INVALID", "detail": str(exc)[:240]}, "location": None}
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    connection.sock = sock
    path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    try:
        connection.putrequest("HEAD", path, skip_accept_encoding=True)
        host_header = host if port in {80, 443} else f"{host}:{port}"
        connection.putheader("Host", host_header)
        connection.putheader("User-Agent", "EmailGuard-SafeScanner/1.0")
        connection.putheader("Connection", "close")
        connection.endheaders()
        response = connection.getresponse()
        location = response.getheader("Location")
        result = {"status": response.status, "tls": tls_info, "location": location}
        response.close()
        return result
    finally:
        connection.close()


def _probe_redirects(url: str, max_hops: int = MAX_URL_REDIRECTS) -> dict:
    chain: list[dict] = []
    current = url
    tls: dict = {"status": "NOT_CHECKED"}
    error = None
    redirect_count = 0
    initial_host = (urlsplit(url).hostname or "").lower()
    final_host = initial_host
    downgrade = False
    domain_changed = False
    for _ in range(max_hops + 1):
        try:
            result = _one_safe_head(current)
        except Exception as exc:
            error = str(exc)[:240]
            if redirect_count and (not chain or chain[-1].get("url") != current):
                chain.append({"url": current, "status": None, "blocked": True})
            break
        tls = result.get("tls", tls)
        chain.append({"url": current, "status": result.get("status")})
        location = result.get("location")
        if not location or result.get("status") not in {301, 302, 303, 307, 308}:
            break
        redirect_count += 1
        next_url = urljoin(current, location)
        next_parts = urlsplit(next_url)
        if next_parts.scheme.lower() not in {"http", "https"} or not next_parts.hostname:
            current = next_url
            error = "Redirect target was not an HTTP(S) URL"
            break
        if urlsplit(current).scheme.lower() == "https" and next_parts.scheme.lower() == "http":
            downgrade = True
        next_host = next_parts.hostname.lower()
        domain_changed = domain_changed or next_host != initial_host
        final_host = next_host
        current = next_url
    else:
        error = "Redirect limit reached"
    if current and urlsplit(current).hostname:
        final_host = urlsplit(current).hostname.lower()
    return {
        "chain": chain,
        "redirect_count": redirect_count,
        "final_url": current,
        "final_domain": final_host,
        "domain_changed": domain_changed,
        "https_downgrade": downgrade,
        "tls": tls,
        "error": error,
    }

def analyze_url(raw_url: str, network_checks: bool = False) -> dict:
    value = (raw_url or "").strip()
    if not value:
        raise ValueError("A URL is required")
    lowered_input = value.lower()
    if lowered_input.startswith(("javascript:", "data:", "file:", "ftp:", "mailto:", "chrome:", "chrome-extension:", "ws:", "wss:")):
        raise ValueError("Only HTTP and HTTPS URLs can be analyzed")
    if "://" in value and not lowered_input.startswith(("http://", "https://")):
        raise ValueError("Only HTTP and HTTPS URLs can be analyzed")
    if not lowered_input.startswith(("http://", "https://")):
        value = "https://" + value
    try:
        parts = urlsplit(value)
        host_input = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"Invalid URL: {exc}") from exc
    if parts.scheme.lower() not in {"http", "https"} or not host_input:
        raise ValueError("Enter a valid HTTP or HTTPS URL")
    if parts.username or parts.password:
        raise ValueError("URLs containing embedded credentials are not accepted")
    scheme = parts.scheme.lower()
    try:
        host = host_input.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized domain name") from exc
    registered, subdomain = _registrable_domain(host)
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    similarity = {"detected": False, "brand": None, "similarity": None} if is_ip else _domain_similarity(host)
    path_and_query = f"{parts.path} {parts.query}".lower()
    hostname_text = host.lower()
    suspicious_keywords = sorted(term for term in SUSPICIOUS_TERMS if term in path_and_query or term in hostname_text)
    labels = host.split(".")
    excessive_subdomains = len(labels) >= 5
    encoded = "%" in (parts.path + parts.query)
    expected_port = 443 if scheme == "https" else 80
    unusual_port = port is not None and port != expected_port
    try:
        resolved_ip = ipaddress.ip_address(host)
        public_ip = resolved_ip.is_global
    except ValueError:
        public_ip = None
    private_hostname = host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".internal", ".lan"))
    private_network_target = private_hostname or (is_ip and public_ip is False)
    active_requested = bool(network_checks)
    active_allowed = active_requested and ALLOW_ACTIVE_URL_CHECKS
    probe = None
    if active_allowed and private_network_target:
        probe = {
            "chain": [], "redirect_count": 0, "final_url": value, "final_domain": host,
            "domain_changed": False, "https_downgrade": False, "tls": {"status": "NOT_CHECKED"},
            "error": "Private or loopback destination was blocked before DNS/network probing",
        }
    elif active_allowed:
        probe = _probe_redirects(value)
    redirects = probe or {
        "chain": [], "redirect_count": 0, "final_url": value, "final_domain": host,
        "domain_changed": False, "https_downgrade": False,
        "tls": {"status": "NOT_CHECKED"},
        "error": "Active checks are disabled by server configuration" if active_requested else "Passive mode: no network request was made",
    }
    final_similarity = _domain_similarity(redirects.get("final_domain", host)) if redirects.get("final_domain") else similarity
    lookalike = similarity["detected"] or final_similarity["detected"]
    brand = similarity["brand"] or final_similarity["brand"]
    redirect_suspicious = bool(redirects.get("redirect_count", 0) and (redirects.get("domain_changed") or redirects.get("https_downgrade") or final_similarity["detected"]))
    tls_status = redirects.get("tls", {}).get("status", "NOT_CHECKED")
    flags = {
        "lookalike_domain": lookalike,
        "suspicious_keyword": bool(suspicious_keywords),
        "ip_based_url": is_ip,
        "non_public_ip": is_ip and public_ip is False,
        "private_network_url": private_network_target,
        "insecure_http": scheme == "http",
        "excessive_subdomains": excessive_subdomains,
        "encoded_url": encoded,
        "unusual_port": unusual_port,
        "suspicious_redirect": redirect_suspicious,
        "tls_invalid": tls_status in {"INVALID", "TLS_INVALID"},
        "tls_valid": tls_status == "VALID",
    }
    # URL words such as "login" or "verify" are weak context signals by themselves.
    # They contribute only a small weight and must not alone label a destination suspicious.
    suspicious = any(flags[key] for key in ("lookalike_domain", "ip_based_url", "private_network_url", "excessive_subdomains", "suspicious_redirect", "tls_invalid"))
    reasons: list[str] = []
    if private_network_target:
        reasons.append("The URL points to a loopback or private-network target; active probing is blocked.")
    if lookalike:
        reasons.append(f"This domain resembles {brand or 'a known brand'} but is not its registered domain.")
    if is_ip:
        reasons.append("The URL uses a raw IP address instead of a registered domain.")
    if suspicious_keywords:
        reasons.append("Sensitive-looking URL terms: " + ", ".join(suspicious_keywords[:5]) + ". These terms are signals, not proof of phishing.")
    if excessive_subdomains:
        reasons.append("The hostname contains an unusually deep subdomain chain.")
    if encoded:
        reasons.append("The path or query contains percent-encoding; inspect the decoded destination carefully.")
    if unusual_port:
        reasons.append(f"The URL uses a non-standard port ({port}).")
    if scheme == "http":
        reasons.append("The connection uses HTTP without transport encryption.")
    if redirects.get("redirect_count"):
        reasons.append(f"A redirect chain was observed ({redirects['redirect_count']} hop(s)).")
    if redirects.get("domain_changed"):
        reasons.append("The redirect changes the destination hostname.")
    if redirects.get("https_downgrade"):
        reasons.append("The redirect downgrades from HTTPS to HTTP.")
    if redirects.get("error") and active_requested:
        reasons.append("Active network checks did not complete: " + redirects["error"])
    if not reasons:
        reasons.append("No high-confidence phishing indicator was detected in the passive URL checks.")

    return {
        "url": value,
        "scheme": scheme.upper(),
        "domain": host,
        "registered_domain": registered,
        "subdomain": subdomain,
        "path": parts.path or "/",
        "query_present": bool(parts.query),
        "port": port if port is not None else expected_port,
        "is_https": scheme == "https",
        "host_is_ip": is_ip,
        "ip_is_public": public_ip,
        "punycode": host.startswith("xn--") or ".xn--" in host,
        "domain_similarity": similarity,
        "lookalike_detected": lookalike,
        "lookalike_brand": brand,
        "suspicious_keywords": suspicious_keywords,
        "flags": flags,
        "redirects": redirects,
        "tls": redirects.get("tls", {"status": "NOT_CHECKED"}),
        "suspicious": suspicious,
        "reasons": reasons,
        "network_checks_requested": active_requested,
        "network_checks_performed": active_allowed and not private_network_target,
        "limitations": [
            "A valid HTTPS certificate only encrypts the connection; it does not establish that the site is trustworthy.",
            "Passive checks do not open the URL or follow redirects.",
        ] if not active_allowed else ["TLS and redirects are limited to public IPs, standard ports, short timeouts, and a small redirect cap."],
    }
