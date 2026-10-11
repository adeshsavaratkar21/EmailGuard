# EmailGuard

**Analyze. Verify. Score. Protect.**

EmailGuard is a multi-layer email and web security analyzer. It parses `.eml` files and URLs, correlates email-authentication, cryptographic, domain and phishing indicators, and produces an explainable **0–100 Safety Score** with a classification and recommended action. A Manifest V3 Chrome Extension sends the active page URL to the same FastAPI engine.

> **Prototype, not proof:** EmailGuard reports the risk suggested by the checks performed. It cannot mathematically prove an email or website is safe, and this project is not a replacement for a commercial email-security service.

## What’s implemented

- **React + TypeScript + Vite dashboard:** Tailwind CSS utilities, Recharts activity graph, responsive overview, `.eml` analysis, URL scanner, history, detailed reports, scoring factors, and methodology.
- **FastAPI backend:** Upload and URL-analysis APIs, health, history, dashboard stats, and full report retrieval.
- **Email parsing:** From/To/Reply-To/Return-Path, subject, date, message ID, Received and Authentication-Results headers, MIME/body metadata, HTML anchors, URLs, and attachment metadata. Attachments are never opened or executed.
- **Authentication evidence:** Receiver-reported SPF/DKIM/DMARC results are surfaced. Optional `dkimpy` verification and optional SPF/DMARC DNS policy lookups can be enabled. The analyzer does not claim a fresh SPF check when an untrusted `.eml` has no verified SMTP peer IP. Statuses keep *"cannot verify"* separate from *"failed"*: an unfetchable DKIM key is `KEY_UNAVAILABLE`, a domain with no DMARC record is `NO_POLICY`, and a DNS lookup that errors is `DNS_ERROR` — none of them is scored as a failure.
- **Cryptography:** SHA-256 and SHA-512 digests over decoded message text; DKIM, S/MIME and PGP/OpenPGP presence indicators; optional DKIM verification. S/MIME signatures are verified with OpenSSL CMS — signature validity and certificate-chain trust are reported separately, and the signer certificate's subject, issuer and validity window are included in the report. Hashes are integrity identifiers, not sender authentication.
- **URL/domain checks:** HTTP(S) parsing, IP literals, IDN/punycode, known-brand look-alikes, sensitive-looking terms, subdomain depth, percent encoding, and unusual ports.
- **Optional active checks:** A bounded public-endpoint `HEAD` probe can inspect redirects and TLS/X.509 data. It is disabled by default and refuses private/reserved IPs, embedded URL credentials, non-standard ports, long timeouts and unbounded redirects.
- **Explainable scoring:** Configurable rules, individual score contributions, reasons, thresholds and recommended action.
- **History:** SQLAlchemy persistence; SQLite is the local default and PostgreSQL is provided through Docker Compose.
- **Chrome Extension:** Manifest V3 popup for the active HTTP(S) tab. No Gmail scraping, auto-navigation, link clicking or attachment downloads.
- **Synthetic sample view:** The dashboard displays clearly labelled illustrative data before the first live analysis.

## Project layout

```text
emailguard/
├── frontend/                 React + TypeScript + Vite dashboard
├── backend/                  FastAPI + SQLAlchemy analyzers/risk engine
├── extension/                Chrome Manifest V3 extension
├── tests/fixtures/            Synthetic .eml examples
├── docker-compose.yml         PostgreSQL + API + Nginx-served UI
└── README.md
```

## Run locally

### 1. Start the API

```bash
cd backend
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

By default, the API stores reports in `backend/emailguard.db` (SQLite). Set `DATABASE_URL` to use another SQLAlchemy database URL.

### 2. Start the web app

In a second terminal:

```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0
```

Open the Vite URL printed by the command. The dev server proxies `/api` requests to `http://127.0.0.1:8000`; browser code uses relative API paths.

### 3. Try it

- Select **Email analyzer** and upload one of the synthetic samples in `tests/fixtures/`.
- Select **URL scanner** and try `https://paypa1-security.com/login` for a look-alike-domain demonstration.
- Use **Load sample report** to see the detailed report without uploading a file.
- Visit `http://localhost:8000/docs` for the interactive API docs.

### Optional Docker Compose

From the project root:

```bash
docker compose up --build
```

Then open `http://localhost:8080`. The API is available at `http://localhost:8000`; PostgreSQL data is kept in the `emailguard_pgdata` volume. Compose keeps active URL checks and DNS lookups disabled.

## Chrome Extension

1. Start the FastAPI backend at `http://localhost:8000`.
2. Open `chrome://extensions` and enable **Developer mode**.
3. Select **Load unpacked** and choose the `extension/` directory.
4. Open an HTTP(S) page and click the EmailGuard icon.

The extension’s API base is `http://localhost:8000` in `extension/background/service-worker.js`. To use another API host, update that constant and the host permissions in `extension/manifest.json`. Gmail integration is intentionally deferred.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Engine and active-check status |
| `POST` | `/api/analyze/email` | Multipart upload of an `.eml` (10 MB default max) |
| `POST` | `/api/analyze/url` | JSON `{ "url": "https://example.com", "network_checks": false }` |
| `GET` | `/api/analyze/{analysis_id}` | Retrieve a full saved report |
| `GET` | `/api/history?limit=50` | Recent analyses |
| `GET` | `/api/dashboard/stats` | Counts, mean score, recent activity |

## Risk model

The interface displays **Safety Score = 100 − Risk Score**. Higher Safety Score means lower observed risk. Defaults are an explainable prototype starting point—not empirically validated weights:

| Signal | Default contribution to Risk Score |
|---|---:|
| SPF fail / softfail | +15 / +7 |
| DKIM fail | +15 |
| DMARC fail | +20 |
| Suspicious URL / look-alike domain | +20 / +25 |
| Suspicious redirect | +20 |
| TLS validation issue / hostname mismatch | +15 / +25 |
| IP-based URL / private-network target / sensitive-looking URL terms | +10 / +15 / +6 |
| Visible From domain has no DNS records at all | +10 |
| SPF pass / DKIM pass / DMARC pass | −5 / −5 / −10 |
| Valid TLS | −2 |
| Passive-only or limited evidence | +8 |

**"Cannot verify" is never scored as "failed."** An unfetchable DKIM key (`KEY_UNAVAILABLE`), an
S/MIME or PGP signature whose trust cannot be established (`CERT_UNTRUSTED`, `PASS_SIG_ONLY`,
`GPG_UNAVAILABLE`, `KEY_UNAVAILABLE`), a domain that publishes no DMARC policy (`NO_POLICY`), a
failed DNS lookup (`DNS_ERROR`), or missing transport context (`CONTEXT_UNAVAILABLE`) all contribute
**0** risk. Only positive evidence of a problem — a signature that does not match (`+25`), a real
SPF/DKIM/DMARC failure, phishing URL patterns — adds risk. `sender_domain_unresolvable` is separate
from DMARC: it fires only when the visible From domain has no MX, A, AAAA or NS records, which
indicates a forged sender rather than a merely unconfigured domain.

Signals combine and the risk score is clamped to 0–100. Classification thresholds default to **80–100 Safety = SAFE / ALLOW**, **50–79 = SUSPICIOUS / WARN**, **0–49 = MALICIOUS / QUARANTINE**. Override them with `EMAILGUARD_SAFE_THRESHOLD` and `EMAILGUARD_SUSPICIOUS_THRESHOLD`. Environment variable `EMAILGUARD_SCORING_WEIGHTS` accepts JSON weight overrides, for example:

```bash
EMAILGUARD_SCORING_WEIGHTS='{"lookalike_domain":30,"dmarc_fail":22}'
```

A URL keyword such as `/login` is only a weak indicator and does **not** alone make a URL suspicious or malicious. Positive SPF/DKIM/DMARC/TLS evidence never overrides a high-risk URL or other independent signal.

## Optional checks

DKIM and DMARC DNS lookups are **enabled by default**, so DKIM verification and DMARC alignment happen automatically when you send a `.eml` file. S/MIME certificate chain trust is also checked automatically using the `certifi` CA bundle.

Active URL checks remain opt-in:

```bash
EMAILGUARD_ALLOW_ACTIVE_URL_CHECKS=true  # allow bounded public-only redirect/TLS probes
```

To **disable** DNS lookups (e.g. in an air-gapped environment):

```bash
EMAILGUARD_DNS_LOOKUPS=false
EMAILGUARD_DKIM_DNS_LOOKUPS=false
```

Active URL checks also require the request's `network_checks` flag. **Do not enable active probes in an internet-facing deployment without a security review.** URL probes validate all resolved addresses as public, allow only ports 80/443, send no cookies or user credentials, use 2.5-second DNS/socket timeouts, issue HEAD requests, cap chains at three redirects, and limit each email to three active URL probes. Redirects and TLS are not checked at all in the default passive mode.

## What works out of the box (just send the `.eml`)

The following checks run automatically with no extra configuration when you upload an `.eml` file:

| Check | What happens | Requirement |
|---|---|---|
| **DKIM** | Signatures in the email are cryptographically verified against the sender's public DNS key (the key lookup is performed by EmailGuard, so an unpublished selector is reported as `KEY_UNAVAILABLE`, not as a failed signature) | `dkimpy` + `dnspython` installed (in requirements.txt) |
| **DMARC** | Alignment is computed from DKIM/SPF results + the sender's DNS DMARC policy; a domain with no policy is `NO_POLICY` (no penalty) and a failed lookup is `DNS_ERROR` | `dnspython` + `publicsuffix2` installed (in requirements.txt) |
| **S/MIME** | Cryptographic signature is verified; certificate chain is checked against the `certifi` CA bundle; signer certificate subject/issuer/validity are reported. Signature validity and chain trust are reported separately (`PASS`, `PASS_SIG_ONLY`, `CERT_UNTRUSTED`, `SIGNATURE_INVALID`) | `openssl` on system PATH |
| **PGP** | Signature is detected; verified if trusted keys are configured (see below). `gpg` missing → `GPG_UNAVAILABLE`, key not in the keyring → `KEY_UNAVAILABLE`; neither is scored as a failure | `gpg` on system PATH |

### SPF (requires extra context)

SPF is the only check that **cannot** run from a `.eml` file alone, because SPF validates the IP address of the *sending server*, which is not reliably present in a static file. Options:

* **Production**: Configure `EMAILGUARD_TRUSTED_AUTHSERV_IDS=mx.yourdomain.com` so EmailGuard extracts the real IP from your trusted MTA's `Authentication-Results` header.
* **Local testing**: Pass `spf_client_ip` and `spf_mailfrom` query parameters to `/api/analyze/email`.

### Optional overrides

| Variable | Default | Purpose |
|---|---|---|
| `EMAILGUARD_SMIME_CA_BUNDLE` | `certifi` CA bundle | Override the CA bundle for S/MIME chain validation |
| `EMAILGUARD_PGP_KEYRING_DIR` | *(empty)* | Directory of trusted `.asc`/`.pub` keys for PGP verification |
| `EMAILGUARD_TRUSTED_AUTHSERV_IDS` | *(empty)* | Comma-separated trusted receiver hostnames for SPF |

## Privacy and security notes

- Uploads are limited to 10 MB by default; the raw email file and decoded message body are not stored.
- A report stores parsed sender/recipient/subject metadata, hashes, attachment metadata, URL references and security findings in the configured database. Treat that database as sensitive; URLs can contain personal or tracking parameters.
- Attachments are not extracted, opened, rendered or executed.
- Authentication-Results headers inside a user-supplied `.eml` can be forged. They are labelled receiver-reported evidence and should only be trusted when the receiving system is known.
- Fresh SPF verification requires a trustworthy connecting IP / SMTP envelope. A `.eml` file alone does not reliably supply that context.
- A valid TLS certificate does not establish that a site is benign. It only indicates encryption and certificate/hostname validation for the connection.
- The prototype has no user authentication or production rate limiter. Do not deploy it publicly or upload sensitive mail without adding authentication, authorization, quotas, audit controls and a reviewed retention policy.
- `Authentication-Results` and `Received` headers can contain untrusted input; outputs are displayed as text, not HTML.

## Tests

From `backend/` after installing `requirements-dev.txt`: 

```bash
pytest -q
```

Synthetic inputs are in `tests/fixtures/`; no real people's emails are included. To print a small confusion matrix, malicious-detection rate, false-positive rate and mean analysis time, run `python evaluate_dataset.py` from `backend/`. These metrics use a tiny illustrative corpus and are not a benchmark.

`tests/test_crypto_signatures.py` generates a throw-away RSA key pair and a **real** CMS signature with `openssl` and runs the actual S/MIME verifier, so the signed-data path (a previously broken code path) is exercised end to end rather than mocked. Those tests skip automatically when `openssl` is not on PATH.

A larger set of ready-to-upload demo messages, with the measured result of every check, is in `../demo_emails/` together with `../demo_emails/DEMO_GUIDE.md`.

## CNS syllabus connections

- **Network security:** layered security model, threat signals, SSRF defense and network-safe probing.
- **Asymmetric cryptography:** DKIM and certificate public-key concepts; RSA/ECC metadata when a verified TLS certificate is available.
- **Integrity and signatures:** SHA-256/SHA-512 message digests, DKIM, S/MIME and OpenPGP indicators.
- **Key management / PKI:** X.509 subject, issuer, validity, SANs, signature algorithm and public-key type during optional TLS checks.
- **Internet security:** SPF/DKIM/DMARC, TLS, phishing domains and browser integration.

## Project description

> EmailGuard is a multi-layer email and web security analyzer that evaluates `.eml` files and URLs using email authentication evidence, cryptographic integrity, PKI/certificate analysis, domain intelligence and phishing indicators. It correlates these signals through an explainable risk engine and returns a 0–100 safety score, classification and recommended action. A React dashboard and Chrome Extension use a shared Python FastAPI security engine.
