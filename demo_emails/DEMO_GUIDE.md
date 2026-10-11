# EmailGuard — Demo .EML Bank & Presentation Guide

**Prepared:** 11 Oct 2026 · **For:** college demonstration of the EmailGuard prototype
**Contents:** 15 synthetic `.eml` files (safe / dangerous / crypto) + this guide.

> Every expected result in this document was **measured**, not guessed: all 15 files were run
> through the project's own engine (`app.service.analyze_email_bytes`, the same function the API uses)
> with live DNS on 11 Oct 2026. Your screen should match the numbers below when the demo machine has internet.
>
> **Nothing in the repository's code was changed.** This `demo_emails/` folder is new and self-contained.

---

## 1. How to start the demo

**Terminal 1 — API (FastAPI engine):**

```bash
cd emailguard/backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 — dashboard (React + Vite):**

```bash
cd emailguard/frontend
npm install
npm run dev -- --host 0.0.0.0
```

Open the Vite URL it prints → **Email analyzer** → drop an `.eml` file → **Analyze email**.
Leave the *"Probe public links for redirects & TLS"* toggle **OFF** — every expected result below is for the default passive mode.

Optional checks worth showing the professor:
* Interactive API docs: `http://localhost:8000/docs`
* Health / feature flags: `http://localhost:8000/api/health`
* CSV-style API check of one file:

```bash
curl -s -F "file=@demo_emails/dangerous/10_danger_lookalike_phishing.eml" \
  "http://localhost:8000/api/analyze/email?network_checks=false" | python -m json.tool | head -60
```

> **Internet is required for the authentication checks.** SPF, DKIM and DMARC are verified against
> real DNS records. Without internet those checks report `CONTEXT_UNAVAILABLE` / `TEMPERROR` / `DNS_ERROR`
> instead of pass/fail — see §8 for what changes.

---

## 2. How the score works (say this at the start)

**Safety Score = 100 − Risk Score.** Risk is the sum of transparent, weighted factors, clamped to 0–100.

| Safety Score | Classification | Recommendation | Meaning in the UI |
|---:|---|---|---|
| 80 – 100 | **SAFE** | ALLOW | Low observed risk |
| 50 – 79 | **SUSPICIOUS** | WARN | Review recommended |
| 0 – 49 | **MALICIOUS** | QUARANTINE | High risk detected |

Weights come from `backend/app/config.py` (`DEFAULT_WEIGHTS`) and are listed in §6.
The report shows **every factor and its contribution** in the *"Why this score?"* card — that is the
"explainable" part of the project. The engine is also careful *not* to punish absence of evidence:
missing S/MIME/PGP is not a risk factor, and a key that cannot be fetched is not treated as a forgery.

---

## 3. The test matrix — SAFE files

| # | File | Test it demonstrates | Verdict (measured) | Factors that fired | What to point at on screen |
|---|---|---|---|---|---|
| 01 | `safe/01_safe_genuine_auth_pass.eml` | SPF **PASS** + DMARC **PASS**, computed by EmailGuard itself | **SAFE · 100** (risk 0) · confidence Limited | `spf_pass −5`, `dmarc_pass −10` | Authentication card: SPF PASS, DKIM *(reported)*, DMARC PASS. Factor card shows the two negative (risk-reducing) contributions. SHA-256 body digest in the crypto card. |
| 02 | `safe/02_safe_keyword_only_link.eml` | A sensitive-looking word in a link is only a **weak** signal | **SAFE · 100** (risk 0) | `spf_pass −5`, `dmarc_pass −10`, `suspicious_keyword +6` | The link `https://portal.example.com/login` is **not** flagged as suspicious (Links card shows *NO ALERT*), yet the factor list still shows `+6`. Keyword alone ≠ phishing. |
| 03 | `safe/03_safe_attachment_metadata.eml` | Attachments are **metadata only** | **SAFE · 100** (risk 0) | `spf_pass −5`, `dmarc_pass −10` | Report lists `lab-report.pdf` with `inspection: "metadata only; not opened or executed"`. The file is never extracted or run. |
| 04 | `safe/04_safe_untrusted_reported_headers.eml` | **Authentication-Results headers cannot be trusted** (they are inside a file you upload) | **SAFE · 85** (risk 15) | `spf_pass −5` *(receiver-reported)*, `dmarc_fail +20` *(computed)* | Headers claim `spf=pass; dkim=pass; dmarc=pass`, but with no transport context they are labelled **Reported**, and EmailGuard's **own** DMARC computation failed → risk 15 instead of a perfect 0. Great "anti-forgery" talking point. |
| 05 | `safe/05_safe_limited_evidence.eml` | **Limited-evidence penalty** when nothing can be evaluated | **SAFE · 92** (risk 8) · confidence Limited | `limited_evidence +8` | Its `From:` header has no domain, so DMARC cannot even be evaluated → the only factor is the honest `+8` penalty. This reproduces the exact 92 the repo's own test expects. |

## 4. The test matrix — DANGEROUS files

| # | File | Test it demonstrates | Verdict (measured) | Factors that fired | What to point at on screen |
|---|---|---|---|---|---|
| 06 | `dangerous/06_danger_spoofed_gmail_softfail.eml` | SPF **SOFTFAIL** (genuine) — a spoofed Gmail sender | **SUSPICIOUS · 73** (risk 27) | `spf_softfail +7`, `dmarc_fail +20` | The message claims `@gmail.com` but was "sent" from `8.8.8.8`. Gmail's published policy ends in `~all` → **softfail**, not hard fail. Shows that real mail policy determines the outcome. |
| 07 | `dangerous/07_danger_spoofed_bank_spf_fail.eml` | SPF **FAIL** (genuine) — spoofed bank sender | **SUSPICIOUS · 65** (risk 35) | `spf_fail +15`, `dmarc_fail +20` | Same idea against `icicibank.com`, which publishes a hard `-all` policy and DMARC `p=reject` → genuine hard fail. (Great local example: ICICI/HDFC/SBI all publish `-all`.) |
| 08 | `dangerous/08_danger_tampered_dkim_signature.eml` | **DKIM verification FAILS** (genuine, key fetched from DNS) | **SUSPICIOUS · 58** (risk 42) | `spf_softfail +7`, `dkim_fail +15`, `dmarc_fail +20` | The `bh=` body hash does not match the delivered body. `dkimpy` fetches Gmail's **real** public key for `s=20230601` and rejects the signature → DKIM FAIL with `verification_type = independent` (i.e. EmailGuard's own verification). |
| 09 | `dangerous/09_danger_reply_to_mismatch.eml` | **Reply-To domain differs** from the visible sender | **SUSPICIOUS · 72** (risk 28) | `dmarc_fail +20`, `reply_to_mismatch +8` | Visible sender `service@paypal.com`, but Reply-To `refunds@paypa1-secure.com`. The Message-details card marks the Reply-To row with a **mismatch** warning. Classic refund-scam pattern. |
| 10 | `dangerous/10_danger_lookalike_phishing.eml` | **Look-alike domain** + credential phishing pattern | **MALICIOUS · 34** (risk 66) | `lookalike_domain +25`, `suspicious_url +20`, `suspicious_keyword +6`, `dmarc_fail +20`, `spf_pass −5` | The flagship demo. `paypa1-security.com` is compared against the brand list and matched to **paypal** ("Similar to paypal" in the Links card). Note the small `−5`: a *receiver-reported* `spf=pass` for the attacker's own domain does not cancel the real signals. |
| 11 | `dangerous/11_danger_ip_and_private_links.eml` | **IP-based URL** + **private-network/loopback URL** | **MALICIOUS · 0** (risk 100) | `suspicious_url +40`, `ip_based_url +20`, `suspicious_keyword +6`, `insecure_http +5`, `private_network_url +15`, `dmarc_fail +20` | Link 1 is a raw public IP (`http://93.184.216.34/secure/login`); link 2 is loopback (`http://127.0.0.1/admin`), which the prober would refuse to touch (SSRF defence, README §Optional checks). |
| 12 | `dangerous/12_danger_encoded_port_subdomains.eml` | **Encoded path + non-standard port + deep sub-domains + unencrypted HTTP** | **MALICIOUS · 30** (risk 70) | `dmarc_fail +20`, `suspicious_url +20`, `unusual_port +8`, `suspicious_keyword +6`, `excessive_subdomains +6`, `encoded_url +5`, `insecure_http +5` | One link, six independent URL signals: `http://a.b.c.d.secure-login.example:8080/%76erify` (`%76` hides the letter *v* in "verify"). |

## 5. The test matrix — CRYPTO / structure files

| # | File | Test it demonstrates | Verdict (measured) | Crypto status shown | Notes |
|---|---|---|---|---|---|
| 13 | `crypto/13_smime_encrypted_not_decrypted.eml` | S/MIME detection, **never decrypted** | **SAFE · 100** | `S/MIME: ENCRYPTED_NOT_DECRYPTED` | EmailGuard refuses to decrypt: decryption needs the recipient's private key + authorisation. No score impact (encryption is not a threat signal). |
| 14 | `crypto/14_pgp_encrypted_not_decrypted.eml` | PGP/OpenPGP detection, **never decrypted** | **SAFE · 100** | `OpenPGP: ENCRYPTED_NOT_DECRYPTED` | `multipart/encrypted; protocol="application/pgp-encrypted"`. |
| 15 | `crypto/15_pgp_signed_detected.eml` | PGP **signature detection** + keyring dependency | **SAFE · 100** | `OpenPGP: GPG_UNAVAILABLE` (this machine) / `KEY_UNAVAILABLE` or `VERIFIER_ERROR` (machine with `gpg`) | The message contains an inline clear-signed block. Verification needs `gpg` on PATH **and** a trusted key via `EMAILGUARD_PGP_KEYRING_DIR`; the app never auto-imports keys from the message. The signature here is a synthetic placeholder, so no tool can call it valid. |

---

## 6. Scoring weights reference (from `backend/app/config.py`)

| Signal | Weight | Signal | Weight |
|---|---:|---|---:|
| `lookalike_domain` | +25 | `spf_pass` | −5 |
| `hostname_mismatch` | +25 | `dkim_pass` | −5 |
| `invalid_signature` (S/MIME/PGP bad) | +25 | `dmarc_pass` | −10 |
| `dmarc_fail` | +20 | `valid_signature` (S/MIME/PGP good) | −10 |
| `suspicious_url` | +20 (cap ×2) | `valid_tls` | −2 |
| `suspicious_redirect` | +20 (cap ×1) | `limited_evidence` | **+8** |
| `spf_fail` / `spf_softfail` | +15 / +7 | `dkim_fail` | +15 |
| `private_network_url` | +15 (cap ×1) | `ip_based_url` | +10 (cap ×2) |
| `expired_tls` / `tls_invalid` | +15 | `unusual_port` | +8 (cap ×1) |
| `reply_to_mismatch` | +8 | `excessive_subdomains` | +6 (cap ×1) |
| `suspicious_keyword` | +6 (cap ×2) | `insecure_http` | +5 (cap ×1) |
| `encoded_url` | +5 (cap ×1) | | |

Thresholds are configurable (`EMAILGUARD_SAFE_THRESHOLD`, `EMAILGUARD_SUSPICIOUS_THRESHOLD`) and weights can be
overridden with `EMAILGUARD_SCORING_WEIGHTS` — e.g. `EMAILGUARD_SCORING_WEIGHTS='{"lookalike_domain":30}'`.
Positive evidence (SPF/DKIM/DMARC/TLS pass) **never outweighs** an independent high-risk signal.

---

## 7. Suggested presentation order (≈10–12 minutes)

1. **Framing (30 s).** "EmailGuard parses an `.eml`, runs layered checks — SPF/DKIM/DMARC, S/MIME/PGP, SHA-256/512 integrity, URL & look-alike analysis — and returns an explainable 0–100 safety score."
2. **Methodology page first.** Show the weight table/thresholds in the UI so the professor sees the scoring is not a black box.
3. **Safe flagship: file 01.** Ring = 100, SPF PASS + DMARC PASS (−5 / −10), SHA-256 digest, confidence "Limited" (be honest: passive checks only).
4. **Dangerous flagship: file 10.** Ring = 34, MALICIOUS → **QUARANTINE**, "Similar to paypal", factors +25 / +20 / +6 / +20, reasons list.
5. **Now the test-by-test pairs** (upload in this order, 30–45 s each):
   * SPF: **01 PASS** → **06 SOFTFAIL** → **07 FAIL**. Explain: the *sender's published policy* decides soft vs hard fail (Gmail `~all`, ICICI `-all`).
   * DKIM: **08 FAIL** (EmailGuard fetched Gmail's real DNS key and rejected the signature) — then note that 01–03 carry a *reported* `dkim=pass` shown as **Reported**, not Verified.
   * DMARC: **01 PASS** (real `_dmarc.gmail.com` record, aligned SPF) vs **07 FAIL** (real `p=reject` record, no alignment).
   * Reply-To: **09** — Reply-To row flagged "mismatch", +8.
   * URL engine: **10** (look-alike), **11** (IP + loopback), **12** (encoded/port/sub-domains/HTTP), **02** (keyword-only → still SAFE).
   * Crypto: **13 / 14** ("we never decrypt"), **15** (PGP detected; needs `gpg` + keyring), **03** (attachment metadata only).
   * Honesty: **04** (self-asserted pass headers are not trusted) and **05** (+8 limited-evidence penalty).
6. **URL scanner page.** Paste URLs from §9 — same engine, no file needed. If you enabled active checks, show TLS certificate details (issuer, SANs, key type).
7. **Close with limitations.** "Prototype rules, not validated probabilities; `.eml` alone can't prove SPF without a trusted receiver; a valid TLS certificate doesn't make a site trustworthy." This is in the repo's README and the report's own disclaimer strip.

---

## 8. If the demo machine has **no** internet (measured offline results)

The URL/look-alike engine is pure parsing and keeps working; the DNS-based authentication checks degrade honestly.

| File | Online (intended) | Offline (measured) |
|---|---|---|
| `safe/01, 02, 03, crypto/13, 14, 15` | SAFE 100 | SAFE 80 (auth checks unavailable; file 02 becomes SUSPICIOUS 74) |
| `safe/04_safe_untrusted_reported_headers` | SAFE 85 | SAFE 85 (unchanged) |
| `safe/05_safe_limited_evidence` | SAFE 92 | SAFE 92 (unchanged) |
| `dangerous/06_danger_spoofed_gmail_softfail` | SUSPICIOUS 73 | SAFE 80 → **do not use offline** |
| `dangerous/07_danger_spoofed_bank_spf_fail` | SUSPICIOUS 65 | SAFE 80 → **do not use offline** |
| `dangerous/08_danger_tampered_dkim_signature` | SUSPICIOUS 58 | SUSPICIOUS 65 (still works) |
| `dangerous/09_danger_reply_to_mismatch` | SUSPICIOUS 72 | SUSPICIOUS 72 |
| `dangerous/10_danger_lookalike_phishing` | MALICIOUS 34 | MALICIOUS 34 |
| `dangerous/11_danger_ip_and_private_links` | MALICIOUS 0 | MALICIOUS 0 |
| `dangerous/12_danger_encoded_port_subdomains` | MALICIOUS 30 | MALICIOUS 30 |

**Offline demo set (use these):** 04, 05, 08, 09, 10, 11, 12.

---

## 9. Bonus: URL-scanner test cases (no `.eml` needed)

Paste these into the **URL scanner** page (passive mode, measured results):

| URL | Verdict | Why |
|---|---|---|
| `https://classroom.google.com/` | SAFE · 92 | Nothing suspicious; `+8` passive-only penalty |
| `https://example.com/about` | SAFE · 92 | identical baseline |
| `https://example.com/login` | SAFE · 86 | keyword `login` only (`+6`) |
| `https://icicibank.com/login` | SAFE · 86 | the *real* bank domain: keyword only, not a look-alike |
| `https://paypa1-security.com/login` | MALICIOUS · 41 | look-alike of paypal (`+25`), suspicious URL (`+20`), keyword (`+6`) |
| `https://xn--pypal-4ve.com/login` | MALICIOUS · 41 | punycode/IDN look-alike — domain similarity sees through `xn--` |
| `http://93.184.216.34/secure/login` | SUSPICIOUS · 51 | raw IP (`+10`) + HTTP (`+5`) + keyword (`+6`) |
| `http://cloud-storage-notice.example:8080/%76erify` | SUSPICIOUS · 74 | odd port + encoded path + HTTP (this is the repo's own demo URL) |
| `http://127.0.0.1/admin` | MALICIOUS · 42 | loopback/private target (`+15`), IP-based (`+10`) — active probing is refused by design |
| `http://a.b.c.d.secure-login.example:8080/%76erify` | MALICIOUS · 42 | six independent URL signals |

**Active redirect/TLS checks** (optional, opt-in): start the API with

```bash
EMAILGUARD_ALLOW_ACTIVE_URL_CHECKS=true uvicorn app.main:app --host 0.0.0.0 --port 8000
```

then switch the UI toggle ON. Safe by design: only ports 80/443, public IPs only, 2.5 s timeouts,
HEAD requests, max 3 redirects, max 3 probed URLs per email, no cookies/credentials.
Try a site you can reach, e.g. `https://github.com` → `valid_tls −2` plus a real certificate summary
(issuer, valid-until, SANs, public-key type); a redirect example such as
`https://httpbin.org/redirect-to?url=http%3A%2F%2Fexample.com` should produce `suspicious_redirect +20`
(HTTPS→HTTP downgrade). These require live internet and are not covered by the measured numbers above.

---

## 10. Honest Q&A — things the professor may ask

1. **"How can a static `.eml` prove SPF? The sending IP isn't in the file."**
   Correct — that is why the project states SPF needs transport context. For the demo, files 01/06/07 put a
   *plausible* IP in the `Received` header and the envelope sender in `Return-Path`; the engine extracts them and
   runs a **real** `pyspf` DNS evaluation, labelling it `extracted_from_headers` (i.e. "can be forged").
   In production you configure `EMAILGUARD_TRUSTED_AUTHSERV_IDS` to trust a real receiver, or the API accepts
   `?spf_client_ip=…&spf_mailfrom=…` (labelled `operator_supplied_context` — tested: same FAIL result).
   The factor title still prints "Receiver-reported:" for these because the code only marks a check
   `independent` when the IP came from a trusted receiver — a labelling nuance, not a hidden assumption.
2. **"Why does a made-up domain add +20 DMARC failed?"**
   For a domain with no `_dmarc` record the DNS answer is `NXDOMAIN`, and this version's DNSSEC/DNS error text
   ("The DNS query name does not exist") is mapped to `DNS_ERROR` rather than `NO_RECORD`, so the evaluator
   reports DMARC failed. Files 10–12 therefore carry a `+20 dmarc_fail` on top of their URL signals. For real
   domains with published records (01, 04, 06, 07, 08, 09) the DMARC result is genuine.
3. **"Can you show a DKIM PASS?"**
   Not with a hand-written file: a PASS requires a message signed by a private key whose public key is published
   in DNS. The bank shows (a) reported `dkim=pass` labelled **Reported**, and (b) a genuine DKIM **FAIL** against
   Google's real key (file 08). If you want, a real DKIM-signed sample from a public test corpus can be added.
   Related nuance: when a selector's key is missing from DNS, `dkimpy` returns `False` (not an error), so this
   version currently reports "DKIM failed" rather than "key unavailable".
4. **"You also have S/MIME — why didn't you demo a signed one?"**
   Fair question — and worth answering honestly: the *signed-data* path in `smime_verifier.py` currently has a bug
   (it removes the CA path from the openssl command twice → `pop index out of range` → status `VERIFIER_ERROR`).
   The encrypted case (file 13) is unaffected. Without changing code you can avoid the crash by starting the API with
   `EMAILGUARD_SMIME_CA_BUNDLE=""`; then a genuine signature would report `PASS_SIG_ONLY`/`CERT_UNTRUSTED` and a
   tampered one `SIGNATURE_INVALID` (`+25`). A one-line code fix would make the default path work.
5. **"Is any of this a real verdict on an email?"**
   No — the report says it itself: prototype rules, not statistically validated probabilities. The README and the
   report's disclaimer strip state that a valid TLS certificate does not make a site benign and that positive
   authentication evidence never overrides an independent high-risk URL signal.
6. **"Did you handle the dangerous files safely?"** Yes: all content is synthetic, no real people's mail is used,
   attachments are never opened, no link is ever clicked in passive mode, and active probing is disabled by default
   and refused for private/loopback targets.

---

## 11. Supporting evidence you can show

* **Test suite:** `cd emailguard/backend && pytest -q` → `48 passed in 0.30s` (measured on this machine).
* **Repo's own corpus metric script:** `python evaluate_dataset.py` → 4 fixtures,
  predictions `SAFE 80 / SAFE 80 / SUSPICIOUS 56 / MALICIOUS 34`, **accuracy 100 %**, false-positive rate 0 %,
  mean analysis time ≈28 ms (prototype scale — not a benchmark).
* **API:** `/docs` (interactive OpenAPI), `/api/health` (shows whether active URL checks are enabled),
  `/api/history`, `/api/dashboard/stats` (the dashboard's counters update with each upload).
* **Chrome extension (Manifest V3):** load `extension/` unpacked, open an HTTP(S) page, click the icon →
  the active page URL is analysed by the same engine.

---

## 12. Pre-demo checklist

- [ ] API running on `http://localhost:8000` (`/api/health` → `"status": "ok"`).
- [ ] Dashboard running and `/api` proxied (upload one file to confirm end-to-end).
- [ ] Internet working — verify with file 01 first: it must show **SPF PASS + DMARC PASS**.
- [ ] Optional clean history: stop the API, delete `emailguard/backend/emailguard.db`, restart (local SQLite only).
- [ ] Switch off the network-checks toggle (all measured results assume passive mode).
- [ ] Keep file 10 (paypal look-alike) and file 07 (ICICI spoof) ready as the "wow" examples.
- [ ] Remember the three headline numbers: **100 SAFE / 65–73 SUSPICIOUS / 34 MALICIOUS**.
