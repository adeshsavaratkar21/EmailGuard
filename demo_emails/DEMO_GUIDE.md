# EmailGuard — Demo .EML Bank & Presentation Guide

**Prepared:** 11 Oct 2026 · **For:** college demonstration of the EmailGuard prototype
**Revision 2** — updated after the authentication/crypto fix set (see §2).
**Contents:** 18 synthetic `.eml` files (safe / dangerous / crypto) + this guide.

> Every expected result in this document was **measured**, not guessed: all files were run
> through the project's own engine (`app.service.analyze_email_bytes`, the same function the API uses)
> with live DNS on 11 Oct 2026. Your screen should match the numbers below when the demo machine has internet.
>
> **Measuring machine:** Python 3.11, dkimpy 1.x, dnspython, pyspf, cryptography, OpenSSL 3.0,
> certifi CA bundle. gpg was not installed, which is why the PGP cases show GPG_UNAVAILABLE rather
> than a signature verdict (§6, §11).

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
* One-shot API check of one file:

```bash
curl -s -F "file=@demo_emails/dangerous/17_danger_tampered_smime_signature.eml" \
  "http://localhost:8000/api/analyze/email?network_checks=false" | python -m json.tool | head -60
```

> **Internet is required for the authentication checks.** SPF, DKIM and DMARC are verified against
> real DNS records. Without internet those checks report inconclusive states instead of pass/fail — see §9.

---

## 2. What this fix set changed (and why it matters in the viva)

Two things used to be true of this prototype, and both are worth stating out loud before the demo, because
the professor is likely to ask "how do you know your verdicts are right?":

* **"Cannot verify" used to collapse into "forged".** A DKIM key that could not be fetched, or a domain that
  simply publishes no DMARC policy, was scored as an authentication **failure**.
* **The signed-S/MIME path used to crash**, so every signed message came back as `VERIFIER_ERROR` instead of
  a verdict — which is why earlier revisions of this guide had no signed-S/MIME example.

| # | Defect (before) | Fix (now) | Test that locks it |
|---|---|---|---|
| A | **Every signed S/MIME message reported `VERIFIER_ERROR`.** The signature-only `openssl cms` command removed the CA-bundle path and its `-CAfile` flag with two `list.pop()` calls; because the path was the last argument, the second pop raised `IndexError: pop index out of range`. | The signature-only and chain-trust commands are built **independently** from one immutable `base_cmd`, so the failure mode is gone. | `test_signed_message_reaches_a_verdict_when_ca_bundle_is_configured` + the three real-signature tests in `tests/test_crypto_signatures.py` |
| B | **A DKIM key that could not be fetched was reported as `FAIL`.** `dkimpy` returns `False` both for "key missing" and "signature wrong", so "cannot verify" collapsed into "forged". | EmailGuard now performs the DNS key lookup itself through dkimpy's `dnsfunc` hook; a failed lookup becomes `KEY_UNAVAILABLE` — score 0, never a forgery. | `test_missing_public_key_is_key_unavailable_not_fail`, `test_genuine_signature_is_independently_verified_as_pass` |
| C | **"No DMARC policy published" was scored as DMARC *failed*** (+20). dnspython reports that very common case as `NXDOMAIN`, whose message text ("The DNS query name does not exist") contains no word "nxdomain", so it fell through to `DNS_ERROR` and was scored as a failure. | The evaluator matches dnspython **exception types**: a missing `_dmarc` record → `NO_POLICY` (no penalty), a failed lookup → `DNS_ERROR` (inconclusive, no penalty). | `test_dmarc_no_record_is_not_a_dmarc_failure`, `test_dmarc_dns_failure_is_inconclusive_not_failed` |
| C2 | **New signal.** With C fixed, a *forged* sender using a domain that does not exist at all would have gone unpunished, because "no policy" is not "no domain". | New weight `sender_domain_unresolvable: 10`, fired exactly once, only when the visible From domain has no MX, A, AAAA or NS records. | `test_unresolvable_sender_domain_is_scored_once_and_is_not_a_dmarc_failure` |
| D | **Signer certificate details never appeared** in the report: the parser only matched `subject=`/`issuer=` (RFC2253), but `openssl x509 -text` prints `Subject:`/`Issuer:`. | Both forms are accepted, so the certificate card is populated. | `test_signer_certificate_details_are_parsed_from_openssl_output` |

Net effect on the demo: the crypto cases now produce real verdicts, "cannot verify" is never misreported as
"forged", and messages from domains that don't exist are still flagged — while ordinary domains without a
DMARC policy are no longer punished for it.

---

## 3. How the score works (say this at the start)

**Safety Score = 100 − Risk Score.** Risk is the sum of transparent, weighted factors, clamped to 0–100.

| Safety Score | Classification | Recommendation | Meaning in the UI |
|---:|---|---|---|
| 80 – 100 | **SAFE** | ALLOW | Low observed risk |
| 50 – 79 | **SUSPICIOUS** | WARN | Review recommended |
| 0 – 49 | **MALICIOUS** | QUARANTINE | High risk detected |

Weights come from `backend/app/config.py` (`DEFAULT_WEIGHTS`) and are listed in §7.
The report shows **every factor and its contribution** in the *"Why this score?"* card — that is the
"explainable" part of the project.

**The engine's design rule: "cannot verify" is never scored as "malicious".** Missing S/MIME/PGP is not a
risk factor at all, and neither is a key that cannot be fetched, a certificate whose trust cannot be
established, or a domain that publishes no DMARC policy: `KEY_UNAVAILABLE`, `GPG_UNAVAILABLE`,
`OPENSSL_UNAVAILABLE`, `CERT_UNTRUSTED`, `PASS_SIG_ONLY`, `NO_POLICY`, `DNS_ERROR`, `CONTEXT_UNAVAILABLE`
and `ENCRYPTED_NOT_DECRYPTED` all contribute **zero**. Only positive evidence — a signature that does not
match, a real SPF/DKIM/DMARC failure, phishing URL patterns — adds risk.

---

## 4. The test matrix — SAFE files

| # | File | Test it demonstrates | Verdict (measured) | Factors that fired | What to point at on screen |
|---|---|---|---|---|---|
| 01 | `safe/01_safe_genuine_auth_pass.eml` | SPF **PASS** + DMARC **PASS**, computed by EmailGuard itself | **SAFE · 100** (risk 0) · confidence Limited | `spf_pass −5`, `dmarc_pass −10` | Authentication card: SPF PASS, DKIM *(reported)*, DMARC PASS. Factor card shows the two negative (risk-reducing) contributions. SHA-256 body digest in the crypto card. |
| 02 | `safe/02_safe_keyword_only_link.eml` | A sensitive-looking word in a link is only a **weak** signal | **SAFE · 100** (risk 0) | `spf_pass −5`, `dmarc_pass −10`, `suspicious_keyword +6` | The link `https://portal.example.com/login` is **not** flagged as suspicious (Links card shows *NO ALERT*), yet the factor list still shows `+6`. Keyword alone ≠ phishing. |
| 03 | `safe/03_safe_attachment_metadata.eml` | Attachments are **metadata only** | **SAFE · 100** (risk 0) | `spf_pass −5`, `dmarc_pass −10` | Report lists `lab-report.pdf` with `inspection: "metadata only; not opened or executed"`. The file is never extracted or run. |
| 04 | `safe/04_safe_untrusted_reported_headers.eml` | **Authentication-Results headers cannot be trusted** (they are inside a file you upload) | **SAFE · 85** (risk 15) | `spf_pass −5` *(receiver-reported)*, `dmarc_fail +20` *(computed)* | Headers claim `spf=pass; dkim=pass; dmarc=pass`, but with no transport context they are labelled **Reported**, and EmailGuard's **own** DMARC computation on the real `_dmarc.gmail.com` fails (no alignment) → risk 15 instead of a perfect 0. Great "anti-forgery" talking point. |
| 05 | `safe/05_safe_limited_evidence.eml` | **Limited-evidence penalty** when nothing can be evaluated | **SAFE · 92** (risk 8) · confidence Limited | `limited_evidence +8` | Its `From:` header has no domain, so DMARC cannot even be evaluated (`CONTEXT_UNAVAILABLE`) → the only factor is the honest `+8` penalty. This reproduces the exact 92 the repo's own test expects. |
| 06 | `safe/06_safe_dkim_key_unavailable.eml` | **A DKIM key that cannot be fetched is not a forgery** (fix #B in §2) | **SAFE · 100** (risk 0) | `spf_pass −5`, `dmarc_pass −10` | Selector `20250716-demo-retired` is **not published in DNS** → the DKIM row shows **KEY_UNAVAILABLE**, the report says the signature *could not be checked*, and **no risk is added**. Compare with file 08, where a key *was* fetched and the signature genuinely failed (+15). |

## 5. The test matrix — DANGEROUS files

| # | File | Test it demonstrates | Verdict (measured) | Factors that fired | What to point at on screen |
|---|---|---|---|---|---|
| 06 | `dangerous/06_danger_spoofed_gmail_softfail.eml` | SPF **SOFTFAIL** (genuine) — a spoofed Gmail sender | **SUSPICIOUS · 73** (risk 27) | `spf_softfail +7`, `dmarc_fail +20` | The message claims `@gmail.com` but was "sent" from `8.8.8.8`. Gmail's published policy ends in `~all` → **softfail**, not hard fail. Shows that real mail policy determines the outcome. |
| 07 | `dangerous/07_danger_spoofed_bank_spf_fail.eml` | SPF **FAIL** (genuine) — spoofed bank sender | **SUSPICIOUS · 65** (risk 35) | `spf_fail +15`, `dmarc_fail +20` | Same idea against `icicibank.com`, which publishes a hard `-all` policy and DMARC `p=reject` → genuine hard fail. (Great local example: ICICI/HDFC/SBI all publish `-all`.) |
| 08 | `dangerous/08_danger_tampered_dkim_signature.eml` | **DKIM verification FAILS** (genuine, key fetched from DNS) | **SUSPICIOUS · 58** (risk 42) | `spf_softfail +7`, `dkim_fail +15`, `dmarc_fail +20` | The `bh=` body hash does not match the delivered body. `dkimpy` fetches Gmail's **real** public key for `s=20230601` and rejects the signature → DKIM FAIL with `verification_type = independent` (i.e. EmailGuard's own verification). |
| 09 | `dangerous/09_danger_reply_to_mismatch.eml` | **Reply-To domain differs** from the visible sender | **SUSPICIOUS · 72** (risk 28) | `dmarc_fail +20`, `reply_to_mismatch +8` | Visible sender `service@paypal.com`, but Reply-To `refunds@paypa1-secure.com`. The Message-details card marks the Reply-To row with a **mismatch** warning. Classic refund-scam pattern. |
| 10 | `dangerous/10_danger_lookalike_phishing.eml` | **Look-alike domain** + credential phishing pattern | **MALICIOUS · 44** (risk 56) | `lookalike_domain +25`, `suspicious_url +20`, `suspicious_keyword +6`, `sender_domain_unresolvable +10`, `spf_pass −5` | The flagship demo. `paypa1-security.com` is compared against the brand list and matched to **paypal** ("Similar to paypal" in the Links card). Note the small `−5`: a *receiver-reported* `spf=pass` for the attacker's own domain does not cancel the real signals. The `+10` is the new §2 signal C2: the From domain does not exist at all. |
| 11 | `dangerous/11_danger_ip_and_private_links.eml` | **IP-based URL** + **private-network/loopback URL** | **MALICIOUS · 0** (risk 100) | `suspicious_url +40`, `ip_based_url +20`, `private_network_url +15`, `sender_domain_unresolvable +10`, `limited_evidence +8`, `suspicious_keyword +6`, `insecure_http +5` | Link 1 is a raw public IP (`http://93.184.216.34/secure/login`); link 2 is loopback (`http://127.0.0.1/admin`), which the prober would refuse to touch (SSRF defence, README §Optional checks). |
| 12 | `dangerous/12_danger_encoded_port_subdomains.eml` | **Encoded path + non-standard port + deep sub-domains + unencrypted HTTP** | **MALICIOUS · 32** (risk 68) | `suspicious_url +20`, `sender_domain_unresolvable +10`, `unusual_port +8`, `limited_evidence +8`, `suspicious_keyword +6`, `excessive_subdomains +6`, `encoded_url +5`, `insecure_http +5` | One link, six independent URL signals: `http://a.b.c.d.secure-login.example:8080/%76erify` (`%76` hides the letter *v* in "verify"). |
| 17 | `dangerous/17_danger_tampered_smime_signature.eml` | **A real S/MIME signature that no longer matches — tampering detected** (fix #A in §2) | **MALICIOUS · 6** (risk 94) | `invalid_signature +25`, `lookalike_domain +25`, `suspicious_url +20`, `sender_domain_unresolvable +10`, `limited_evidence +8`, `suspicious_keyword +6` | The message really was signed with a demo certificate, and the signed body was edited afterwards ("UPDATED BY THE ATTACKER…"). `openssl cms -verify` fails → **`SIGNATURE_INVALID`** → `+25`. Over HTTP, not HTTPS: this is the "crypto evidence beats a good story" case. |

## 6. The test matrix — CRYPTO / structure files

| # | File | Test it demonstrates | Verdict (measured) | Crypto status shown | Notes |
|---|---|---|---|---|---|
| 13 | `crypto/13_smime_encrypted_not_decrypted.eml` | S/MIME detection, **never decrypted** | **SAFE · 100** | `S/MIME: ENCRYPTED_NOT_DECRYPTED` | EmailGuard refuses to decrypt: decryption needs the recipient's private key + authorisation. No score impact (encryption is not a threat signal). |
| 14 | `crypto/14_pgp_encrypted_not_decrypted.eml` | PGP/OpenPGP detection, **never decrypted** | **SAFE · 100** | `OpenPGP: ENCRYPTED_NOT_DECRYPTED` | `multipart/encrypted; protocol="application/pgp-encrypted"`. |
| 15 | `crypto/15_pgp_signed_detected.eml` | PGP **signature detection** + keyring dependency | **SAFE · 100** | `OpenPGP: GPG_UNAVAILABLE` (this machine — no `gpg`) / `KEY_UNAVAILABLE` when `gpg` exists but no trusted key is configured | The message contains an inline clear-signed block. Verification needs `gpg` on PATH **and** a trusted key via `EMAILGUARD_PGP_KEYRING_DIR`; the app never auto-imports keys from the message. Either way this is **never scored as a failure** (§3). |
| 16 | `crypto/16_smime_signed_selfsigned.eml` | **A REAL S/MIME signature that verifies** — valid signature, untrusted certificate | **SAFE · 100** | `S/MIME: CERT_UNTRUSTED`, `signature_valid: true`, `cert_trusted: false` | Signed by `OU=Teaching Sample,O=EmailGuard Demo,CN=EmailGuard Demo Signer`, self-signed, valid to 2036. **Zero risk added**: a valid signature from a self-signed certificate is not proof of identity. Point at the certificate card (subject/issuer/validity) and then at the contrast with file 17. |

---

## 7. Scoring weights reference (from `backend/app/config.py`)

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
| `encoded_url` | +5 (cap ×1) | **`sender_domain_unresolvable`** | **+10 (new)** |

`sender_domain_unresolvable` fires only when the **visible From domain** has no MX, A, AAAA or NS records at
all — it cannot send or receive mail, which is typical of a forged sender. It is deliberately **not** the same
as "no DMARC policy published".

**Zero-weight (never a failure):** `NO_POLICY`, `DNS_ERROR`, `CONTEXT_UNAVAILABLE`, `KEY_UNAVAILABLE`,
`GPG_UNAVAILABLE`, `OPENSSL_UNAVAILABLE`, `ENCRYPTED_NOT_DECRYPTED`, `CERT_UNTRUSTED`, `PASS_SIG_ONLY` —
plus "no S/MIME/PGP present". All contribute **0** and must never be rendered as a failure.

Thresholds are configurable (`EMAILGUARD_SAFE_THRESHOLD`, `EMAILGUARD_SUSPICIOUS_THRESHOLD`) and weights can be
overridden with `EMAILGUARD_SCORING_WEIGHTS` — e.g. `EMAILGUARD_SCORING_WEIGHTS='{"lookalike_domain":30}'`.
Positive evidence (SPF/DKIM/DMARC/TLS pass) **never outweighs** an independent high-risk signal.

---

## 8. Suggested presentation order (≈12–15 minutes)

1. **Framing (30 s).** "EmailGuard parses an `.eml`, runs layered checks — SPF/DKIM/DMARC, S/MIME/PGP, SHA-256/512 integrity, URL & look-alike analysis — and returns an explainable 0–100 safety score."
2. **Methodology page first.** Show the weight table/thresholds in the UI so the professor sees the scoring is not a black box.
3. **Engine design rule (30 s).** *"Cannot verify is not the same as malicious."* Point at the zero-weight list in §7: a key we could not fetch, a certificate we cannot trust, a domain with no DMARC policy — all score **0**. Then say the corollary: only *positive* evidence adds risk. This single sentence is the strongest design argument in the project.
4. **Safe flagship: file 01.** Ring = 100, SPF PASS + DMARC PASS (−5 / −10), SHA-256 digest, confidence "Limited" (be honest: passive checks only).
5. **Dangerous flagship: file 10.** Ring = 44, MALICIOUS → **QUARANTINE**, "Similar to paypal", factors +25 / +20 / +6 / +10, reasons list.
6. **S/MIME pair — the crypto money shot: file 16 vs file 17.**
   * **16** → `CERT_UNTRUSTED`: the signature **is** cryptographically valid (`signature_valid: true`) but the certificate is self-signed (`cert_trusted: false`). Show the signer CN `EmailGuard Demo Signer` and the 2036 expiry in the certificate card. **Risk 0** — a valid signature from an untrusted certificate is not proof of identity.
   * **17** → `SIGNATURE_INVALID`: the same certificate, but the *body was edited after signing* → `+25` and MALICIOUS. This is the pair that proves tamper detection actually works.
7. **Now the test-by-test pairs** (upload in this order, 30–45 s each):
   * SPF: **01 PASS** → **06 SOFTFAIL** → **07 FAIL**. Explain: the *sender's published policy* decides soft vs hard fail (Gmail `~all`, ICICI `-all`).
   * DKIM: **08 FAIL** (EmailGuard fetched Gmail's real DNS key and rejected the signature) vs **06 KEY_UNAVAILABLE** (selector not published — reported, *not* penalised; fix #B in §2) — then note that 01–03 carry a *reported* `dkim=pass` shown as **Reported**, not Verified.
   * DMARC: **01 PASS** (real `_dmarc.gmail.com` record, aligned SPF) vs **07 FAIL** (real `p=reject` record, no alignment) vs **10 NO_POLICY** (no record published — no penalty; the risk there comes from the look-alike brand match and the nonexistent From domain).
   * Reply-To: **09** — Reply-To row flagged "mismatch", +8.
   * URL engine: **10** (look-alike), **11** (IP + loopback), **12** (encoded/port/sub-domains/HTTP), **02** (keyword-only → still SAFE).
   * Crypto: **16 / 17** (the signed pair above), **13 / 14** ("we never decrypt"), **15** (PGP detected; needs `gpg` + keyring), **03** (attachment metadata only).
   * Honesty: **04** (self-asserted pass headers are not trusted) and **05** (+8 limited-evidence penalty).
8. **URL scanner page.** Paste URLs from §10 — same engine, no file needed. If you enabled active checks, show TLS certificate details (issuer, SANs, key type).
9. **Close with limitations.** "Prototype rules, not validated probabilities; `.eml` alone can't prove SPF without a trusted receiver; a valid TLS certificate doesn't make a site trustworthy." This is in the repo's README and the report's own disclaimer strip.

---

## 9. If the demo machine has **no** internet (measured offline results)

The URL/look-alike engine and the S/MIME verifier are pure local processing and keep working; only the
DNS-based authentication checks degrade. Offline the DNS-based checks report `TEMPERROR` (SPF) / `NO_POLICY`
/ `DNS_ERROR` (DMARC) — honest "no evidence" states, never invented verdicts.

| File | Online | Offline | Use offline? |
|---|---|---|---|
| `safe/01, 03, 06`, `crypto/13–16` | SAFE 100 | SAFE 100 | ✅ |
| `safe/02_safe_keyword_only_link` | SAFE 100 | SAFE 94 | ✅ |
| `safe/04_safe_untrusted_reported_headers` | SAFE 85 | SAFE 100 | ✅ (reported headers still shown) |
| `safe/05_safe_limited_evidence` | SAFE 92 | SAFE 92 | ✅ |
| `dangerous/09_danger_reply_to_mismatch` | SUSPICIOUS 72 | SAFE 84 | ⚠️ Reply-To factor still fires; DMARC doesn't |
| `dangerous/10_danger_lookalike_phishing` | MALICIOUS 44 | SUSPICIOUS 54 | ✅ (URL signals carry it) |
| `dangerous/11_danger_ip_and_private_links` | MALICIOUS 0 | MALICIOUS 6 | ✅ |
| `dangerous/12_danger_encoded_port_subdomains` | MALICIOUS 32 | MALICIOUS 42 | ✅ |
| `dangerous/17_danger_tampered_smime_signature` | MALICIOUS 6 | MALICIOUS 16 | ✅ (S/MIME is local) |
| `dangerous/06, 07, 08` (SPF/DKIM cases) | SUSPICIOUS 73/65/58 | SAFE 100 | ❌ **do not use offline** |

**Offline demo set (use these):** 01, 02, 03, 04, 05, 10, 11, 12, 13, 14, 15, 16, 17.

Note how the *safe* files score 100 offline too (their authentication passes simply become unavailable, and
"unavailable" is worth 0 — §3), while every *dangerous* file that relies on URL evidence still lands where it
should. Only the SPF/DKIM demo cases genuinely need DNS.

---

## 10. Bonus: URL-scanner test cases (no `.eml` needed)

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
| `http://cloud-storage-notice.example:8080/%76erify` | SUSPICIOUS · 74 | odd port + encoded path + HTTP |
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

## 11. Honest Q&A — things the professor may ask

1. **"How can a static `.eml` prove SPF? The sending IP isn't in the file."**
   Correct — that is why the project states SPF needs transport context. For the demo, files 01/06/07 put a
   *plausible* IP in the `Received` header and the envelope sender in `Return-Path`; the engine extracts them and
   runs a **real** `pyspf` DNS evaluation, labelling it `extracted_from_headers` (i.e. "can be forged").
   In production you configure `EMAILGUARD_TRUSTED_AUTHSERV_IDS` to trust a real receiver, or the API accepts
   `?spf_client_ip=…&spf_mailfrom=…` (labelled `operator_supplied_context` — tested: same FAIL result).
   The factor title still prints "Receiver-reported:" for these because the code only marks a check
   `independent` when the IP came from a trusted receiver — a labelling nuance, not a hidden assumption.
2. **"Could you show a DKIM PASS?"**
   With a *demo* file, no: a PASS needs a message signed by a private key whose public key is published in DNS,
   which a hand-written `.eml` cannot have. What the bank shows instead is the honest range:
   (a) a receiver-reported `dkim=pass` labelled **Reported** (files 01–03),
   (b) a genuine DKIM **FAIL** against Google's real published key (file 08), and
   (c) **KEY_UNAVAILABLE** when the selector is not published at all (file 06 — reported, not penalised).
   The PASS path itself is proven in the test suite: `test_genuine_signature_is_independently_verified_as_pass`
   generates a key pair, signs with `dkimpy`, injects the matching TXT record through the same DNS hook dkimpy
   uses, and asserts `verified_status == "PASS"` with `verification_type == "independent"`.
3. **"You fixed DMARC — so why is a nonexistent domain still risky?"**
   Because "no policy published" and "domain does not exist" are *different observations*. Most small domains
   simply never publish a DMARC record; that is configuration debt, so it now scores 0 (`NO_POLICY`). A domain
   with **no MX, A, AAAA or NS records at all** cannot send or receive mail — that is a strong sign of a forged
   sender, so it has its own weight, `sender_domain_unresolvable +10` (§7). Files 10, 11, 12 and 17 exercise it.
4. **"You have S/MIME — does a valid signature mean the sender is genuine?"**
   No, and the bank demonstrates both halves. File **16** carries a real, cryptographically valid CMS signature
   (`signature_valid: true`) — but it is signed with a **self-signed** certificate, so the chain check fails and
   the status is `CERT_UNTRUSTED`: **zero risk added**, because a valid signature is not an identity. File **17**
   uses the same certificate but the body was modified after signing → `SIGNATURE_INVALID` and `+25`. Identity
   would need a trusted chain (configure `EMAILGUARD_SMIME_CA_BUNDLE`).
5. **"Is any of this a real verdict on an email?"**
   No — the report says it itself: prototype rules, not statistically validated probabilities. The README and the
   report's disclaimer strip state that a valid TLS certificate does not make a site benign and that positive
   authentication evidence never overrides an independent high-risk URL signal.
6. **"Did you handle the dangerous files safely?"** Yes: all content is synthetic, no real people's mail is used,
   attachments are never opened, no link is ever clicked in passive mode, and active probing is disabled by default
   and refused for private/loopback targets.
7. **"Why do the offline numbers differ so much?"**
   Because SPF/DKIM/DMARC are *DNS* checks. Without internet, a pass becomes "unavailable", and unavailable is
   worth 0 — so files whose only evidence was an authentication failure (06/07/08) fall back to SAFE and must not
   be used offline. Everything that is decided locally (URL patterns, look-alikes, S/MIME, attachment metadata)
   still works: see the measured table in §9.

---

## 12. Supporting evidence you can show

* **Test suite:** `cd emailguard/backend && python -m pytest -q` → **`60 passed`** (measured on this machine;
  the baseline before the fix set was 48). Three of those tests live in `tests/test_crypto_signatures.py` and
  generate a throw-away RSA key pair plus a **real** CMS signature with `openssl`, so the signed-S/MIME path is
  exercised end to end rather than mocked; they skip automatically if `openssl` is not installed.
* **Repo's own corpus metric script:** `python evaluate_dataset.py` → 4 fixtures,
  predictions `SAFE 82 / SAFE 82 / SUSPICIOUS 58 / MALICIOUS 44`, **accuracy 100 %**, false-positive rate 0 %,
  mean analysis time ≈50–75 ms (prototype scale — not a benchmark; DNS latency makes it vary).
* **API:** `/docs` (interactive OpenAPI), `/api/health` (shows whether active URL checks are enabled),
  `/api/history`, `/api/dashboard/stats` (the dashboard's counters update with each upload).
* **Chrome extension (Manifest V3):** load `extension/` unpacked, open an HTTP(S) page, click the icon →
  the active page URL is analysed by the same engine.

---

## 13. Pre-demo checklist

- [ ] API running on `http://localhost:8000` (`/api/health` → `"status": "ok"`).
- [ ] Dashboard running and `/api` proxied (upload one file to confirm end-to-end).
- [ ] Internet working — verify with file 01 first: it must show **SPF PASS + DMARC PASS**.
- [ ] `openssl` on PATH if you show files 16/17 (the S/MIME verifier shells out to it).
- [ ] Optional clean history: stop the API, delete `emailguard/backend/emailguard.db`, restart (local SQLite only).
- [ ] Switch off the network-checks toggle (all measured results assume passive mode).
- [ ] Keep file 10 (paypal look-alike), 17 (tampered signature) and 07 (ICICI spoof) ready as the "wow" examples.
- [ ] Remember the three headline numbers: **100 SAFE / 58–73 SUSPICIOUS / 6–44 MALICIOUS**.
