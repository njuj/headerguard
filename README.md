# headerguard

**Grade a website's HTTP security posture from a single request.** Security headers, CSP quality, cookie flags, TLS version and certificate health come out as one letter grade, and the CLI can fail your pipeline when a deploy regresses. Zero dependencies.

[![ci](https://github.com/njuj/headerguard/actions/workflows/ci.yml/badge.svg)](https://github.com/njuj/headerguard/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-00ff9c?labelColor=0b0f17)
![deps](https://img.shields.io/badge/dependencies-0-00ff9c?labelColor=0b0f17)
![license](https://img.shields.io/badge/license-MIT-00ff9c?labelColor=0b0f17)

```text
$ headerguard github.com

 headerguard v0.1.0  →  https://github.com  200 · TLSv1.3 · cert 86d

   GRADE   A+   95/100

   ✔ HTTPS                       served over HTTPS
   ✔ TLS                         TLSv1.3, certificate valid for 86 more days (Sectigo Limited)
   ✔ Strict-Transport-Security   max-age 31536000, preload
   ✔ Content-Security-Policy     strict policy, 15 directives
   ✔ Clickjacking                CSP frame-ancestors 'none'
   ✔ X-Content-Type-Options      nosniff
   ✔ Referrer-Policy             strict-origin-when-cross-origin
   ⚠ Permissions-Policy          missing: camera, mic, geolocation etc. not restricted  -3
   · Cross-Origin-Opener-Policy  not set (needed for cross-origin isolation)
   ⚠ Cookies                     _octo without HttpOnly  -2
   ✔ Version disclosure          no version banners
```

## What it checks

| Check | Pass | Penalty |
|---|---|---|
| **HTTPS** | final URL is `https://` (http → https redirects are detected) | plain HTTP: **-30, grade capped at F** |
| **TLS** | TLS 1.2+, certificate verifies, more than 14 days left | rejected/expired cert or TLS ≤ 1.1: **F** · expiring soon: -8 |
| **HSTS** | `max-age` ≥ 180 days + `includeSubDomains` | missing -15 · short -8 · no subdomains -3 |
| **CSP** | scripts locked down, `object-src 'none'`, `base-uri` set | missing -20 · report-only -15 · `unsafe-inline` without nonce/hash -10 · `unsafe-eval` -5 · wildcard sources -8 *(max -18)* |
| **Clickjacking** | `frame-ancestors` or `X-Frame-Options: DENY/SAMEORIGIN` | -10 |
| **MIME sniffing** | `X-Content-Type-Options: nosniff` | -5 |
| **Referrer-Policy** | anything that doesn't leak full URLs | missing -3 · `unsafe-url` / `no-referrer-when-downgrade` -5 |
| **Permissions-Policy** | present | -3 |
| **Cookies** | every `Set-Cookie` has `Secure` (on HTTPS), `HttpOnly`, `SameSite` | -2 per cookie *(max -8)* |
| **Version disclosure** | no versioned `Server`, no `X-Powered-By` / `X-AspNet-Version` | -2 per banner *(max -6)* |
| **COOP**, legacy `X-XSS-Protection` | reported for information | 0 |

`A+` ≥ 95 with no failed check · `A` ≥ 90 · `B` ≥ 80 · `C` ≥ 70 · `D` ≥ 60 · `F` otherwise

### Details that matter

* **CSP is parsed per the spec, not grepped.** Only the first occurrence of a directive counts, `script-src` falls back to `default-src`, and `'unsafe-inline'` is *not* penalised when a nonce, hash or `'strict-dynamic'` is present (CSP2+ browsers ignore it then).
* **Referrer-Policy honours fallback lists:** in `unsafe-url, no-referrer` the last policy wins.
* **A rejected certificate still gets a full report.** headerguard re-fetches without verification, grades the headers anyway, and records the TLS failure. Run it on `expired.badssl.com` to see this. Python validates against the OS trust store and does not fetch missing intermediates, so a server that sends an incomplete chain gets reported as well. Browsers sometimes hide that bug, while `curl`, mobile apps and API clients break on it.
* **4xx/5xx responses are graded too.** Error pages are part of your attack surface.

## Install

```bash
pip install git+https://github.com/njuj/headerguard
```

Or run it straight from a checkout: `python -m headerguard example.com`

## Usage

```bash
headerguard example.com                       # bare host → https:// assumed
headerguard http://example.com                # also verifies the http → https upgrade
headerguard site-a.com site-b.com --json      # machine-readable
headerguard staging.example.com --min-grade A # exit 1 if worse than A
```

### As a deploy gate

```yaml
# .github/workflows/security-headers.yml
- run: pip install git+https://github.com/njuj/headerguard
- run: headerguard https://staging.example.com --min-grade A
```

**Exit codes:** `0` ok · `1` below `--min-grade` · `2` network error

## Layout

```
headerguard/
├── model.py    Snapshot (one fetch, pure data) + Check
├── fetch.py    single GET with redirect tracking + TLS handshake
├── checks.py   one pure function per check: Snapshot → Check
├── grade.py    scoring and letter grades
└── cli.py      argparse, renderer, exit codes
tests/          every check is tested against hand-built snapshots (no network in tests)
```

Every check is a pure function of a `Snapshot`, so the whole test suite runs offline in milliseconds:

```bash
python -m unittest discover -s tests -v
```

## Ethics

headerguard sends **one ordinary GET request** per URL and opens one TLS handshake, the same traffic as a browser visit. It does not probe, fuzz or brute-force anything.

---

<sub>built by <a href="https://github.com/njuj">kira</a> · trust nothing, verify everything</sub>
