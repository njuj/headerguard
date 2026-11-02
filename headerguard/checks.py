"""Security checks. Each takes a Snapshot and returns one Check; penalties are subtracted from 100."""

from __future__ import annotations

import re

from .model import FAIL, INFO, PASS, WARN, Check, Snapshot

HSTS_MIN_AGE = 15_552_000  # 180 days
STRICT_SOURCES = ("'nonce-", "'sha256-", "'sha384-", "'sha512-", "'strict-dynamic'")
LEAKY_HEADERS = ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator")
WEAK_TLS = {"SSLv3", "TLSv1", "TLSv1.1"}


def parse_csp(value: str) -> dict[str, list[str]]:
    """Directive -> sources. Per spec, only the first occurrence of a directive counts."""
    policy: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            policy.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return policy


def check_https(s: Snapshot) -> Check:
    if not s.https:
        return Check("https", "HTTPS", FAIL, "served over plain HTTP", 30)
    upgraded = s.requested.lower().startswith("http://")
    return Check("https", "HTTPS", PASS, "http:// redirects to https://" if upgraded else "served over HTTPS")


def check_tls(s: Snapshot) -> Check:
    title = "TLS"
    if not s.https:
        return Check("tls", title, INFO, "not applicable over HTTP")
    if not s.tls:
        return Check("tls", title, INFO, "handshake details unavailable")
    if s.tls.get("error"):
        return Check("tls", title, FAIL, f"certificate rejected: {s.tls['error']}", 30)
    version, days = s.tls["version"], s.tls["days_left"]
    if days < 0:
        return Check("tls", title, FAIL, f"certificate expired {-days} day(s) ago", 30)
    if version in WEAK_TLS:
        return Check("tls", title, FAIL, f"{version} negotiated; TLS 1.2+ required", 15)
    if days < 14:
        return Check("tls", title, WARN, f"{version}, certificate expires in {days} day(s)", 8)
    return Check("tls", title, PASS, f"{version}, certificate valid for {days} more days ({s.tls.get('issuer', '?')})")


def check_hsts(s: Snapshot) -> Check:
    title = "Strict-Transport-Security"
    if not s.https:
        return Check("hsts", title, INFO, "not applicable over HTTP")
    value = s.get(title)
    if not value:
        return Check("hsts", title, FAIL, "missing: the first visit can be downgraded to HTTP", 15)
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    age = int(m.group(1)) if m else 0
    lowered = value.lower()
    notes, penalty = [f"max-age {age}"], 0
    if age < HSTS_MIN_AGE:
        notes.append("shorter than 180 days")
        penalty += 8
    if "includesubdomains" not in lowered:
        notes.append("no includeSubDomains")
        penalty += 3
    if "preload" in lowered:
        notes.append("preload")
    return Check("hsts", title, WARN if penalty else PASS, ", ".join(notes), penalty)


def check_csp(s: Snapshot) -> Check:
    title = "Content-Security-Policy"
    value = s.get(title)
    if not value:
        if s.get("Content-Security-Policy-Report-Only"):
            return Check("csp", title, WARN, "report-only: violations are logged, not blocked", 15)
        return Check("csp", title, FAIL, "missing: no defense-in-depth against XSS", 20)

    csp = parse_csp(value)
    scripts = csp.get("script-src", csp.get("default-src"))
    issues, penalty = [], 0
    if scripts is None:
        issues.append("no script-src or default-src")
        penalty += 10
    else:
        strict = any(t.startswith(STRICT_SOURCES) for t in scripts)
        # CSP2+ browsers ignore 'unsafe-inline' when a nonce or hash is present
        if "'unsafe-inline'" in scripts and not strict:
            issues.append("scripts allow 'unsafe-inline'")
            penalty += 10
        if "'unsafe-eval'" in scripts:
            issues.append("scripts allow 'unsafe-eval'")
            penalty += 5
        if "'strict-dynamic'" not in scripts and any(t in ("*", "http:", "https:", "data:") for t in scripts):
            issues.append("wildcard script source")
            penalty += 8
    if csp.get("object-src", csp.get("default-src")) != ["'none'"]:
        issues.append("object-src is not 'none'")
        penalty += 2
    if "base-uri" not in csp:
        issues.append("no base-uri")
        penalty += 2
    if issues:
        return Check("csp", title, WARN, ", ".join(issues), min(penalty, 18))
    return Check("csp", title, PASS, f"strict policy, {len(csp)} directives")


def check_framing(s: Snapshot) -> Check:
    title = "Clickjacking"
    ancestors = parse_csp(s.get("Content-Security-Policy") or "").get("frame-ancestors")
    if ancestors is not None:
        return Check("framing", title, PASS, "CSP frame-ancestors " + " ".join(ancestors))
    xfo = (s.get("X-Frame-Options") or "").strip().upper()
    if xfo in ("DENY", "SAMEORIGIN"):
        return Check("framing", title, PASS, f"X-Frame-Options {xfo}")
    return Check("framing", title, FAIL, "no X-Frame-Options or CSP frame-ancestors", 10)


def check_nosniff(s: Snapshot) -> Check:
    title = "X-Content-Type-Options"
    if (s.get(title) or "").strip().lower() == "nosniff":
        return Check("nosniff", title, PASS, "nosniff")
    return Check("nosniff", title, FAIL, "missing: browsers may MIME-sniff responses", 5)


def check_referrer(s: Snapshot) -> Check:
    title = "Referrer-Policy"
    value = s.get(title)
    if not value:
        return Check("referrer", title, WARN, "missing: browser default applies", 3)
    policy = value.split(",")[-1].strip().lower()  # the last policy the browser understands wins
    if policy in ("unsafe-url", "no-referrer-when-downgrade"):
        return Check("referrer", title, WARN, f"{policy} leaks full URLs to third parties", 5)
    return Check("referrer", title, PASS, policy)


def check_permissions(s: Snapshot) -> Check:
    title = "Permissions-Policy"
    if s.get(title):
        return Check("permissions", title, PASS, "browser features restricted")
    return Check("permissions", title, WARN, "missing: camera, mic, geolocation etc. not restricted", 3)


def check_coop(s: Snapshot) -> Check:
    title = "Cross-Origin-Opener-Policy"
    value = s.get(title)
    if value:
        return Check("coop", title, PASS, value.strip())
    return Check("coop", title, INFO, "not set (needed for cross-origin isolation)")


def check_cookies(s: Snapshot) -> Check:
    title = "Cookies"
    cookies = s.get_all("Set-Cookie")
    if not cookies:
        return Check("cookies", title, INFO, "no cookies set")
    issues = []
    for cookie in cookies:
        name = cookie.split("=", 1)[0].strip()
        attrs = {a.strip().split("=", 1)[0].lower() for a in cookie.split(";")[1:]}
        wanted = [("Secure", "secure")] if s.https else []
        wanted += [("HttpOnly", "httponly"), ("SameSite", "samesite")]
        missing = [flag for flag, key in wanted if key not in attrs]
        if missing:
            issues.append(f"{name} without {'/'.join(missing)}")
    if issues:
        return Check("cookies", title, WARN, "; ".join(issues), min(8, 2 * len(issues)))
    return Check("cookies", title, PASS, f"{len(cookies)} cookie(s), all hardened")


def check_leaks(s: Snapshot) -> Check:
    title = "Version disclosure"
    leaks = []
    server = s.get("Server")
    if server and re.search(r"\d", server):
        leaks.append(f"Server: {server}")
    leaks += [f"{h}: {s.get(h)}" for h in LEAKY_HEADERS if s.get(h)]
    if leaks:
        return Check("leaks", title, WARN, "; ".join(leaks), min(6, 2 * len(leaks)))
    return Check("leaks", title, PASS, "no version banners")


def check_legacy_xss(s: Snapshot) -> Check | None:
    value = s.get("X-XSS-Protection")
    if value and not value.strip().startswith("0"):
        return Check("xss", "X-XSS-Protection", INFO, "legacy auditor enabled; modern advice is '0' or omit")
    return None


CHECKS = (check_https, check_tls, check_hsts, check_csp, check_framing, check_nosniff, check_referrer,
          check_permissions, check_coop, check_cookies, check_leaks, check_legacy_xss)


def run_checks(s: Snapshot) -> list[Check]:
    return [c for c in (check(s) for check in CHECKS) if c is not None]
