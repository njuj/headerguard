"""--fix: the headers this site is missing, as a block to paste into its server config.

The Content-Security-Policy is written from the page itself: the origins it loads each kind of resource from,
and a SHA-256 hash for every inline script and event handler, so it allows what the page does today and
nothing else. It is emitted as Report-Only, because no single page shows every request a site makes.
"""

from __future__ import annotations

from . import page as html
from .checks import run_checks
from .model import PASS, Snapshot

SERVERS = ("nginx", "apache", "caddy", "headers")
HSTS = "max-age=63072000; includeSubDomains"
PERMISSIONS = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"


def build_csp(p: html.Page, url: str) -> tuple[str, list[str]]:
    """(policy, notes) for page `p` served at `url`."""
    own = html.origin_of(url)
    sources: dict[str, list[str]] = {}
    for r in p.resources:
        directive = html.KIND_DIRECTIVE[r.kind]
        origin = html.origin_of(r.url)
        src = "'self'" if origin == own else origin
        if r.url.startswith("http://") and url.startswith("https://"):
            continue                                    # upgrade-insecure-requests below takes care of it
        sources.setdefault(directive, [])
        if src not in sources[directive]:
            sources[directive].append(src)

    # stylesheets pull their own fonts and images (kernel.org: CSS on www. loads www. fonts)
    for origin in sources.get("style-src", []):
        for directive in ("font-src", "img-src"):
            if origin not in sources.setdefault(directive, []):
                sources[directive].append(origin)
    if "https://fonts.googleapis.com" in sources.get("style-src", []) and \
            "https://fonts.gstatic.com" not in sources["font-src"]:
        sources["font-src"].append("https://fonts.gstatic.com")

    notes = []
    scripts =["'self'"] + [s for s in sources.get("script-src", []) if s != "'self'"]
    hashes = list(dict.fromkeys(html.csp_hash(s) for s in p.inline_scripts))
    scripts += hashes
    if p.handlers:
        scripts += ["'unsafe-hashes'"] + list(dict.fromkeys(html.csp_hash(h) for h in p.handlers))
        notes.append(f"{len(p.handlers)} inline event handler(s) (onclick=...) are allowed by hash with "
                     "'unsafe-hashes'; moving them to addEventListener lets you drop it")
    if p.js_urls:
        notes.append(f"{p.js_urls} javascript: link(s) will stop working: no hash can allow them")
    if hashes:
        notes.append(f"{len(hashes)} inline script(s) allowed by SHA-256 hash: a changed script needs a new hash "
                     "(or switch to a nonce from your templates)")

    # scripts set style= at runtime even when the HTML has none (seen on python.org), so this is unconditional
    styles = ["'self'"] + [s for s in sources.get("style-src", []) if s != "'self'"] + ["'unsafe-inline'"]
    notes.append("styles keep 'unsafe-inline': pages and their scripts set style= at runtime; "
                 "that is a small risk next to scripts")

    def own_first(directive, extra=()):
        return ["'self'", *extra] + [s for s in sources.get(directive, []) if s != "'self'"]

    policy = [("default-src", ["'self'"]), ("script-src", scripts), ("style-src", styles),
              ("img-src", own_first("img-src", ["data:"])), ("font-src", own_first("font-src", ["data:"])),
              ("connect-src", own_first("connect-src"))]
    for directive in ("media-src", "frame-src", "manifest-src", "worker-src"):
        if directive in sources:
            policy.append((directive, own_first(directive)))
    policy += [("object-src", ["'none'"]), ("base-uri", ["'self'"]), ("form-action", own_first("form-action")),
               ("frame-ancestors", ["'self'"])]
    text = "; ".join(f"{d} {' '.join(v)}" for d, v in policy)
    if url.startswith("https://"):
        text += "; upgrade-insecure-requests"
    notes.append("the policy covers what the HTML loads: what scripts add at runtime (API calls, analytics, "
                 "tag-manager scripts) shows up as Report-Only violations; add those origins before enforcing")
    return text, notes


def recommend(s: Snapshot) -> tuple[list[tuple[str, str]], list[str], list[str]]:
    """([(header, value)], [server-specific lines to remove banners], [notes]) for what is not passing."""
    checks = {c.id: c for c in run_checks(s)}
    headers, notes = [], []
    ok = lambda cid: cid in checks and checks[cid].status == PASS
    if s.https and not ok("hsts"):
        headers.append(("Strict-Transport-Security", HSTS))
        notes.append("HSTS: add '; preload' and submit to hstspreload.org only once every subdomain serves HTTPS")
    if not ok("csp"):
        p = html.read(s.body, s.url) if s.body else html.Page(s.url)
        csp, csp_notes = build_csp(p, s.url)
        headers.append(("Content-Security-Policy-Report-Only", csp))
        notes += ["CSP: " + n for n in csp_notes]
        notes.append("CSP: watch the browser console (or add report-to) for a few days, then rename the header to "
                     "Content-Security-Policy to enforce it")
    if not ok("framing"):
        headers.append(("X-Frame-Options", "SAMEORIGIN"))   # Report-Only CSP does not enforce frame-ancestors
    if not ok("nosniff"):
        headers.append(("X-Content-Type-Options", "nosniff"))
    if not ok("referrer"):
        headers.append(("Referrer-Policy", "strict-origin-when-cross-origin"))
    if not ok("permissions"):
        headers.append(("Permissions-Policy", PERMISSIONS))
        notes.append("Permissions-Policy: leave out any feature the site really uses (e.g. camera for video calls)")
    if "cookies" in checks and checks["cookies"].status != PASS and checks["cookies"].penalty:
        notes.append(f"cookies are set by the application, not the server: {checks['cookies'].detail}; "
                     "add Secure; HttpOnly; SameSite=Lax where they are created")
    banners = checks.get("leaks") is not None and checks["leaks"].status != PASS
    return headers, (["leaks"] if banners else []), notes


def render(s: Snapshot, server: str) -> str:
    headers, banners, notes = recommend(s)
    if not headers and not banners:
        return f"# headerguard: {s.url} already sends every header it checks for; nothing to add\n"
    head = f"headerguard --fix {server} for {s.url}"
    if server == "nginx":
        out = [f"# {head}", "# inside the server { } block (add_header in a location { } replaces these: repeat them there)"]
        out += [f'add_header {h} "{v}" always;' for h, v in headers]
        out += ["server_tokens off;", "proxy_hide_header X-Powered-By;"] if banners else []
    elif server == "apache":
        out = [f"# {head}", "# in the VirtualHost or .htaccess (needs mod_headers)"]
        out += [f'Header always set {h} "{v}"' for h, v in headers]
        out += ["Header always unset X-Powered-By", "# and in the main config: ServerTokens Prod"] if banners else []
    elif server == "caddy":
        out = [f"# {head}", "# in the site block", "header {"]
        out += [f'\t{h} "{v}"' for h, v in headers]
        out += ["\t-Server", "\t-X-Powered-By"] if banners else []
        out.append("}")
    else:
        out = [f"# {head}", "# a _headers file (Netlify, Cloudflare Pages)", "/*"]
        out += [f"  {h}: {v}" for h, v in headers]
    out += [""] + [f"# note: {n}" for n in notes]
    return "\n".join(out) + "\n"
