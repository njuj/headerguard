"""Check the CSP that --fix writes against real pages, enforced by real Chrome.

    python tests/csp_in_chrome.py python.org bbc.com nodejs.org

For each site: fetch the page once, build the policy, save a copy of the HTML with that policy in a
<meta> tag ('self' spelled out as the site's origin, since the copy is a file:// page), load it in
headless Chrome and count the CSP violations it logs. A control run removes the hashes from the same
policy: Chrome must then block every inline script, which proves a zero is real. Set CHROME to the
browser binary if it is not in the default place.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from headerguard import fix, page as html          # noqa: E402
from headerguard.fetch import fetch                # noqa: E402

CHROME = os.environ.get("CHROME") or next(
    (c for c in (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                 "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                 shutil.which("google-chrome") or "", shutil.which("chromium") or "") if c and Path(c).exists()),
    "google-chrome")


def meta_policy(csp: str, origin: str, drop_hashes: bool) -> str:
    out = []
    for d in csp.split("; "):
        if d.startswith("frame-ancestors"):                 # ignored in <meta>
            continue
        if drop_hashes:
            d = re.sub(r" 'sha256-[^']+'", "", d).replace(" 'unsafe-hashes'", "")
        out.append(d.replace("'self'", origin))
    return "; ".join(out)


def violations(page: Path, profile: str) -> dict[str, int]:
    r = subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--enable-logging=stderr",
                        "--v=0", "--virtual-time-budget=8000", f"--user-data-dir={profile}", "--dump-dom",
                        page.as_uri()], capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=120)
    kinds: dict[str, int] = {}
    for line in r.stderr.splitlines():
        if "Content Security Policy" in line:
            m = re.search(r"directive:? \"?'?([a-z-]+)", line)
            kinds[m.group(1) if m else "other"] = kinds.get(m.group(1) if m else "other", 0) + 1
    return kinds


def main(sites: list[str]) -> None:
    work = Path(tempfile.mkdtemp(prefix="hg-csp-"))
    for site in sites:
        try:
            s = fetch(site, 30)
        except Exception as e:
            print(f"{site}: {e}")
            continue
        p = html.read(s.body, s.url)
        csp, _ = fix.build_csp(p, s.url)
        found = {}
        for label, drop in (("policy", False), ("control", True)):
            head = (f'<base href="{s.url}"><meta http-equiv="Content-Security-Policy" '
                    f'content="{meta_policy(csp, html.origin_of(s.url), drop)}">')
            doc = re.sub(r"(<head[^>]*>)", lambda m: m.group(1) + head, s.body, count=1, flags=re.I)
            f = work / f"{re.sub(r'[^\w]+', '_', site)}_{label}.html"
            f.write_text(doc if doc != s.body else head + s.body, encoding="utf-8", newline="")
            found[label] = violations(f, str(work / "profile"))
        print(f"{site:24} inline scripts {len(p.inline_scripts):3}  handlers {len(p.handlers):2}  "
              f"blocked with policy {sum(found['policy'].values()):3} {found['policy'] or ''}  "
              f"without hashes {sum(found['control'].values()):3}", flush=True)
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main(sys.argv[1:] or ["example.com"])
