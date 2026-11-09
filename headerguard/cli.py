"""Command-line entry point. Exit codes: 0 ok · 1 below --min-grade · 2 fetch error."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

from . import __version__
from .checks import run_checks
from .fetch import FetchError, fetch
from .grade import GRADES, at_least, grade, score
from .model import FAIL, INFO, PASS, WARN

STATUS_COLOR = {PASS: "32", WARN: "33", FAIL: "31", INFO: "2"}
GRADE_COLOR = {"A+": "1;32", "A": "1;32", "B": "1;36", "C": "1;33", "D": "1;31", "F": "1;31"}
UNICODE = {PASS: "✔", WARN: "⚠", FAIL: "✖", INFO: "·", "arrow": "→", "sep": "·"}
ASCII = {PASS: "+", WARN: "!", FAIL: "x", INFO: "-", "arrow": "->", "sep": "|"}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="headerguard",
                                 description="Grade a website's HTTP security headers, cookies and TLS from one request.")
    ap.add_argument("urls", nargs="+", help="URLs or bare hostnames (https:// is assumed)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--min-grade", choices=GRADES, metavar="GRADE",
                    help=f"exit 1 if any site grades below this ({', '.join(GRADES)})")
    ap.add_argument("--timeout", type=float, default=10, metavar="S", help="network timeout in seconds (default: 10)")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def audit(url: str, timeout: float) -> dict:
    snap = fetch(url, timeout)
    checks = run_checks(snap)
    return {"requested": snap.requested, "url": snap.url, "status": snap.status, "redirects": snap.redirects,
            "tls": snap.tls, "grade": grade(checks), "score": score(checks), "checks": [asdict(c) for c in checks]}


def render(report: dict, color: bool, glyphs: dict) -> str:
    def paint(text, code):
        return f"\033[{code}m{text}\033[0m" if color else text

    g, sep = glyphs, f" {glyphs['sep']} "
    meta = [str(report["status"])]
    tls = report["tls"] or {}
    if "version" in tls:
        meta += [tls["version"], f"cert {tls['days_left']}d"]
    elif "error" in tls:
        meta.append("certificate rejected")
    letter = report["grade"]
    badge = paint(f" {letter:<2} ", GRADE_COLOR[letter] + ";7")
    lines = [
        paint(f" headerguard v{__version__}", "1;36") + f"  {g['arrow']}  {report['url']}  " + paint(sep.join(meta), "2"),
        "",
        f"   GRADE  {badge}  " + paint(f"{report['score']}/100", "2"),
        "",
    ]
    width = max(len(c["title"]) for c in report["checks"])
    for c in report["checks"]:
        penalty = paint(f"  -{c['penalty']}", STATUS_COLOR[c["status"]]) if c["penalty"] else ""
        lines.append(f"   {paint(g[c['status']], STATUS_COLOR[c['status']])} {c['title']:<{width}}  " +
                     paint(c["detail"], "2" if c["status"] in (PASS, INFO) else "0") + penalty)
    return "\n".join(lines) + "\n"


def _glyphs(stream) -> dict:
    try:
        "".join(UNICODE.values()).encode(getattr(stream, "encoding", None) or "ascii")
        return UNICODE
    except (UnicodeEncodeError, LookupError):
        return ASCII


def main(argv: list[str] | None = None) -> int:
    for s in (sys.stdout, sys.stderr):   # a piped Windows console is cp1252: never crash on a glyph
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    reports, failed = [], False
    for url in args.urls:
        try:
            reports.append(audit(url, args.timeout))
        except FetchError as e:
            print(f"headerguard: {e}", file=sys.stderr)
            failed = True

    if args.json:
        print(json.dumps({"version": __version__, "reports": reports}, indent=2))
    else:
        color = not args.no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()
        glyphs = _glyphs(sys.stdout)
        for r in reports:
            print(render(r, color, glyphs))

    if failed:
        return 2
    if args.min_grade and any(not at_least(r["grade"], args.min_grade) for r in reports):
        return 1
    return 0
