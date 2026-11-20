import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

from headerguard import cli, fix
from headerguard import page as html
from headerguard.checks import run_checks
from headerguard.model import FAIL, INFO, PASS, WARN, Snapshot

from test_headerguard import HARDENED, TLS_OK

PAGE = """<!doctype html><html><head>
<base href="https://example.com/app/">
<script src="/js/app.js"></script>
<script src="https://cdn.example.net/lib.js" integrity="sha384-x" crossorigin></script>
<script src="https://cdn.jsdelivr.net/npm/x@1/x.js"></script>
<script>window.boot = 1;</script>
<script type="application/json">{"not": "code"}</script>
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=X">
<link rel="preload" as="font" href="https://fonts.gstatic.com/a.woff2">
<link rel="manifest" href="site.webmanifest">
<style>body{margin:0}</style>
</head><body>
<img src="logo.png" srcset="a.png 1x, https://img.example.org/b.png 2x">
<img src="data:image/png;base64,AAAA">
<iframe src="https://www.youtube.com/embed/1"></iframe>
<button onclick="go()">go</button>
<a href="javascript:void(0)">x</a>
<form method="post"><input name="q"></form>
</body></html>"""


def snap(body, url="https://example.com/", headers=()):
    return Snapshot(requested=url, url=url, status=200, headers=list(headers),
                    tls=TLS_OK if url.startswith("https") else None, body=body)


def by_id(checks):
    return {c.id: c for c in checks}


class PageTest(unittest.TestCase):
    def setUp(self):
        self.p = html.read(PAGE, "https://example.com/")

    def urls(self, kind):
        return [r.url for r in self.p.resources if r.kind == kind]

    def test_resources_resolve_against_base(self):
        self.assertEqual(self.urls("script"), ["https://example.com/js/app.js", "https://cdn.example.net/lib.js",
                                               "https://cdn.jsdelivr.net/npm/x@1/x.js"])
        self.assertIn("https://example.com/app/logo.png", self.urls("img"))
        self.assertIn("https://img.example.org/b.png", self.urls("img"))
        self.assertEqual(self.urls("form"), ["https://example.com/app/"])
        self.assertEqual(self.urls("manifest"), ["https://example.com/app/site.webmanifest"])
        self.assertEqual(self.urls("font"), ["https://fonts.gstatic.com/a.woff2"])
        self.assertFalse(any(u.startswith("data:") for u in self.urls("img")))

    def test_inline_code(self):
        self.assertEqual(self.p.inline_scripts, ["window.boot = 1;"])   # JSON data block is not script
        self.assertEqual(self.p.handlers, ["go()"])
        self.assertEqual((self.p.js_urls, self.p.inline_styles), (1, 1))

    def test_integrity_flag(self):
        flags = {r.url: r.integrity for r in self.p.resources if r.kind == "script"}
        self.assertTrue(flags["https://cdn.example.net/lib.js"])
        self.assertFalse(flags["https://cdn.jsdelivr.net/npm/x@1/x.js"])

    def test_hash_matches_browser(self):
        self.assertEqual(html.csp_hash(""), "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='")
        crlf = html.read("<script>a();\r\nb();</script>", "https://e.com/")
        self.assertEqual(crlf.inline_scripts, ["a();\nb();"])   # browsers hash after newline normalisation

    def test_urls_in_inline_css(self):
        p = html.read("<style>@font-face{src:url('https://f.cdn.net/a.woff2?v=2') format('woff2')}"
                      " .h{background:url(/bg.jpg)} .d{background:url(data:image/png;base64,AA)}</style>",
                      "https://e.com/")
        self.assertEqual([(r.kind, r.url) for r in p.resources],
                         [("font", "https://f.cdn.net/a.woff2?v=2"), ("img", "https://e.com/bg.jpg")])

    def test_broken_markup_does_not_raise(self):
        html.read("<script>never closed <a href=", "https://e.com/")


class PageChecksTest(unittest.TestCase):
    def test_sri(self):
        c = by_id(run_checks(snap(PAGE)))["sri"]
        self.assertEqual(c.status, WARN)
        self.assertIn("cdn.jsdelivr.net", c.detail)
        self.assertNotIn("cdn.example.net", c.detail)   # that one is pinned
        self.assertEqual(c.penalty, 4)                  # jsdelivr + googleapis
        own = by_id(run_checks(snap('<script src="/a.js"></script>')))["sri"]
        self.assertEqual(own.status, INFO)
        pinned = by_id(run_checks(snap('<script src="https://c.net/a.js" integrity="sha384-x"></script>')))["sri"]
        self.assertEqual(pinned.status, PASS)

    def test_mixed_content(self):
        active = by_id(run_checks(snap('<script src="http://cdn.net/a.js"></script>')))["mixed"]
        self.assertEqual((active.status, active.penalty), (FAIL, 10))
        passive = by_id(run_checks(snap('<img src="http://cdn.net/a.png">')))["mixed"]
        self.assertEqual((passive.status, passive.penalty), (WARN, 3))
        self.assertEqual(by_id(run_checks(snap(PAGE)))["mixed"].status, PASS)
        self.assertNotIn("mixed", by_id(run_checks(snap(PAGE, url="http://example.com/"))))

    def test_forms(self):
        bad = by_id(run_checks(snap('<form action="http://example.com/login"></form>')))["forms"]
        self.assertEqual((bad.status, bad.penalty), (FAIL, 10))
        self.assertEqual(by_id(run_checks(snap(PAGE)))["forms"].status, PASS)

    def test_no_body_means_no_page_checks(self):
        self.assertFalse({"sri", "mixed", "forms"} & set(by_id(run_checks(snap("")))))


class FixTest(unittest.TestCase):
    def policy(self, body, url="https://example.com/"):
        csp, notes = fix.build_csp(html.read(body, url), url)
        return dict((d.split(" ", 1) + [""])[:2] for d in csp.split("; ")), notes

    def test_csp_from_page(self):
        d, notes = self.policy(PAGE)
        script = d["script-src"].split()
        self.assertEqual(script[:3], ["'self'", "https://cdn.example.net", "https://cdn.jsdelivr.net"])
        self.assertIn(html.csp_hash("window.boot = 1;"), script)
        self.assertIn("'unsafe-hashes'", script)
        self.assertIn(html.csp_hash("go()"), script)
        self.assertNotIn("'unsafe-inline'", script)
        self.assertIn("'unsafe-inline'", d["style-src"])
        self.assertIn("https://fonts.googleapis.com", d["style-src"])
        self.assertEqual(d["font-src"], "'self' data: https://fonts.gstatic.com https://fonts.googleapis.com")
        css, _ = self.policy('<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=X">'
                             '<link rel="stylesheet" href="https://www.example.com/main.css">')
        self.assertEqual(css["font-src"], "'self' data: https://fonts.googleapis.com https://www.example.com "
                                          "https://fonts.gstatic.com")
        self.assertIn("https://www.example.com", css["img-src"])
        self.assertEqual(d["frame-src"], "'self' https://www.youtube.com")
        self.assertEqual(d["object-src"], "'none'")
        self.assertIn("upgrade-insecure-requests", d)
        self.assertTrue(any("javascript:" in n for n in notes))

    def test_http_resources_are_left_to_upgrade(self):
        d, _ = self.policy('<script src="http://cdn.net/a.js"></script>')
        self.assertEqual(d["script-src"], "'self'")

    def test_plain_page_gets_tight_policy(self):
        d, _ = self.policy("<p>hi</p>")
        self.assertEqual(d["script-src"], "'self'")
        self.assertEqual(d["style-src"], "'self' 'unsafe-inline'")
        self.assertNotIn("frame-src", d)

    def test_render_formats(self):
        s = snap(PAGE, headers=[("Server", "nginx/1.25.3")])
        nginx = fix.render(s, "nginx")
        self.assertIn('add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;', nginx)
        self.assertIn("add_header Content-Security-Policy-Report-Only", nginx)
        self.assertIn("server_tokens off;", nginx)
        self.assertIn('Header always set X-Content-Type-Options "nosniff"', fix.render(s, "apache"))
        caddy = fix.render(s, "caddy")
        self.assertIn("header {", caddy)
        self.assertIn("\t-Server", caddy)
        self.assertIn("  X-Frame-Options: SAMEORIGIN", fix.render(s, "headers"))

    def test_hardened_site_needs_nothing(self):
        out = fix.render(snap("", headers=HARDENED), "nginx")
        self.assertIn("nothing to add", out)

    def test_only_missing_headers(self):
        s = snap("", headers=[h for h in HARDENED if h[0] != "Referrer-Policy"])
        names = [h for h, _ in fix.recommend(s)[0]]
        self.assertEqual(names, ["Referrer-Policy"])

    def test_cli_fix(self):
        out = io.StringIO()
        with mock.patch("headerguard.cli.fetch", return_value=snap(PAGE)), redirect_stdout(out):
            cli.main(["example.com", "--no-color", "--fix", "caddy"])
        self.assertIn("header {", out.getvalue())
        out = io.StringIO()
        with mock.patch("headerguard.cli.fetch", return_value=snap(PAGE)), redirect_stdout(out):
            cli.main(["example.com", "--json", "--fix", "nginx"])
        self.assertIn("add_header", json.loads(out.getvalue())["reports"][0]["fix"])


if __name__ == "__main__":
    unittest.main()
