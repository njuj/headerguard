import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from headerguard import cli
from headerguard.checks import parse_csp, run_checks
from headerguard.fetch import FetchError, normalize
from headerguard.grade import at_least, grade, score
from headerguard.model import FAIL, INFO, PASS, WARN, Snapshot

TLS_OK = {"version": "TLSv1.3", "days_left": 80, "expires": "2027-01-21", "issuer": "Let's Encrypt"}

HARDENED = [
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
    ("Content-Security-Policy", "default-src 'self'; script-src 'self' 'nonce-r4nd0m' 'unsafe-inline'; "
                                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Set-Cookie", "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"),
    ("Server", "nginx"),
]


def snap(headers=(), url="https://example.com/", requested=None, tls=TLS_OK):
    return Snapshot(requested=requested or url, url=url, status=200, headers=list(headers), tls=tls)


def by_id(checks):
    return {c.id: c for c in checks}


class GradeTest(unittest.TestCase):
    def test_hardened_site_is_a_plus(self):
        checks = run_checks(snap(HARDENED, requested="http://example.com"))
        self.assertEqual((grade(checks), score(checks)), ("A+", 100))
        self.assertEqual(by_id(checks)["https"].detail, "http:// redirects to https://")

    def test_bare_https_site_fails(self):
        checks = run_checks(snap())
        self.assertEqual(score(checks), 44)
        self.assertEqual(grade(checks), "F")

    def test_plain_http_is_always_f(self):
        checks = run_checks(snap(HARDENED, url="http://example.com/", tls=None))
        self.assertEqual(by_id(checks)["https"].status, FAIL)
        self.assertEqual(by_id(checks)["hsts"].status, INFO)
        self.assertEqual(grade(checks), "F")

    def test_expired_or_weak_tls_is_f(self):
        for tls in ({**TLS_OK, "days_left": -3}, {**TLS_OK, "version": "TLSv1.1"}):
            with self.subTest(tls=tls):
                self.assertEqual(grade(run_checks(snap(HARDENED, tls=tls))), "F")

    def test_rejected_certificate_is_f(self):
        checks = run_checks(snap(HARDENED, tls={"error": "certificate has expired"}))
        self.assertEqual(by_id(checks)["tls"].status, FAIL)
        self.assertEqual(grade(checks), "F")

    def test_grade_order(self):
        self.assertTrue(at_least("A+", "B"))
        self.assertTrue(at_least("B", "B"))
        self.assertFalse(at_least("C", "B"))


class CSPTest(unittest.TestCase):
    def csp(self, policy):
        return by_id(run_checks(snap([("Content-Security-Policy", policy)])))["csp"]

    def test_parse_keeps_first_directive(self):
        self.assertEqual(parse_csp("script-src 'self'; script-src *")["script-src"], ["'self'"])

    def test_unsafe_inline_without_nonce(self):
        c = self.csp("default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'")
        self.assertEqual(c.status, WARN)
        self.assertIn("unsafe-inline", c.detail)

    def test_nonce_neutralises_unsafe_inline(self):
        c = self.csp("script-src 'nonce-x' 'unsafe-inline'; object-src 'none'; base-uri 'none'")
        self.assertEqual(c.status, PASS)

    def test_wildcards_and_eval(self):
        c = self.csp("default-src *; script-src https: 'unsafe-eval'")
        for issue in ("unsafe-eval", "wildcard", "object-src", "base-uri"):
            self.assertIn(issue, c.detail)
        self.assertLessEqual(c.penalty, 18)

    def test_report_only(self):
        c = by_id(run_checks(snap([("Content-Security-Policy-Report-Only", "default-src 'self'")])))["csp"]
        self.assertEqual((c.status, c.penalty), (WARN, 15))


class HeaderChecksTest(unittest.TestCase):
    def check(self, cid, headers, **kw):
        return by_id(run_checks(snap(headers, **kw)))[cid]

    def test_hsts_weak(self):
        c = self.check("hsts", [("Strict-Transport-Security", "max-age=3600")])
        self.assertEqual((c.status, c.penalty), (WARN, 11))

    def test_framing_via_xfo(self):
        self.assertEqual(self.check("framing", [("X-Frame-Options", "sameorigin")]).status, PASS)
        self.assertEqual(self.check("framing", [("X-Frame-Options", "ALLOW-FROM x")]).status, FAIL)

    def test_referrer_last_token_wins(self):
        self.assertEqual(self.check("referrer", [("Referrer-Policy", "unsafe-url, no-referrer")]).status, PASS)
        self.assertEqual(self.check("referrer", [("Referrer-Policy", "no-referrer-when-downgrade")]).status, WARN)

    def test_cookie_flags(self):
        c = self.check("cookies", [("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Strict"),
                                   ("Set-Cookie", "tracker=2; Path=/")])
        self.assertEqual(c.status, WARN)
        self.assertIn("tracker without Secure/HttpOnly/SameSite", c.detail)
        self.assertNotIn("a without", c.detail)

    def test_secure_flag_not_required_over_http(self):
        c = self.check("cookies", [("Set-Cookie", "a=1; HttpOnly; SameSite=Lax")], url="http://x.test/", tls=None)
        self.assertEqual(c.status, PASS)

    def test_version_disclosure(self):
        c = self.check("leaks", [("Server", "Apache/2.4.41 (Ubuntu)"), ("X-Powered-By", "PHP/7.4.3")])
        self.assertEqual((c.status, c.penalty), (WARN, 4))
        self.assertEqual(self.check("leaks", [("Server", "cloudflare")]).status, PASS)

    def test_legacy_xss_header_is_informational(self):
        checks = by_id(run_checks(snap([("X-XSS-Protection", "1; mode=block")])))
        self.assertEqual((checks["xss"].status, checks["xss"].penalty), (INFO, 0))
        self.assertNotIn("xss", by_id(run_checks(snap([("X-XSS-Protection", "0")]))))

    def test_header_lookup_is_case_insensitive(self):
        self.assertEqual(self.check("nosniff", [("x-content-type-options", "NoSniff")]).status, PASS)


class CLITest(unittest.TestCase):
    def run_cli(self, *argv, snapshot=None, error=None):
        out, err = io.StringIO(), io.StringIO()
        side = FetchError(error) if error else None
        with mock.patch("headerguard.cli.fetch", return_value=snapshot, side_effect=side), \
                redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_json_report(self):
        code, out, _ = self.run_cli("example.com", "--json", snapshot=snap(HARDENED))
        report = json.loads(out)["reports"][0]
        self.assertEqual((code, report["grade"], report["tls"]["version"]), (0, "A+", "TLSv1.3"))

    def test_min_grade_gate(self):
        self.assertEqual(self.run_cli("example.com", "--min-grade", "B", snapshot=snap())[0], 1)
        self.assertEqual(self.run_cli("example.com", "--min-grade", "B", snapshot=snap(HARDENED))[0], 0)

    def test_text_output(self):
        code, out, _ = self.run_cli("example.com", "--no-color", snapshot=snap())
        self.assertIn("GRADE   F", out)
        self.assertIn("Content-Security-Policy", out)

    def test_fetch_error(self):
        code, _, err = self.run_cli("nope.invalid", error="nope.invalid: Name or service not known")
        self.assertEqual(code, 2)
        self.assertIn("not known", err)

    def test_normalize(self):
        self.assertEqual(normalize("example.com"), "https://example.com")
        self.assertEqual(normalize("http://example.com"), "http://example.com")


if __name__ == "__main__":
    unittest.main()
