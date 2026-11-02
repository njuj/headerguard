"""One GET request (following redirects) plus a TLS handshake. Nothing else is sent."""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import __version__
from .model import Snapshot

USER_AGENT = f"headerguard/{__version__} (+https://github.com/njuj/headerguard)"


class FetchError(RuntimeError):
    pass


class _RedirectRecorder(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append(req.full_url)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def normalize(url: str) -> str:
    return url if "://" in url else "https://" + url


class _CertificateRejected(Exception):
    pass


def fetch(url: str, timeout: float = 10) -> Snapshot:
    """Fetch with full certificate verification. If the certificate is rejected, still grade the
    headers over an unverified connection and record the TLS failure, which caps the grade at F."""
    url = normalize(url)
    try:
        return _get(url, timeout, verify=True)
    except _CertificateRejected as e:
        snap = _get(url, timeout, verify=False)
        snap.tls = {"error": str(e)}
        return snap


def _get(url: str, timeout: float, verify: bool) -> Snapshot:
    recorder = _RedirectRecorder()
    handlers: list = [recorder]
    if not verify:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as e:
        response = e  # 4xx/5xx pages still carry the security headers we care about
    except urllib.error.URLError as e:
        if verify and isinstance(e.reason, ssl.SSLCertVerificationError):
            raise _CertificateRejected(e.reason.verify_message or str(e.reason)) from None
        raise FetchError(f"{url}: {e.reason}") from None
    except (TimeoutError, socket.timeout):
        raise FetchError(f"{url}: timed out after {timeout}s") from None

    with response:
        final, status, headers = response.geturl(), response.getcode(), list(response.headers.items())

    tls = None
    if verify and final.lower().startswith("https://"):
        try:
            tls = tls_info(final, timeout)
        except (OSError, ssl.SSLError, ValueError):
            tls = None
    return Snapshot(requested=url, url=final, status=status, headers=headers, redirects=recorder.chain, tls=tls)


def tls_info(url: str, timeout: float) -> dict:
    parts = urlsplit(url)
    host, port = parts.hostname, parts.port or 443
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert, version = tls.getpeercert(), tls.version()
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    issuer = dict(item[0] for item in cert.get("issuer", ())).get("organizationName", "?")
    return {
        "version": version,
        "expires": expires.date().isoformat(),
        "days_left": (expires - datetime.now(timezone.utc)).days,
        "issuer": issuer,
    }
