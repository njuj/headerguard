"""What the HTML of the fetched page loads, read with the standard library's HTML parser.

Feeds three checks (subresource integrity, mixed content, insecure forms) and the CSP that --fix writes.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

# which CSP directive governs each kind of resource
KIND_DIRECTIVE = {"script": "script-src", "style": "style-src", "img": "img-src", "font": "font-src",
                  "media": "media-src", "frame": "frame-src", "connect": "connect-src", "manifest": "manifest-src",
                  "form": "form-action", "worker": "worker-src"}
CSS_URL = re.compile(r"""url\(\s*['"]?([^'")\s]+)""")
FONT_FILE = re.compile(r"\.(?:woff2?|ttf|otf|eot)(?:[?#]|$)", re.I)
PRELOAD_AS = {"script": "script", "style": "style", "font": "font", "image": "img", "fetch": "connect",
              "audio": "media", "video": "media", "track": "media", "worker": "worker"}


@dataclass
class Resource:
    kind: str           # script | style | img | font | media | frame | form | connect | manifest | worker
    url: str            # absolute
    integrity: bool = False


@dataclass
class Page:
    base: str
    resources: list[Resource] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)     # bodies of <script> without src
    inline_styles: int = 0                                       # <style> blocks
    style_attrs: int = 0                                         # style="..." attributes
    handlers: list[str] = field(default_factory=list)            # onclick="..." etc.
    js_urls: int = 0                                             # href="javascript:..."
    meta_csp: str | None = None

    def origin(self) -> str:
        p = urlsplit(self.base)
        return f"{p.scheme}://{p.netloc}"


class _Reader(HTMLParser):
    def __init__(self, url: str):
        super().__init__(convert_charrefs=True)
        self.page = Page(url)
        self._script: list[str] | None = None
        self._script_type = ""
        self._style: list[str] | None = None

    def _add(self, kind: str, ref: str | None, integrity: bool = False):
        ref = (ref or "").strip()
        if not ref or ref.startswith(("#", "data:", "blob:", "javascript:", "about:", "mailto:", "tel:")):
            return
        url = urljoin(self.page.base, ref)
        if url.startswith(("http://", "https://")):
            self.page.resources.append(Resource(kind, url, integrity))

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        for k, v in a.items():
            if k.startswith("on") and v.strip():
                self.page.handlers.append(v)
        if "style" in a and a["style"].strip():
            self.page.style_attrs += 1
        if a.get("href", "").strip().lower().startswith("javascript:") and tag == "a":
            self.page.js_urls += 1
        if tag == "base" and a.get("href"):
            self.page.base = urljoin(self.page.base, a["href"])
        elif tag == "script":
            if a.get("src"):
                self._add("script", a["src"], "integrity" in a)
            else:
                self._script, self._script_type = [], a.get("type", "").strip().lower()
        elif tag == "link":
            rel = a.get("rel", "").lower().split()
            if "stylesheet" in rel:
                self._add("style", a.get("href"), "integrity" in a)
            elif "manifest" in rel:
                self._add("manifest", a.get("href"))
            elif {"preload", "modulepreload", "prefetch"} & set(rel):
                kind = "script" if "modulepreload" in rel else PRELOAD_AS.get(a.get("as", "").lower())
                if kind:
                    self._add(kind, a.get("href"), "integrity" in a)
            elif "icon" in rel or "apple-touch-icon" in rel:
                self._add("img", a.get("href"))
        elif tag in ("img", "source", "input") and (tag != "input" or a.get("type", "").lower() == "image"):
            kind = "img" if tag != "source" or "srcset" in a and "src" not in a else "media"
            self._add(kind, a.get("src"))
            for candidate in a.get("srcset", "").split(","):
                self._add(kind, candidate.strip().split(" ")[0] if candidate.strip() else "")
        elif tag in ("audio", "video", "track"):
            self._add("media", a.get("src"))
            if tag == "video":
                self._add("img", a.get("poster"))
        elif tag in ("iframe", "frame"):
            self._add("frame", a.get("src"))
        elif tag in ("object", "embed"):
            self._add("frame", a.get("data") or a.get("src"))
        elif tag == "form":
            self._add("form", a.get("action") or self.page.base)
        elif tag == "meta" and a.get("http-equiv", "").lower() == "content-security-policy":
            self.page.meta_csp = a.get("content")
        elif tag == "style":
            self.page.inline_styles += 1
            self._style = []

    def handle_data(self, data):
        if self._script is not None:
            self._script.append(data)
        elif self._style is not None:
            self._style.append(data)

    def handle_endtag(self, tag):
        if tag == "style" and self._style is not None:
            # @font-face and background images declared in the page itself (BBC loads its fonts this way)
            for ref in CSS_URL.findall("".join(self._style)):
                self._add("font" if FONT_FILE.search(ref) else "img", ref)
            self._style = None
        if tag == "script" and self._script is not None:
            body = "".join(self._script)
            # JSON, templates and import maps are not executed as script... except import maps, which CSP governs
            if self._script_type in ("", "text/javascript", "application/javascript", "module", "importmap") \
                    and body.strip():
                self.page.inline_scripts.append(body)
            self._script = None


def read(html: str, url: str) -> Page:
    reader = _Reader(url)
    html = html.replace("\r\n", "\n").replace("\r", "\n")   # what the browser's parser does before hashing
    try:
        reader.feed(html)
        reader.close()
    except (AssertionError, ValueError):   # malformed markup: keep what was read
        pass
    return reader.page


def csp_hash(text: str) -> str:
    """CSP hash source for an inline script or handler: exactly the bytes between the tags, UTF-8."""
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode() + "'"


def origin_of(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"
