#!/usr/bin/env python3
"""
verify.py — the verification engine.

The one job of this module is to answer, mechanically, one question:

    "Does this exact document, fetched right now, actually contain this text?"

It answers PASS, FAIL, or UNVERIFIABLE. It never answers "probably".

Hard rules, enforced in code, not in prose:

  1. NO MODEL OPINION CAN PRODUCE PASS. There is no LLM in this file. A PASS
     requires byte-level containment of the token in text that was fetched
     over the wire in this process and hashed into a file on disk.

  2. A cited source that answers "no" is a hard FAIL: HTTP >= 400, a
     non-document content type, or an unsafe/refused URL. A source we cannot
     reach at all (DNS failure, timeout, connection error) is UNVERIFIABLE:
     there is no evidence the source is wrong, only evidence we could not look.
     Containment is never attempted in either case.

  3. UNVERIFIABLE means "we could not check" — network down, timeout, PDF we
     could not parse, encrypted content, empty body. It is NOT a soft FAIL and
     it must never be reported as a pass. The difference matters: FAIL says the
     source does not support the claim; UNVERIFIABLE says we do not know.

  4. Every verdict carries fetched_at and sha256. A verdict you cannot re-check
     is not a verdict.

  5. We never invent a URL, a source, or a quotation. If we cannot fetch it,
     the JSON says so and the URL field echoes exactly what we were given.

Three stages, one per function:

    resolve()     -> what is at this URL? status, redirect target, type, bytes
    fetch()       -> give me the text, and prove you hashed it
    check_tokens()-> is each token in that text, and where exactly?

verify() runs all three and returns the verdict dict.

CLI:
    python3 verify.py --url URL --must-contain "41GW" --must-contain "six projects" --json
    python3 verify.py --batch claims.json --json
    python3 verify.py --url URL --must-contain "41GW"          # human-readable

Batch file shape — either a JSON list, or {"claims": [...]}:
    [
      {"url": "...", "must_contain": ["41GW", "six projects"], "id": "optional"},
      ...
    ]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import time
import unicodedata
from datetime import datetime, timezone
from functools import lru_cache
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import requests

import config

log = logging.getLogger("research_hunter.verify")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PASS = "PASS"
FAIL = "FAIL"
UNVERIFIABLE = "UNVERIFIABLE"

VERDICTS = (PASS, FAIL, UNVERIFIABLE)

USER_AGENT = config.VERIFY_USER_AGENT or (
    "ResearchHunterVerify/1.0 (documentary fact-checking; "
    f"{config.CONTACT_EMAIL or 'no-contact-set'})"
)

# Content types we consider a document we can extract text from. Anything not
# on this list — image/png, application/zip, video/mp4 — is a hard FAIL at the
# resolution stage. A JPEG is not a source you can quote.
DOCUMENT_CONTENT_TYPES = {
    "text/html",
    "application/xhtml+xml",
    "text/plain",
    "text/csv",
    "text/tab-separated-values",
    "application/xml",
    "text/xml",
    "application/json",
    "application/pdf",
    "application/x-pdf",
}

# PDFs that are really PDFs sometimes arrive as octet-stream. We allow it, but
# only if the body actually starts with %PDF — the magic bytes decide, not the
# header, because servers lie about headers and do not lie about magic bytes.
MAGIC_PDF = b"%PDF-"

# Boilerplate lines that add noise to containment checks. Kept deliberately
# short and conservative: we only strip navigation furniture that could never
# carry a factual claim.
_BOILERPLATE_PATTERNS = [
    re.compile(r"^\s*(skip to (main )?content|jump to (main )?content)\s*$", re.I),
    re.compile(r"^\s*(accept (all )?cookies|we use cookies.*|cookie (policy|settings).*)\s*$", re.I),
    re.compile(r"^\s*(privacy (policy|notice)|terms (of use|and conditions)|terms & conditions)\s*$", re.I),
    re.compile(r"^\s*(subscribe|sign up)( to our newsletter)?\s*$", re.I),
    re.compile(r"^\s*(share|share this|share on (twitter|facebook|linkedin)|print|email this page)\s*$", re.I),
    re.compile(r"^\s*(back to top|home|menu|search|close)\s*$", re.I),
    re.compile(r"^\s*(©|copyright|\(c\)).{0,120}$", re.I),
]

# How many characters of the document to keep in the JSON response. We store
# the FULL text on disk; the JSON carries a prefix for human spot-checks so a
# batch report does not become 200 MB of HTML.
TEXT_PREVIEW_CHARS = 4000


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _now_iso():
    """UTC timestamp, ISO 8601, second precision, always with a Z."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _base_content_type(raw):
    """'text/html; charset=UTF-8' -> 'text/html'. Missing -> ''."""
    if not raw:
        return ""
    return raw.split(";", 1)[0].strip().lower()


def _looks_like_pdf(body):
    return body[:5] == MAGIC_PDF


def _is_document(content_type, body, url=""):
    """
    Decide whether a response body is a document we can quote from.

    Returns (ok: bool, reason: str). The reason is what goes in errors[] when
    we refuse, so it has to be specific enough to act on.
    """
    ct = _base_content_type(content_type)

    # A PDF is a PDF if it starts with %PDF, whatever the server claimed.
    if _looks_like_pdf(body):
        return True, ""

    if ct in DOCUMENT_CONTENT_TYPES:
        return True, ""

    if not ct:
        # No content-type header at all. Accept only if the body reads as text:
        # a handful of government servers omit the header entirely.
        head = body[:2048]
        if head and b"\x00" not in head:
            try:
                head.decode("utf-8")
                return True, ""
            except UnicodeDecodeError:
                pass
        return False, f"no usable content-type and body is not text (url={url})"

    if ct.startswith("text/"):
        # text/css, text/javascript are technically text but never evidence.
        if ct in ("text/css", "text/javascript"):
            return False, f"content-type {ct!r} is an asset, not a document"
        return True, ""

    return False, f"content-type {ct!r} is not a quotable document"


# ---------------------------------------------------------------------------
# STAGE 1 — RESOLVE
# ---------------------------------------------------------------------------

# SSRF guard. A verifier takes URLs from untrusted input, so it must never be
# able to read a developer's own services or a cloud metadata endpoint. Keep
# this list explicit; "looks like a public URL" is not a security control.
_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
        "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
        "224.0.0.0/4", "240.0.0.0/4",
        "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
        "2001:db8::/32",
    )
)


def _ip_is_blocked(address):
    """True for loopback, private, link-local, reserved or multicast IPs."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    # IPv4-mapped IPv6 addresses must be judged as IPv4.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return any(ip.version == net.version and ip in net for net in _BLOCKED_NETWORKS)


@lru_cache(maxsize=2048)
def _dns_addresses(hostname):
    """All A/AAAA answers for a host, memoised for the life of the process."""
    try:
        answers = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except OSError:
        return ()
    return tuple(sorted({item[4][0] for item in answers}))


def _check_public_url(url):
    """Return '' if this URL may be fetched, else a specific refusal reason.

    Checked before every request AND after every redirect. A hostname that
    resolves to even one blocked address is refused: allowing a mixed answer
    would make the decision depend on which DNS reply the resolver used.
    """
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        return f"unsupported URL scheme {parsed.scheme!r} (only http/https)"
    if not parsed.netloc or not parsed.hostname:
        return "URL has no host"
    if parsed.username or parsed.password:
        return "URL credentials are not accepted"

    if config.VERIFY_ALLOW_PRIVATE_HOSTS:
        return ""

    host = parsed.hostname.rstrip(".").lower()

    if host == "localhost" or host.endswith(".localhost"):
        return f"localhost is not a public source ({host})"

    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return "invalid port"
    if port not in (80, 443):
        return f"port {port} is not a public web port (host={host})"

    literal = None
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        pass
    if literal is not None:
        return (f"blocked network address ({host})" if _ip_is_blocked(host)
                else "")

    addresses = _dns_addresses(host)
    if not addresses:
        return f"host does not resolve to any address ({host})"
    blocked = [a for a in addresses if _ip_is_blocked(a)]
    if blocked:
        return f"host resolves to a blocked address ({host} -> {blocked[0]})"
    return ""


_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def resolve(url, session=None, max_redirects=None):
    """Stage 1: go and look, with an SSRF guard on every hop.

    Returns a dict with url, final_url, status, content_type, bytes, ok, error,
    body, redirect_chain and elapsed_ms. Network problems are results, never
    exceptions: a dead URL is the most common thing we are asked to check.
    """
    session = session or requests.Session()
    max_redirects = config.VERIFY_MAX_REDIRECTS if max_redirects is None else max_redirects

    result = {
        "url": url,
        "final_url": url,
        "status": 0,
        "content_type": "",
        "bytes": 0,
        "ok": False,
        "error": "",
        "body": b"",
        "redirect_chain": [],
        "elapsed_ms": 0,
    }

    if not isinstance(url, str) or not url.strip():
        result["error"] = "empty or non-string URL"
        return result

    url = url.strip()
    result["url"] = url

    started = time.monotonic()
    resp = None
    chain = []
    current = url

    try:
        for hop in range(max_redirects + 1):
            refusal = _check_public_url(current)
            if refusal:
                # A hostname with no DNS answer is a network unknown, not an
                # unsafe destination. Keep the SSRF refusal prefix for every
                # actual policy block, but label DNS failure so the verdict
                # stage can return UNVERIFIABLE instead of FAIL.
                prefix = (
                    "DNS failure: "
                    if refusal.startswith("host does not resolve to any address")
                    else "blocked URL: "
                )
                result["error"] = f"{prefix}{refusal}"
                result["final_url"] = current
                result["redirect_chain"] = chain
                return result

            try:
                resp = session.get(
                    current,
                    timeout=config.VERIFY_TIMEOUT,
                    allow_redirects=False,  # we follow redirects ourselves
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept": "text/html,application/xhtml+xml,application/pdf,"
                                  "text/plain,application/xml,application/json;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-GB,en;q=0.9",
                    },
                    stream=True,
                )
            except requests.exceptions.TooManyRedirects as exc:
                result["error"] = f"redirect loop: {exc}"
                return result
            except requests.exceptions.Timeout:
                result["error"] = f"timed out after {config.VERIFY_TIMEOUT}s"
                return result
            except requests.exceptions.SSLError as exc:
                result["error"] = f"TLS error: {exc}"
                return result
            except requests.exceptions.ConnectionError as exc:
                result["error"] = f"connection failed: {exc}"
                return result
            except requests.exceptions.RequestException as exc:
                result["error"] = f"request failed: {exc}"
                return result

            chain.append(resp.url)

            if resp.status_code in _REDIRECT_STATUSES:
                location = resp.headers.get("Location", "")
                if not location:
                    result["error"] = (
                        f"HTTP {resp.status_code} redirect with no Location header"
                    )
                    return result
                if hop >= max_redirects:
                    result["error"] = (
                        f"redirect chain exceeds {max_redirects} hops; refusing to follow"
                    )
                    return result
                current = urljoin(resp.url, location)
                resp.close()
                resp = None
                continue

            break

        result["status"] = resp.status_code
        result["final_url"] = resp.url
        result["content_type"] = resp.headers.get("Content-Type", "")
        result["redirect_chain"] = chain

        if resp.status_code >= 400:
            # Read a little for the record, but never use an error page as
            # evidence. An error page is not the cited source.
            try:
                resp.raw.read(4096, decode_content=True)
            except Exception:
                pass
            result["error"] = f"HTTP {resp.status_code} {resp.reason or ''}".strip()
            return result

        if resp.status_code >= 300:
            result["error"] = f"HTTP {resp.status_code} with no usable redirect target"
            return result

        # Bounded read. We never trust Content-Length; we count as we go.
        body = bytearray()
        try:
            for chunk in resp.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                body.extend(chunk)
                if len(body) > config.VERIFY_MAX_BYTES:
                    result["error"] = (
                        f"response exceeds {config.VERIFY_MAX_BYTES} byte limit "
                        f"(truncated at {len(body)}); refusing to verify against a partial document"
                    )
                    result["bytes"] = len(body)
                    result["body"] = bytes(body)
                    return result
        except requests.exceptions.RequestException as exc:
            result["bytes"] = len(body)
            result["body"] = bytes(body)
            result["error"] = f"connection dropped mid-body after {len(body)} bytes: {exc}"
            return result

        result["bytes"] = len(body)
        result["body"] = bytes(body)

        if not body:
            result["error"] = "empty response body"
            return result

        doc_ok, doc_reason = _is_document(result["content_type"], result["body"], result["final_url"])
        if not doc_ok:
            result["error"] = doc_reason
            return result

        result["ok"] = True
        return result

    finally:
        if resp is not None:
            resp.close()
        result["elapsed_ms"] = int((time.monotonic() - started) * 1000)


# ---------------------------------------------------------------------------
# STAGE 2 — FETCH & NORMALISE
# ---------------------------------------------------------------------------

class _TextExtractor(HTMLParser):
    """
    Pull visible text out of HTML without pulling in a parser dependency.

    We deliberately skip <script>, <style>, <noscript>, <svg>, and <head> meta
    noise. What survives is what a reader would actually see, which is the
    only thing it is fair to hold a claim to.
    """

    SKIP = {"script", "style", "noscript", "svg", "head", "template", "iframe"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._chunks = []
        self._block_tags = {
            "p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6",
            "section", "article", "header", "footer", "blockquote", "table",
            "ul", "ol", "dd", "dt", "figure", "figcaption", "main", "aside",
            "nav", "form", "td", "th", "hr", "pre",
        }

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip_depth += 1
        elif tag in self._block_tags:
            self._chunks.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP:
            if self._skip_depth:
                self._skip_depth -= 1
        elif tag in self._block_tags:
            self._chunks.append("\n")

    def handle_data(self, data):
        if not self._skip_depth:
            self._chunks.append(data)

    def text(self):
        return "".join(self._chunks)


def _decode_bytes(body, content_type):
    """
    Turn raw bytes into a string. Charset from the header if present, else
    utf-8, else latin-1 — never raise, because a mojibake document is still
    better evidence than no document, as long as we say so.
    """
    charset = None
    if content_type and "charset=" in content_type.lower():
        tail = content_type.lower().split("charset=", 1)[1]
        charset = re.split(r"[;\s]", tail.strip())[0].strip("\"'")

    for enc in [charset, "utf-8", "cp1252", "latin-1"]:
        if not enc:
            continue
        try:
            return body.decode(enc), enc
        except (UnicodeDecodeError, LookupError):
            continue
    # latin-1 cannot fail, so this is unreachable in practice.
    return body.decode("latin-1", errors="replace"), "latin-1"


def _extract_pdf_text(body):
    """
    Extract text from a PDF with pypdf. Returns (text, error).

    If pypdf is not installed we return UNVERIFIABLE-worthy error text rather
    than silently producing empty text, because empty text would make every
    token FAIL and that is a lie about a document we simply could not read.
    """
    try:
        import pypdf  # noqa: F401
    except ImportError:
        return "", "pypdf is not installed; cannot extract PDF text"

    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(body))
        if getattr(reader, "is_encrypted", False):
            try:
                reader.decrypt("")
            except Exception:
                return "", "PDF is encrypted and cannot be opened"

        pages = []
        page_errors = 0
        for page in reader.pages:
            try:
                pages.append(page.extract_text() or "")
            except Exception as exc:
                page_errors += 1
                log.debug("PDF page extraction failed: %s", exc)
        text = "\n\n".join(pages)
        if not text.strip():
            return "", f"PDF yielded no extractable text ({page_errors} page errors); may be a scan"
        return text, ""
    except Exception as exc:
        return "", f"PDF parse failed: {exc}"


_WS_RE = re.compile(r"[ \t\u00a0\u2007\u202f]+")
_NL_RE = re.compile(r"\s*\n\s*")
_MULTI_NL_RE = re.compile(r"\n{3,}")


def normalise(text):
    """
    Normalise text for containment matching.

    What we do:
      - NFKC unicode normalise, so 'ＧＷ', ligatures, and non-breaking spaces
        collapse to their plain forms. A document that says "41 GW" in a full-
        width font is still saying 41 GW.
      - Collapse every run of horizontal whitespace (including nbsp / thin
        space) to a single space.
      - Collapse whitespace around newlines, then collapse 3+ newlines to 2.
      - Strip trailing whitespace on every line.

    What we do NOT do:
      - We do not lowercase (each token is lowercased at match time instead, so
        the stored snapshot keeps its original casing for quoting).
      - We do not remove punctuation, because removing it would let "10,5"
        match "10 5" and produce a false PASS.

    The returns must be byte-stable: same input, same output, forever, or the
    stored hash stops meaning anything.
    """
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("\u00a0", " ").replace("\u2007", " ").replace("\u202f", " ")
    text = _WS_RE.sub(" ", text)
    text = _NL_RE.sub("\n", text)
    text = _MULTI_NL_RE.sub("\n\n", text)
    lines = [ln.strip() for ln in text.split("\n")]
    text = "\n".join(lines)
    return text.strip()


def strip_boilerplate(text):
    """
    Remove obvious navigation/cookie chrome so it cannot contribute a spurious
    match. Conservative on purpose: we only drop whole lines that are pure
    furniture. We never drop a line that contains anything substantive.
    """
    if not text:
        return ""
    kept = []
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            kept.append("")
            continue
        if len(stripped) < 200 and any(p.match(stripped) for p in _BOILERPLATE_PATTERNS):
            continue
        kept.append(line)
    return _MULTI_NL_RE.sub("\n\n", "\n".join(kept)).strip()


def _snapshot_path(sha):
    return os.path.join(config.SNAPSHOT_DIR, f"{sha}.txt")


def _write_snapshot(sha, text):
    """
    Persist the exact normalised text. If a file of this name already exists it
    already IS this text (sha256 collision aside), so we leave it alone — that
    is the whole point of content addressing.
    """
    try:
        os.makedirs(config.SNAPSHOT_DIR, exist_ok=True)
        path = _snapshot_path(sha)
        if os.path.exists(path):
            return path
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
        return path
    except OSError as exc:
        log.warning("could not write snapshot %s: %s", sha, exc)
        return ""


def fetch(resolved):
    """
    Stage 2: given a successful resolve() result, produce normalised text and
    prove we hashed it.

    Returns dict:
        {
          "text":          normalised full text ("" on failure),
          "sha256":        hex digest of that text, or "",
          "snapshot_path": path on disk, or "",
          "encoding":      charset used,
          "content_kind":  "html" | "pdf" | "text" | "json" | "xml",
          "error":         "" if fine, else why we could not produce text,
        }
    """
    out = {
        "text": "",
        "sha256": "",
        "snapshot_path": "",
        "encoding": "",
        "content_kind": "",
        "error": "",
    }

    if not resolved.get("ok"):
        out["error"] = resolved.get("error") or "nothing fetched"
        return out

    body = resolved.get("body") or b""
    ct = _base_content_type(resolved.get("content_type", ""))

    if _looks_like_pdf(body):
        raw_text, err = _extract_pdf_text(body)
        out["content_kind"] = "pdf"
        out["encoding"] = "pdf"
        if err:
            out["error"] = err
            return out
    else:
        raw_text, enc = _decode_bytes(body, resolved.get("content_type", ""))
        out["encoding"] = enc
        if ct in ("application/xhtml+xml", "text/html") or raw_text.lstrip()[:15].lower().startswith("<!doctype html"):
            extractor = _TextExtractor()
            try:
                extractor.feed(raw_text)
                text = extractor.text()
            except Exception as exc:
                log.debug("HTML parse fell back to raw text: %s", exc)
                text = raw_text
            out["content_kind"] = "html"
        elif ct.endswith("json"):
            out["content_kind"] = "json"
            text = raw_text
        elif ct.endswith("xml"):
            out["content_kind"] = "xml"
            extractor = _TextExtractor()
            try:
                extractor.feed(raw_text)
                text = extractor.text()
            except Exception:
                text = raw_text
        else:
            out["content_kind"] = "text"
            text = raw_text

        raw_text = text

    normalised = strip_boilerplate(normalise(raw_text))
    if not normalised:
        out["error"] = "document contained no extractable text"
        return out

    sha = _sha256(normalised)
    out["text"] = normalised
    out["sha256"] = sha
    out["snapshot_path"] = _write_snapshot(sha, normalised)
    return out


# ---------------------------------------------------------------------------
# STAGE 3 — CONTAINMENT
# ---------------------------------------------------------------------------

# Multipliers written out in words, mapped to the digits a claim might use.
# "41 gigawatts" must match "41GW"; "six projects" must match "6 projects".
_NUMBER_WORDS = {
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
    "ten": "10", "eleven": "11", "twelve": "12", "thirteen": "13",
    "fourteen": "14", "fifteen": "15", "sixteen": "16", "seventeen": "17",
    "eighteen": "18", "nineteen": "19", "twenty": "20", "thirty": "30",
    "forty": "40", "fifty": "50", "sixty": "60", "seventy": "70",
    "eighty": "80", "ninety": "90", "hundred": "100", "thousand": "1000",
}

# Unit spellings that are equivalent for matching purposes. The left side is
# what a claim might write; the right side is the canonical compact form.
_UNIT_ALIASES = {
    "gigawatt": "gw", "gigawatts": "gw", "gw": "gw",
    "megawatt": "mw", "megawatts": "mw", "mw": "mw",
    "kilowatt": "kw", "kilowatts": "kw", "kw": "kw",
    "terawatt": "tw", "terawatts": "tw", "tw": "tw",
    "watt": "w", "watts": "w",
    "gigawatt hour": "gwh", "gigawatt hours": "gwh", "gwh": "gwh",
    "terawatt hour": "twh", "terawatt hours": "twh", "twh": "twh",
    "megatonne": "mt", "megatonnes": "mt", "megaton": "mt", "megatons": "mt",
    "tonne": "t", "tonnes": "t", "ton": "t", "tons": "t",
    "percentage point": "pp", "percentage points": "pp",
    "per cent": "%", "percent": "%",
    "billion pounds": "bn", "billion": "bn", "million": "m",
}

# A "number boundary": the character before and after a numeric token must not
# be a digit and must not be a decimal separator followed by a digit. This is
# what makes "10" not match inside "10.5", "100", or "10,000".
_NUM_CHARS = "0-9"
_DEC_SEP = ".,"


def _build_number_regex(num_str):
    """
    Build a regex that matches num_str as a standalone number, allowing the
    equivalences a real document uses:

        41     -> 41, 41.0 (not 410, not 10.41)
        10     -> 10 (NOT 10.5, NOT 10,000)
        41GW   -> handled by the unit layer, not here

    Boundaries:
        (?<!\\d)  no digit immediately before
        (?!\\d)   no digit immediately after
        also reject if followed by [.,] and a digit -> that is a different number

    We allow an optional trailing ".0" so "41.0GW" matches a claim of 41GW,
    but we never allow an arbitrary decimal tail.
    """
    esc = re.escape(num_str)
    return (
        r"(?<![\d.,])" + esc + r"(?:\.0+)?(?![\d])" + r"(?![.,]\d)"
    )


def _token_variants(token):
    """
    Generate the set of surface forms a token may legitimately take in a
    document. Returns a list of (regex, description) pairs.

    The rules:
      - Whitespace in the token is flexible: "41 GW" matches "41GW" and
        "41  GW" shown as "41 GW".
      - Case-insensitive throughout.
      - Number words expand: "six projects" -> also "6 projects".
      - Unit words expand:  "41GW" -> also "41 GW", "41 gigawatts".
      - Punctuation inside the token is literal, but a hyphen may render as a
        space or a non-breaking hyphen.
    """
    tok = token.strip()
    if not tok:
        return []

    variants = []

    # --- Build the core pattern -------------------------------------------
    # Split into runs of digits and non-digits so we can give numeric parts
    # boundary guards and treat the rest as flexible whitespace.
    parts = re.split(r"(\d+(?:[.,]\d+)?)", tok)

    pattern_pieces = []
    for part in parts:
        if not part:
            continue
        if re.fullmatch(r"\d+(?:[.,]\d+)?", part):
            num = part.replace(",", "")
            pattern_pieces.append(_build_number_regex(num))
        else:
            # Non-numeric run. Whitespace becomes "\s*" so "41 GW" == "41GW";
            # hyphens and dashes become a class that also eats a space, so
            # "cost-of-living" matches "cost of living"; everything else is
            # escaped literally (we keep punctuation meaningful).
            piece = ""
            for ch in part:
                if ch.isspace():
                    piece += r"\s*"
                elif ch in "-‐‑‒–—":
                    piece += r"[\s\-‐‑‒–—]*"
                elif ch in "'’‘`":
                    piece += r"['’‘`]"
                elif ch in '"“”':
                    piece += r'["“”]'
                else:
                    piece += re.escape(ch)
            pattern_pieces.append(piece)

    core = "".join(pattern_pieces)
    # Trim a leading/trailing \s* so we do not eat neighbouring words.
    core = re.sub(r"^\\s\*", "", core)
    core = re.sub(r"\\s\*$", "", core)
    # Guard the left edge of the whole token so "41GW" does not match inside
    # "141GW". Only apply when the token starts with a word character.
    if tok[0].isalnum():
        core = r"(?<![A-Za-z0-9])" + core
    if tok[-1].isalnum():
        core = core + r"(?![A-Za-z0-9])"

    variants.append((re.compile(core, re.I), "literal"))

    # --- Number-word expansion -------------------------------------------
    # "six projects" -> "6 projects". We only expand the FIRST number word,
    # because compound expansions ("twenty-six") need real NLP and would risk
    # false positives.
    word_match = re.match(r"^([A-Za-z]+)(\b.*)$", tok)
    if word_match and word_match.group(1).lower() in _NUMBER_WORDS:
        digitised = _NUMBER_WORDS[word_match.group(1).lower()] + word_match.group(2)
        for pat, _ in _token_variants(digitised)[:1]:
            variants.append((pat, "number-word"))

    # --- Unit expansion ---------------------------------------------------
    # "41GW" -> "41 gigawatts". We rewrite the trailing unit if we recognise it.
    unit_match = re.match(r"^(.*?)(\d+(?:\.\d+)?)\s*([A-Za-z%]+)$", tok)
    if unit_match:
        prefix, num, unit = unit_match.group(1), unit_match.group(2), unit_match.group(3)
        unit_key = unit.lower()
        canonical = _UNIT_ALIASES.get(unit_key)
        if canonical:
            # Build alternation of every spelling that maps to this canonical unit.
            spellings = sorted(
                {k for k, v in _UNIT_ALIASES.items() if v == canonical},
                key=len,
                reverse=True,
            )
            alt = "|".join(re.escape(s) for s in spellings)
            num_pat = _build_number_regex(num)
            extended = (
                r"(?<![A-Za-z0-9])" + re.escape(prefix).replace(r"\ ", r"\s*")
                + num_pat + r"\s*(?:" + alt + r")(?![A-Za-z0-9])"
            )
            try:
                variants.append((re.compile(extended, re.I), "unit-expanded"))
            except re.error:
                pass

    return variants


def _find_span(text, match):
    """Expand a regex match into a quotable span with surrounding context."""
    ctx = config.VERIFY_SPAN_CONTEXT
    start = max(0, match.start() - ctx)
    end = min(len(text), match.end() + ctx)
    quoted = text[start:end]
    # Do not start or end mid-word if we can help it.
    if start > 0:
        sp = quoted.find(" ")
        if 0 <= sp < 40:
            quoted = quoted[sp + 1:]
    if end < len(text):
        sp = quoted.rfind(" ")
        if len(quoted) - sp < 40:
            quoted = quoted[:sp]
    quoted = re.sub(r"\s+", " ", quoted).strip()

    hit = text[match.start():match.end()]
    hit = re.sub(r"\s+", " ", hit).strip()

    return {
        "start": match.start(),
        "end": match.end(),
        "matched_text": hit,
        "quote": quoted,
    }


_CLAIM_NUM_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([A-Za-z%]*)")
_DOC_NUM_RE = re.compile(r"(?<![\d.,])(\d+(?:\.\d+)?)\s*([A-Za-z%]*)")


def _near_miss(text, token, window=60):
    """
    On a failure, find the closest place the document came near the token, so a
    human can see WHY it failed — "you asked for 61GW, the page says 41GW".

    This is diagnostic only. It NEVER changes a verdict. A near miss is a
    failure with an explanation, not a soft pass.

    Strategy, in priority order:
      1. NUMERIC near-miss. If the claim contains a number, find the document
         number with the same unit that is arithmetically closest to it. This
         is what catches the 41GW/61GW class of error, which is the most
         dangerous kind of factual mistake.
      2. LEXICAL near-miss. Otherwise find the longest word from the claim that
         appears anywhere in the document.

    Returns a dict or None.
    """
    claim_nums = _CLAIM_NUM_RE.findall(token)
    if claim_nums:
        want_val, want_unit = claim_nums[0]
        try:
            want = float(want_val)
        except ValueError:
            want = None
        if want is not None:
            best = None
            for m in _DOC_NUM_RE.finditer(text):
                try:
                    got = float(m.group(1))
                except ValueError:
                    continue
                got_unit = m.group(2).lower()
                # Prefer a unit match; treat a bare number as compatible.
                unit_bonus = 0.0
                if want_unit and got_unit:
                    if got_unit.startswith(want_unit.lower()[:2]) or want_unit.lower().startswith(got_unit[:2]):
                        unit_bonus = -1.0  # makes it "closer" than any non-matching unit
                    else:
                        unit_bonus = 1e6  # effectively disqualify a different unit
                distance = abs(got - want) + unit_bonus
                if best is None or distance < best[0]:
                    best = (distance, m)

            if best and best[0] < 1e6:  # only if the unit actually matched
                m = best[1]
                start = max(0, m.start() - window)
                end = min(len(text), m.end() + window)
                quote = re.sub(r"\s+", " ", text[start:end]).strip()
                found = text[m.start():m.end()]
                return {
                    "kind": "numeric",
                    "closest_value": found,
                    "position": m.start(),
                    "quote": quote,
                    "note": f"claim says {want_val}{want_unit}, nearest matching-unit number in document is {found}",
                }

    words = [w for w in re.split(r"[^A-Za-z0-9%.]+", token) if len(w) >= 2]
    if not words:
        return None
    pattern = re.compile(
        r"(?<![A-Za-z0-9])(?:" + "|".join(re.escape(w) for w in sorted(words, key=len, reverse=True)) + r")(?![A-Za-z0-9])",
        re.I,
    )
    m = pattern.search(text)
    if not m:
        return None
    start = max(0, m.start() - window)
    end = min(len(text), m.end() + window)
    quote = re.sub(r"\s+", " ", text[start:end]).strip()
    return {
        "kind": "lexical",
        "closest_word": m.group(0),
        "position": m.start(),
        "quote": quote,
    }


def check_tokens(text, tokens):
    """
    Stage 3: for each token, is it in the text, and where?

    Returns a list of:
        {
          "token":      exactly as supplied,
          "matched":    bool,
          "span":       {start, end, matched_text, quote} or null,
          "matched_via":"literal" | "number-word" | "unit-expanded",
          "occurrences": int,     # how many times it appears
          "near_miss":  {...} or null (only when not matched),
        }
    """
    results = []
    for token in tokens:
        entry = {
            "token": token,
            "matched": False,
            "span": None,
            "matched_via": "",
            "occurrences": 0,
            "near_miss": None,
        }

        if not isinstance(token, str) or not token.strip():
            entry["error"] = "empty token"
            results.append(entry)
            continue

        variants = _token_variants(token)
        best = None
        for pattern, via in variants:
            matches = list(pattern.finditer(text))
            if matches and best is None:
                best = (matches, via)

        if best:
            matches, via = best
            entry["matched"] = True
            entry["span"] = _find_span(text, matches[0])
            entry["matched_via"] = via
            entry["occurrences"] = len(matches)
            if len(matches) > 1:
                entry["all_spans"] = [_find_span(text, m) for m in matches[:5]]
        else:
            entry["near_miss"] = _near_miss(text, token)

        results.append(entry)

    return results


# ---------------------------------------------------------------------------
# THE VERDICT
# ---------------------------------------------------------------------------

def _verdict_from(resolved, fetched, token_results):
    """
    The decision function. Kept deliberately small and dull so it can be
    audited in one reading.

    Order matters:
      1. Resolution must have succeeded. If not -> FAIL. Full stop, no
         containment attempt. (Exception: a pure network failure where we
         never reached the server is UNVERIFIABLE, because there is no evidence
         the source is wrong — only evidence we could not look. A 404 or a
         content-type rejection IS evidence the source is wrong.)
      2. Text must have been extracted. If not -> UNVERIFIABLE (we could not
         read the document; that is not the document's fault).
      3. Every token must have matched. Any miss -> FAIL.
      4. Otherwise PASS.

    There is no path to PASS that does not pass through step 3 with matched
    True on every token. No heuristics, no "close enough", no model.
    """
    # --- 1. Resolution ----------------------------------------------------
    if not resolved.get("ok"):
        status = resolved.get("status", 0)
        err = resolved.get("error", "") or "resolution failed"

        # Distinguish "the server told us no" from "we could not reach it".
        network_unknown = (
            status == 0
            and any(
                marker in err
                for marker in (
                    "timed out",
                    "connection failed",
                    "connection dropped",
                    "request failed",
                    "redirect loop",
                    "DNS failure",
                )
            )
        )
        body_unknown = (
            status == 200
            and any(
                marker in err
                for marker in (
                    "empty response body",
                    "byte limit",
                )
            )
        )
        if network_unknown or body_unknown:
            return UNVERIFIABLE, f"could not reach source: {err}"
        return FAIL, f"source did not resolve to a document: {err}"

    # --- 2. Text extraction ----------------------------------------------
    if fetched.get("sha256") and not fetched.get("snapshot_path"):
        return UNVERIFIABLE, (
            "snapshot could not be written; refusing PASS without on-disk evidence"
        )
    if fetched.get("error") or not fetched.get("sha256"):
        return UNVERIFIABLE, f"document fetched but could not be read: {fetched.get('error')}"

    # --- 3. Containment ---------------------------------------------------
    if not token_results:
        # A verification with no tokens proves nothing. Refuse rather than
        # hand back a vacuous PASS.
        return UNVERIFIABLE, "no must_contain tokens supplied; nothing to verify"

    missing = [t["token"] for t in token_results if not t.get("matched")]
    if missing:
        return FAIL, "token(s) not found in document: " + ", ".join(repr(m) for m in missing)

    return PASS, ""


def verify(url, must_contain=None, session=None):
    """
    Run the full three-stage check and return one JSON-ready dict.

    This is the only function callers should need.
    """
    if must_contain is None:
        must_contain = []
    if isinstance(must_contain, str):
        must_contain = [must_contain]

    started_at = _now_iso()

    resolved = resolve(url, session=session)
    fetched = fetch(resolved)

    if fetched.get("text"):
        token_results = check_tokens(fetched["text"], must_contain)
    else:
        # No text means we never get to look. Report tokens as unmatched but
        # say why, so nobody reads "matched: false" as "absent from source".
        token_results = [
            {
                "token": t,
                "matched": False,
                "span": None,
                "matched_via": "",
                "occurrences": 0,
                "near_miss": None,
                "error": "not checked: no extractable document text",
            }
            for t in must_contain
        ]

    verdict, reason = _verdict_from(resolved, fetched, token_results)

    errors = []


    def _add_error(msg):
        """
        Append an error message unless an equivalent one is already recorded.

        The verdict reason is usually a stage error with a human prefix
        ("source did not resolve to a document: HTTP 404 Not Found" contains
        "HTTP 404 Not Found"), so an exact-equality check lets the same fault
        be reported twice. Compare on containment instead, and add the
        specific stage errors first so the prefixed duplicate is dropped.
        """
        if not msg:
            return
        for existing in errors:
            # Drop the new message when it is either contained in, or
            # contains, an entry already recorded. The latter is the common
            # case: the prefixed verdict reason arrives after the bare stage
            # error it was built from.
            if msg == existing or msg in existing or existing in msg:
                return
        errors.append(msg)


    _add_error(resolved.get("error"))
    _add_error(fetched.get("error"))
    _add_error(reason)

    text = fetched.get("text", "")

    return {
        # --- what was asked ---
        "url": resolved.get("url", url),
        "must_contain": list(must_contain),

        # --- stage 1: resolution ---
        "final_url": resolved.get("final_url", ""),
        "status": resolved.get("status", 0),
        "content_type": resolved.get("content_type", ""),
        "bytes": resolved.get("bytes", 0),
        "redirect_chain": resolved.get("redirect_chain", []),
        "elapsed_ms": resolved.get("elapsed_ms", 0),

        # --- stage 2: fetch & normalise ---
        "sha256": fetched.get("sha256", ""),
        "snapshot_path": fetched.get("snapshot_path", ""),
        "content_kind": fetched.get("content_kind", ""),
        "encoding": fetched.get("encoding", ""),
        "text_chars": len(text),
        "text_preview": text[:TEXT_PREVIEW_CHARS],

        # --- stage 3: containment ---
        "tokens": token_results,

        # --- stage 4: verdict ---
        "verdict": verdict,
        "reason": reason,
        "fetched_at": _now_iso(),
        "started_at": started_at,
        "errors": errors,
        "engine": "verify.py/1.0",
    }


# ---------------------------------------------------------------------------
# BATCH
# ---------------------------------------------------------------------------

def verify_batch(claims, session=None):
    """
    Verify a list of claims. Each claim is {url, must_contain, id?}.

    Sequential on purpose: this is used against public statistical and
    parliamentary APIs, and hammering them in parallel is how you get blocked
    and then get told the source is unreachable when it is not.
    """
    session = session or requests.Session()
    results = []
    for i, claim in enumerate(claims):
        url = (claim or {}).get("url", "") if isinstance(claim, dict) else ""
        tokens = (claim or {}).get("must_contain", []) if isinstance(claim, dict) else []

        if not url:
            results.append({
                "url": "",
                "must_contain": tokens if isinstance(tokens, list) else [tokens],
                "final_url": "",
                "status": 0,
                "content_type": "",
                "bytes": 0,
                "sha256": "",
                "snapshot_path": "",
                "verdict": UNVERIFIABLE,
                "tokens": [],
                "fetched_at": _now_iso(),
                "errors": [f"claim {i} has no url"],
                "engine": "verify.py/1.0",
                "claim_index": i,
                "claim_id": (claim or {}).get("id", "") if isinstance(claim, dict) else "",
            })
            continue

        res = verify(url, tokens, session=session)
        res["claim_index"] = i
        res["claim_id"] = claim.get("id", "") if isinstance(claim, dict) else ""
        results.append(res)
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _summarise(result):
    """Human-readable one-block render of a verdict."""
    lines = []
    lines.append(f"VERDICT: {result['verdict']}")
    if result.get("reason"):
        lines.append(f"  reason:      {result['reason']}")
    lines.append(f"  url:         {result.get('url', '')}")
    if result.get("final_url") and result["final_url"] != result.get("url"):
        lines.append(f"  final_url:   {result['final_url']}")
    lines.append(f"  status:      {result.get('status')}  ({result.get('content_type', '') or 'no content-type'}, {result.get('bytes', 0)} bytes)")
    lines.append(f"  sha256:      {result.get('sha256') or '(none)'}")
    lines.append(f"  snapshot:    {result.get('snapshot_path') or '(none)'}")
    lines.append(f"  fetched_at:  {result.get('fetched_at')}")
    lines.append("  tokens:")
    for t in result.get("tokens", []):
        mark = "HIT " if t.get("matched") else "MISS"
        via = f" via {t['matched_via']}" if t.get("matched_via") and t["matched_via"] != "literal" else ""
        lines.append(f"    [{mark}] {t['token']!r}{via}")
        if t.get("span"):
            lines.append(f"           ...{t['span']['quote']}...")
        if t.get("near_miss"):
            lines.append(f"           nearest: {t['near_miss']['quote']!r}")
    if result.get("errors"):
        lines.append("  errors:")
        for e in result["errors"]:
            lines.append(f"    - {e}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Verify that a live document actually contains the text a claim attributes to it.",
        epilog="Exit codes: 0 if all PASS, 1 if any FAIL, 2 if any UNVERIFIABLE and no FAIL.",
    )
    parser.add_argument("--url", help="URL to verify")
    parser.add_argument(
        "--must-contain",
        action="append",
        default=[],
        metavar="TOKEN",
        help="Text that must appear in the document. Repeatable.",
    )
    parser.add_argument("--batch", help="Path to a JSON file of claims, or - for stdin")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of prose")
    parser.add_argument("--out", help="Write the JSON report to this path as well")
    parser.add_argument("-v", "--verbose", action="store_true", help="Log debug detail to stderr")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if not args.batch and not args.url:
        parser.error("one of --url or --batch is required")

    if args.batch:
        try:
            if args.batch == "-":
                payload = json.load(sys.stdin)
            else:
                with open(args.batch, "r", encoding="utf-8") as fh:
                    payload = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"could not read batch file: {exc}", file=sys.stderr)
            return 2

        if isinstance(payload, dict):
            claims = payload.get("claims", [])
        elif isinstance(payload, list):
            claims = payload
        else:
            print("batch file must be a JSON list or an object with a 'claims' list", file=sys.stderr)
            return 2

        results = verify_batch([c for c in claims if isinstance(c, dict)])

        report = {
            "generated_at": _now_iso(),
            "engine": "verify.py/1.0",
            "count": len(results),
            "summary": {
                PASS: sum(1 for r in results if r["verdict"] == PASS),
                FAIL: sum(1 for r in results if r["verdict"] == FAIL),
                UNVERIFIABLE: sum(1 for r in results if r["verdict"] == UNVERIFIABLE),
            },
            "results": results,
        }

        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)

        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            for r in results:
                print(_summarise(r))
                print()
            s = report["summary"]
            print(f"{s[PASS]} pass, {s[FAIL]} fail, {s[UNVERIFIABLE]} unverifiable, {len(results)} total")

        if report["summary"][FAIL]:
            return 1
        if report["summary"][UNVERIFIABLE]:
            return 2
        return 0

    result = verify(args.url, args.must_contain)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(_summarise(result))

    if result["verdict"] == PASS:
        return 0
    if result["verdict"] == FAIL:
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
