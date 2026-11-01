"""Resolve Byse embeds without executing the JavaScript player."""

import base64
import binascii
import ipaddress
import json
import re
from html.parser import HTMLParser
from time import monotonic
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import requests

from dataclasses import dataclass

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/155.0.0.0 Safari/537.36"
)


@dataclass(frozen=True)
class ResolvedStream:
    """A temporary HLS URL and optional quality label."""

    url: str
    quality: str | None = None

try:
    from ._byse_pow import search as _native_pow_batch
except ImportError as error:
    raise ImportError("Byse: required Cython extension unavailable. Run python -m pip install . "
                      "with a C compiler installed.") from error

_CODE = re.compile(r"/e/([A-Za-z0-9_-]{6,64})(?:/[A-Za-z0-9_-]+)?/?$")


class _TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.finished = False
        self.text = []

    def handle_starttag(self, tag, attrs):
        if tag == "title" and not self.finished:
            self.in_title = True

    def handle_endtag(self, tag):
        if tag == "title" and self.in_title:
            self.in_title = False
            self.finished = True

    def handle_data(self, data):
        if self.in_title:
            self.text.append(data)


def solve_pow(nonce, difficulty, *, timeout=120):
    """Solve proof of work in Cython, checking the deadline between batches."""
    if not isinstance(nonce, str) or not nonce or type(difficulty) is not int or not 0 <= difficulty <= 20:
        raise ValueError("Byse: invalid challenge")
    if difficulty == 0:
        return "0"
    deadline = monotonic() + timeout
    prefix = (nonce + ":").encode("utf-8")
    start = 0
    while monotonic() < deadline:
        result = _native_pow_batch(prefix, difficulty, start, 2048)
        if result is not None:
            return result
        start += 2048
    raise TimeoutError("Byse: proof-of-work deadline exceeded")


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value):
    if not isinstance(value, str):
        raise ValueError("Byse: invalid Base64URL")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def decrypt_playback(envelope):
    """Decrypt the playback configuration containing sources and tracks."""
    try:
        parts = envelope["key_parts"]
        version = int(envelope["version"])
        if not isinstance(parts, list) or not parts:
            raise ValueError("missing key parts")
        if 1 <= version <= 20 and max(version, 31 - version) <= len(parts):
            parts = [parts[version - 1], parts[30 - version]]
        key = b"".join(_unb64(part) for part in parts if part)
        clear = AESGCM(key).decrypt(_unb64(envelope["iv"]), _unb64(envelope["payload"]), None)
        data = json.loads(clear)
        if not isinstance(data, dict) or not isinstance(data.get("sources"), list):
            raise ValueError("missing sources")
        return data
    except (KeyError, TypeError, ValueError, InvalidTag, UnicodeError, binascii.Error) as error:
        raise ValueError("Byse: invalid playback configuration") from error


def _external_https(url):
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if parsed.scheme != "https" or not host or parsed.username or parsed.password:
            return False
        if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
            return False
        try:
            return ipaddress.ip_address(host).is_global
        except ValueError:
            return "." in host
    except (TypeError, ValueError):
        return False


def _attestation(challenge):
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_numbers()
    signature = key.sign(challenge["nonce"].encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(signature)
    return {
        "viewer_id": "", "device_id": "",
        "challenge_id": challenge["challenge_id"], "nonce": challenge["nonce"],
        "signature": _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big")),
        "public_key": {"kty": "EC", "crv": "P-256", "ext": True, "key_ops": ["verify"],
                       "x": _b64(public.x.to_bytes(32, "big")),
                       "y": _b64(public.y.to_bytes(32, "big"))},
        "client": {"user_agent": DEFAULT_USER_AGENT, "platform": "Windows",
                   "languages": ["pt-BR"], "timezone": "America/Sao_Paulo"},
        "storage": {}, "attributes": {"entropy": "low"},
    }


class ByseResolver:
    """Resolve a Byse embed to a temporary HLS stream."""

    def __init__(self, *, session_factory=requests.Session, solve=solve_pow):
        self.session_factory = session_factory
        self.solve = solve

    @staticmethod
    def is_embed_url(url):
        """Check URL format; resolve/supports additionally check HTML identity."""
        if not _external_https(url):
            return False
        return bool(_CODE.fullmatch(urlsplit(url).path))

    @staticmethod
    def _matches_title(session, url, *, referer=None):
        with session.request("GET", url, headers={"Referer": referer or url}, json=None,
                             timeout=15, allow_redirects=False) as response:
            if 300 <= response.status_code < 400:
                raise ValueError("Byse: unexpected redirect")
            response.raise_for_status()
            parser = _TitleParser()
            parser.feed(response.text)
            parser.close()
        return parser.finished and " ".join("".join(parser.text).split()) == "Byse Frontend"

    def supports(self, url, *, referer=None):
        """Identify the player by its HTML title across domain aliases."""
        if not self.is_embed_url(url):
            return False
        with self.session_factory() as session:
            session.headers["User-Agent"] = DEFAULT_USER_AGENT
            return self._matches_title(session, url, referer=referer)

    @staticmethod
    def _request(session, method, url, *, headers=None, body=None):
        with session.request(method, url, headers=headers, json=body, timeout=15,
                             allow_redirects=False) as response:
            if 300 <= response.status_code < 400:
                raise ValueError("Byse: unexpected redirect")
            if response.status_code == 403:
                try:
                    error = response.json()
                except ValueError:
                    error = {}
                if isinstance(error, dict) and "embedding from this domain is not allowed" in str(error.get("error", "")):
                    raise ValueError("Byse: embedding domain rejected; supply referer= with the URL "
                                     "of the page containing the player")
            response.raise_for_status()
            data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Byse: invalid JSON response")
        return data

    def resolve(self, url, *, referer=None):
        if not self.is_embed_url(url):
            raise ValueError("Byse: unsupported embed URL")
        parts = urlsplit(url)
        code = _CODE.fullmatch(parts.path)[1]
        site = f"{parts.scheme}://{parts.netloc}"
        parent = {"Referer": url, "X-Embed-Parent": url}
        if referer:
            page = urlsplit(referer)
            if page.scheme not in ("http", "https") or not page.hostname or page.username or page.password:
                raise ValueError("Byse: invalid page Referer")
            parent["X-Embed-Origin"] = page.hostname.removeprefix("www.")
            parent["X-Embed-Referer"] = referer
        with self.session_factory() as session:
            session.headers["User-Agent"] = DEFAULT_USER_AGENT
            if not self._matches_title(session, url, referer=referer):
                raise ValueError("Byse: unrecognized player title")
            details = self._request(session, "GET", f"{site}/api/videos/{code}/embed/details", headers=parent)
            frame = details.get("embed_frame_url")
            if not _external_https(frame):
                raise ValueError("Byse: invalid iframe")
            frame_parts = urlsplit(frame)
            origin = f"{frame_parts.scheme}://{frame_parts.netloc}"
            base = f"{origin}/api/videos/{code}/embed/"
            frame_headers = {**parent, "Referer": frame}
            settings = self._request(session, "GET", base + "settings", headers=frame_headers)
            challenge = self._request(session, "POST", f"{origin}/api/videos/access/challenge",
                                      headers={"Referer": frame, "Origin": origin})
            identity = self._request(session, "POST", f"{origin}/api/videos/access/attest",
                                     headers={"Referer": frame, "Origin": origin},
                                     body=_attestation(challenge))
            fingerprint = {key: identity[key] for key in ("token", "viewer_id", "device_id", "confidence")}
            captcha_token = None
            post_headers = {**frame_headers, "Origin": origin}
            if settings.get("captcha_required"):
                check = self._request(session, "POST", base + "captcha", headers=post_headers,
                                      body={"fingerprint": fingerprint})
                if check.get("algorithm") != "sha256-leading-zero-bits":
                    raise ValueError("Byse: unsupported proof-of-work algorithm")
                solution = self.solve(check["pow_nonce"], check["pow_difficulty"])
                verified = self._request(session, "POST", base + "captcha/verify", headers=post_headers,
                                         body={"pow_token": check["pow_token"], "solution": solution,
                                               "fingerprint": fingerprint})
                if verified.get("status") != "ok" or not verified.get("token"):
                    raise ValueError("Byse: proof of work rejected")
                captcha_token = verified["token"]
            if captcha_token:
                post_headers["X-Captcha-Token"] = captcha_token
            playback = self._request(session, "POST", base + "playback", headers=post_headers,
                                     body={"fingerprint": fingerprint})
            media = decrypt_playback(playback["playback"])
        candidates = []
        for source in media["sources"]:
            if not isinstance(source, dict) or not _external_https(source.get("url")):
                continue
            mime = source.get("mime_type")
            if mime not in ("application/vnd.apple.mpegurl", "application/x-mpegurl"):
                continue
            label = source.get("label")
            height = source.get("height")
            quality = label if isinstance(label, str) and label else f"{height}p" if type(height) is int else None
            candidates.append((height if type(height) is int else 0, ResolvedStream(source["url"], quality)))
        return max(candidates, key=lambda item: item[0])[1] if candidates else None
