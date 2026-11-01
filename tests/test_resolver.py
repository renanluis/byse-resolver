"""Resolver tests using local protocol fixtures."""

import base64
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from byse_resolver.resolver import ByseResolver, ResolvedStream, decrypt_playback, solve_pow
from byse_resolver import _byse_pow


EMBED = "https://bysebuho.com/e/34nkolnsbdse"
FRAME = "https://n1mwq.org/rotating/34nkolnsbdse"
STREAM = "https://media.example/master.m3u8?token=short-lived"


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def envelope(sources):
    key = bytes(range(32))
    iv = bytes(range(12))
    payload = AESGCM(key).encrypt(iv, json.dumps({"sources": sources}).encode(), None)
    parts = [""] * 30
    parts[0], parts[29] = b64(key[:16]), b64(key[16:])
    return {"algorithm": "AES-256-GCM", "version": "1", "key_parts": parts,
            "iv": b64(iv), "payload": b64(payload)}


class Response:
    status_code = 200

    def __init__(self, data):
        self.data = data
        self.text = data if isinstance(data, str) else ""

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def raise_for_status(self):
        pass

    def json(self):
        return self.data


class Session:
    def __init__(self, *, captcha=True, html="<title>Byse Frontend</title>"):
        self.headers = {}
        self.calls = []
        self.captcha = captcha
        self.html = html

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def request(self, method, url, *, headers, json, timeout, allow_redirects):
        self.calls.append((method, url, headers, json, timeout, allow_redirects))
        if urlsplit(url).path.startswith("/e/"):
            data = self.html
        elif url.endswith("/embed/details"):
            data = {"embed_frame_url": FRAME}
        elif url.endswith("/embed/settings"):
            data = {"captcha_required": self.captcha}
        elif url.endswith("/access/challenge"):
            data = {"challenge_id": "challenge", "nonce": "nonce"}
        elif url.endswith("/access/attest"):
            data = {"token": "identity", "viewer_id": "viewer", "device_id": "device", "confidence": 0.35}
        elif url.endswith("/embed/captcha"):
            data = {"algorithm": "sha256-leading-zero-bits", "pow_nonce": "nonce", "pow_difficulty": 16,
                    "pow_token": "pow"}
        elif url.endswith("/embed/captcha/verify"):
            data = {"status": "ok", "token": "captcha"}
        elif url.endswith("/embed/playback"):
            data = {"playback": envelope([{"url": STREAM, "label": "1080p", "height": 1080,
                                           "mime_type": "application/vnd.apple.mpegurl"}])}
        else:
            raise AssertionError(url)
        return Response(data)


class ByseTests(unittest.TestCase):
    def test_native_hash_matches_fixed_vectors_with_uint32_overflow(self):
        vectors = json.loads((Path(__file__).parent / "fixtures" / "byse-pow.json").read_text())
        for vector in vectors:
            with self.subTest(value=vector["value"]):
                self.assertEqual(_byse_pow.digest(vector["value"].encode()), tuple(vector["words"]))

    def test_native_search_returns_first_valid_candidate_and_captured_solution(self):
        for start in [0, 100, 1000]:
            candidates = [str(n) for n in range(start, start + 64)
                          if _byse_pow.digest(f"nonce:{n}".encode())[0] < (1 << 28)]
            self.assertEqual(_byse_pow.search(b"nonce:", 4, start, 64), next(iter(candidates), None))
        self.assertEqual(_byse_pow.search(b"4cc3a467b5b51a2cefb42e345a96e184:", 16, 0, 9950), "9949")
        self.assertIsNone(_byse_pow.search(b"nonce:", 16, 0, 0))

    def test_native_solver_honors_deadline_between_batches(self):
        native = Mock(return_value=None)
        with patch("byse_resolver.resolver._native_pow_batch", native), \
                patch("byse_resolver.resolver.monotonic", side_effect=[0, 0, 2]):
            with self.assertRaises(TimeoutError):
                solve_pow("nonce", 16, timeout=1)
        native.assert_called_once_with(b"nonce:", 16, 0, 2048)

    def test_missing_extension_fails_import_with_setup_instructions(self):
        result = subprocess.run([sys.executable, "-c",
                                 "import sys; sys.modules['byse_resolver._byse_pow'] = None; "
                                 "import byse_resolver.resolver"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required Cython extension unavailable", result.stderr)
        self.assertIn("python -m pip install .", result.stderr)

    def test_captured_pow_vector(self):
        words = _byse_pow.digest(b"4cc3a467b5b51a2cefb42e345a96e184:9949")
        self.assertEqual(words[0], 0x9CB9)
        self.assertLess(words[0], 1 << 16)
        self.assertGreaterEqual(words[0], 1 << 15)

    def test_decrypts_versioned_aes_gcm(self):
        self.assertEqual(decrypt_playback(envelope([{"url": STREAM}]))["sources"], [{"url": STREAM}])
        bad = envelope([])
        bad["payload"] = b64(bytes(48))
        with self.assertRaisesRegex(ValueError, "configuration"):
            decrypt_playback(bad)

    def test_resolves_full_flow_without_media_headers(self):
        session = Session()
        solve = Mock(return_value="9949")
        result = ByseResolver(session_factory=lambda: session, solve=solve).resolve(EMBED)
        self.assertEqual(result, ResolvedStream(STREAM, "1080p"))
        solve.assert_called_once_with("nonce", 16)
        urls = [call[1] for call in session.calls]
        self.assertIn("https://n1mwq.org/api/videos/34nkolnsbdse/embed/playback", urls)
        self.assertNotIn(FRAME, urls)
        playback = session.calls[-1]
        self.assertEqual(playback[2]["X-Captcha-Token"], "captcha")
        self.assertEqual(playback[2]["X-Embed-Parent"], EMBED)
        self.assertEqual(playback[3]["fingerprint"]["token"], "identity")
        self.assertTrue(all(call[4] == 15 and call[5] is False for call in session.calls))

    def test_skips_captcha_when_disabled(self):
        session = Session(captcha=False)
        result = ByseResolver(session_factory=lambda: session, solve=Mock()).resolve(EMBED)
        self.assertEqual(result.url, STREAM)
        self.assertFalse(any("/captcha" in call[1] for call in session.calls))

    def test_preserves_actual_embedding_page_through_the_handshake(self):
        session = Session()
        page = "https://www.source.example/watch/episode"
        result = ByseResolver(session_factory=lambda: session, solve=Mock(return_value="9949")).resolve(
            EMBED, referer=page)
        self.assertEqual(result.url, STREAM)
        self.assertEqual(session.calls[0][2], {"Referer": page})
        for _, url, headers, *_ in session.calls:
            if "/embed/" in url:
                self.assertEqual(headers["X-Embed-Origin"], "source.example")
                self.assertEqual(headers["X-Embed-Referer"], page)
                self.assertEqual(headers["X-Embed-Parent"], EMBED)
                self.assertEqual(headers["Referer"], EMBED if url.endswith("/details") else FRAME)

    def test_explains_rejected_embedding_domain(self):
        response = Response({"error": "embedding from this domain is not allowed for this video"})
        response.status_code = 403
        session = Mock()
        session.request.return_value = response
        with self.assertRaisesRegex(ValueError, "embedding domain rejected.*referer="):
            ByseResolver._request(session, "GET", "https://alias.example/api/videos/code/embed/details")

    def test_recognizes_aliases_by_title_and_resolves_from_their_origin(self):
        for host in ["bysebuho.com", "filemoon.sx", "pomfy-cdn.shop", "new-alias.example"]:
            with self.subTest(host=host):
                url = f"https://{host}/e/34nkolnsbdse"
                session = Session(html="<!doctype html><TITLE>\n Byse&#32;Frontend </TITLE>")
                resolver = ByseResolver(session_factory=lambda: session, solve=Mock(return_value="9949"))
                self.assertTrue(resolver.supports(url))
                session.calls.clear()
                self.assertEqual(resolver.resolve(url), ResolvedStream(STREAM, "1080p"))
                self.assertEqual([call[1] for call in session.calls[:2]],
                                 [url, f"https://{host}/api/videos/34nkolnsbdse/embed/details"])

    def test_rejects_other_titles_before_api_requests(self):
        for html in ["", "<title>Another player</title>", "<title>Byse Frontend clone</title>",
                     "<!-- <title>Byse Frontend</title> -->", "<body>Byse Frontend</body>"]:
            with self.subTest(html=html):
                session = Session(html=html)
                resolver = ByseResolver(session_factory=lambda: session)
                self.assertFalse(resolver.supports(EMBED))
                session.calls.clear()
                with self.assertRaisesRegex(ValueError, "title"):
                    resolver.resolve(EMBED)
                self.assertEqual(len(session.calls), 1)

    def test_resolves_optional_title_slug_using_only_the_video_code(self):
        page = "https://embedplay.vip/filme/tt22084616"
        for suffix in ["", "/", "/spider-man-brand-new-day-2026-1080p-embedplay",
                       "/spider-man-brand-new-day-2026-1080p-embedplay/"]:
            with self.subTest(suffix=suffix):
                url = f"https://embedplaybyse.top/e/34nkolnsbdse{suffix}"
                session = Session(captcha=False)
                resolver = ByseResolver(session_factory=lambda: session)
                self.assertTrue(resolver.supports(url, referer=page))
                session.calls.clear()
                self.assertEqual(resolver.resolve(url, referer=page), ResolvedStream(STREAM, "1080p"))
                self.assertEqual(session.calls[0][1], url)
                self.assertEqual(session.calls[1][1],
                                 "https://embedplaybyse.top/api/videos/34nkolnsbdse/embed/details")
                self.assertEqual(session.calls[1][2]["X-Embed-Parent"], url)
                self.assertEqual(session.calls[1][2]["X-Embed-Referer"], page)

    def test_title_slug_does_not_bypass_player_identification(self):
        session = Session(html="<title>Another player</title>")
        resolver = ByseResolver(session_factory=lambda: session)
        url = "https://embedplaybyse.top/e/34nkolnsbdse/title"
        self.assertFalse(resolver.supports(url))
        session.calls.clear()
        with self.assertRaisesRegex(ValueError, "title"):
            resolver.resolve(url)
        self.assertEqual(len(session.calls), 1)

    def test_rejects_unsupported_embed(self):
        resolver = ByseResolver(session_factory=Mock())
        for url in ["http://bysebuho.com/e/34nkolnsbdse", "https://filemoon.sx/not-an-embed",
                    "https://localhost/e/34nkolnsbdse", "https://user:pass@bysebuho.com/e/34nkolnsbdse",
                    "https://bysebuho.com/e/34nkolnsbdse/title/extra",
                    "https://bysebuho.com/e/34nkolnsbdse//title",
                    "https://bysebuho.com/e/34nkolnsbdse/..",
                    "https://bysebuho.com/e/34nkolnsbdse/%2Ftitle"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                resolver.resolve(url)
        resolver.session_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
