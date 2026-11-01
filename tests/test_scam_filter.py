import base64
import io
import random
import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from aiohttp import web
from PIL import Image, ImageDraw

import scam_filter as sf


def sample_image(seed: int, size=(480, 640)) -> Image.Image:
    rng = random.Random(seed)
    img = Image.new("RGB", size, (rng.randrange(256), rng.randrange(256), rng.randrange(256)))
    draw = ImageDraw.Draw(img)
    for _ in range(40):
        x, y = rng.randrange(size[0]), rng.randrange(size[1])
        box = (x, y, x + rng.randrange(20, 200), y + rng.randrange(20, 200))
        draw.rectangle(box, fill=(rng.randrange(256), rng.randrange(256), rng.randrange(256)))
    return img


def encode(img: Image.Image, fmt="PNG", **options) -> bytes:
    buffer = io.BytesIO()
    img.save(buffer, fmt, **options)
    return buffer.getvalue()


class ImageHashTests(unittest.TestCase):
    def test_reencoded_and_resized_copies_match_but_other_images_do_not(self):
        original = sample_image(1)
        known = {sf.image_hash(encode(original)): "scam"}
        copies = (
            encode(original, "JPEG", quality=40),
            encode(original.resize((240, 320))),
            encode(original, "WEBP", quality=50),
        )
        for data in copies:
            with self.subTest(size=len(data)):
                self.assertEqual(sf.closest_match(sf.image_hash(data), known, 40)[0], "scam")
        for seed in range(2, 30):
            other = sf.image_hash(encode(sample_image(seed)))
            self.assertIsNone(sf.closest_match(other, known, 40))

    def test_unreadable_data_is_ignored(self):
        self.assertIsNone(sf.image_hash(b"not an image"))
        self.assertIsNone(sf.closest_match(123, {}, 40))

    def test_load_image_dir_skips_other_files_and_missing_dir(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "scam.png").write_bytes(encode(sample_image(1)))
            (path / "broken.jpg").write_bytes(b"broken")
            (path / "notes.txt").write_text("not an image")
            with self.assertLogs("scam_filter", level="WARNING"):
                hashes = sf.load_image_dir(path)
            self.assertEqual(list(hashes.values()), ["scam.png"])
            self.assertEqual(sf.load_image_dir(path / "missing"), {})


class TextTests(unittest.TestCase):
    def test_domain_pattern_matches_domain_and_subdomains_only(self):
        pattern = sf.domain_pattern(["wispwin.com", " ", "www.Example.org"])
        for text in ("go to https://wispwin.com/x", "WWW.WISPWIN.COM", "a.example.org!"):
            self.assertIsNotNone(pattern.search(text), text)
        for text in ("notwispwin.com", "wispwin.company", "wispwin com"):
            self.assertIsNone(pattern.search(text), text)
        self.assertIsNone(sf.domain_pattern(["", " "]))

    def test_has_link(self):
        self.assertTrue(sf.has_link("see https://x.io"))
        self.assertTrue(sf.has_link("see bit.ly/abc"))
        self.assertFalse(sf.has_link("hello there. how are you"))


class ScamWordTests(unittest.TestCase):
    def test_finds_words_ignoring_case_spaces_and_punctuation(self):
        words = sf.DEFAULT_SCAM_WORDS
        self.assertEqual(sf.find_word("MrBeast (@MrBeast) / X", words), "mrbeast")
        self.assertEqual(sf.find_word("Mr. Beast giveaway", words), "mrbeast")
        self.assertEqual(sf.find_word("my own CRYPTOCURRENCY", words), "crypto")
        self.assertEqual(sf.find_word("online\nCasino", words), "casino")
        self.assertIsNone(sf.find_word("Withdrawal successful, USDC", words))
        self.assertIsNone(sf.find_word("anything", ["", " "]))

    def test_ocr_jpeg_shrinks_large_images_and_rejects_junk(self):
        noisy = Image.effect_noise((4000, 3000), 100).convert("RGB")
        jpeg = sf.ocr_jpeg(encode(noisy))
        self.assertLessEqual(len(jpeg), sf.OCR_MAX_BYTES)
        with Image.open(io.BytesIO(jpeg)) as img:
            self.assertEqual(max(img.size), sf.OCR_MAX_SIDE)
        self.assertIsNone(sf.ocr_jpeg(b"not an image"))


class GoogleVisionReaderTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.replies = []
        self.requests = []

        async def handler(request):
            body = await request.json()
            image = body["requests"][0]
            self.requests.append(
                (request.headers.get("X-Goog-Api-Key"), image["features"][0]["type"])
            )
            self.assertTrue(base64.b64decode(image["image"]["content"]).startswith(b"\xff\xd8"))
            status, reply = self.replies.pop(0)
            return web.json_response(reply, status=status)

        app = web.Application()
        app.router.add_post("/v1/images:annotate", handler)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        port = self.runner.addresses[0][1]
        self.url = f"http://127.0.0.1:{port}/v1/images:annotate"
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.usage_path = Path(self.temp.name) / "vision_usage.json"
        self.reader = self.make_reader()
        retry_wait = patch.object(sf, "OCR_RETRY_SECONDS", 0)
        retry_wait.start()
        self.addCleanup(retry_wait.stop)
        self.image = encode(sample_image(1))

    def make_reader(self, limit=1000):
        return sf.GoogleVisionReader("key", self.usage_path, limit, url=self.url)

    async def asyncTearDown(self):
        await self.reader.close()
        await self.runner.cleanup()

    @staticmethod
    def ok(text):
        return 200, {"responses": [{"fullTextAnnotation": {"text": text}}]}

    async def test_reads_text_and_remembers_it_by_fingerprint(self):
        self.replies.append(self.ok("MrBeast\ncasino"))
        self.assertEqual(await self.reader.read(self.image, 1), "MrBeast\ncasino")
        self.assertEqual(await self.reader.read(self.image, 1), "MrBeast\ncasino")
        self.assertEqual(self.requests, [("key", "TEXT_DETECTION")])

    async def test_image_without_text_reads_as_empty(self):
        self.replies.append((200, {"responses": [{}]}))
        self.assertEqual(await self.reader.read(self.image, 1), "")

    async def test_one_failure_is_retried(self):
        self.replies += [(503, {"error": {"message": "unavailable"}}), self.ok("casino")]
        with self.assertLogs("scam_filter", level="WARNING") as logs:
            self.assertEqual(await self.reader.read(self.image, 1), "casino")
        self.assertEqual(
            logs.output, ["WARNING:scam_filter:Google Vision request failed: HTTP 503: unavailable"]
        )

    async def test_two_failures_pause_reading(self):
        denied = (403, {"error": {"message": "API key not valid"}})
        self.replies += [denied, denied]
        with self.assertLogs("scam_filter", level="WARNING") as logs:
            self.assertIsNone(await self.reader.read(self.image, 1))
        self.assertIn("API key not valid", logs.output[0])
        self.assertIn("pausing for 5 minutes", logs.output[-1])
        self.assertIsNone(await self.reader.read(self.image, 2))  # paused: no request
        self.assertEqual(len(self.requests), 2)

        for reply in (
            (200, {"responses": [{"error": {"code": 3, "message": "Bad image data."}}]}),
            (200, "not json at all"),
            (500, {}),
        ):
            self.reader.paused_until = time.monotonic() - 1
            self.replies += [reply, reply]
            with self.subTest(reply=reply), self.assertLogs("scam_filter", level="WARNING"):
                self.assertIsNone(await self.reader.read(self.image, 3))
        self.reader.paused_until = time.monotonic() - 1
        self.replies.append(self.ok("fine"))
        self.assertEqual(await self.reader.read(self.image, 3), "fine")

    async def test_monthly_limit_stops_reading_and_survives_restart(self):
        await self.reader.close()
        self.reader = self.make_reader(limit=2)
        self.replies += [self.ok("a"), self.ok("b")]
        self.assertEqual(await self.reader.read(self.image, 1), "a")
        self.assertEqual(await self.reader.read(self.image, 2), "b")
        with self.assertLogs("scam_filter", level="WARNING") as logs:
            self.assertIsNone(await self.reader.read(self.image, 3))
            self.assertIsNone(await self.reader.read(self.image, 4))
        self.assertEqual(len(logs.output), 1)  # warned once, not per image
        self.assertIn("GOOGLE_VISION_MONTHLY_LIMIT", logs.output[0])
        self.assertEqual(await self.reader.read(self.image, 1), "a")  # cached still works
        self.assertEqual(len(self.requests), 2)

        await self.reader.close()
        self.reader = self.make_reader(limit=2)  # restart keeps the count
        with self.assertLogs("scam_filter", level="WARNING"):
            self.assertIsNone(await self.reader.read(self.image, 5))
        self.assertEqual(len(self.requests), 2)

    def test_usage_resets_each_pacific_month(self):
        usage = sf.MonthlyUsage(self.usage_path, 1)
        # 07:00 UTC on 1 December is still 30 November in Pacific time.
        usage.add(datetime(2026, 12, 1, 7, tzinfo=UTC))
        self.assertEqual(usage.month, "2026-11")
        self.assertTrue(usage.used_up(datetime(2026, 12, 1, 7, 30, tzinfo=UTC)))
        self.assertFalse(usage.used_up(datetime(2026, 12, 1, 9, tzinfo=UTC)))
        self.assertFalse(sf.MonthlyUsage(None, 0).used_up())  # 0: no limit

    def test_unreadable_usage_file_starts_from_zero(self):
        self.usage_path.write_text("{broken", "utf-8")
        with self.assertLogs("scam_filter", level="WARNING"):
            usage = sf.MonthlyUsage(self.usage_path, 5)
        self.assertEqual(usage.count, 0)

    async def test_unreadable_image_is_not_sent(self):
        self.assertIsNone(await self.reader.read(b"broken", 1))
        self.assertEqual(self.requests, [])


class RepeatTrackerTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def test_returns_all_copies_once_posted_in_enough_channels(self):
        tracker = sf.RepeatTracker(3)
        self.assertEqual(tracker.add(1, 10, "spam", "a", self.now), [])
        self.assertEqual(tracker.add(1, 10, "spam", "b", self.now), [])  # same channel
        self.assertEqual(tracker.add(1, 11, "other", "c", self.now), [])
        self.assertEqual(tracker.add(2, 12, "spam", "d", self.now), [])  # other author
        self.assertEqual(tracker.add(1, 12, "spam", "e", self.now), [])  # only 2 channels
        self.assertEqual(tracker.add(1, 13, "spam", "f", self.now), ["a", "b", "e", "f"])
        self.assertEqual(tracker.add(1, 14, "spam", "g", self.now), [])  # copies were cleared

    def test_old_posts_expire_and_zero_disables(self):
        tracker = sf.RepeatTracker(2, timedelta(minutes=2))
        tracker.add(1, 10, "spam", "a", self.now)
        self.assertEqual(tracker.add(1, 11, "spam", "b", self.now + timedelta(minutes=3)), [])
        disabled = sf.RepeatTracker(0)
        for channel in range(5):
            self.assertEqual(disabled.add(1, channel, "spam", "x", self.now), [])


if __name__ == "__main__":
    unittest.main()
