import io
import random
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
