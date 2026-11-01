"""Recognize scam posts: known scam images, scam words in images, blocked links, and
cross-channel spam."""

from __future__ import annotations

import asyncio
import io
import logging
import re
import time
from collections import OrderedDict, deque
from collections.abc import Hashable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import aiohttp
from PIL import Image, ImageOps

log = logging.getLogger(__name__)

HASH_SIZE = 16  # 16x16 difference hash = 256-bit fingerprint
MAX_IMAGE_BYTES = 10 * 1024 * 1024
IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp")

# Fingerprints of the "MrBeast crypto casino" (wispwin.com, fapwin.com) images posted
# by compromised accounts. Add new examples by dropping images into SCAM_IMAGES_DIR.
KNOWN_SCAM_IMAGES = {
    0x678A6790346D276C6791378FB319F391B39EB3B9F799718CF197F51B711A351A: "wispwin bonus page",
    0x60099F591B11C0B3CD45C21B4C3BCE7DCE61CC6DC49AC48BC449C8718CC998E5: "wispwin withdrawal",
    0x7E48B9B1C1CB634B315B73D9432172E4369E72AD43E358C3D9F8019B199703D5: "fake MrBeast X post",
    0x9C18299E2986DC8D609F6D9B3AD6099509B471B8198D8990ADA4056481860127: "fake USDT payout",
    0x3D924F6C8B769C06BDC8BD92A6F892D2BED28F16CF76CF80C3A6CDAEDE533797: "fake MrBeast X profile",
    0x23E027DCCD07B287B22FCC75CD3FCD3FC52CCDB3CF73CD8CCF72CF37D965C13B: "fapwin bonus page",
    0x27806DB3BC0CA4DC88F28A3B8E688C8E0C9F8C3B980B82718257800F944D4850: "fapwin withdrawal",
    0x0FFD01FE0C111DC534C93C5906594FEA0BE905D91DD41AE74BC724D92E455866: "fake USDC payout",
}
DEFAULT_BLOCKED_DOMAINS = ("wispwin.com", "fapwin.com")
# Images whose text contains any of these words are scams. Spaces, punctuation and case
# are ignored, and a word also matches inside a longer one ("crypto" in "cryptocurrency").
DEFAULT_SCAM_WORDS = ("mrbeast", "crypto", "casino")

OCR_URL = "https://api.ocr.space/parse/image"
OCR_MAX_BYTES = 1024 * 1024  # OCR.space free plan limit
OCR_MAX_SIDE = 1600
OCR_TIMEOUT_SECONDS = 30
OCR_RETRY_SECONDS = 3  # wait before the one retry of a failed request
OCR_PAUSE_SECONDS = 300  # after a retry fails, so a used-up quota does not flood the logs

URL_PATTERN = re.compile(r"https?://\S+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}/\S*", re.IGNORECASE)


def image_hash(data: bytes) -> int | None:
    """Return a 256-bit difference hash, or None if the data is not a readable image.

    The hash survives re-compression, resizing, and small colour changes, but not
    large crops or mirroring.
    """
    try:
        with Image.open(io.BytesIO(data)) as img:
            img.draft("L", (HASH_SIZE * 8, HASH_SIZE * 8))  # faster JPEG decoding
            small = (
                ImageOps.exif_transpose(img)
                .convert("L")
                .resize((HASH_SIZE + 1, HASH_SIZE), Image.Resampling.LANCZOS)
            )
    except (OSError, ValueError, Image.DecompressionBombError):
        return None
    pixels = small.tobytes()
    bits = 0
    for row in range(HASH_SIZE):
        start = row * (HASH_SIZE + 1)
        for col in range(HASH_SIZE):
            bits = (bits << 1) | (pixels[start + col] > pixels[start + col + 1])
    return bits


def load_image_dir(directory: Path) -> dict[int, str]:
    """Fingerprint every image in a directory. A missing directory is allowed."""
    if not directory.is_dir():
        return {}
    hashes = {}
    for path in sorted(directory.iterdir()):
        if path.suffix.lower() not in IMAGE_SUFFIXES:
            continue
        value = image_hash(path.read_bytes())
        if value is None:
            log.warning("Skipping unreadable scam example image: %s", path)
        else:
            hashes[value] = path.name
    return hashes


def closest_match(value: int, known: dict[int, str], max_distance: int) -> tuple[str, int] | None:
    best = min(
        ((name, (value ^ ref).bit_count()) for ref, name in known.items()),
        key=lambda x: x[1],
        default=None,
    )
    if best is None or best[1] > max_distance:
        return None
    return best


def domain_pattern(domains: Iterable[str]) -> re.Pattern[str] | None:
    """Match each domain and its subdomains as a whole word, e.g. www.wispwin.com."""
    parts = [re.escape(d.strip().lower().removeprefix("www.")) for d in domains if d.strip()]
    if not parts:
        return None
    return re.compile(
        rf"(?<![a-z0-9-])(?:[a-z0-9-]+\.)*(?:{'|'.join(parts)})(?![a-z0-9-])", re.IGNORECASE
    )


def has_link(text: str) -> bool:
    return URL_PATTERN.search(text) is not None


def _squash(text: str) -> str:
    return re.sub(r"[\W_]+", "", text.lower())


def find_word(text: str, words: Iterable[str]) -> str | None:
    """The first word found in the text, ignoring case, spaces and punctuation."""
    squashed = _squash(text)
    return next((word for word in words if _squash(word) and _squash(word) in squashed), None)


def ocr_jpeg(data: bytes) -> bytes | None:
    """Shrink an image to a JPEG small enough for the OCR service, or None if unreadable.

    Animated images use their first frame.
    """
    try:
        with Image.open(io.BytesIO(data)) as img:
            img.draft("RGB", (OCR_MAX_SIDE, OCR_MAX_SIDE))
            rgb = ImageOps.exif_transpose(img).convert("RGB")
        rgb.thumbnail((OCR_MAX_SIDE, OCR_MAX_SIDE))
        for quality in (85, 70, 50, 30):
            buffer = io.BytesIO()
            rgb.save(buffer, "JPEG", quality=quality)
            if buffer.tell() <= OCR_MAX_BYTES:
                return buffer.getvalue()
    except (OSError, ValueError, Image.DecompressionBombError):
        pass
    return None


class OcrSpaceReader:
    """Read text in images with the OCR.space API (free key at https://ocr.space/ocrapi).

    Results are remembered by image fingerprint, so a reposted image uses no quota.
    A failed request is retried once. If that fails too, such as when the daily quota
    is used up, reading pauses for a while.
    """

    def __init__(self, api_key: str, url: str = OCR_URL, cache_size: int = 500) -> None:
        self.api_key = api_key
        self.url = url
        self.cache_size = cache_size
        self.cache: OrderedDict[int, str] = OrderedDict()
        self.paused_until = 0.0
        self.session: aiohttp.ClientSession | None = None

    async def read(self, data: bytes, fingerprint: int) -> str | None:
        """The image's text, or None if it could not be read."""
        if fingerprint in self.cache:
            self.cache.move_to_end(fingerprint)
            return self.cache[fingerprint]
        if time.monotonic() < self.paused_until:
            return None
        jpeg = await asyncio.to_thread(ocr_jpeg, data)
        if jpeg is None:
            return None
        text = await self._request(jpeg)
        if text is None:
            await asyncio.sleep(OCR_RETRY_SECONDS)
            text = await self._request(jpeg)
        if text is None:
            log.warning(
                "Could not read text in an image; pausing for %s minutes", OCR_PAUSE_SECONDS // 60
            )
            self.paused_until = time.monotonic() + OCR_PAUSE_SECONDS
            return None
        self.cache[fingerprint] = text
        if len(self.cache) > self.cache_size:
            self.cache.popitem(last=False)
        return text

    async def _request(self, jpeg: bytes) -> str | None:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=OCR_TIMEOUT_SECONDS)
            )
        form = aiohttp.FormData()
        form.add_field("OCREngine", "2")
        form.add_field("file", jpeg, filename="image.jpg", content_type="image/jpeg")
        body: object = None
        try:
            async with self.session.post(
                self.url, data=form, headers={"apikey": self.api_key}
            ) as response:
                if response.status == 200:
                    body = await response.json(content_type=None)
                    problem = _ocr_problem(body)
                else:
                    problem = f"HTTP {response.status}"
        except (aiohttp.ClientError, TimeoutError, ValueError) as exc:
            problem = type(exc).__name__
        if problem or not isinstance(body, dict):
            log.warning("OCR.space request failed: %s", problem)
            return None
        return "\n".join(str(page.get("ParsedText", "")) for page in body["ParsedResults"])

    async def close(self) -> None:
        if self.session is not None:
            await self.session.close()


def _ocr_problem(body: object) -> str | None:
    """Why an OCR.space reply has no text, or None if it is fine."""
    if not isinstance(body, dict):
        return str(body)[:200]  # quota errors come back as a bare string
    if body.get("IsErroredOnProcessing") or not isinstance(body.get("ParsedResults"), list):
        message = body.get("ErrorMessage") or "unknown error"
        return " ".join(message) if isinstance(message, list) else str(message)
    return None


@dataclass
class _Post:
    at: datetime
    channel_id: int
    signature: Hashable
    message: Any


class RepeatTracker:
    """Spot one author posting the same thing in several channels within a short window."""

    def __init__(self, channels: int, window: timedelta = timedelta(minutes=2)) -> None:
        self.channels = channels
        self.window = window
        self.posts: dict[int, deque[_Post]] = {}

    def add(
        self, author_id: int, channel_id: int, signature: Hashable, message: Any, now: datetime
    ) -> list[Any]:
        """Record a post. Return every copy of it once it reaches the channel limit."""
        if self.channels <= 0:
            return []
        if len(self.posts) > 10_000:
            self._prune_all(now)
        history = self.posts.setdefault(author_id, deque(maxlen=50))
        while history and now - history[0].at > self.window:
            history.popleft()
        history.append(_Post(now, channel_id, signature, message))
        same = [post for post in history if post.signature == signature]
        if len({post.channel_id for post in same}) < self.channels:
            return []
        for post in same:
            history.remove(post)
        return [post.message for post in same]

    def _prune_all(self, now: datetime) -> None:
        for author_id in list(self.posts):
            if not self.posts[author_id] or now - self.posts[author_id][-1].at > self.window:
                del self.posts[author_id]
