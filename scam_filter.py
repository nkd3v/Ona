"""Recognize scam posts: known scam images, blocked links, and cross-channel spam."""

from __future__ import annotations

import io
import logging
import re
from collections import deque
from collections.abc import Hashable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from PIL import Image, ImageOps

log = logging.getLogger(__name__)

HASH_SIZE = 16  # 16x16 difference hash = 256-bit fingerprint
MAX_IMAGE_BYTES = 10 * 1024 * 1024
IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp")

# Fingerprints of the "MrBeast crypto casino" (wispwin.com) images posted by
# compromised accounts. Add new examples by dropping images into SCAM_IMAGES_DIR.
KNOWN_SCAM_IMAGES = {
    0x678A6790346D276C6791378FB319F391B39EB3B9F799718CF197F51B711A351A: "wispwin bonus page",
    0x60099F591B11C0B3CD45C21B4C3BCE7DCE61CC6DC49AC48BC449C8718CC998E5: "wispwin withdrawal",
    0x7E48B9B1C1CB634B315B73D9432172E4369E72AD43E358C3D9F8019B199703D5: "fake MrBeast X post",
    0x9C18299E2986DC8D609F6D9B3AD6099509B471B8198D8990ADA4056481860127: "fake USDT payout",
}
DEFAULT_BLOCKED_DOMAINS = ("wispwin.com",)

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
