"""Log deleted and edited messages, remove scam posts and run a spam-bot trap channel."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import re
from collections.abc import Mapping
from contextlib import closing
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiohttp
import discord
from discord import app_commands
from dotenv import load_dotenv

import scam_filter

log = logging.getLogger(__name__)

# Relative paths are resolved from the bot's folder, so it starts the same way
# whatever directory a hosting panel launches it from.
BASE_DIR = Path(__file__).resolve().parent

SCAM_ACTIONS = ("none", "timeout", "kick", "ban")
MODERATION_PERMISSIONS = {
    "none": (),
    "timeout": ("moderate_members",),
    "kick": ("kick_members",),
    "ban": ("ban_members",),
}
MAX_TIMEOUT_MINUTES = 28 * 24 * 60  # Discord's limit
# Longer timeouts are set in blocks a little under Discord's limit, and renewed before
# each block ends. The hourly check renews any block that ends within RENEW_BEFORE.
TIMEOUT_BLOCK = timedelta(minutes=MAX_TIMEOUT_MINUTES) - timedelta(hours=1)
RENEW_BEFORE = timedelta(days=2)
RENEW_CHECK_SECONDS = 3600
MAX_DURATION_MINUTES = 10 * 365 * 1440  # anything longer should be "permanent"
DURATION_UNITS = {
    **dict.fromkeys(("m", "min", "mins", "minute", "minutes"), 1),
    **dict.fromkeys(("h", "hr", "hrs", "hour", "hours"), 60),
    **dict.fromkeys(("d", "day", "days"), 1440),
    **dict.fromkeys(("w", "wk", "wks", "week", "weeks"), 10080),
    **dict.fromkeys(("mo", "month", "months"), 30 * 1440),
    **dict.fromkeys(("y", "yr", "yrs", "year", "years"), 365 * 1440),
}
DURATION_PART = re.compile(r"(\d+)\s*([a-z]+)")
PERMANENT_WORDS = frozenset(("permanent", "permanently", "perm", "forever", "indefinite"))
DURATION_SUGGESTIONS = (
    "1 hour",
    "1 day",
    "1 week",
    "28 days",
    "3 months",
    "1 year",
    "permanent",
)
LOG_CHANNEL_PERMISSIONS = ("view_channel", "send_messages", "embed_links", "attach_files")
# The trap channel needs these to post its notice and delete what members post there.
TRAP_CHANNEL_PERMISSIONS = (
    "view_channel",
    "send_messages",
    "embed_links",
    "read_message_history",
    "manage_messages",
)
# Server-wide: deleting a caught member's messages in other channels, and timing them out.
TRAP_SERVER_PERMISSIONS = ("manage_messages", "moderate_members")
TRAP_DELETE_CHOICES = {"10 minutes": 10, "1 hour": 60, "6 hours": 360, "1 day": 1440}
# Remember who was just punished, so a burst of messages gets one timeout and one count.
ACTION_MEMORY = timedelta(minutes=5)


def resolve(path: str | Path) -> Path:
    path = Path(path).expanduser()
    return path if path.is_absolute() else BASE_DIR / path


def missing_permissions(permissions: discord.Permissions, names: tuple[str, ...]) -> list[str]:
    return [name for name in names if not getattr(permissions, name)]


@dataclass(frozen=True)
class Settings:
    token: str
    cache_size: int = 10_000
    scam_action: str = "timeout"
    timeout_minutes: int = 24 * 60
    image_match_distance: int = 40
    blocked_domains: tuple[str, ...] = scam_filter.DEFAULT_BLOCKED_DOMAINS
    scam_images_dir: Path = field(default_factory=lambda: BASE_DIR / "scam-images")
    repeat_channels: int = 3
    data_dir: Path = field(default_factory=lambda: BASE_DIR / "data")

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Settings:
        token = env.get("DISCORD_TOKEN", "").strip()
        if not token or token == "replace_with_your_bot_token":
            raise ValueError(
                "Set DISCORD_TOKEN to your Discord bot token, either in a .env file or in "
                "your host's environment variables."
            )
        try:
            cache_size = int(env.get("MESSAGE_CACHE_SIZE", "10000"))
        except ValueError as exc:
            raise ValueError("MESSAGE_CACHE_SIZE must be an integer.") from exc
        if cache_size <= 0:
            raise ValueError("MESSAGE_CACHE_SIZE must be positive.")

        action = env.get("SCAM_ACTION", "timeout").strip().lower()
        if action not in SCAM_ACTIONS:
            raise ValueError(f"SCAM_ACTION must be one of: {', '.join(SCAM_ACTIONS)}.")
        try:
            timeout_minutes = int(env.get("SCAM_TIMEOUT_MINUTES", "1440"))
            distance = int(env.get("SCAM_IMAGE_MATCH_DISTANCE", "40"))
            repeat_channels = int(env.get("SPAM_REPEAT_CHANNELS", "3"))
        except ValueError as exc:
            raise ValueError(
                "SCAM_TIMEOUT_MINUTES, SCAM_IMAGE_MATCH_DISTANCE and SPAM_REPEAT_CHANNELS "
                "must be integers."
            ) from exc
        if not 1 <= timeout_minutes <= MAX_TIMEOUT_MINUTES:
            raise ValueError(f"SCAM_TIMEOUT_MINUTES must be 1-{MAX_TIMEOUT_MINUTES}.")
        if not 0 <= distance <= 100:
            raise ValueError("SCAM_IMAGE_MATCH_DISTANCE must be 0-100.")
        if repeat_channels == 1 or repeat_channels < 0:
            raise ValueError("SPAM_REPEAT_CHANNELS must be 0 (off) or at least 2.")
        domains = env.get("BLOCKED_DOMAINS")
        blocked = (
            scam_filter.DEFAULT_BLOCKED_DOMAINS
            if domains is None
            else tuple(d.strip() for d in domains.split(",") if d.strip())
        )
        return cls(
            token,
            cache_size,
            scam_action=action,
            timeout_minutes=timeout_minutes,
            image_match_distance=distance,
            blocked_domains=blocked,
            scam_images_dir=resolve(env.get("SCAM_IMAGES_DIR") or "scam-images"),
            repeat_channels=repeat_channels,
            data_dir=resolve(env.get("DATA_DIR") or "data"),
        )


class LogChannelStore:
    """Each server's log channel, chosen with /logchannel set and saved to a JSON file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.channels: dict[int, int] = {}
        try:
            raw = json.loads(path.read_text("utf-8"))
            self.channels = {int(k): int(v) for k, v in raw.items()}
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            raise ValueError(f"Cannot read saved log channels from {path}: {exc}") from exc

    def set(self, guild_id: int, channel_id: int | None) -> None:
        """Save a server's channel, or forget it when channel_id is None."""
        channels = dict(self.channels)
        if channel_id is None:
            channels.pop(guild_id, None)
        else:
            channels[guild_id] = channel_id
        save_json(self.path, {str(k): v for k, v in channels.items()})
        self.channels = channels


def save_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(data, indent=2), "utf-8")
    os.replace(temp, path)  # atomic, so a crash never leaves a half-written file


@dataclass(frozen=True)
class Trap:
    """A server's trap channel: anyone who posts there is treated as a spam bot."""

    channel_id: int
    timeout_minutes: int | None = 1440  # None: permanent
    delete_minutes: int = 60
    notice_id: int | None = None  # the bot's warning post, which shows the counter
    count: int = 0  # members timed out by the trap so far

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> Trap:
        notice = raw.get("notice_id")
        timeout = raw.get("timeout_minutes", 1440)
        return cls(
            channel_id=int(raw["channel_id"]),
            timeout_minutes=None if timeout is None else int(timeout),
            delete_minutes=int(raw.get("delete_minutes", 60)),
            notice_id=None if notice is None else int(notice),
            count=int(raw.get("count", 0)),
        )


class TrapStore:
    """Each server's trap channel, chosen with /trapchannel set and saved to a JSON file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.traps: dict[int, Trap] = {}
        try:
            raw = json.loads(path.read_text("utf-8"))
            self.traps = {int(k): Trap.from_dict(v) for k, v in raw.items()}
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError, AttributeError, KeyError) as exc:
            raise ValueError(f"Cannot read saved trap channels from {path}: {exc}") from exc

    def set(self, guild_id: int, trap: Trap | None) -> None:
        """Save a server's trap, or forget it when trap is None."""
        traps = dict(self.traps)
        if trap is None:
            traps.pop(guild_id, None)
        else:
            traps[guild_id] = trap
        save_json(self.path, {str(k): asdict(v) for k, v in traps.items()})
        self.traps = traps


@dataclass(frozen=True)
class LongTimeout:
    """A timeout longer than Discord allows in one go, which the bot keeps renewing."""

    until: datetime | None  # None: permanent
    applied_until: datetime  # when the timeout the bot last set on Discord ends
    reason: str = ""
    left: bool = False  # the member left; renewed if they post again after rejoining

    def to_dict(self) -> dict[str, object]:
        return {
            "until": self.until.isoformat() if self.until else None,
            "applied_until": self.applied_until.isoformat(),
            "reason": self.reason,
            "left": self.left,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> LongTimeout:
        until = raw.get("until")
        return cls(
            until=None if until is None else datetime.fromisoformat(str(until)),
            applied_until=datetime.fromisoformat(str(raw["applied_until"])),
            reason=str(raw.get("reason", "")),
            left=bool(raw.get("left", False)),
        )


class LongTimeoutStore:
    """Timeouts the bot renews, keyed by (server ID, member ID) and saved to a JSON file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.entries: dict[tuple[int, int], LongTimeout] = {}
        try:
            raw = json.loads(path.read_text("utf-8"))
            for key, value in raw.items():
                guild_id, member_id = key.split(":")
                self.entries[int(guild_id), int(member_id)] = LongTimeout.from_dict(value)
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError, AttributeError, KeyError) as exc:
            raise ValueError(f"Cannot read saved timeouts from {path}: {exc}") from exc

    def set(self, key: tuple[int, int], entry: LongTimeout | None) -> None:
        """Save a member's long timeout, or forget it when entry is None."""
        entries = dict(self.entries)
        if entry is None:
            if key not in entries:
                return
            del entries[key]
        else:
            entries[key] = entry
        save_json(self.path, {f"{g}:{m}": v.to_dict() for (g, m), v in entries.items()})
        self.entries = entries


def shorten(text: str, limit: int) -> str:
    """Stay within Discord's UTF-16 length limits, including emoji."""
    encoded = text.encode("utf-16-le")
    if len(encoded) <= limit * 2:
        return text
    return encoded[: (limit - 1) * 2].decode("utf-16-le", errors="ignore") + "…"


UNKNOWN_ACTOR = "unknown (a delete event does not identify who deleted it)"


def transcript(
    guild_id: int,
    channel_id: int | str,
    message_ids: set[int],
    cached: Mapping[int, discord.Message],
    actor: str = UNKNOWN_ACTOR,
) -> str:
    lines = [
        "Deleted-message log",
        f"Recorded at: {datetime.now(UTC).isoformat()}",
        f"Server ID: {guild_id}",
        f"Channel ID: {channel_id}",
        f"Deletion actor: {actor}",
        "Attachment links are metadata only; deleted files may no longer be available.",
    ]
    for message_id in sorted(message_ids):
        lines.extend(["", "=" * 60, f"Message ID: {message_id}"])
        message = cached.get(message_id)
        if message is None:
            lines.append("Content and author unavailable: message was not in the bot's cache.")
            continue
        lines.extend(
            [
                f"Author: {message.author} (ID: {message.author.id})",
                f"Sent at: {message.created_at.isoformat()}",
                "Content:",
                message.content or "[No text content]",
            ]
        )
        if message.attachments:
            lines.append("Attachments:")
            lines.extend(f"- {item.filename}: {item.url}" for item in message.attachments)
    return "\n".join(lines) + "\n"


def edit_transcript(before: discord.Message | None, after: discord.Message) -> str:
    def version(label: str, message: discord.Message) -> list[str]:
        lines = [f"{label}:", message.content or "[No text content]"]
        if message.attachments:
            lines.append(f"{label} attachments:")
            lines.extend(f"- {item.filename}: {item.url}" for item in message.attachments)
        return lines

    lines = [
        "Edited-message log",
        f"Recorded at: {datetime.now(UTC).isoformat()}",
        f"Server ID: {after.guild.id}",
        f"Channel ID: {after.channel.id}",
        f"Message ID: {after.id}",
        f"Link: {after.jump_url}",
        f"Author: {after.author} (ID: {after.author.id})",
        f"Sent at: {after.created_at.isoformat()}",
        f"Edited at: {after.edited_at.isoformat() if after.edited_at else 'unknown'}",
        "",
    ]
    if before is None:
        lines.append("Before: unavailable, the message was not in the bot's cache.")
    else:
        lines.extend(version("Before", before))
    lines.append("")
    lines.extend(version("After", after))
    return "\n".join(lines) + "\n"


# A real edit stamps the message with the edit time. Other updates, such as a link
# preview loading or a pin, repeat the old stamp, so an old stamp means no new edit.
RECENT_EDIT = timedelta(minutes=5)


class ModeratorBot(discord.Client):
    def __init__(self, settings: Settings) -> None:
        intents = discord.Intents.none()
        intents.guilds = True
        intents.guild_messages = True
        intents.message_content = True
        super().__init__(
            intents=intents,
            max_messages=settings.cache_size,
            allowed_mentions=discord.AllowedMentions.none(),
        )
        self.settings = settings
        self.store = LogChannelStore(settings.data_dir / "log_channels.json")
        self.traps = TrapStore(settings.data_dir / "trap_channels.json")
        self.long_timeouts = LongTimeoutStore(settings.data_dir / "long_timeouts.json")
        self.renew_task: asyncio.Task[None] | None = None
        self.known_images = dict(scam_filter.KNOWN_SCAM_IMAGES)
        self.known_images.update(scam_filter.load_image_dir(settings.scam_images_dir))
        self.blocked_domains = scam_filter.domain_pattern(settings.blocked_domains)
        self.repeats = scam_filter.RepeatTracker(settings.repeat_channels)
        # Messages this bot deleted; they get a scam log instead of a deletion log.
        self.removed_ids: set[int] = set()
        # (server ID, member ID) -> when the scam action was applied.
        self.actioned: dict[tuple[int, int], datetime] = {}
        # (server ID, member ID) -> when the trap channel timed them out.
        self.trapped: dict[tuple[int, int], datetime] = {}
        # (server ID, member ID) -> when a lapsed long timeout was set again.
        self.reapplied: dict[tuple[int, int], datetime] = {}
        self.tree = app_commands.CommandTree(self)
        self.tree.add_command(LogChannelCommands(self))
        self.tree.add_command(TrapChannelCommands(self))
        self.tree.add_command(timeout_command)
        self.tree.add_command(untimeout_command)

    async def setup_hook(self) -> None:
        try:
            await self.tree.sync()
        except discord.HTTPException:
            # Logging keeps working with commands registered by an earlier start.
            log.exception("Could not register slash commands with Discord")
        self.renew_task = asyncio.create_task(self.renew_loop())

    async def close(self) -> None:
        if self.renew_task is not None:
            self.renew_task.cancel()
        await super().close()

    def log_channel_for(self, guild_id: int | None) -> discord.TextChannel | None:
        """The server's log channel, if one was set and the bot can still see it."""
        if guild_id is None or (channel_id := self.store.channels.get(guild_id)) is None:
            return None
        channel = self.get_channel(channel_id)
        if isinstance(channel, discord.TextChannel) and channel.guild.id == guild_id:
            return channel
        return None

    def server_permission_problems(self, guild: discord.Guild) -> list[str]:
        """Server-wide permissions the scam filter needs but the bot lacks."""
        if guild.me is None:
            return []
        needed = ("manage_messages", *MODERATION_PERMISSIONS[self.settings.scam_action])
        return missing_permissions(guild.me.guild_permissions, needed)

    def trap_channel_for(self, guild_id: int) -> discord.TextChannel | None:
        """The server's trap channel, if one was set and the bot can still see it."""
        trap = self.traps.traps.get(guild_id)
        channel = self.get_channel(trap.channel_id) if trap else None
        if isinstance(channel, discord.TextChannel) and channel.guild.id == guild_id:
            return channel
        return None

    async def on_ready(self) -> None:
        # Problems here are logged, not fatal: admins fix them with /logchannel set.
        log.info("Logged in as %s in %s server(s)", self.user, len(self.guilds))
        active = 0
        for guild in self.guilds:
            channel_id = self.store.channels.get(guild.id)
            if channel_id is None:
                continue
            channel = self.log_channel_for(guild.id)
            if channel is None:
                log.warning(
                    "Server %s (%s): log channel %s is gone; run /logchannel set again.",
                    guild,
                    guild.id,
                    channel_id,
                )
                continue
            active += 1
            log.info("Server %s (%s): logging to #%s (%s)", guild, guild.id, channel, channel.id)
            if guild.me is not None:
                missing = missing_permissions(
                    channel.permissions_for(guild.me), LOG_CHANNEL_PERMISSIONS
                )
                if missing:
                    log.warning("Server %s: log channel lacks %s", guild.id, ", ".join(missing))
            if missing := self.server_permission_problems(guild):
                log.warning(
                    "Server %s: scam removal needs these permissions: %s",
                    guild.id,
                    ", ".join(missing),
                )
        if not active:
            log.info("No log channel set yet. In your server, run /logchannel set.")
        for guild in self.guilds:
            if (trap := self.traps.traps.get(guild.id)) is None:
                continue
            channel = self.trap_channel_for(guild.id)
            if channel is None:
                log.warning(
                    "Server %s (%s): trap channel %s is gone; run /trapchannel set again.",
                    guild,
                    guild.id,
                    trap.channel_id,
                )
                continue
            log.info(
                "Server %s (%s): trap channel is #%s (%s)", guild, guild.id, channel, channel.id
            )
            if guild.me is not None:
                missing = missing_permissions(
                    channel.permissions_for(guild.me), TRAP_CHANNEL_PERMISSIONS
                ) + missing_permissions(guild.me.guild_permissions, TRAP_SERVER_PERMISSIONS)
                if missing:
                    log.warning(
                        "Server %s: trap channel needs these permissions: %s",
                        guild.id,
                        ", ".join(dict.fromkeys(missing)),
                    )
        log.info(
            "Scam filter: %s known images, %s blocked domains, action=%s",
            len(self.known_images),
            len(self.settings.blocked_domains),
            self.settings.scam_action,
        )

    async def on_raw_message_delete(self, payload: discord.RawMessageDeleteEvent) -> None:
        if payload.message_id in self.removed_ids:
            self.removed_ids.discard(payload.message_id)
            return
        cached = {payload.message_id: payload.cached_message} if payload.cached_message else {}
        await self.log_deletion(payload.guild_id, payload.channel_id, {payload.message_id}, cached)

    async def on_raw_bulk_message_delete(self, payload: discord.RawBulkMessageDeleteEvent) -> None:
        # Leave out messages this bot removed itself; they have their own log.
        message_ids = payload.message_ids - self.removed_ids
        self.removed_ids -= payload.message_ids
        cached = {message.id: message for message in payload.cached_messages}
        await self.log_deletion(payload.guild_id, payload.channel_id, message_ids, cached)

    async def log_deletion(
        self,
        guild_id: int | None,
        channel_id: int,
        message_ids: set[int],
        cached: Mapping[int, discord.Message],
    ) -> None:
        # Each server's messages go to its own log. Exclude the log channel to avoid recursion.
        if not message_ids:
            return
        channel = self.log_channel_for(guild_id)
        if channel is None or channel_id == channel.id:
            return

        embed = discord.Embed(
            title="Message deleted"
            if len(message_ids) == 1
            else f"{len(message_ids)} messages deleted",
            colour=discord.Colour.orange(),
            timestamp=datetime.now(UTC),
        )
        embed.add_field(name="Channel", value=f"<#{channel_id}> (`{channel_id}`)", inline=False)
        if len(message_ids) == 1:
            message_id = next(iter(message_ids))
            message = cached.get(message_id)
            embed.set_footer(text=f"Message ID: {message_id} • Deletion actor unknown")
            if message is not None:
                embed.description = shorten(message.content or "[No text content]", 3500)
                embed.add_field(
                    name="Author",
                    value=f"{shorten(str(message.author), 200)} (`{message.author.id}`)",
                    inline=False,
                )
                if message.attachments:
                    embed.add_field(name="Attachments", value=str(len(message.attachments)))
            else:
                embed.description = "Content and author unavailable: message was not in my cache."
        else:
            available = len(message_ids.intersection(cached))
            embed.description = (
                f"Content available for {available}/{len(message_ids)} messages. "
                "See the attached transcript for message IDs, authors, text, and attachment links."
            )
            embed.set_footer(text="Deletion actor unknown")

        data = transcript(guild_id, channel_id, message_ids, cached).encode("utf-8")
        filename = f"deleted-{min(message_ids)}.txt"
        try:
            with closing(discord.File(io.BytesIO(data), filename=filename)) as file:
                await channel.send(
                    embed=embed, file=file, allowed_mentions=discord.AllowedMentions.none()
                )
        except discord.HTTPException:
            # Do not print potentially sensitive message contents to application logs.
            log.exception(
                "Could not log %s deletion(s) from channel %s", len(message_ids), channel_id
            )

    async def on_raw_message_edit(self, payload: discord.RawMessageUpdateEvent) -> None:
        await self.log_edit(payload.cached_message, payload.message)

    @staticmethod
    def is_text_edit(before: discord.Message | None, after: discord.Message) -> bool:
        """Whether the author changed the text or removed files, not just a preview or pin."""
        if before is not None:
            return before.content != after.content or {a.id for a in before.attachments} != {
                a.id for a in after.attachments
            }
        # Without the old copy, trust only a fresh edit stamp.
        return after.edited_at is not None and datetime.now(UTC) - after.edited_at < RECENT_EDIT

    async def log_edit(self, before: discord.Message | None, after: discord.Message) -> None:
        # Bots, including this one, edit their own posts constantly; skip them.
        if after.guild is None or after.author.bot or not self.is_text_edit(before, after):
            return
        channel = self.log_channel_for(after.guild.id)
        if channel is None or after.channel.id == channel.id:
            return

        author = after.author
        embed = discord.Embed(
            title="Message edited",
            description=f"[Jump to message]({after.jump_url})",
            colour=discord.Colour.blue(),
            timestamp=datetime.now(UTC),
        )
        embed.add_field(
            name="Channel", value=f"<#{after.channel.id}> (`{after.channel.id}`)", inline=False
        )
        embed.add_field(
            name="Author",
            value=f"<@{author.id}> {shorten(str(author), 200)} (`{author.id}`)",
            inline=False,
        )
        if before is None:
            old_text = "Unavailable: the message was not in my cache."
        else:
            old_text = shorten(before.content or "[No text content]", 1024)
        embed.add_field(name="Before", value=old_text, inline=False)
        embed.add_field(
            name="After", value=shorten(after.content or "[No text content]", 1024), inline=False
        )
        if before is not None:
            kept = {item.id for item in after.attachments}
            removed = [item.filename for item in before.attachments if item.id not in kept]
            if removed:
                embed.add_field(
                    name="Removed attachments",
                    value=shorten(", ".join(removed), 1024),
                    inline=False,
                )
        embed.set_footer(text=f"Message ID: {after.id}")

        data = edit_transcript(before, after).encode("utf-8")
        try:
            filename = f"edited-{after.id}.txt"
            with closing(discord.File(io.BytesIO(data), filename=filename)) as file:
                await channel.send(
                    embed=embed, file=file, allowed_mentions=discord.AllowedMentions.none()
                )
        except discord.HTTPException:
            # Do not print potentially sensitive message contents to application logs.
            log.exception("Could not log edit of message %s", after.id)

    # Scam filter

    @staticmethod
    def is_member_post(message: discord.Message) -> bool:
        """A server post by an ordinary member. Bots and moderators are trusted."""
        author = message.author
        return (
            message.guild is not None
            and not author.bot
            and isinstance(author, discord.Member)
            and not author.guild_permissions.manage_messages
        )

    def should_scan(self, message: discord.Message) -> bool:
        """Scan members' posts in servers with a log channel."""
        if not self.is_member_post(message):
            return False
        channel = self.log_channel_for(message.guild.id)
        return channel is not None and message.channel.id != channel.id

    def trap_for(self, message: discord.Message) -> Trap | None:
        """The server's trap, if this member post is in its trap channel."""
        if not self.is_member_post(message):
            return None
        trap = self.traps.traps.get(message.guild.id)
        return trap if trap is not None and message.channel.id == trap.channel_id else None

    async def on_message(self, message: discord.Message) -> None:
        if await self.enforce_long_timeout(message):
            return
        if (trap := self.trap_for(message)) is not None:
            await self.spring_trap(message, trap)
            return
        if not self.should_scan(message):
            return
        found = await self.find_scam(message)
        if found is not None:
            reason, copies = found
            await self.remove_scam(message, reason, copies)

    async def find_scam(self, message: discord.Message) -> tuple[str, list[discord.Message]] | None:
        """Return why the message is a scam and every copy to delete, or None."""
        text, attachments = message_parts(message)
        if self.blocked_domains and (match := self.blocked_domains.search(text)):
            return f"Blocked link: {match.group(0)}", [message]

        hashes = await self.hash_images(attachments)
        for value in hashes:
            if value is None:
                continue
            match = scam_filter.closest_match(
                value, self.known_images, self.settings.image_match_distance
            )
            if match:
                return f"Known scam image: {match[0]} (difference {match[1]})", [message]

        # Only posts with files or links count, so ordinary chat is never matched.
        if attachments or scam_filter.has_link(text):
            files = sorted(
                f"{value:x}" if value is not None else f"{item.filename}:{item.size}"
                for item, value in zip(attachments, hashes, strict=True)
            )
            signature = (" ".join(text.lower().split()), tuple(files))
            copies = self.repeats.add(
                message.author.id, message.channel.id, signature, message, datetime.now(UTC)
            )
            if copies:
                channels = len({copy.channel.id for copy in copies})
                return f"Same post in {channels} channels within 2 minutes", copies
        return None

    async def hash_images(self, attachments: list[discord.Attachment]) -> list[int | None]:
        async def one(item: discord.Attachment) -> int | None:
            content_type = item.content_type or ""
            suffix_ok = item.filename.lower().endswith(scam_filter.IMAGE_SUFFIXES)
            is_image = content_type.startswith("image/") or suffix_ok
            if not is_image or item.size > scam_filter.MAX_IMAGE_BYTES:
                return None
            try:
                data = await item.read()
            except (discord.HTTPException, aiohttp.ClientError, TimeoutError):
                log.warning("Could not download attachment %s for scanning", item.id)
                return None
            return await asyncio.to_thread(scam_filter.image_hash, data)

        return list(await asyncio.gather(*(one(item) for item in attachments)))

    async def delete_messages(self, messages: list[discord.Message], reason: str) -> int:
        """Delete messages without logging them as ordinary deletions; return how many went.

        Several messages in one channel go in one bulk request.
        """
        if len(self.removed_ids) > 1_000:  # delete events missed while disconnected
            self.removed_ids.clear()
        by_channel: dict[int, list[discord.Message]] = {}
        for message in messages:
            # Skip messages another handler is already deleting.
            if message.id not in self.removed_ids:
                by_channel.setdefault(message.channel.id, []).append(message)
        deleted = 0
        for channel_messages in by_channel.values():
            for start in range(0, len(channel_messages), 100):  # Discord's bulk limit
                batch = channel_messages[start : start + 100]
                ids = {message.id for message in batch}
                self.removed_ids |= ids
                try:
                    if len(batch) == 1:
                        await batch[0].delete()
                    else:
                        await batch[0].channel.delete_messages(batch, reason=shorten(reason, 500))
                    deleted += len(batch)
                except discord.HTTPException as exc:
                    self.removed_ids -= ids
                    if not isinstance(exc, discord.NotFound):
                        log.warning(
                            "Could not delete %s message(s) in channel %s (HTTP %s)",
                            len(batch),
                            batch[0].channel.id,
                            exc.status,
                        )
        return deleted

    async def remove_scam(
        self, message: discord.Message, reason: str, copies: list[discord.Message]
    ) -> None:
        deleted = await self.delete_messages(copies, f"Scam filter: {reason}")
        action = await self.punish(message.author, reason)
        await self.log_removal(message, copies, reason, deleted, action)

    @staticmethod
    def claim(recent: dict[tuple[int, int], datetime], key: tuple[int, int]) -> bool:
        """Record an action on a member; False if they were already actioned just now.

        Call it before awaiting, so messages handled in parallel don't repeat the action.
        """
        now = datetime.now(UTC)
        for old in [k for k, when in recent.items() if now - when >= ACTION_MEMORY]:
            del recent[old]
        if key in recent:
            return False
        recent[key] = now
        return True

    async def punish(self, member: discord.Member, reason: str) -> str:
        action = self.settings.scam_action
        if action == "none":
            return "None (SCAM_ACTION=none)"
        key = (member.guild.id, member.id)
        if not self.claim(self.actioned, key):
            return "Already actioned for an earlier copy"
        audit_reason = shorten(f"Scam filter: {reason}", 500)
        try:
            if action == "timeout":
                minutes = self.settings.timeout_minutes
                await member.timeout(timedelta(minutes=minutes), reason=audit_reason)
                return f"Timed out for {format_minutes(minutes)}"
            if action == "kick":
                await member.kick(reason=audit_reason)
                return "Kicked"
            await member.guild.ban(member, reason=audit_reason, delete_message_seconds=3600)
            return "Banned; their messages from the last hour were deleted"
        except discord.HTTPException as exc:
            self.actioned.pop(key, None)
            log.warning("Could not %s member %s (HTTP %s)", action, member.id, exc.status)
            return (
                f"{action.title()} failed (HTTP {exc.status}). Check the bot's permissions "
                "and that its role is above the member's highest role."
            )

    async def spring_trap(self, message: discord.Message, trap: Trap) -> None:
        """Delete the member's recent messages, time them out and count the catch."""
        member = message.author
        guild_id = message.guild.id
        since = message.created_at - timedelta(minutes=trap.delete_minutes)
        # Discord has no "delete this member's messages" call short of a ban, so use
        # the bot's message cache, which holds recent messages from every channel.
        recent = {
            cached.id: cached
            for cached in self.cached_messages
            if cached.guild is not None
            and cached.guild.id == guild_id
            and cached.author.id == member.id
            and cached.created_at >= since
        }
        recent[message.id] = message
        messages = sorted(recent.values(), key=lambda item: item.id)
        reason = f"Trap channel: posted in #{message.channel}"
        deleted = await self.delete_messages(messages, reason)

        caught = False
        if not self.claim(self.trapped, (guild_id, member.id)):
            action = "Already timed out for an earlier message"
        else:
            try:
                await self.apply_timeout(member, trap.timeout_minutes, reason)
                action = timeout_text(trap.timeout_minutes).capitalize()
                caught = True
            except discord.HTTPException as exc:
                self.trapped.pop((guild_id, member.id), None)
                log.warning("Could not time out member %s (HTTP %s)", member.id, exc.status)
                action = (
                    f"Timeout failed (HTTP {exc.status}). Check the bot's permissions "
                    "and that its role is above the member's highest role."
                )

        await self.log_removal(
            message,
            messages,
            f"Posted in the trap channel <#{message.channel.id}>",
            deleted,
            action,
            title="Trap channel triggered",
            actor="this bot's trap channel",
            file_prefix="trap",
        )
        if caught:
            await self.count_catch(guild_id)

    async def count_catch(self, guild_id: int) -> None:
        """Add one to the trap's counter and show it on the notice."""
        trap = self.traps.traps.get(guild_id)
        if trap is None:
            return
        trap = replace(trap, count=trap.count + 1)
        try:
            self.traps.set(guild_id, trap)
        except OSError:
            log.exception("Could not save the trap counter for server %s", guild_id)
        channel = self.trap_channel_for(guild_id)
        if channel is None or trap.notice_id is None:
            return
        view = trap_notice(trap)
        try:
            # Clearing the embed also turns a notice from an older version into the new layout.
            await channel.get_partial_message(trap.notice_id).edit(
                content=None, embed=None, view=view
            )
        except discord.HTTPException as exc:
            log.warning(
                "Could not update the trap notice in server %s (HTTP %s)", guild_id, exc.status
            )
        finally:
            view.stop()

    # Timeouts of any length

    def save_long_timeout(self, key: tuple[int, int], entry: LongTimeout | None) -> None:
        try:
            self.long_timeouts.set(key, entry)
        except OSError:
            log.exception("Could not save the long timeout of member %s", key[1])

    async def apply_timeout(self, member: discord.Member, minutes: int | None, reason: str) -> None:
        """Time a member out for any length, or permanently (minutes=None).

        Past Discord's 28-day limit the bot saves the timeout and keeps renewing it.
        Raises discord.HTTPException if Discord refuses.
        """
        key = (member.guild.id, member.id)
        reason = shorten(reason, 500)
        if minutes is not None and minutes <= MAX_TIMEOUT_MINUTES:
            await member.timeout(timedelta(minutes=minutes), reason=reason)
            self.save_long_timeout(key, None)  # a new, shorter timeout replaces a long one
            return
        now = datetime.now(UTC)
        block = now + TIMEOUT_BLOCK
        await member.timeout(block, reason=reason)
        until = None if minutes is None else now + timedelta(minutes=minutes)
        self.save_long_timeout(key, LongTimeout(until, block, reason))

    async def renew_loop(self) -> None:
        await self.wait_until_ready()
        while not self.is_closed():
            try:
                await self.renew_timeouts()
            except Exception:
                log.exception("Could not renew long timeouts")
            await asyncio.sleep(RENEW_CHECK_SECONDS)

    async def renew_timeouts(self) -> None:
        """Renew each long timeout whose current block ends soon."""
        now = datetime.now(UTC)
        for key, entry in list(self.long_timeouts.entries.items()):
            if entry.left or entry.applied_until - now > RENEW_BEFORE:
                continue
            guild = self.get_guild(key[0])
            if guild is None:
                continue  # not connected to that server right now; try again later
            try:
                member = await guild.fetch_member(key[1])
            except discord.NotFound:
                # Without the members intent the bot cannot see them rejoin, so it
                # renews the timeout if they post again instead.
                self.save_long_timeout(key, replace(entry, left=True))
                continue
            except discord.HTTPException as exc:
                log.warning("Could not look up member %s (HTTP %s)", key[1], exc.status)
                continue
            await self.renew_timeout(member, entry)

    async def renew_timeout(self, member: discord.Member, entry: LongTimeout) -> bool:
        """Set the next block of a long timeout. False if it ended or a moderator changed it."""
        key = (member.guild.id, member.id)
        now = datetime.now(UTC)
        if entry.until is not None and entry.until <= now:
            self.save_long_timeout(key, None)
            return False
        current = member.timed_out_until if member.is_timed_out() else None
        if not timeout_is_ours(current, entry, now):
            # Forget it before awaiting, so a second message does not repeat this.
            self.save_long_timeout(key, None)
            log.info("Member %s: long timeout was removed or changed by someone else", member.id)
            embed = discord.Embed(
                title="Long timeout stopped",
                description=(
                    f"<@{member.id}>'s timeout was removed or changed by someone else, "
                    "so the bot no longer renews it."
                ),
                colour=discord.Colour.orange(),
                timestamp=now,
            )
            await self.post_log(member.guild.id, embed)
            return False
        end = now + TIMEOUT_BLOCK
        final = entry.until is not None and entry.until <= end
        if final:
            end = entry.until
        reason = shorten(f"Renewing a long timeout: {entry.reason or 'no reason given'}", 500)
        try:
            await member.timeout(end, reason=reason)
        except discord.HTTPException as exc:
            log.warning("Could not renew the timeout of member %s (HTTP %s)", member.id, exc.status)
            return False
        self.save_long_timeout(
            key, None if final else replace(entry, applied_until=end, left=False)
        )
        return True

    async def enforce_long_timeout(self, message: discord.Message) -> bool:
        """Time out again a member whose long timeout lapsed, such as after rejoining.

        Returns True when the message was from such a member and was deleted.
        """
        author = message.author
        if message.guild is None or not isinstance(author, discord.Member):
            return False
        key = (message.guild.id, author.id)
        entry = self.long_timeouts.entries.get(key)
        if entry is None:
            return False
        if self.claim(self.reapplied, key):
            if not await self.renew_timeout(author, entry):
                self.reapplied.pop(key, None)
                return False
        await self.delete_messages([message], "Posted while under a long timeout")
        return True

    async def post_log(self, guild_id: int, embed: discord.Embed) -> None:
        channel = self.log_channel_for(guild_id)
        if channel is None:
            return
        try:
            await channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:
            log.exception("Could not post to the log channel of server %s", guild_id)

    async def log_removal(
        self,
        message: discord.Message,
        copies: list[discord.Message],
        reason: str,
        deleted: int,
        action: str,
        *,
        title: str = "Scam post removed",
        actor: str = "this bot's scam filter",
        file_prefix: str = "scam",
    ) -> None:
        channel = self.log_channel_for(message.guild.id)
        if channel is None:
            return
        author = message.author
        channel_ids = sorted({copy.channel.id for copy in copies})
        embed = discord.Embed(
            title=title,
            description=shorten(reason, 1000),
            colour=discord.Colour.red(),
            timestamp=datetime.now(UTC),
        )
        embed.add_field(
            name="Author",
            value=f"<@{author.id}> {shorten(str(author), 200)} (`{author.id}`)",
            inline=False,
        )
        embed.add_field(
            name="Channels",
            value=shorten(" ".join(f"<#{cid}>" for cid in channel_ids), 1000),
            inline=False,
        )
        embed.add_field(name="Deleted", value=f"{deleted}/{len(copies)} messages")
        embed.add_field(name="Action", value=shorten(action, 1000))

        ids = {copy.id for copy in copies}
        data = transcript(
            channel.guild.id,
            ", ".join(map(str, channel_ids)),
            ids,
            {copy.id: copy for copy in copies},
            actor=f"{actor} ({reason})",
        ).encode("utf-8")
        try:
            filename = f"{file_prefix}-{min(ids)}.txt"
            with closing(discord.File(io.BytesIO(data), filename=filename)) as file:
                await channel.send(
                    embed=embed, file=file, allowed_mentions=discord.AllowedMentions.none()
                )
        except discord.HTTPException:
            log.exception("Could not log removal of message %s", message.id)


async def duration_choices(
    interaction: discord.Interaction, current: str
) -> list[app_commands.Choice[str]]:
    """Suggestions while typing a duration, starting with what was typed if it is valid."""
    typed = current.strip()
    choices = []
    if typed:
        try:
            minutes = parse_duration(typed)
        except ValueError:
            pass
        else:
            label = "permanent" if minutes is None else format_minutes(minutes)
            choices.append(
                app_commands.Choice(name=shorten(f"{typed} ({label})", 100), value=typed)
            )
    choices += [
        app_commands.Choice(name=s, value=s)
        for s in DURATION_SUGGESTIONS
        if typed.lower() in s and s != typed
    ]
    return choices[:25]


def timeout_problem(interaction: discord.Interaction, member: discord.Member) -> str | None:
    """Why the person running /timeout or /untimeout cannot do it to this member, if so."""
    guild = interaction.guild
    me = guild.me if guild else None
    if guild is None or me is None:
        return "Invite the bot to this server first."
    if not me.guild_permissions.moderate_members:
        return "I need the Timeout Members permission first."
    if member.id == interaction.user.id:
        return "You cannot do this to yourself."
    if member.id == guild.owner_id:
        return "The server owner cannot be timed out."
    if member.guild_permissions.administrator:
        return "Discord does not allow timing out administrators."
    actor = interaction.user
    if actor.id != guild.owner_id and (
        not isinstance(actor, discord.Member) or actor.top_role <= member.top_role
    ):
        return f"Your highest role must be above {member.mention}'s."
    if me.top_role <= member.top_role:
        return f"My highest role must be above {member.mention}'s."
    return None


@app_commands.command(
    name="timeout", description="Time out a member for any length, or permanently"
)
@app_commands.guild_only()
@app_commands.default_permissions(moderate_members=True)
@app_commands.describe(
    member="Who to time out",
    duration="For example 30m, 2h, 3d, 2w, 6 months or permanent",
    reason="Shown in the audit log and the log channel",
)
@app_commands.autocomplete(duration=duration_choices)
async def timeout_command(
    interaction: discord.Interaction,
    member: discord.Member,
    duration: app_commands.Range[str, 1, 100],
    reason: app_commands.Range[str, 1, 400] | None = None,
) -> None:
    bot: ModeratorBot = interaction.client
    if problem := timeout_problem(interaction, member):
        await reply(interaction, problem)
        return
    try:
        minutes = parse_duration(duration)
    except ValueError as exc:
        await reply(interaction, str(exc))
        return
    await acknowledge(interaction)
    audit = f"By {interaction.user}: {reason or 'no reason given'}"
    try:
        await bot.apply_timeout(member, minutes, audit)
    except discord.HTTPException as exc:
        await reply(interaction, f"Discord refused the timeout (HTTP {exc.status}).")
        return
    text = f"{member.mention} is {timeout_text(minutes)}."
    if minutes is None or minutes > MAX_TIMEOUT_MINUTES:
        text += (
            " Discord allows at most 28 days at a time, so I renew it before each block "
            "ends. Use `/untimeout` to end it early."
        )
    await reply(interaction, text)
    embed = discord.Embed(
        title="Member timed out",
        colour=discord.Colour.orange(),
        timestamp=datetime.now(UTC),
    )
    embed.add_field(
        name="Member", value=f"<@{member.id}> {shorten(str(member), 200)} (`{member.id}`)"
    )
    embed.add_field(name="By", value=f"<@{interaction.user.id}>")
    embed.add_field(
        name="Duration", value="Permanent" if minutes is None else format_minutes(minutes)
    )
    embed.add_field(name="Reason", value=reason or "No reason given", inline=False)
    await bot.post_log(member.guild.id, embed)


@app_commands.command(name="untimeout", description="End a member's timeout, including permanent")
@app_commands.guild_only()
@app_commands.default_permissions(moderate_members=True)
@app_commands.describe(member="Whose timeout to end")
async def untimeout_command(interaction: discord.Interaction, member: discord.Member) -> None:
    bot: ModeratorBot = interaction.client
    if problem := timeout_problem(interaction, member):
        await reply(interaction, problem)
        return
    await acknowledge(interaction)
    key = (member.guild.id, member.id)
    saved = bot.long_timeouts.entries.get(key)
    try:
        await member.timeout(None, reason=shorten(f"Timeout ended by {interaction.user}", 500))
    except discord.HTTPException as exc:
        await reply(interaction, f"Discord refused to end the timeout (HTTP {exc.status}).")
        return
    bot.save_long_timeout(key, None)
    if saved is None and not member.is_timed_out():
        await reply(interaction, f"{member.mention} was not timed out.")
        return
    await reply(interaction, f"{member.mention}'s timeout has ended.")
    embed = discord.Embed(
        title="Timeout ended",
        description=f"<@{member.id}>'s timeout was ended by <@{interaction.user.id}>.",
        colour=discord.Colour.green(),
        timestamp=datetime.now(UTC),
    )
    await bot.post_log(member.guild.id, embed)


class LogChannelCommands(
    app_commands.Group,
    name="logchannel",
    description="Choose where this server's moderation logs go",
    guild_only=True,
    # Hidden from members without Manage Server. Admins can change this in
    # Server Settings > Integrations.
    default_permissions=discord.Permissions(manage_guild=True),
):
    def __init__(self, bot: ModeratorBot) -> None:
        super().__init__()
        self.bot = bot

    @app_commands.command(name="set", description="Post deletion, edit and scam logs in a channel")
    @app_commands.describe(channel="A private channel that only moderators can read")
    async def set_channel(
        self, interaction: discord.Interaction, channel: discord.TextChannel
    ) -> None:
        guild = interaction.guild
        if guild is None or guild.me is None:
            await reply(interaction, "Invite the bot to this server first.")
            return
        missing = missing_permissions(channel.permissions_for(guild.me), LOG_CHANNEL_PERMISSIONS)
        if missing:
            await reply(
                interaction,
                f"I need these permissions in {channel.mention} first: {', '.join(missing)}.",
            )
            return
        embed = discord.Embed(
            title="Moderation log channel",
            description=(
                "Deleted and edited messages and removed scam posts from this server will be "
                "logged here. "
                "Keep this channel private to moderators."
            ),
            colour=discord.Colour.green(),
            timestamp=datetime.now(UTC),
        )
        embed.set_footer(text=f"Set by {shorten(str(interaction.user), 100)}")
        await acknowledge(interaction)
        try:
            await channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException as exc:
            await reply(interaction, f"I could not post in {channel.mention} (HTTP {exc.status}).")
            return
        try:
            self.bot.store.set(guild.id, channel.id)
        except OSError:
            log.exception("Could not save the log channel for server %s", guild.id)
            await reply(interaction, "I could not save this setting. Check the bot's console.")
            return
        log.info("Server %s (%s): log channel set to %s", guild, guild.id, channel.id)
        text = f"Logs will go to {channel.mention}, and the scam filter is on."
        if problems := self.bot.server_permission_problems(guild):
            text += (
                "\nTo delete scam posts and apply the scam action I also need these server "
                f"permissions: {', '.join(problems)}."
            )
        await reply(interaction, text)

    @app_commands.command(name="show", description="Show the current log channel")
    async def show(self, interaction: discord.Interaction) -> None:
        guild_id = interaction.guild_id
        channel_id = self.bot.store.channels.get(guild_id) if guild_id else None
        if channel_id is None:
            text = "No log channel is set. Use `/logchannel set` to choose one."
        elif self.bot.log_channel_for(guild_id) is None:
            text = f"The log channel (`{channel_id}`) is gone or hidden from me. Set a new one."
        else:
            text = f"Logs go to <#{channel_id}>."
        await reply(interaction, text)

    @app_commands.command(name="off", description="Stop logging and scam removal here")
    async def off(self, interaction: discord.Interaction) -> None:
        guild_id = interaction.guild_id
        if guild_id is None or guild_id not in self.bot.store.channels:
            await reply(interaction, "No log channel is set, so logging is already off.")
            return
        try:
            self.bot.store.set(guild_id, None)
        except OSError:
            log.exception("Could not save the log channel for server %s", guild_id)
            await reply(interaction, "I could not save this setting. Check the bot's console.")
            return
        await reply(
            interaction,
            "Logging and the scam filter are off in this server. "
            "Use `/logchannel set` to turn them back on.",
        )


class TrapChannelCommands(
    app_commands.Group,
    name="trapchannel",
    description="Catch spam bots with a channel nobody should post in",
    guild_only=True,
    default_permissions=discord.Permissions(manage_guild=True),
):
    def __init__(self, bot: ModeratorBot) -> None:
        super().__init__()
        self.bot = bot

    @app_commands.command(
        name="set", description="Time out anyone who posts in a channel and delete their messages"
    )
    @app_commands.rename(timeout_for="timeout")
    @app_commands.describe(
        channel="A channel members can see and post in, but are told not to",
        timeout_for="For example 30m, 2h, 3d, 6 months or permanent (default: 1 day)",
        delete_messages="How far back to delete their messages in every channel (default: 1 hour)",
    )
    @app_commands.autocomplete(timeout_for=duration_choices)
    @app_commands.choices(
        delete_messages=[
            app_commands.Choice(name=k, value=v) for k, v in TRAP_DELETE_CHOICES.items()
        ],
    )
    async def set_channel(
        self,
        interaction: discord.Interaction,
        channel: discord.TextChannel,
        timeout_for: app_commands.Range[str, 1, 100] | None = None,
        delete_messages: app_commands.Choice[int] | None = None,
    ) -> None:
        guild = interaction.guild
        if guild is None or guild.me is None:
            await reply(interaction, "Invite the bot to this server first.")
            return
        try:
            timeout_minutes = parse_duration(timeout_for) if timeout_for else 1440
        except ValueError as exc:
            await reply(interaction, str(exc))
            return
        if channel.id == self.bot.store.channels.get(guild.id):
            await reply(interaction, "The log channel cannot also be the trap channel.")
            return
        missing = missing_permissions(channel.permissions_for(guild.me), TRAP_CHANNEL_PERMISSIONS)
        if missing:
            await reply(
                interaction,
                f"I need these permissions in {channel.mention} first: {', '.join(missing)}.",
            )
            return
        old = self.bot.traps.traps.get(guild.id)
        trap = Trap(
            channel.id,
            timeout_minutes=timeout_minutes,
            delete_minutes=delete_messages.value if delete_messages else 60,
            count=old.count if old else 0,
        )
        view = trap_notice(trap)
        await acknowledge(interaction)
        try:
            notice = await channel.send(view=view, allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException as exc:
            await reply(interaction, f"I could not post in {channel.mention} (HTTP {exc.status}).")
            return
        finally:
            view.stop()
        trap = replace(trap, notice_id=notice.id)
        try:
            self.bot.traps.set(guild.id, trap)
        except OSError:
            log.exception("Could not save the trap channel for server %s", guild.id)
            await self.bot.delete_messages([notice], "Trap channel setup failed")
            await reply(interaction, "I could not save this setting. Check the bot's console.")
            return
        log.info("Server %s (%s): trap channel set to %s", guild, guild.id, channel.id)
        await reply(interaction, self.describe(guild, trap))
        if old is not None and old.notice_id is not None:
            await delete_notice(self.bot, old)

    def describe(self, guild: discord.Guild, trap: Trap) -> str:
        text = (
            f"Trap channel: <#{trap.channel_id}>. Anyone without Manage Messages who posts there "
            f"is {timeout_text(trap.timeout_minutes)}, and their messages from "
            f"the last {format_minutes(trap.delete_minutes)} are deleted in every channel. "
            f"Caught so far: {trap.count:,}."
        )
        if guild.me is not None and (
            problems := missing_permissions(guild.me.guild_permissions, TRAP_SERVER_PERMISSIONS)
        ):
            text += f"\nI also need these server permissions: {', '.join(problems)}."
        if self.bot.log_channel_for(guild.id) is None:
            text += "\nSet a log channel with `/logchannel set` to get a report of each catch."
        return text

    @app_commands.command(name="show", description="Show the current trap channel")
    async def show(self, interaction: discord.Interaction) -> None:
        guild = interaction.guild
        trap = self.bot.traps.traps.get(guild.id) if guild else None
        if trap is None:
            text = "No trap channel is set. Use `/trapchannel set` to choose one."
        elif self.bot.trap_channel_for(guild.id) is None:
            text = (
                f"The trap channel (`{trap.channel_id}`) is gone or hidden from me. Set a new one."
            )
        else:
            text = self.describe(guild, trap)
        await reply(interaction, text)

    @app_commands.command(name="off", description="Stop the trap channel")
    async def off(self, interaction: discord.Interaction) -> None:
        guild_id = interaction.guild_id
        trap = self.bot.traps.traps.get(guild_id) if guild_id else None
        if trap is None:
            await reply(interaction, "No trap channel is set, so the trap is already off.")
            return
        try:
            self.bot.traps.set(guild_id, None)
        except OSError:
            log.exception("Could not save the trap channel for server %s", guild_id)
            await reply(interaction, "I could not save this setting. Check the bot's console.")
            return
        await reply(
            interaction,
            f"The trap in <#{trap.channel_id}> is off and its notice is removed. "
            "Use `/trapchannel set` to turn it back on.",
        )
        await delete_notice(self.bot, trap)


def trap_notice(trap: Trap) -> discord.ui.LayoutView:
    """The warning posted in the trap channel, with the catch counter inside the same box.

    The whole box is sent again on every edit, so it needs the full trap settings.
    Call stop() on it after sending, so the bot does not keep it in memory.
    """
    heading = discord.ui.TextDisplay("## DO NOT SEND MESSAGES IN THIS CHANNEL")
    body = discord.ui.TextDisplay(
        "This channel is used to catch spam bots. Anyone who sends a message here is "
        f"**{timeout_text(trap.timeout_minutes)}**, and their messages "
        f"from the last {format_minutes(trap.delete_minutes)} are deleted."
    )
    counter = discord.ui.Button(
        label=f"Timeouts: {trap.count:,}", style=discord.ButtonStyle.secondary, disabled=True
    )
    view = discord.ui.LayoutView(timeout=None)
    # An invisible divider leaves a gap between the text and the counter.
    gap = discord.ui.Separator(visible=False, spacing=discord.SeparatorSpacing.large)
    view.add_item(discord.ui.Container(heading, body, gap, discord.ui.ActionRow(counter)))
    return view


async def delete_notice(bot: ModeratorBot, trap: Trap) -> None:
    """Remove an old trap notice, if it is still there."""
    channel = bot.get_channel(trap.channel_id)
    if trap.notice_id is None or not isinstance(channel, discord.TextChannel):
        return
    await bot.delete_messages(
        [channel.get_partial_message(trap.notice_id)], "Trap channel moved or turned off"
    )


async def acknowledge(interaction: discord.Interaction) -> None:
    """Show "thinking..." before slow work.

    Discord drops a command that gets no answer within 3 seconds. After this, reply() can
    answer up to 15 minutes later.
    """
    if not interaction.response.is_done():
        await interaction.response.defer(ephemeral=True, thinking=True)


async def reply(interaction: discord.Interaction, text: str) -> None:
    """Answer only the person who ran the command."""
    mentions = discord.AllowedMentions.none()
    if interaction.response.is_done():
        await interaction.followup.send(text, ephemeral=True, allowed_mentions=mentions)
    else:
        await interaction.response.send_message(text, ephemeral=True, allowed_mentions=mentions)


def message_parts(message: discord.Message) -> tuple[str, list[discord.Attachment]]:
    """Text and attachments of a message, including any forwarded message inside it."""
    texts = [message.content]
    attachments = list(message.attachments)
    for snapshot in getattr(message, "message_snapshots", None) or ():
        texts.append(snapshot.content)
        attachments.extend(snapshot.attachments)
    return "\n".join(text for text in texts if text), attachments


def format_minutes(minutes: int) -> str:
    days, rest = divmod(minutes, 1440)
    hours, mins = divmod(rest, 60)
    parts = [
        f"{n} {unit}" + ("s" if n != 1 else "")
        for n, unit in ((days, "day"), (hours, "hour"), (mins, "minute"))
        if n
    ]
    return " ".join(parts) or "0 minutes"


def timeout_text(minutes: int | None) -> str:
    if minutes is None:
        return "timed out permanently"
    return f"timed out for {format_minutes(minutes)}"


def parse_duration(text: str) -> int | None:
    """Minutes in a duration such as "90m", "2d 12h" or "6 months"; None means permanent."""
    cleaned = " ".join(text.lower().replace(",", " ").split()).replace(" and ", " ")
    if cleaned in PERMANENT_WORDS:
        return None
    parts = DURATION_PART.findall(cleaned)
    if not parts or DURATION_PART.sub("", cleaned).strip():
        raise ValueError(
            f"`{shorten(text, 50)}` is not a duration. Try 30m, 2h, 3d, 2w, 6 months or permanent."
        )
    try:
        minutes = sum(int(n) * DURATION_UNITS[unit] for n, unit in parts)
    except KeyError as exc:
        raise ValueError(
            f"Unknown unit `{exc.args[0]}`. Use m, h, d, w, months or years."
        ) from None
    if minutes < 1:
        raise ValueError("The duration must be at least 1 minute.")
    if minutes > MAX_DURATION_MINUTES:
        raise ValueError("That is over 10 years. Use permanent instead.")
    return minutes


def timeout_is_ours(current: datetime | None, entry: LongTimeout, now: datetime) -> bool:
    """Whether a member's timeout is still the block the bot set, or ran out unattended.

    No timeout before the block was due to end, or a different end, means someone else
    removed or changed it.
    """
    slack = timedelta(minutes=1)
    if current is None:
        return entry.applied_until <= now + slack
    return abs(current - entry.applied_until) <= slack


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    load_dotenv(BASE_DIR / ".env")
    if os.environ.get("DISCORD_LOG_CHANNEL_ID"):
        log.warning("DISCORD_LOG_CHANNEL_ID is no longer used. Run /logchannel set in your server.")
    try:
        settings = Settings.from_env(os.environ)
        ModeratorBot(settings).run(settings.token, log_handler=None)
    except (ValueError, discord.LoginFailure, discord.PrivilegedIntentsRequired) as exc:
        raise SystemExit(f"Bot startup failed: {exc}") from exc


if __name__ == "__main__":
    main()
