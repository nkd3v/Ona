"""Log message deletions and remove scam posts in Discord servers."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass, field
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
LOG_CHANNEL_PERMISSIONS = ("view_channel", "send_messages", "embed_links", "attach_files")


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
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(".tmp")
        temp.write_text(json.dumps({str(k): v for k, v in channels.items()}, indent=2), "utf-8")
        os.replace(temp, self.path)  # atomic, so a crash never leaves a half-written file
        self.channels = channels


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
        self.known_images = dict(scam_filter.KNOWN_SCAM_IMAGES)
        self.known_images.update(scam_filter.load_image_dir(settings.scam_images_dir))
        self.blocked_domains = scam_filter.domain_pattern(settings.blocked_domains)
        self.repeats = scam_filter.RepeatTracker(settings.repeat_channels)
        # Messages this bot deleted; they get a scam log instead of a deletion log.
        self.removed_ids: set[int] = set()
        # (server ID, member ID) -> when the scam action was applied.
        self.actioned: dict[tuple[int, int], datetime] = {}
        self.tree = app_commands.CommandTree(self)
        self.tree.add_command(LogChannelCommands(self))

    async def setup_hook(self) -> None:
        try:
            await self.tree.sync()
        except discord.HTTPException:
            # Logging keeps working with commands registered by an earlier start.
            log.exception("Could not register the /logchannel command with Discord")

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
        cached = {message.id: message for message in payload.cached_messages}
        await self.log_deletion(payload.guild_id, payload.channel_id, payload.message_ids, cached)

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

    # Scam filter

    def should_scan(self, message: discord.Message) -> bool:
        """Scan members' posts in servers with a log channel. Bots and moderators are trusted."""
        author = message.author
        if (
            message.guild is None
            or author.bot
            or not isinstance(author, discord.Member)
            or author.guild_permissions.manage_messages
        ):
            return False
        channel = self.log_channel_for(message.guild.id)
        return channel is not None and message.channel.id != channel.id

    async def on_message(self, message: discord.Message) -> None:
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

    async def remove_scam(
        self, message: discord.Message, reason: str, copies: list[discord.Message]
    ) -> None:
        if len(self.removed_ids) > 1_000:  # delete events missed while disconnected
            self.removed_ids.clear()
        deleted = 0
        for copy in copies:
            self.removed_ids.add(copy.id)
            try:
                await copy.delete()
                deleted += 1
            except discord.HTTPException as exc:
                self.removed_ids.discard(copy.id)
                if not isinstance(exc, discord.NotFound):
                    log.warning(
                        "Could not delete scam message %s in channel %s (HTTP %s)",
                        copy.id,
                        copy.channel.id,
                        exc.status,
                    )
        action = await self.punish(message.author, reason)
        await self.log_removal(message, copies, reason, deleted, action)

    async def punish(self, member: discord.Member, reason: str) -> str:
        action = self.settings.scam_action
        if action == "none":
            return "None (SCAM_ACTION=none)"
        now = datetime.now(UTC)
        self.actioned = {
            key: when for key, when in self.actioned.items() if now - when < timedelta(minutes=5)
        }
        key = (member.guild.id, member.id)
        if key in self.actioned:
            return "Already actioned for an earlier copy"
        self.actioned[key] = now  # before awaiting, so parallel copies don't repeat it
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

    async def log_removal(
        self,
        message: discord.Message,
        copies: list[discord.Message],
        reason: str,
        deleted: int,
        action: str,
    ) -> None:
        channel = self.log_channel_for(message.guild.id)
        if channel is None:
            return
        author = message.author
        channel_ids = sorted({copy.channel.id for copy in copies})
        embed = discord.Embed(
            title="Scam post removed",
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
            actor=f"this bot's scam filter ({reason})",
        ).encode("utf-8")
        try:
            with closing(discord.File(io.BytesIO(data), filename=f"scam-{min(ids)}.txt")) as file:
                await channel.send(
                    embed=embed, file=file, allowed_mentions=discord.AllowedMentions.none()
                )
        except discord.HTTPException:
            log.exception("Could not log scam removal for message %s", message.id)


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

    @app_commands.command(name="set", description="Post deletion and scam logs in a channel")
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
                "Deleted messages and removed scam posts from this server will be logged here. "
                "Keep this channel private to moderators."
            ),
            colour=discord.Colour.green(),
            timestamp=datetime.now(UTC),
        )
        embed.set_footer(text=f"Set by {shorten(str(interaction.user), 100)}")
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


async def reply(interaction: discord.Interaction, text: str) -> None:
    """Answer only the person who ran the command."""
    await interaction.response.send_message(
        text, ephemeral=True, allowed_mentions=discord.AllowedMentions.none()
    )


def message_parts(message: discord.Message) -> tuple[str, list[discord.Attachment]]:
    """Text and attachments of a message, including any forwarded message inside it."""
    texts = [message.content]
    attachments = list(message.attachments)
    for snapshot in getattr(message, "message_snapshots", None) or ():
        texts.append(snapshot.content)
        attachments.extend(snapshot.attachments)
    return "\n".join(text for text in texts if text), attachments


def format_minutes(minutes: int) -> str:
    if minutes % 1440 == 0:
        days = minutes // 1440
        return f"{days} day" + ("s" if days != 1 else "")
    if minutes % 60 == 0:
        hours = minutes // 60
        return f"{hours} hour" + ("s" if hours != 1 else "")
    return f"{minutes} minute" + ("s" if minutes != 1 else "")


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
