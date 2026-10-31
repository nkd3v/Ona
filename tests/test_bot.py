import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import discord

import scam_filter
from bot import ModeratorBot, Settings, format_minutes, shorten, transcript
from tests.test_scam_filter import encode, sample_image


def message(message_id=10, content="A deleted message"):
    return SimpleNamespace(
        id=message_id,
        author=SimpleNamespace(id=42),
        content=content,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        attachments=[SimpleNamespace(filename="image.png", url="https://example.com/image.png")],
    )


class SettingsTests(unittest.TestCase):
    def test_valid_config_and_defaults(self):
        settings = Settings.from_env({"DISCORD_TOKEN": "secret", "DISCORD_LOG_CHANNEL_ID": "123"})
        self.assertEqual(settings.log_channel_id, 123)
        self.assertEqual(settings.cache_size, 10_000)

    def test_rejects_missing_placeholder_and_invalid_config(self):
        for env in (
            {},
            {"DISCORD_TOKEN": "replace_with_your_bot_token"},
            {"DISCORD_TOKEN": "secret", "DISCORD_LOG_CHANNEL_ID": "abc"},
            {"DISCORD_TOKEN": "secret", "DISCORD_LOG_CHANNEL_ID": "0"},
            {"DISCORD_TOKEN": "secret", "DISCORD_LOG_CHANNEL_ID": "1", "MESSAGE_CACHE_SIZE": "-1"},
        ):
            with self.subTest(env=env), self.assertRaises(ValueError):
                Settings.from_env(env)

    def test_scam_settings_defaults_and_overrides(self):
        base = {"DISCORD_TOKEN": "secret", "DISCORD_LOG_CHANNEL_ID": "123"}
        settings = Settings.from_env(base)
        self.assertEqual(settings.scam_action, "timeout")
        self.assertEqual(settings.timeout_minutes, 1440)
        self.assertEqual(settings.blocked_domains, ("wispwin.com",))
        self.assertEqual(settings.scam_images_dir, Path("scam-images"))
        settings = Settings.from_env(
            base
            | {
                "SCAM_ACTION": "BAN",
                "SCAM_TIMEOUT_MINUTES": "60",
                "BLOCKED_DOMAINS": "a.com, b.net,",
                "SCAM_IMAGES_DIR": "/tmp/x",
                "SPAM_REPEAT_CHANNELS": "0",
            }
        )
        self.assertEqual(settings.scam_action, "ban")
        self.assertEqual(settings.blocked_domains, ("a.com", "b.net"))
        self.assertEqual(settings.repeat_channels, 0)
        self.assertEqual(Settings.from_env(base | {"BLOCKED_DOMAINS": ""}).blocked_domains, ())

    def test_rejects_invalid_scam_settings(self):
        base = {"DISCORD_TOKEN": "secret", "DISCORD_LOG_CHANNEL_ID": "123"}
        for extra in (
            {"SCAM_ACTION": "explode"},
            {"SCAM_TIMEOUT_MINUTES": "0"},
            {"SCAM_TIMEOUT_MINUTES": "40321"},
            {"SCAM_IMAGE_MATCH_DISTANCE": "x"},
            {"SCAM_IMAGE_MATCH_DISTANCE": "101"},
            {"SPAM_REPEAT_CHANNELS": "1"},
        ):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                Settings.from_env(base | extra)

    def test_format_minutes(self):
        self.assertEqual(format_minutes(1440), "1 day")
        self.assertEqual(format_minutes(2880), "2 days")
        self.assertEqual(format_minutes(120), "2 hours")
        self.assertEqual(format_minutes(1), "1 minute")

    def test_unicode_preview_respects_discord_limit(self):
        result = shorten("😀" * 4000, 3500)
        self.assertLessEqual(len(result.encode("utf-16-le")) // 2, 3500)
        self.assertTrue(result.endswith("…"))
        self.assertEqual(shorten("short text", 100), "short text")

    def test_transcript_preserves_full_text_and_missing_messages(self):
        content = "😀" * 4000 + "\n@everyone"
        result = transcript(1, 2, {10, 11}, {10: message(content=content)})
        self.assertIn(content, result)
        self.assertIn("Message ID: 11", result)
        self.assertIn("not in the bot's cache", result)
        self.assertIn("image.png: https://example.com/image.png", result)
        self.assertIn("ID: 42", result)


class BotTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.bot = ModeratorBot(Settings("unused", 999))
        self.sent = []

        async def send(**kwargs):
            self.sent.append(
                {
                    "embed": kwargs["embed"],
                    "text": kwargs["file"].fp.read().decode("utf-8"),
                    "mentions": kwargs["allowed_mentions"].to_dict(),
                }
            )

        self.bot.log_channel = SimpleNamespace(id=999, guild=SimpleNamespace(id=1), send=send)

    async def asyncTearDown(self):
        await self.bot.close()

    async def test_cached_single_delete_has_full_transcript_and_no_pings(self):
        content = "@everyone " + "😀" * 4000
        payload = SimpleNamespace(
            guild_id=1, channel_id=2, message_id=10, cached_message=message(content=content)
        )
        await self.bot.on_raw_message_delete(payload)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]["embed"].title, "Message deleted")
        self.assertIn(content, self.sent[0]["text"])
        self.assertEqual(self.sent[0]["mentions"]["parse"], [])
        self.assertFalse(self.sent[0]["mentions"].get("replied_user", False))
        self.assertLessEqual(len(self.sent[0]["embed"]), 6000)

    async def test_uncached_single_delete_still_logs_ids(self):
        payload = SimpleNamespace(guild_id=1, channel_id=2, message_id=10, cached_message=None)
        await self.bot.on_raw_message_delete(payload)
        self.assertIn("unavailable", self.sent[0]["embed"].description)
        self.assertIn("Message ID: 10", self.sent[0]["text"])

    async def test_bulk_delete_logs_cached_and_uncached_in_one_send(self):
        payload = SimpleNamespace(
            guild_id=1, channel_id=2, message_ids={10, 11}, cached_messages=[message()]
        )
        await self.bot.on_raw_bulk_message_delete(payload)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]["embed"].title, "2 messages deleted")
        self.assertIn("1/2", self.sent[0]["embed"].description)
        self.assertIn("A deleted message", self.sent[0]["text"])
        self.assertIn("Message ID: 11", self.sent[0]["text"])

    async def test_ignores_dms_other_servers_log_channel_and_empty_events(self):
        for guild_id, channel_id, ids in (
            (None, 2, {10}),
            (3, 2, {10}),
            (1, 999, {10}),
            (1, 2, set()),
        ):
            await self.bot.log_deletion(guild_id, channel_id, ids, {})
        self.bot.log_channel = None
        await self.bot.log_deletion(1, 2, {10}, {})
        self.assertEqual(self.sent, [])

    async def test_send_failure_is_reported_without_crashing_handler(self):
        response = SimpleNamespace(status=403, reason="Forbidden")
        self.bot.log_channel.send = AsyncMock(side_effect=discord.Forbidden(response, "Denied"))
        with self.assertLogs("bot", level="ERROR") as captured:
            await self.bot.log_deletion(1, 2, {10}, {10: message(content="private content")})
        self.assertIn("Could not log", captured.output[0])
        self.assertNotIn("private content", captured.output[0])

    async def test_startup_rejects_missing_permissions(self):
        channel = MagicMock(spec=discord.TextChannel)
        channel.guild.me = object()
        channel.permissions_for.return_value = SimpleNamespace(
            view_channel=True, send_messages=True, embed_links=True, attach_files=False
        )
        self.bot.get_channel = MagicMock(return_value=channel)
        self.bot.close = AsyncMock()
        with self.assertLogs("bot", level="ERROR") as captured:
            await self.bot.on_ready()
        self.bot.close.assert_awaited_once()
        self.assertIn("attach_files", captured.output[0])


def member(member_id=42, moderator=False, bot=False):
    author = MagicMock(spec=discord.Member)
    author.id = member_id
    author.bot = bot
    author.guild_permissions = SimpleNamespace(manage_messages=moderator)
    author.timeout = AsyncMock()
    author.kick = AsyncMock()
    author.guild = SimpleNamespace(ban=AsyncMock())
    author.__str__.return_value = "spammer"
    return author


def attachment(data: bytes, filename="DSC_1009.png", attachment_id=5):
    return SimpleNamespace(
        id=attachment_id,
        filename=filename,
        content_type="image/png",
        size=len(data),
        url=f"https://cdn.example/{filename}",
        read=AsyncMock(return_value=data),
    )


def post(author, message_id=10, channel_id=2, content="", attachments=(), guild_id=1):
    return SimpleNamespace(
        id=message_id,
        guild=SimpleNamespace(id=guild_id),
        channel=SimpleNamespace(id=channel_id),
        author=author,
        content=content,
        attachments=list(attachments),
        message_snapshots=[],
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        delete=AsyncMock(),
    )


class ScamFilterBotTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.bot = ModeratorBot(Settings("unused", 999, scam_images_dir=Path("/nonexistent")))
        self.scam_png = encode(sample_image(1))
        self.bot.known_images[scam_filter.image_hash(self.scam_png)] = "test scam"
        self.sent = []

        async def send(**kwargs):
            self.sent.append(
                {"embed": kwargs["embed"], "text": kwargs["file"].fp.read().decode("utf-8")}
            )

        self.bot.log_channel = SimpleNamespace(id=999, guild=SimpleNamespace(id=1), send=send)

    async def asyncTearDown(self):
        await self.bot.close()

    async def test_built_in_hashes_are_loaded(self):
        for value in scam_filter.KNOWN_SCAM_IMAGES:
            self.assertIn(value, self.bot.known_images)

    async def test_known_scam_image_is_deleted_timed_out_and_logged_once(self):
        author = member()
        jpeg = encode(sample_image(1), "JPEG", quality=50)  # re-uploaded copy
        message = post(author, attachments=[attachment(jpeg)])
        await self.bot.on_message(message)

        message.delete.assert_awaited_once()
        author.timeout.assert_awaited_once()
        self.assertEqual(author.timeout.await_args.args[0], timedelta(days=1))
        self.assertEqual(len(self.sent), 1)
        embed = self.sent[0]["embed"]
        self.assertEqual(embed.title, "Scam post removed")
        self.assertIn("test scam", embed.description)
        self.assertIn("Timed out for 1 day", str(embed.fields))
        self.assertIn("scam filter", self.sent[0]["text"])

        # The bot's own deletion is not logged a second time.
        payload = SimpleNamespace(guild_id=1, channel_id=2, message_id=10, cached_message=message)
        await self.bot.on_raw_message_delete(payload)
        self.assertEqual(len(self.sent), 1)

    async def test_second_copy_is_deleted_without_a_second_timeout(self):
        author = member()
        for message_id in (10, 11):
            await self.bot.on_message(
                post(author, message_id, attachments=[attachment(self.scam_png)])
            )
        author.timeout.assert_awaited_once()
        self.assertIn("Already actioned", str(self.sent[1]["embed"].fields))

    async def test_blocked_link_and_forwarded_message_are_removed(self):
        author = member()
        message = post(author, content="free $2500 at WWW.wispwin.com/promo")
        await self.bot.on_message(message)
        message.delete.assert_awaited_once()
        self.assertIn("Blocked link", self.sent[0]["embed"].description)

        forwarded = post(member(43), message_id=20)
        forwarded.message_snapshots = [
            SimpleNamespace(content="", attachments=[attachment(self.scam_png)])
        ]
        await self.bot.on_message(forwarded)
        forwarded.delete.assert_awaited_once()

    async def test_same_post_in_three_channels_removes_every_copy(self):
        author = member()
        unknown = encode(sample_image(7))
        copies = [
            post(author, 10 + i, channel_id=2 + i, attachments=[attachment(unknown)])
            for i in range(3)
        ]
        await self.bot.on_message(copies[0])
        await self.bot.on_message(copies[1])
        self.assertEqual(self.sent, [])
        await self.bot.on_message(copies[2])
        for copy in copies:
            copy.delete.assert_awaited_once()
        self.assertIn("3 channels", self.sent[0]["embed"].description)
        self.assertIn("3/3", str(self.sent[0]["embed"].fields))

    async def test_plain_chat_repeated_across_channels_is_left_alone(self):
        author = member()
        for i in range(4):
            message = post(author, 10 + i, channel_id=2 + i, content="good morning everyone")
            await self.bot.on_message(message)
            message.delete.assert_not_awaited()
        self.assertEqual(self.sent, [])

    async def test_moderators_bots_other_servers_and_log_channel_are_skipped(self):
        scam = [attachment(self.scam_png)]
        messages = [
            post(member(moderator=True), attachments=scam),
            post(member(bot=True), attachments=scam),
            post(member(), attachments=scam, guild_id=3),
            post(member(), attachments=scam, channel_id=999),
        ]
        for message in messages:
            await self.bot.on_message(message)
            message.delete.assert_not_awaited()
        self.assertEqual(self.sent, [])

    async def test_non_images_and_unreadable_downloads_are_not_flagged(self):
        response = SimpleNamespace(status=404, reason="Not Found")
        broken = attachment(self.scam_png)
        broken.read = AsyncMock(side_effect=discord.NotFound(response, "gone"))
        text_file = attachment(b"hello", filename="notes.txt")
        text_file.content_type = "text/plain"
        message = post(member(), attachments=[broken, text_file])
        with self.assertLogs("bot", level="WARNING"):
            await self.bot.on_message(message)
        message.delete.assert_not_awaited()
        text_file.read.assert_not_awaited()

    async def test_failed_timeout_is_reported_in_log(self):
        author = member()
        response = SimpleNamespace(status=403, reason="Forbidden")
        author.timeout = AsyncMock(side_effect=discord.Forbidden(response, "hierarchy"))
        with self.assertLogs("bot", level="WARNING"):
            await self.bot.on_message(post(author, attachments=[attachment(self.scam_png)]))
        self.assertIn("Timeout failed (HTTP 403)", str(self.sent[0]["embed"].fields))
        self.assertNotIn(author.id, self.bot.actioned)  # a later copy may retry

    async def test_other_actions(self):
        for action in ("none", "kick", "ban"):
            with self.subTest(action=action):
                self.bot.settings = Settings("unused", 999, scam_action=action)
                self.bot.actioned.clear()
                author = member()
                await self.bot.on_message(post(author, attachments=[attachment(self.scam_png)]))
                author.timeout.assert_not_awaited()
                self.assertEqual(author.kick.await_count, action == "kick")
                self.assertEqual(author.guild.ban.await_count, action == "ban")


if __name__ == "__main__":
    unittest.main()
