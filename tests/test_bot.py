import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import discord

import bot as bot_module
import scam_filter
from bot import (
    LogChannelStore,
    ModeratorBot,
    Settings,
    Trap,
    TrapStore,
    format_minutes,
    shorten,
    transcript,
)
from tests.test_scam_filter import encode, sample_image


def text_channel(send, channel_id=999, guild_id=1):
    channel = MagicMock(spec=discord.TextChannel)
    channel.id = channel_id
    channel.guild = SimpleNamespace(id=guild_id)
    channel.mention = f"<#{channel_id}>"
    channel.send = send
    return channel


def make_bot(test, send, **settings):
    """A bot whose server 1 logs to channel 999, with settings saved in a temp folder."""
    folder = tempfile.TemporaryDirectory()
    test.addCleanup(folder.cleanup)
    bot = ModeratorBot(Settings("unused", data_dir=Path(folder.name), **settings))
    channel = text_channel(send)
    bot.get_channel = MagicMock(side_effect=lambda cid: channel if cid == channel.id else None)
    bot.store.channels = {1: 999}
    return bot, channel


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
        settings = Settings.from_env({"DISCORD_TOKEN": "secret"})
        self.assertEqual(settings.cache_size, 10_000)
        self.assertEqual(settings.data_dir, bot_module.BASE_DIR / "data")
        self.assertFalse(hasattr(settings, "log_channel_id"))

    def test_rejects_missing_placeholder_and_invalid_config(self):
        for env in (
            {},
            {"DISCORD_TOKEN": "replace_with_your_bot_token"},
            {"DISCORD_TOKEN": "secret", "MESSAGE_CACHE_SIZE": "abc"},
            {"DISCORD_TOKEN": "secret", "MESSAGE_CACHE_SIZE": "-1"},
        ):
            with self.subTest(env=env), self.assertRaises(ValueError):
                Settings.from_env(env)

    def test_scam_settings_defaults_and_overrides(self):
        base = {"DISCORD_TOKEN": "secret"}
        settings = Settings.from_env(base)
        self.assertEqual(settings.scam_action, "timeout")
        self.assertEqual(settings.timeout_minutes, 1440)
        self.assertEqual(settings.blocked_domains, ("wispwin.com",))
        self.assertEqual(settings.scam_images_dir, bot_module.BASE_DIR / "scam-images")
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
        self.assertEqual(settings.scam_images_dir, Path("/tmp/x"))
        self.assertEqual(Settings.from_env(base | {"BLOCKED_DOMAINS": ""}).blocked_domains, ())

    def test_rejects_invalid_scam_settings(self):
        base = {"DISCORD_TOKEN": "secret"}
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
        self.sent = []

        async def send(**kwargs):
            self.sent.append(
                {
                    "embed": kwargs["embed"],
                    "text": kwargs["file"].fp.read().decode("utf-8"),
                    "mentions": kwargs["allowed_mentions"].to_dict(),
                }
            )

        self.bot, self.channel = make_bot(self, send)

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
        self.bot.store.channels = {}  # no log channel set
        await self.bot.log_deletion(1, 2, {10}, {})
        self.bot.store.channels = {1: 12345}  # channel was deleted
        await self.bot.log_deletion(1, 2, {10}, {})
        self.assertEqual(self.sent, [])

    async def test_send_failure_is_reported_without_crashing_handler(self):
        response = SimpleNamespace(status=403, reason="Forbidden")
        self.channel.send = AsyncMock(side_effect=discord.Forbidden(response, "Denied"))
        with self.assertLogs("bot", level="ERROR") as captured:
            await self.bot.log_deletion(1, 2, {10}, {10: message(content="private content")})
        self.assertIn("Could not log", captured.output[0])
        self.assertNotIn("private content", captured.output[0])

    async def test_startup_warns_about_problems_without_stopping(self):
        guild = SimpleNamespace(
            id=1,
            me=SimpleNamespace(
                guild_permissions=SimpleNamespace(manage_messages=True, moderate_members=False)
            ),
        )
        gone = SimpleNamespace(id=2, me=None)
        self.channel.permissions_for.return_value = SimpleNamespace(
            view_channel=True, send_messages=True, embed_links=True, attach_files=False
        )
        self.bot.store.channels = {1: 999, 2: 555}
        self.bot.close = AsyncMock()
        with (
            patch.object(type(self.bot), "guilds", new_callable=PropertyMock) as guilds,
            self.assertLogs("bot", level="WARNING") as captured,
        ):
            guilds.return_value = [guild, gone]
            await self.bot.on_ready()
        self.bot.close.assert_not_awaited()
        output = "\n".join(captured.output)
        self.assertIn("attach_files", output)
        self.assertIn("moderate_members", output)
        self.assertIn("555 is gone", output)


class LogChannelStoreTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "data" / "log_channels.json"

    def test_saves_and_reloads_per_server_channels(self):
        store = LogChannelStore(self.path)
        self.assertEqual(store.channels, {})
        store.set(1, 100)
        store.set(2, 200)
        store.set(1, 101)
        self.assertEqual(LogChannelStore(self.path).channels, {1: 101, 2: 200})
        store.set(2, None)
        self.assertEqual(LogChannelStore(self.path).channels, {1: 101})

    def test_unreadable_file_is_reported(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text("not json")
        with self.assertRaises(ValueError):
            LogChannelStore(self.path)


def interaction(guild_id=1):
    guild = SimpleNamespace(
        id=guild_id,
        me=SimpleNamespace(
            guild_permissions=SimpleNamespace(manage_messages=True, moderate_members=True)
        ),
    )
    return SimpleNamespace(
        guild=guild,
        guild_id=guild_id,
        user="admin",
        response=SimpleNamespace(send_message=AsyncMock()),
    )


ALL_LOG_PERMISSIONS = SimpleNamespace(
    view_channel=True, send_messages=True, embed_links=True, attach_files=True
)


class LogChannelCommandTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.bot, self.channel = make_bot(self, AsyncMock())
        self.bot.store.channels = {}
        self.commands = self.bot.tree.get_command("logchannel")

    async def asyncTearDown(self):
        await self.bot.close()

    def answer(self, action):
        action.response.send_message.assert_awaited_once()
        call = action.response.send_message.await_args
        self.assertTrue(call.kwargs["ephemeral"])
        return call.args[0]

    async def run_command(self, name, action, *args):
        await self.commands.get_command(name).callback(self.commands, action, *args)

    def test_only_server_managers_see_the_command(self):
        data = self.commands.to_dict(self.bot.tree)
        self.assertEqual(int(data["default_member_permissions"]), 32)  # Manage Server
        self.assertFalse(data["dm_permission"])

    async def test_set_saves_channel_and_posts_confirmation(self):
        self.channel.permissions_for.return_value = ALL_LOG_PERMISSIONS
        action = interaction()
        await self.run_command("set", action, self.channel)
        self.channel.send.assert_awaited_once()
        self.assertIn("<#999>", self.answer(action))
        self.assertEqual(LogChannelStore(self.bot.store.path).channels, {1: 999})
        self.assertIs(self.bot.log_channel_for(1), self.channel)

    async def test_set_refuses_channel_without_permissions(self):
        self.channel.permissions_for.return_value = SimpleNamespace(
            view_channel=True, send_messages=False, embed_links=True, attach_files=True
        )
        action = interaction()
        await self.run_command("set", action, self.channel)
        self.assertIn("send_messages", self.answer(action))
        self.channel.send.assert_not_awaited()
        self.assertEqual(self.bot.store.channels, {})

    async def test_set_reports_failed_test_post(self):
        self.channel.permissions_for.return_value = ALL_LOG_PERMISSIONS
        response = SimpleNamespace(status=403, reason="Forbidden")
        self.channel.send = AsyncMock(side_effect=discord.Forbidden(response, "Denied"))
        action = interaction()
        await self.run_command("set", action, self.channel)
        self.assertIn("HTTP 403", self.answer(action))
        self.assertEqual(self.bot.store.channels, {})

    async def test_show_and_off(self):
        action = interaction()
        await self.run_command("show", action)
        self.assertIn("No log channel", self.answer(action))

        self.bot.store.set(1, 999)
        action = interaction()
        await self.run_command("show", action)
        self.assertIn("<#999>", self.answer(action))

        action = interaction()
        await self.run_command("off", action)
        self.assertIn("off", self.answer(action))
        self.assertEqual(LogChannelStore(self.bot.store.path).channels, {})


def member(member_id=42, moderator=False, bot=False):
    author = MagicMock(spec=discord.Member)
    author.id = member_id
    author.bot = bot
    author.guild_permissions = SimpleNamespace(manage_messages=moderator)
    author.timeout = AsyncMock()
    author.kick = AsyncMock()
    author.guild = SimpleNamespace(id=1, ban=AsyncMock())
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
        self.sent = []

        async def send(**kwargs):
            self.sent.append(
                {"embed": kwargs["embed"], "text": kwargs["file"].fp.read().decode("utf-8")}
            )

        self.bot, _ = make_bot(self, send, scam_images_dir=Path("/nonexistent"))
        self.scam_png = encode(sample_image(1))
        self.bot.known_images[scam_filter.image_hash(self.scam_png)] = "test scam"

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
        self.assertNotIn((1, author.id), self.bot.actioned)  # a later copy may retry

    async def test_other_actions(self):
        for action in ("none", "kick", "ban"):
            with self.subTest(action=action):
                self.bot.settings = Settings("unused", scam_action=action)
                self.bot.actioned.clear()
                author = member()
                await self.bot.on_message(post(author, attachments=[attachment(self.scam_png)]))
                author.timeout.assert_not_awaited()
                self.assertEqual(author.kick.await_count, action == "kick")
                self.assertEqual(author.guild.ban.await_count, action == "ban")


class TrapStoreTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "data" / "trap_channels.json"

    def test_saves_and_reloads_per_server_traps(self):
        store = TrapStore(self.path)
        self.assertEqual(store.traps, {})
        store.set(1, Trap(50, timeout_minutes=60, delete_minutes=10, notice_id=7, count=3))
        store.set(2, Trap(60))
        self.assertEqual(
            TrapStore(self.path).traps,
            {1: Trap(50, 60, 10, 7, 3), 2: Trap(60, 1440, 60, None, 0)},
        )
        store.set(2, None)
        self.assertEqual(set(TrapStore(self.path).traps), {1})

    def test_unreadable_file_is_reported(self):
        self.path.parent.mkdir(parents=True)
        for content in ("not json", '{"1": {"timeout_minutes": 5}}'):
            self.path.write_text(content)
            with self.subTest(content=content), self.assertRaises(ValueError):
                TrapStore(self.path)


TRAP_CHANNEL = 50


def trap_post(author, message_id, channel, minutes_ago=0, guild_id=1):
    message = post(author, message_id, guild_id=guild_id)
    message.channel = channel
    message.created_at = datetime(2026, 1, 1, 12, tzinfo=UTC) - timedelta(minutes=minutes_ago)
    return message


def message_channel(channel_id):
    return SimpleNamespace(id=channel_id, delete_messages=AsyncMock())


class TrapChannelBotTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.sent = []

        async def send(**kwargs):
            self.sent.append(
                {"embed": kwargs["embed"], "text": kwargs["file"].fp.read().decode("utf-8")}
            )

        self.bot, self.log_channel = make_bot(self, send, scam_images_dir=Path("/nonexistent"))
        self.trap_channel = text_channel(AsyncMock(), channel_id=TRAP_CHANNEL)
        self.notice = SimpleNamespace(edit=AsyncMock())
        self.trap_channel.get_partial_message.return_value = self.notice
        channels = {999: self.log_channel, TRAP_CHANNEL: self.trap_channel}
        self.bot.get_channel = MagicMock(side_effect=channels.get)
        self.bot.traps.set(1, Trap(TRAP_CHANNEL, notice_id=77))
        self.cache = []
        patcher = patch.object(
            ModeratorBot, "cached_messages", new_callable=PropertyMock, return_value=self.cache
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        # Messages seen in the trap channel and two other channels.
        self.trap = message_channel(TRAP_CHANNEL)
        self.general = message_channel(2)
        self.memes = message_channel(3)

    async def asyncTearDown(self):
        await self.bot.close()

    async def test_post_in_trap_deletes_recent_messages_times_out_and_counts(self):
        spammer, bystander = member(42), member(43)
        recent = [
            trap_post(spammer, 1, self.general, minutes_ago=5),
            trap_post(spammer, 2, self.general, minutes_ago=50),
            trap_post(spammer, 3, self.memes, minutes_ago=1),
        ]
        old = trap_post(spammer, 4, self.general, minutes_ago=61)
        other_server = trap_post(spammer, 5, self.general, minutes_ago=1, guild_id=3)
        someone_else = trap_post(bystander, 6, self.general, minutes_ago=1)
        bait = trap_post(spammer, 9, self.trap)
        self.cache.extend([*recent, old, other_server, someone_else, bait])

        await self.bot.on_message(bait)

        self.general.delete_messages.assert_awaited_once()
        bulk = self.general.delete_messages.await_args.args[0]
        self.assertEqual([m.id for m in bulk], [1, 2])
        recent[2].delete.assert_awaited_once()
        bait.delete.assert_awaited_once()
        for kept in (old, other_server, someone_else):
            kept.delete.assert_not_awaited()
        spammer.timeout.assert_awaited_once()
        self.assertEqual(spammer.timeout.await_args.args[0], timedelta(days=1))

        self.assertEqual(len(self.sent), 1)
        embed = self.sent[0]["embed"]
        self.assertEqual(embed.title, "Trap channel triggered")
        self.assertIn(f"<#{TRAP_CHANNEL}>", embed.description)
        self.assertIn("4/4", str(embed.fields))
        self.assertIn("Timed out for 1 day", str(embed.fields))
        self.assertIn("trap channel", self.sent[0]["text"])

        self.assertEqual(TrapStore(self.bot.traps.path).traps[1].count, 1)
        self.trap_channel.get_partial_message.assert_called_once_with(77)
        view = self.notice.edit.await_args.kwargs["view"]
        self.assertEqual(view.children[0].label, "Timeouts: 1")
        self.assertTrue(view.children[0].disabled)

        # Discord's delete events for these are not logged as ordinary deletions.
        await self.bot.on_raw_bulk_message_delete(
            SimpleNamespace(guild_id=1, channel_id=2, message_ids={1, 2}, cached_messages=bulk)
        )
        await self.bot.on_raw_message_delete(
            SimpleNamespace(guild_id=1, channel_id=TRAP_CHANNEL, message_id=9, cached_message=bait)
        )
        self.assertEqual(len(self.sent), 1)

    async def test_second_message_is_deleted_without_second_timeout_or_count(self):
        spammer = member()
        for message_id in (9, 10):
            await self.bot.on_message(trap_post(spammer, message_id, self.trap))
        spammer.timeout.assert_awaited_once()
        self.assertEqual(self.bot.traps.traps[1].count, 1)
        self.assertIn("Already timed out", str(self.sent[1]["embed"].fields))

    async def test_works_without_a_log_channel_and_skips_scam_filter(self):
        self.bot.store.channels = {}
        spammer = member()
        bait = trap_post(spammer, 9, self.trap)
        await self.bot.on_message(bait)
        bait.delete.assert_awaited_once()
        spammer.timeout.assert_awaited_once()
        self.assertEqual(self.sent, [])
        self.assertEqual(self.bot.traps.traps[1].count, 1)

    async def test_moderators_bots_and_other_channels_are_ignored(self):
        messages = [
            trap_post(member(moderator=True), 9, self.trap),
            trap_post(member(bot=True), 10, self.trap),
            trap_post(member(), 11, self.general),
        ]
        for message in messages:
            await self.bot.on_message(message)
            message.delete.assert_not_awaited()
            message.author.timeout.assert_not_awaited()
        self.assertEqual(self.bot.traps.traps[1].count, 0)

    async def test_failed_timeout_is_reported_and_not_counted(self):
        spammer = member()
        response = SimpleNamespace(status=403, reason="Forbidden")
        spammer.timeout = AsyncMock(side_effect=discord.Forbidden(response, "hierarchy"))
        with self.assertLogs("bot", level="WARNING"):
            await self.bot.on_message(trap_post(spammer, 9, self.trap))
        self.assertIn("Timeout failed (HTTP 403)", str(self.sent[0]["embed"].fields))
        self.assertEqual(self.bot.traps.traps[1].count, 0)
        self.notice.edit.assert_not_awaited()
        self.assertNotIn((1, spammer.id), self.bot.trapped)  # a later message may retry


class TrapChannelCommandTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.bot, self.log_channel = make_bot(self, AsyncMock())
        self.channel = text_channel(
            AsyncMock(return_value=SimpleNamespace(id=500)), channel_id=TRAP_CHANNEL
        )
        self.channel.permissions_for.return_value = SimpleNamespace(
            view_channel=True,
            send_messages=True,
            embed_links=True,
            read_message_history=True,
            manage_messages=True,
        )
        self.old_notice = SimpleNamespace(id=400, channel=self.channel, delete=AsyncMock())
        self.channel.get_partial_message.return_value = self.old_notice
        channels = {999: self.log_channel, TRAP_CHANNEL: self.channel}
        self.bot.get_channel = MagicMock(side_effect=channels.get)
        self.commands = self.bot.tree.get_command("trapchannel")

    async def asyncTearDown(self):
        await self.bot.close()

    def answer(self, action):
        action.response.send_message.assert_awaited_once()
        return action.response.send_message.await_args.args[0]

    async def run_command(self, name, action, *args):
        await self.commands.get_command(name).callback(self.commands, action, *args)

    def test_command_options(self):
        data = self.commands.to_dict(self.bot.tree)
        self.assertEqual(int(data["default_member_permissions"]), 32)  # Manage Server
        options = {o["name"]: o for o in data["options"][0]["options"]}
        self.assertEqual(list(options), ["channel", "timeout", "delete_messages"])
        self.assertEqual(
            [c["value"] for c in options["timeout"]["choices"]], [60, 1440, 10080, 40320]
        )

    async def test_set_posts_notice_saves_and_replaces_old_notice(self):
        self.bot.traps.set(1, Trap(TRAP_CHANNEL, notice_id=400, count=5))
        action = interaction()
        week = discord.app_commands.Choice(name="1 week", value=10080)
        await self.run_command("set", action, self.channel, week, None)

        kwargs = self.channel.send.await_args.kwargs
        self.assertIn("DO NOT SEND", kwargs["embed"].title)
        self.assertIn("7 days", kwargs["embed"].description)
        self.assertEqual(kwargs["view"].children[0].label, "Timeouts: 5")
        self.assertEqual(
            TrapStore(self.bot.traps.path).traps[1],
            Trap(TRAP_CHANNEL, timeout_minutes=10080, delete_minutes=60, notice_id=500, count=5),
        )
        self.assertIn("timed out for 7 days", self.answer(action))
        self.old_notice.delete.assert_awaited_once()

    async def test_set_refuses_log_channel_and_missing_permissions(self):
        action = interaction()
        await self.run_command("set", action, self.log_channel, None, None)
        self.assertIn("log channel", self.answer(action))

        self.channel.permissions_for.return_value.manage_messages = False
        action = interaction()
        await self.run_command("set", action, self.channel, None, None)
        self.assertIn("manage_messages", self.answer(action))
        self.channel.send.assert_not_awaited()
        self.assertEqual(self.bot.traps.traps, {})

    async def test_show_and_off(self):
        action = interaction()
        await self.run_command("show", action)
        self.assertIn("No trap channel", self.answer(action))

        self.bot.traps.set(1, Trap(TRAP_CHANNEL, notice_id=400, count=2))
        action = interaction()
        await self.run_command("show", action)
        self.assertIn("Caught so far: 2", self.answer(action))

        action = interaction()
        await self.run_command("off", action)
        self.assertIn("off", self.answer(action))
        self.assertEqual(TrapStore(self.bot.traps.path).traps, {})
        self.old_notice.delete.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
