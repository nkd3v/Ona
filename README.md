# Discord moderator bot

A Python bot for one Discord server that:

- posts deleted-message logs into a moderator channel. It handles single deletions
  and bulk purges, with author IDs, channel IDs, message IDs, timestamps, cached
  message text, and attachment filenames/links. Each event includes a downloadable
  text transcript. Logged mentions do not send notifications.
- automatically deletes scam posts, such as the "MrBeast crypto casino" (wispwin.com)
  images posted by hacked accounts, and times out the poster. See
  [Scam filter](#scam-filter).

## Setup

1. Install [uv](https://docs.astral.sh/uv/getting-started/installation/).
2. Create an application in the [Discord Developer Portal](https://discord.com/developers/applications).
   In **Bot**, obtain a bot token and enable **Message Content Intent** under
   **Privileged Gateway Intents**. Keep the token private.
3. Use **OAuth2 → URL Generator** with the `bot` scope to invite it to your server.
   Give it **View Channels**, **Read Message History**, **Manage Messages**, and
   **Timeout Members** (use **Kick Members** or **Ban Members** instead if you change
   `SCAM_ACTION`). In a private moderator log channel, also grant **Send Messages**,
   **Embed Links**, and **Attach Files**. Administrator is unnecessary.
   In **Server Settings → Roles**, drag the bot's role above the roles of the members
   it should time out. Discord does not let a bot act on members with equal or
   higher roles.
4. Enable **Developer Mode** under Discord's **User Settings → Advanced**.
   Right-click your moderator log channel and choose **Copy Channel ID**.
5. From this directory, run:

   ```sh
   cp .env.example .env
   ```

   Edit `.env` and fill in `DISCORD_TOKEN` and `DISCORD_LOG_CHANNEL_ID`, then run:

   ```sh
   uv sync --locked --system-certs
   uv run --system-certs bot.py
   ```

6. Send a message in another channel the bot can view, then delete it. Check the
   moderator log channel for an embed and transcript. Try a bulk purge too.

The bot only logs the server containing the configured log channel. Direct messages
and deletions inside the log channel are ignored. Keep the process running on your
computer or a host to receive deletion events. Startup validates channel access;
permission or delivery failures are reported to the process console.

## Scam filter

The bot checks every new message in the server, including forwarded messages, and
deletes it when:

1. **An image matches a known scam image.** The bot fingerprints each uploaded image
   and compares it with the built-in wispwin.com scam images and anything in
   `scam-images/`. Re-saved, resized, or recompressed copies still match. Heavily
   cropped or mirrored copies do not.
2. **It links to a blocked domain** in `BLOCKED_DOMAINS` (default: `wispwin.com`).
3. **One person posts the same files or link in 3 channels within 2 minutes**, which
   is how hacked accounts usually spam. Every copy is deleted. Plain text without a
   file or link is never counted, so normal chat is left alone.

After deleting, the bot applies `SCAM_ACTION` once per person: a 1-day timeout by
default, or `none`, `kick`, or `ban` (ban also deletes their last hour of messages).
Timeouts can be removed from the member's profile. The moderator log channel gets a
red "Scam post removed" embed showing who posted it, where, why it matched, what was
done, and a transcript. These deletions are not logged a second time as ordinary
deletions.

Members with **Manage Messages** (moderators), bots, and the log channel are never
scanned. To catch a new scam, save its images into `scam-images/` or add its domain
to `BLOCKED_DOMAINS`, then restart the bot. If the filter removes something it
should not, lower `SCAM_IMAGE_MATCH_DISTANCE` or set `SPAM_REPEAT_CHANNELS=0`.

Images up to 10 MB are downloaded for checking. Text inside images is not read,
so a new scam with different images is only caught by the cross-channel rule
until you add its images or domain. Startup logs a warning if the bot lacks the
permissions for deleting or timing out.

## What can be recovered?

Discord deletion events do not include deleted text. The bot uses discord.py's
in-memory cache, configured by `MESSAGE_CACHE_SIZE` (default: 10,000 recent messages
across all visible channels). Older messages, messages sent before startup, and
messages unseen while disconnected may lack content; those deletions still produce
a log with the available IDs. Restarting clears the cache. There is no history
backfill or local message database. Message edits update the library cache.

The transcript records text and attachment metadata, not copies of uploaded files,
rich embeds, stickers, or polls. Attachment URLs may expire or stop working after
deletion. The bot does not identify who deleted a message. Delivery is best effort;
failed sends are reported in the console and are not stored for later replay.

Make the log channel private to your moderation team. Transcripts are posted to
Discord and remain there until removed, even though the bot's own cache is temporary.

See the official [intents guide](https://discordpy.readthedocs.io/en/stable/intents.html)
and [raw deletion event documentation](https://discordpy.readthedocs.io/en/stable/api.html#discord.on_raw_message_delete)
for the Discord API requirements and cache behavior.

## Development

```sh
uv run --system-certs python -m unittest discover -s tests -v
uv run --system-certs ruff check .
uv run --system-certs ruff format --check .
```

Tests simulate Discord events locally. A real token and server are needed for the
live send/delete check described above.
