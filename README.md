# Discord moderator bot

A Python bot for Discord servers that:

- posts deleted-message logs into a moderator channel. It handles single deletions
  and bulk purges, with author IDs, channel IDs, message IDs, timestamps, cached
  message text, and attachment filenames/links. Each event includes a downloadable
  text transcript. Logged mentions do not send notifications.
- posts edited-message logs into the same channel, showing the text before and after
  the edit, any attachments removed, and a link to the message. See
  [Edited messages](#edited-messages).
- automatically deletes scam posts, such as the "MrBeast crypto casino" (wispwin.com,
  fapwin.com) images posted by hacked accounts, and times out the poster. It can also
  read the text in images to catch new versions of the scam. See
  [Scam filter](#scam-filter).
- runs a trap channel: anyone who posts in a channel marked "do not send messages
  here" is timed out and their recent messages are deleted. Spam bots post
  everywhere, so they fall for it. See [Trap channel](#trap-channel).
- adds `/timeout` for any length, from minutes to years or permanent, beyond
  Discord's 28-day limit. See [Long and permanent timeouts](#long-and-permanent-timeouts).

## Setup

1. Install [uv](https://docs.astral.sh/uv/getting-started/installation/).
2. Create an application in the [Discord Developer Portal](https://discord.com/developers/applications).
   In **Bot**, obtain a bot token and enable **Message Content Intent** under
   **Privileged Gateway Intents**. Keep the token private.
3. Use **OAuth2 → URL Generator** with the `bot` and `applications.commands` scopes to
   invite it to your server.
   Give it **View Channels**, **Send Messages**, **Embed Links**, **Read Message History**,
   **Manage Messages**, and **Timeout Members** (use **Kick Members** or **Ban Members** instead if you change
   `SCAM_ACTION`). In a private moderator log channel, also grant **Send Messages**,
   **Embed Links**, and **Attach Files**. Administrator is unnecessary.
   In **Server Settings → Roles**, drag the bot's role above the roles of the members
   it should time out. Discord does not let a bot act on members with equal or
   higher roles.
4. From this directory, run:

   ```sh
   cp .env.example .env
   ```

   Edit `.env` and fill in `DISCORD_TOKEN`, then run:

   ```sh
   uv sync --locked --system-certs
   uv run --system-certs bot.py
   ```

   To run it on a hosting panel instead, see [Hosting](#hosting).
5. In your server, run `/logchannel set` and pick a private moderator channel.
   See [Choosing the log channel](#choosing-the-log-channel).
6. Optionally, run `/trapchannel set` to catch spam bots. See [Trap channel](#trap-channel).
7. Send a message in another channel the bot can view, then delete it. Check the
   moderator log channel for an embed and transcript. Try a bulk purge too, and edit
   a message to see an edit log.

Direct messages and deletions inside the log channel are ignored. Keep the process
running on your computer or a host to receive deletion events. Permission or
delivery failures are reported to the process console.

## Choosing the log channel

Each server picks its own log channel in Discord. There is no channel setting in
`.env`. Only members with **Manage Server** see these commands. Admins can change who
may use them in **Server Settings → Integrations**.

| Command | What it does |
| --- | --- |
| `/logchannel set channel:` | Log this server's deleted and edited messages and scam removals in that channel |
| `/logchannel show` | Show the current log channel |
| `/logchannel off` | Stop logging and the scam filter in this server |

Before saving, `/logchannel set` checks that the bot can view the channel and send
messages, embeds, and files there, then posts a confirmation in it. It also warns if
the bot lacks the server permissions the scam filter needs. The bot logs and
filters only servers that have a log channel. Choices are saved in
`data/log_channels.json` (change the folder with `DATA_DIR`), so they survive
restarts. Keep that folder when you move or redeploy the bot.

New slash commands can take a few minutes to appear in Discord the first time the
bot starts.

## Hosting

The bot runs on Pterodactyl-style hosting panels, such as Bot-Hosting.net, that
offer a Python server:

1. Choose Python 3.11 or newer.
2. Upload the project files. Leave out `.venv/`, `.env`, and `__pycache__/`.
   The panel installs the packages listed in `requirements.txt` at startup.
3. Set the startup file to `bot.py`. `main.py` also works, for panels that default to it.
4. Add `DISCORD_TOKEN` as an environment variable, marked secret if the panel allows,
   or upload a `.env` file next to `bot.py`. Other settings from `.env.example` are
   optional. To read text in images, also add `OCR_SPACE_API_KEY` (see
   [Scam filter](#scam-filter)).
5. Start the server. The console should show `Logged in as ...`. Then run
   `/logchannel set` in Discord.

The bot stops at startup only if `DISCORD_TOKEN` is missing or wrong, or if
**Message Content Intent** is off in the Developer Portal. The console says which.

## Scam filter

The bot checks every new message in the server, including forwarded messages, and
deletes it when:

1. **An image matches a known scam image.** The bot fingerprints each uploaded image
   and compares it with the built-in wispwin.com and fapwin.com scam images and
   anything in `scam-images/`. Re-saved, resized, or recompressed copies still match.
   Heavily cropped or mirrored copies do not.
2. **It links to a blocked domain** in `BLOCKED_DOMAINS` (default: `wispwin.com`,
   `fapwin.com`).
3. **The text in an image contains a scam word or a blocked domain** (only with an
   OCR key, see [Reading text in images](#reading-text-in-images)). The default words
   are `mrbeast`, `crypto` and `casino`.
4. **One person posts the same files or link in 3 channels within 2 minutes**, which
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

Images up to 10 MB are downloaded for checking. Startup logs a warning if the bot
lacks the permissions for deleting or timing out.

### Reading text in images

The bot sends images to [OCR.space](https://ocr.space/ocrapi), a free online text
reader, so it uses almost no memory on your host. To turn it on:

1. Register for a free API key at <https://ocr.space/ocrapi>. The key arrives by email.
2. Set `OCR_SPACE_API_KEY` to that key in `.env` or your host's environment variables.
3. Restart the bot.

Without a key, text in images is not read, and the startup log says so.

The bot reads an image only when it is not already a known scam image. It sends a
shrunk JPEG copy (under 1 MB), takes 1 to 5 seconds per image, and remembers the
last 500 results so reposts of the same image cost nothing. The free plan allows
25,000 images a month and 500 a day. If OCR.space fails twice in a row, for example
because the daily limit is used up, the bot stops reading images for 5 minutes and
logs a warning. The other checks keep working.

`SCAM_IMAGE_WORDS` sets the words, separated by commas. Case, spaces and punctuation
are ignored, so `mrbeast` also matches "Mr. Beast", and a word also matches inside a
longer word, so `crypto` matches "cryptocurrency". Any image mentioning these words
is removed, including harmless ones such as a crypto price chart, so remove a word
if your server talks about it. Images posted by moderators are never checked.

Images sent for reading leave your server and go to OCR.space. Their
[privacy policy](https://ocr.space/privacypolicy) says they do not keep them.

## Trap channel

Spam bots and hacked accounts post in every channel they can. A trap channel is a
channel that every member can see and post in, with a notice telling people not to.
Anyone who posts there anyway is caught:

1. Their message is deleted, along with all their messages from the last hour (or the
   period you choose) in every channel the bot can see.
2. They are timed out for 1 day (or the period you choose, up to permanent).
3. The moderator log channel gets a red "Trap channel triggered" embed with what was
   deleted, the result, and a transcript.

When you set it up, the bot posts a "DO NOT SEND MESSAGES IN THIS CHANNEL" notice in
the channel: one box with the warning and a greyed-out **Timeouts:**
counter inside it that goes up with each catch. Run `/trapchannel set` again to replace a
notice from an older version straight away; otherwise it changes on the next catch.

| Command | What it does |
| --- | --- |
| `/trapchannel set channel: timeout: delete_messages:` | Make that channel a trap and post the notice. `timeout` is any duration, such as `1h`, `1d` (default), `2w`, `6 months` or `permanent` (see [Long and permanent timeouts](#long-and-permanent-timeouts)). `delete_messages` is how far back to delete: 10 minutes, 1 hour (default), 6 hours or 1 day |
| `/trapchannel show` | Show the trap channel, its settings and the count |
| `/trapchannel off` | Stop the trap and remove its notice |

Like `/logchannel`, only members with **Manage Server** see these commands. Running
`/trapchannel set` again changes the settings or moves the trap, replacing the old
notice and keeping the count. The trap works without a log channel, but you only get
reports of each catch if one is set.

Set up the channel so that:

- members can see it and send messages in it (otherwise nobody can be caught),
- the bot has **View Channel**, **Send Messages**, **Embed Links**, **Read Message
  History** and **Manage Messages** there (`/trapchannel set` checks this), and
- the bot's role is above the roles of the members it should time out.

Moderators (members with **Manage Messages**) and bots are never caught, so staff can
post in the channel. A spam burst gets one timeout and one count per person. Settings
are saved in `data/trap_channels.json`.

Discord has no way to delete one person's messages short of banning them, so the bot
deletes the messages it has in its memory (see below). Messages sent before the bot
last started, or older than its cache, are not deleted.

## Long and permanent timeouts

Discord's own timeout stops at 28 days. These commands go further:

| Command | What it does |
| --- | --- |
| `/timeout member: duration: reason:` | Time out a member. `duration` is free text with suggestions: `30m`, `2h`, `3d`, `2w`, `1d 12h`, `6 months`, `1 year` (up to 10 years) or `permanent` |
| `/untimeout member:` | End a member's timeout, including a permanent one |

Only members with **Timeout Members** see them, and, as in Discord, you can only time
out members whose highest role is below yours and the bot's. Administrators and the
server owner cannot be timed out. Each use is logged in the log channel.

Timeouts of up to 28 days are set once. For longer or permanent ones the bot sets a
block of just under 28 days, saves it in `data/long_timeouts.json`, and checks every
hour, renewing any block that ends within 2 days. If the bot was offline when a block
ran out, it renews on its next start. The trap channel uses the same system when its
`timeout` is longer than 28 days.

The bot stops renewing when:

- the end date is reached,
- someone runs `/untimeout`, or
- a moderator removes or changes the timeout from Discord's member menu. The log
  channel gets a "Long timeout stopped" note.

A timeout survives leaving and rejoining the server until its current block ends.
The bot cannot see members join (that needs a privileged intent), so if a member
rejoins after that and posts, the bot deletes the post and times them out again.
For someone who should never come back, a ban is still the better tool.

## Edited messages

When a member edits a message, the log channel gets a blue "Message edited" embed
with the author, channel, a **Jump to message** link, the text before and after, and
any attachments the edit removed. The attached transcript has the full text of both
versions and attachment links. Long text is cut short in the embed but not in the
transcript.

The old text comes from the bot's message cache (see below). For a message that is
not in the cache, the log shows only the new text. Edits by bots, including this
one, and edits inside the log channel are not logged. Updates that do not change the
text or files, such as a link preview loading or a message being pinned, are ignored.

## What can be recovered?

Discord deletion events do not include deleted text. The bot uses discord.py's
in-memory cache, configured by `MESSAGE_CACHE_SIZE` (default: 10,000 recent messages
across all visible channels). Older messages, messages sent before startup, and
messages unseen while disconnected may lack content; those deletions still produce
a log with the available IDs. Restarting clears the cache. There is no history
backfill or local message database. Message edits update the cache, so a deletion
log shows the latest version of an edited message.

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
