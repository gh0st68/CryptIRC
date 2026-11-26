<p align="center">
  <img src="branding/cryptirc-mark.svg" width="72" height="72" alt="CryptIRC logo">
</p>

<h1 align="center">CryptIRC</h1>

<p align="center"><strong>IRC that stays connected.</strong><br>Self-hosted. Encrypted history. All your devices.</p>

<p align="center">
  <a href="https://cryptirc.com/news/#v0-5-20"><img src="https://img.shields.io/badge/version-0.5.20-00b894?style=flat-square" alt="Version 0.5.20"></a>
  <img src="https://img.shields.io/badge/server-Linux-5a7085?style=flat-square" alt="Linux server">
  <img src="https://img.shields.io/badge/client-desktop%20%C2%B7%20mobile%20%C2%B7%20terminal-5a7085?style=flat-square" alt="Desktop, mobile, and terminal clients">
</p>

<p align="center">
  <a href="https://client.twistednet.org/cryptirc/"><strong>Open the free hosted client</strong></a> &nbsp;·&nbsp;
  <a href="#get-started">Install on Linux</a> &nbsp;·&nbsp;
  <a href="https://github.com/gh0st68/CryptIRC/releases/latest">Download an app</a> &nbsp;·&nbsp;
  <a href="https://cryptirc.com/">Website</a> &nbsp;·&nbsp;
  <a href="https://gh0st68.github.io/CryptIRC/">Theme gallery</a>
</p>

CryptIRC keeps your IRC networks connected on your server while you move between devices. Catch up on encrypted history, join the conversation from a browser or app, and make the interface your own.

**[Get started](#get-started)** · **[Clients](#clients)** · **[Features](#features)** · **[Privacy](#privacy-and-encryption)** · **[CryptIRC MCP](#cryptirc-mcp)** · **[Translation](#translation)** · **[Passkeys](#passkey-sign-in)** · **[Commands](#commands-and-shortcuts)** · **[Configuration](#configuration)**

<a id="quick-start"></a>
<a id="deployment"></a>

## Get started

### Use the free hosted client

Open [client.twistednet.org/cryptirc](https://client.twistednet.org/cryptirc/) and create an account. You can add TwistedNET or other IRC networks from the same browser client.

### Install on your own Linux server

On Debian 12 or Ubuntu 22.04 or later, run the interactive installer.

```bash
git clone https://github.com/gh0st68/CryptIRC.git
cd CryptIRC
sudo bash deploy/deploy.sh
```

On Arch Linux, run `sudo bash deploy/deploy-arch.sh` from the same checkout.

The installer sets up both Rust services, Caddy, and systemd. It walks you through HTTPS, registration, and creating your first account. Email setup is optional. The web service and IRC daemon run separately, so routine web updates can keep IRC connections open.

See the [installation guide](INSTALL.md) for requirements and manual setup, or follow the [web install and update guide](https://cryptirc.com/install/). The [deployment guide](deploy/README.md) covers prebuilt binaries and service updates.

<p align="center">
  <img src="screenshots/desktop.png?v=20261016" width="960" alt="CryptIRC desktop interface preview with example conversations and a grouped user list">
</p>

## CryptIRC MCP

**Give your AI client real IRC tools.** CryptIRC ships a built-in Model Context Protocol (MCP) server that connects your AI client to the IRC account you already use. Ask it to find an old message, join a channel, or run a moderation command without leaving your AI session. Its actions appear in your regular CryptIRC client, and your existing IRC permissions apply.

| Ask your AI client to… | What CryptIRC can do |
| --- | --- |
| “Show my connected networks and who's in `#dev`.” | List connections, channels, topics, and members. |
| “Find the messages in `#support` that mention the upgrade.” | Read and search IRC history while your vault is unlocked. |
| “Join `#dev` and send a message that I'm here.” | Join and leave channels. Send channel messages, DMs, notices, and IRC actions. |
| “Set the topic in `#dev` to today's release.” | Run raw IRC commands, including network-specific verbs such as `SAMODE` and IRCv3 message tags. The IRC server applies your existing permissions. |
| “Show what's in my CryptIRC notepad.” | Read and update your notepad while the vault is unlocked. |
| “Change this network’s quit message and turn on Do Not Disturb.” | Edit connection settings through `irc_network`, and manage synced preferences, notifications, and bots through `cryptirc_settings`. The same settings tool supports server and link-preview settings for CryptIRC administrators. Appearance has its own tool. |

Network credentials are write-only. Supply replacements or clear saved credentials when switching the server, port, or TLS policy. Use the CryptIRC app for messages in end-to-end encrypted conversations. Keep your MCP token private and revoke it in Profile when you stop using it.

### Connect your AI client

1. In CryptIRC, open **Settings → Profile → MCP access**. Confirm your current login password and create a token.
2. Add a **Streamable HTTP** MCP server in your AI client. Use the URL from Profile, such as `https://irc.example.com/cryptirc/mcp`, and set the `Authorization` header to `Bearer <token>`.
3. Start with **“Use CryptIRC to list my networks and joined channels.”**

<details>
<summary>Connect from the Codex CLI</summary>

Set the token as the environment variable `CRYPTIRC_MCP_TOKEN` before starting Codex. Run this with your server URL, restart your Codex session, and type `/mcp` to check the connection.

```bash
codex mcp add cryptirc --url https://irc.example.com/cryptirc/mcp \
  --bearer-token-env-var CRYPTIRC_MCP_TOKEN
```

</details>

The eleven tools operate within the account that issued the token. Each account has one active token, managed from Profile. Replacing or revoking it takes effect immediately. Web sign-out leaves the integration available. Use the CryptIRC app to unlock the vault, access the password safe, send end-to-end encrypted messages, or apply mIRC color codes to a topic. Removing a network through MCP also removes its saved history.

An `accepted` response to a raw command means CryptIRC accepted it for dispatch. Check the server status or re-read the channel state to confirm the IRC server applied the change.

## Translation

Read IRC in your preferred language. Translate a message, website preview title and description, or X/Twitter post in place. The original text and links are still available. Enable automatic translation for new incoming content, or choose **Translate** when you need it.

1. Open **Settings → Translation**. Select your reading language and choose **Google Cloud Translation** or a provider from the **Bots** lineup.
2. Save your provider credential, check the setup with **Test provider**, and enable translation. Google Cloud Translation Basic uses its own API key. LLM credentials are shared with Bots and encrypted in your vault. Translation works with the chatbot disabled.
3. Use a channel or DM's **Translation…** menu to override incoming behavior or translate outgoing chat as you send. Pick a language for either type of conversation, or let a DM match the language of the other person's latest message. If the provider fails, the draft stays in the composer.

Your provider receives the text selected for translation. Automatic translation is disabled in end-to-end encrypted conversations. To translate encrypted text manually, confirm before sharing it with the provider. Reading and chat preferences are saved on the device. Translated text is kept in the open tab.

[Translation changelog](docs/CHANGES.md#v0513-november-2026)

## Passkey sign-in

Use your device or a compatible security key to sign in. In **Settings → Profile → Passkeys**, name the passkey, confirm your login password, and follow your authenticator's prompt. Next time, choose **Sign In with a Passkey**. You can add or remove passkeys in Profile, and your login password remains available. Your IRC vault keeps its separate passphrase. Account recovery via password reset removes enrolled passkeys.

For self-hosters, MCP token setup and passkeys use the canonical HTTPS URL configured in `CRYPTIRC_BASE_URL`. Local development can use `http://localhost` with the configured port.

## New in 0.5.12

- **Find the setting you want.** Search for MCP, Passkeys, themes, notifications, network options, and more. Results handle common typos, support arrow keys and mobile taps, and open the matching control.
- **Pick up where you were reading.** Switch between channels and DMs and come back to the same message. Scrolling to the bottom resumes following the live conversation.
- **Keep the composer steady.** The chat field keeps its size when focused and is marked separately from sign-in fields to reduce password-manager popups.
- **Keep your avatar visible.** CryptIRC handles long, colored vhosts and refreshes avatars for other eligible viewers when a verified hostmask changes.

[Full v0.5.12 changelog](docs/CHANGES.md#v0512-november-2026)

<a id="available-everywhere"></a>
<a id="terminal-client"></a>
<a id="️-terminal-client"></a>

## Clients

| Where you chat | How to use it |
| --- | --- |
| **Browser** | Open the [hosted client](https://client.twistednet.org/cryptirc), or your own CryptIRC instance. |
| **Windows** | Download the [desktop installer](https://github.com/gh0st68/CryptIRC/releases/latest). |
| **macOS** | Download the [Mac archive](https://github.com/gh0st68/CryptIRC/releases/latest), extract it, and move the app to Applications. Intel and Apple Silicon builds are available. |
| **Linux desktop** | Download the [AppImage](https://github.com/gh0st68/CryptIRC/releases/latest), make it executable, and run it. |
| **Android** | Open the client in a compatible browser and choose **Add to Home Screen** or **Install app**. |
| **iPhone / iPad** | Open the client in Safari, then choose **Share → Add to Home Screen**. |
| **Terminal / SSH / tmux** | Build and run [cryptirc-tui](tui/README.md). It can share an account with the web client. |

Desktop releases support 64-bit Windows, macOS 13 or newer (Intel / Apple Silicon), and Linux.

<details>
<summary><strong>See mobile and terminal previews</strong></summary>

<p align="center">
  <img src="screenshots/mobile.png?v=20261016" width="280" alt="CryptIRC mobile interface preview with an example conversation">
</p>

The terminal client includes a network and channel list, wrapped scrollback, a member list, mouse support, and tab completion. It has **52 terminal themes**, switchable with `/theme`.

<p align="center">
  <img src="screenshots/terminal.png" width="900" alt="cryptirc-tui with a buffer list, conversation, and member list">
</p>

```bash
cd tui
cargo build --release
./target/release/cryptirc-tui -s https://your.server/cryptirc -u yournick
```

<p align="center">
  <img src="screenshots/terminal-themes.png" width="900" alt="Four terminal themes: Dracula, Nord, Catppuccin Mocha, and Phosphor Amber">
</p>

[Terminal setup, commands, and key bindings →](tui/README.md)

</details>

<a id="key-features"></a>

## Features

| | What you get |
| --- | --- |
| **Stay connected** | Multiple IRC networks, encrypted history, reconnect handling, and a separate IRC daemon that survives routine web-server updates. |
| **Pick up anywhere** | Desktop apps, an installable mobile PWA, a terminal client, synced preferences, favorites, and unread markers. |
| **Follow the conversation** | Unified Messages inbox, searchable history, Notices with message jumps, push alerts, custom highlights, mutes, and quiet hours. |
| **Make it yours** | 257 themes, including 64 animated themes and classic IRC client skins, 140 font choices, editable palettes, backgrounds, and resizable columns. |
| **Share more** | Inline images, video and audio, a GIF picker, link previews, file uploads, text / HTML / Markdown pastes, and a URL shortener. |
| **Use familiar IRC tools** | SASL PLAIN/EXTERNAL, IRCv3 capabilities, nick monitoring, channel modes, moderation tools, and slash-command completion. |

### Your IRC, your look

Choose from **257 themes**, with 193 static and 64 animated designs. The 30 new static designs include Witness Mark, Sluice Gate, and Gauge Needle, each with an original pattern and palette. There are also classic IRC skins, illustrated backgrounds, and quieter minimal palettes.

Customize a theme into your own saved copy, adjust fonts and column widths, or add a background image with opacity, blur, dim, and tiling controls. Mobile theme and layout overrides let your phone have its own setup. Optional desktop pets add a little company, with motion controls for quieter sessions.

<p align="center">
  <a href="https://gh0st68.github.io/CryptIRC/"><img src="screenshots/theme-gallery.png" width="900" alt="CryptIRC theme gallery with searchable palette previews"></a>
</p>

[Browse the theme gallery →](https://gh0st68.github.io/CryptIRC/)

### Optional AI and bots

Connect a supported AI provider or an OpenAI-compatible endpoint for channel, DM, or private `/ai` conversations. Opt-in context and bounded IRC actions let the assistant work with your channels; provider requests go to the service you configure.

The server also includes **19 bots** for weather, lookups, quotes, seen records, offline tells, notes, and other utilities. Bot controls include triggers, access rules, cooldowns, and per-channel settings. Channel protection adds auto-op/voice, flood controls, and word filtering.

<details>
<summary><strong>Detailed IRC, interface, and admin features</strong></summary>

#### IRC and IRCv3
- IRC support — channels, DMs, modes, kicks, bans, CTCP, the works
- **IRCv3 capabilities** (17 user-toggleable): away-notify, account-notify, extended-join, server-time, multi-prefix, cap-notify, message-tags, batch, echo-message, invite-notify, setname, account-tag, userhost-in-names, chghost, labeled-response, typing indicators, standard-replies (plus SASL, negotiated separately; nick MONITOR is a separate feature)
- **IRCv3 CAP toggle** — enable/disable individual capabilities per network in settings
- **SASL PLAIN & EXTERNAL** authentication
- Multi-network support — connect to multiple networks simultaneously
- **Nick monitoring** — track when users come online/offline with push notifications
- **KeepNick** — irssi-style nick keeper with ISON polling, QUIT/NICK event detection, and auto-reclaim
- **Auto-identify** — automatically send NickServ IDENTIFY on connect (encrypted credential storage)
- **Auto-rejoin on kick** — automatically rejoin channels after being kicked (with saved channel keys)
- **Channel key manager** — store and auto-send channel keys (+k) when joining
- **Multi-device sync** — messages you send on one device appear on all your other devices
- **Typing indicators** — see when someone is typing (IRCv3 draft/typing)
- **Server-time** — accurate timestamps from the IRC server
- **ZNC playback detection** — detects and batches ZNC buffer playback with summary markers
- **Self-signed cert detection** — popup warning with one-click fix for ZNC/bouncer TLS errors
- **Status message condensing** — Lounge-style grouped join/part/quit (Show All / Condense / Hide)
- Configurable join/part/quit message filtering
- **Infinite scroll** — load older messages from encrypted server logs on demand

#### Chat and interface
- **Lounge-style layout** — clean input bar, grouped nick list, collapsible panels
- **Mobile-first PWA** — installable on iOS/Android with swipe gestures and safe-area support
- **iOS PWA keyboard handling** — adapts to the iOS keyboard and accessory bar
- **Collapsible panels** — sidebar and nick list collapse on desktop with persistent state
- **Nick list grouped by role** — Owners, Admins, Operators, Half-Ops, Voiced, Users
- **Nick context menu** — whois, query, slap, monitor, notes, kick/ban/voice/op based on power level
- **Clickable nicks in messages** — nick mentions in chat text are colored and clickable
- **Smart tab completion** — prioritizes most recent speakers, with Tab cycling
- **@nick autocomplete** — type `@` to search and insert channel nicks
- **#channel autocomplete** — type `#` to autocomplete channel names
- **Inline media previews** — images, videos (.mp4/.webm/.mov), YouTube rich cards with title/author
- **Inline audio player** — .mp3, .ogg, .flac, .wav, .m4a, .aac, .opus with playback controls
- **GIF picker** — type `/gif <search>` (or `/giphy`) for a smooth in-line grid of results, navigable by tap or arrow keys + Enter. Powered by **Giphy or Tenor** — the admin picks the provider and can set a shared key so it works for everyone with no setup, or each user can supply their own
- **Image lightbox** — click to zoom, scroll wheel zoom, pinch-to-zoom on mobile, pan when zoomed
- **Link previews** — server-side metadata fetcher with admin whitelist (SSRF protected)
- **X post previews (optional, off by default)** — rich cards for X/Twitter links: author, text, exact counts, photo galleries, video/GIF after Play, one quoted post, optional published threads. Public unencrypted channels load them automatically; encrypted messages, DMs and unknown contexts stay click-to-load, and disclosure choices stay on the device. No preview provider is contacted until the operator enables one; until then X links behave exactly as before (the generic link preview) — see [X post previews](INSTALL.md#x-post-previews-optional)
- **Pastebin** — share text snippets with password protection and expiration
- **URL shortener** — built-in `/shorten` command creates short redirect URLs with interstitial page
- **Smart paste** — paste multi-line text and it auto-offers "send as pastebin?" instead of flooding
- **Split view** — view two channels side by side on desktop (`/split`)
- **Read markers** — "new messages since you were away" divider line in channels
- **User notes** — attach private notes to any nick (right-click menu or `/note`)
- **Seen database** — `/seen nick` tracks last message time and channel
- **Channel stats dashboard** — most active users with bar chart (`/stats`)
- **ASCII art generator** — `/ascii text` sends block-letter art to channel
- **Urban Dictionary** — `/ud word` looks up and sends definitions
- **DND mode** — Do Not Disturb with scheduled quiet hours (`/dnd`)
- **Encrypted notepad** — private auto-saving notes, encrypted with vault key
- **mIRC color formatting** — Ctrl+K color picker, Ctrl+B/U/I/O for bold/underline/italic/reset
- **Topic bar** with mIRC color rendering and edit/copy/view menu
- **Emoji picker** with colon autocomplete (`:wave:` style)
- **Slash command autocomplete** — type `/` to see all 100+ commands
- **Search** — search messages in current channel with highlighted results
- **File uploads** — drag-and-drop or paperclip, with automatic metadata stripping for images, video, and audio (configurable max size from admin panel)
- **My Uploads panel** — view, manage, and delete your uploaded files
- **Desktop and mobile notifications** — background Web Push, foreground alerts, per-conversation mutes, and Do Not Disturb
- **Smart unread badges** — gray for regular messages, red for mentions and DMs
- **Notices panel** — mentions and unread PMs, with links to the matching message
- **Custom highlight words** — tag-based UI to add/remove trigger words for notifications
- **Synced preferences** — themes, favorites, unread markers, notices, notes, and saved keys
- **Network drag-and-drop** — reorder networks with all their channels (desktop drag + mobile hold-to-drag)
- **Channel drag-and-drop** — reorder channels within a network
- **Favorites filter** — funnel icon filter bar to show only favorited channels
- **Messages inbox** — an optional pinned tab at the top of the sidebar that gathers every DM from all your networks into one unified inbox, iMessage-style (toggle in Appearance ▸ Messages tab)
- **Encryption indicators** — SVG lock/unlock icons on every channel and DM in the sidebar
- **Mobile lag indicator** — ping time shown next to channel name in topbar
- **SVG icon settings menu** — clean Lucide-style line icons, scrollable on small screens
- **Standalone security panel** — vault auto-lock, message expiry, rate limit, PM blocking, spellcheck, link previews
- **140 font choices** — monospace, sans-serif, serif, display, and cursive/handwriting, mostly from Google Fonts
- **Clear all data** — one-click deletion of logs, notepad, and pastes with confirmation

#### Administration
- **Admin panel** — user management, live stats (total / online), registration settings
- **GIF Picker settings** — choose the provider (**Giphy** or **Tenor**), the mode (Off / per-user own-key / shared server key), and store the server-held Giphy + Tenor API keys (never exposed to users)
- **Max upload size** — admin-set per-file upload cap (1–500 MB)
- **Link preview controls** — pick a mode (Off / Whitelist approved-domains-only / All HTTPS links, with private IPs blocked) plus the domain whitelist
- **Registration modes** — open, invite-code, or closed (persists across reboots)
- **User management** — add, approve, disable, delete, set email, toggle upload permission (admin rights are granted on the server with `sudo bash makeadmin.sh <user>`)
- **All admin settings persist** to disk with mutex protection (survives server restarts)

</details>

<a id="encryption--security"></a>

## Privacy and encryption

CryptIRC provides encryption for stored data and optional end-to-end protection for conversations. These protect different parts of the system.

| Protection | Scope |
| --- | --- |
| **Encrypted storage** | Per-user vaults protect chat logs, saved IRC credentials, and private notes with AES-256-GCM. Argon2id protects the vault master key. |
| **End-to-end encrypted DMs** | Compatible clients can use Signal Protocol encryption with X3DH and Double Ratchet. Enable E2E for the conversation. |
| **Shared channel encryption** | Optional AES-256-GCM encryption uses a shared channel key. |
| **IRC connection security** | TLS and SASL PLAIN/EXTERNAL support, with client certificate management and a guard against sending SASL PLAIN over an unencrypted connection. |
| **Account controls** | Vault locking, configurable auto-lock, session revocation, PM blocking, and administrative account controls. |

The server handles ordinary IRC traffic and unlocks the storage vault, so run CryptIRC on a server you trust. Encrypted storage does **not** make ordinary IRC traffic end-to-end encrypted or make the server unable to read unlocked data. AI providers, GIF services, and link previews are optional external integrations.

Use `/encrypt unlock` or **Unlock encrypted chats** in the encryption panel to set up E2E. Save the generated recovery code. You’ll need it on another device or after clearing browser data. The client sends only the wrapped E2E keyring to the server. Changing your vault passphrase leaves the recovery code valid. Existing E2E accounts are prompted to upgrade and keep their existing identities and conversation keys.

The web client still trusts the code served by your CryptIRC host. Upgrading replaces the old storage key, and previously exposed identity keys or channel keys require their own rotation.

Encrypted chats send text over IRC. File uploads and server-hosted pastes are unavailable there because those features store the original content on the host.

## Commands and shortcuts

Type `/` in the composer to browse commands, or use `/help` for the in-app reference.

| Start with | Action |
| --- | --- |
| `/join #channel` | Join a channel. |
| `/query nick` | Open a private conversation. |
| `/whois nick` | Look up a user. |
| `/dnd on` | Enable Do Not Disturb. |
| `/split` | Open a second conversation beside the first. |
| `Tab` | Complete a nickname. |
| `@`, `#`, `:` | Find nicknames, channels, or emoji. |

<details>
<summary><strong>Full command and keyboard reference</strong></summary>

All 100+ commands show in the `/` autocomplete dropdown. Type `/` to browse.

**Channel:**

| Command | Description |
|---------|-------------|
| `/join #channel [key]` | Join a channel (auto-adds # if missing) |
| `/part [#channel] [reason]` | Leave a channel |
| `/cycle` | Part and rejoin channel |
| `/topic [text]` | View or set channel topic |
| `/list` | List all channels on the server |
| `/links` | Show server links |
| `/invite nick` | Invite user to channel |
| `/names` | Refresh the nick list |
| `/key #channel [key]` | Save or clear a channel key (+k) |

**Messaging:**

| Command | Description |
|---------|-------------|
| `/msg nick text` | Send a private message |
| `/query nick [text]` | Open a DM window |
| `/me text` | Send an action |
| `/say text` | Send raw text to current target |
| `/notice nick text` | Send a notice |
| `/ctcp nick command` | Send a CTCP command |
| `/slap nick` | Slap someone with a large trout |

**Identity & Info:**

| Command | Description |
|---------|-------------|
| `/nick newnick` | Change your nickname |
| `/away [message]` | Set away status |
| `/back` | Remove away status |
| `/whois nick` | Look up user info |
| `/whowas nick` | Look up offline user |
| `/who #channel` | List users in a channel |

**User Modes:**

| Command | Description |
|---------|-------------|
| `/mode +mode [args]` | Set channel or user mode |
| `/op` `/deop` | Give/remove operator (+o) |
| `/voice` `/devoice` | Give/remove voice (+v) |
| `/halfop` `/dehalfop` | Give/remove half-op (+h) |
| `/admin` `/deadmin` | Give/remove admin (+a) |
| `/owner` `/deowner` | Give/remove owner (+q) |

**Mass Operations:**

| Command | Description |
|---------|-------------|
| `/opall` | Op everyone in the channel |
| `/deopall` | Deop everyone |
| `/mdop` (aliases `/massdeop`, `/drop`) | Strip ALL status (~&@%+) from everyone except you |
| `/voiceall` `/devoiceall` | Voice/devoice everyone |
| `/kickall` | Kick everyone except yourself |

**Moderation:**

| Command | Description |
|---------|-------------|
| `/kick nick [reason]` | Kick a user |
| `/ban nick` | Ban a user (nick!*@*) |
| `/unban mask` | Remove a ban |
| `/kickban nick [reason]` | Kick and ban |
| `/tban nick seconds` | Temporary ban with auto-unban |
| `/banlist` | View the ban list |
| `/unbanall` | Remove ALL bans from channel |
| `/unexemptall` | Remove all ban exempts (+e) |
| `/ignore nick\|mask` | Ignore a user (supports wildcards) |
| `/unignore nick\|mask` | Stop ignoring a user |
| `/ignorelist` | Show your ignore list |

**Services:**

| Command | Description |
|---------|-------------|
| `/ns command` | Send to NickServ |
| `/cs command` | Send to ChanServ |
| `/identify password` | Identify with NickServ |
| `/register password email` | Register with NickServ |
| `/ghost nick` | Ghost a nick |
| `/regain nick` | Recover/regain a nick |

**IRCOp:**

| Command | Description |
|---------|-------------|
| `/oper login password` | Authenticate as IRCOp |
| `/kill nick reason` | Kill a user from the network |
| `/shun` `/gline` `/zline` `/kline` | Server bans with duration/reason |
| `/rehash` | Reload server configuration |
| `/squit server reason` | Disconnect a linked server |

**Encryption:**

| Command | Description |
|---------|-------------|
| `/encrypt keygen` | Generate Signal protocol identity |
| `/encrypt on` | Enable E2E for current DM |
| `/encrypt off` | Disable E2E for current DM |
| `/encrypt add #channel` | Set a channel encryption key |
| `/encrypt rotate` | Rotate your E2E keys |

**Tools:**

| Command | Description |
|---------|-------------|
| `/ascii text` | Generate ASCII block-letter art |
| `/ud word` | Urban Dictionary lookup (sends to channel) |
| `/gif query` (alias `/giphy`) | Search a GIF and send the top match; add a trailing space to open the live picker; `/gif key <k>`, `/gif rating <g\|pg\|pg-13\|r>` — Giphy or Tenor (admin-selectable) |
| `/shorten url` | Shorten a URL with built-in shortener |
| `/stats` | Channel statistics dashboard (top talkers) |
| `/note nick [text]` | Set or view private notes on a nick |
| `/seen nick` | When a nick was last seen and where |
| `/dnd on\|off` | Toggle Do Not Disturb mode |
| `/dnd schedule HH:MM HH:MM` | Schedule quiet hours |
| `/split` | Toggle split view (two channels side by side) |
| `/keepnick [nick]` | Keep a nick (auto-reclaim via ISON + events) |
| `/unkeepnick` | Stop keeping a nick |
| `/listnick` | List all kept nicks with status |
| `/ratelimit ms` | Set message rate limit (default 500ms) |
| `/expire hours` | Auto-delete old messages (0 = off) |
| `/autolock minutes` | Vault auto-lock after inactivity (0 = off) |

**Connection:**

| Command | Description |
|---------|-------------|
| `/connect` | Connect to the current server |
| `/disconnect` | Disconnect from the current server |
| `/quote text` | Send a raw IRC command |

**Client:**

| Command | Description |
|---------|-------------|
| `/close` | Close the current DM or channel tab |
| `/clear` | Clear current chat history |
| `/clearall` | Clear ALL chat buffers |
| `/help` | Show help panel with all commands |
| `/ping nick` | CTCP ping a user |
| `/version nick` | CTCP version a user |
| `/time nick` | CTCP time a user |
| `/monitor nick` | Monitor nick online/offline |
| `/unmonitor nick` | Stop monitoring |
| `/advertise` (alias `/ad`) | Post the CryptIRC promo banner to the current channel |

**Fun & Emotes:**

| Command | Output |
|---------|--------|
| `/prism text` · `/prism on\|off` | Rainbow mIRC colored text, or toggle rainbow for all your outgoing messages |
| `/color <fg>[,<bg>]` · `/color off` | Set a persistent mIRC colour for your messages (codes 0–15 or names like red, blue) |
| `/shrug` | ¯\\\_(ツ)\_/¯ |
| `/tableflip` | (╯°□°)╯︵ ┻━┻ |
| `/unflip` | ┬─┬ノ( º \_ ºノ) |
| `/lenny` | ( ͡° ͜ʖ ͡°) |
| `/disapprove` | ಠ\_ಠ |
| `/rage` | (ノಠ益ಠ)ノ彡┻━┻ |
| `/bear` | ʕ•ᴥ•ʔ |
| `/sparkle text` | ✧･ﾟ: \*✧ text ✧\*:･ﾟ✧ |
| `/finger` | ╭∩╮(︶︿︶)╭∩╮ |
| `/dance` | ♪┏(・o・)┛♪┗(・o・)┓♪ |
| `/rip name` | ⚰️ R.I.P. name ⚰️ |
| `/hug nick` | (づ｡◕‿‿◕｡)づ nick |

**Keyboard Shortcuts:**

| Shortcut | Action |
|----------|--------|
| `Ctrl+K` | mIRC color picker (16 colors, fg+bg) |
| `Ctrl+B` | Bold text |
| `Ctrl+U` | Underline text |
| `Ctrl+I` | Italic text |
| `Ctrl+O` | Reset formatting |
| `Tab` | Smart nick completion (most recent speaker first, cycles) |
| `@` | Nick autocomplete dropdown |
| `#` | Channel autocomplete dropdown |
| `:` | Emoji autocomplete |
| `/` | Slash command autocomplete (100+ commands) |
| `Escape` | Close autocomplete / overlays |
| `↑` / `↓` | Input history navigation |
| `Enter` | Send message |

</details>

<details>
<summary><strong>Settings panels</strong></summary>

Accessible from the sidebar gear menu:

| Panel | Contents |
|-------|----------|
| Notifications | Push alerts, desktop popups, sounds, trigger rules, custom highlight words (tag UI), per-network mute |
| Theme | 257 themes (64 animated), 140 fonts, customize any theme, font sizes, layout, display options, compact mode, colors, brightness, mobile overrides |
| Security | Vault auto-lock timer, message expiry, rate limit, block PMs (+g), auto-rejoin, link previews, spellcheck |
| Monitor | Nick online/offline tracking with push notifications |
| Notepad | Private encrypted auto-saving notes |
| Certs | Client TLS certificate management for SASL EXTERNAL |
| IRCv3 Caps | Toggle individual IRCv3 capabilities per network |
| Ignored Users | Manage ignore list (nick and wildcard mask support) |
| My Uploads | View, manage, and delete uploaded files with thumbnails |
| Sessions | View and revoke active sessions across devices |
| Vault Password | Change vault passphrase (re-encrypts all data) |
| Help | Complete command reference, features list, keyboard shortcuts |
| Admin | User management, registration settings, link-preview mode (off/whitelist/all), GIF picker (provider/mode/keys), max upload size |

</details>

## Architecture

The `cryptirc` web server handles the API, sessions, encrypted storage, uploads, and notifications. The `irc-core` daemon owns the IRC connections. A local Unix socket connects the two services.

```text
Browser / PWA / desktop app / terminal
                  │
          HTTPS + WebSocket
                  │
         cryptirc (Rust / Axum)
                  │
             Unix socket
                  │
       irc-core (persistent IRC)
                  │
           TLS / IRC networks
```

Routine web-server updates restart `cryptirc` while `irc-core` keeps running. Updating or stopping the IRC daemon itself can reconnect those IRC sessions.

| Layer | Technology |
| --- | --- |
| Server | Rust, Tokio, Axum |
| Web client | JavaScript, Web Crypto API, CSS custom properties |
| Desktop | Electron |
| Encryption | AES-256-GCM, Argon2id, HKDF-SHA256, Signal Protocol |
| Notifications | Web Push / VAPID and desktop notifications |
| Deployment | Caddy, systemd, optional Postfix integration |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYPTIRC_DATA` | `./data` | Path to the data directory |
| `CRYPTIRC_BASE_URL` | `http://localhost:9000` | Public URL of your instance |
| `CRYPTIRC_BASE_PATH` | `/cryptirc` | URL path prefix |
| `CRYPTIRC_PORT` | `9001` | Port the server listens on |
| `CRYPTIRC_HSTS` | `on` | Set to `off` to disable the HSTS header (for self-signed / bare-IP deployments) |
| `CRYPTIRC_FROM_EMAIL` | `noreply@cryptirc.local` | Sender address for emails |
| `CRYPTIRC_REGISTRATION` | `open` | Registration mode: `open`, `closed` |
| `CRYPTIRC_REG_CODE` | (none) | Invite code required for registration |
| `CRYPTIRC_IPC_SOCK` | `$CRYPTIRC_DATA/irc-core.sock` | Unix socket path between the web server and the `irc-core` daemon |
| `CRYPTIRC_TRUSTED_PROXIES` | (none) | Extra reverse proxies / CDN ranges (IPs or CIDRs) whose forwarding headers are believed; loopback is always trusted |
| `CRYPTIRC_REAL_IP_HEADER` | `auto` | Header a trusted proxy's client address comes from: `auto`, `x-forwarded-for`, `x-real-ip` or `off` |
| `CRYPTIRC_AI_ALLOW_PRIVATE` | (off) | Allow the AI bot's custom endpoint to reach private/loopback addresses (e.g. a local Ollama). Off by default; enable only when every account is trusted |
| `RUST_LOG` | `info` | Log level |

`CRYPTIRC_REGISTRATION` and `CRYPTIRC_REG_CODE` are fallbacks for while `admin_settings.json` doesn't hold that setting (it does once it is saved in Settings → Admin). How the client address is chosen for rate limits behind a proxy or CDN is explained in [INSTALL.md](INSTALL.md#client-ip-addresses-behind-a-proxy).

For registration, HTTPS, service configuration, and backups, see [INSTALL.md](INSTALL.md) and the [deployment guide](deploy/README.md).

## Community

Questions, bugs, or ideas? Join **#dev** or **#twisted** on `irc.twistednet.org` (TLS port **6697**), or [open a GitHub issue](https://github.com/gh0st68/CryptIRC/issues).

Built by **gh0st** at [TwistedNET](https://twistednet.org/).

## License

Proprietary. All rights reserved.
