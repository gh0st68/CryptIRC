<p align="center">
  <img src="static/icon.svg" width="80" height="80" alt="CryptIRC">
</p>

<h1 align="center">CryptIRC</h1>

<p align="center">
  <strong>End-to-end encrypted IRC client for the web</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.78+-orange?logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/encryption-AES--256--GCM-green?logo=letsencrypt" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/protocol-Signal%20E2E-blue?logo=signal" alt="Signal Protocol">
  <img src="https://img.shields.io/badge/version-0.8.4-brightgreen" alt="Version">
  <img src="https://img.shields.io/badge/license-private-lightgrey" alt="License">
</p>

<p align="center">
  <img src="screenshots/client.png" width="900" alt="CryptIRC — Desktop Client">
</p>

---

CryptIRC is a self-hosted, privacy-first IRC client that runs in the browser. Every message, log, and credential is encrypted before it ever touches disk. Connect to any IRC network through a clean, modern interface -- no plugins, no Electron, no telemetry.

## Features

### Encryption & Security
- **Per-user vaults** -- each user has their own passphrase and encryption key (Argon2id KDF + AES-256-GCM)
- **Signal-protocol E2E** for direct messages -- X3DH key agreement + Double Ratchet
- **Channel encryption** -- pre-shared AES-256-GCM keys for group channels
- **Encrypted logs** -- every line encrypted at rest with the user's vault key
- **Encrypted notepad** -- private encrypted notes stored server-side
- **Encrypted credential storage** -- IRC passwords and SASL secrets never stored in plaintext
- **Vault lock/unlock** -- locking the vault zeros the key from memory and disconnects IRC
- **Client TLS certificates** -- generate and manage ECDSA P-256 certs for SASL EXTERNAL
- **Zero-knowledge architecture** -- the server cannot read your messages or credentials
- **Timing-safe comparisons** -- registration codes use constant-time comparison
- **XSS protection** -- comprehensive HTML escaping on all user content
- **CSP headers** -- Content-Security-Policy, X-Frame-Options, Referrer-Policy

### IRC & IRCv3
- Full IRC protocol support -- channels, DMs, modes, kicks, bans, CTCP, the works
- **IRCv3 capabilities**: away-notify, account-notify, extended-join, server-time, multi-prefix, cap-notify, message-tags, batch, echo-message, invite-notify, setname, account-tag, userhost-in-names, chghost, labeled-response, typing indicators, standard-replies, MONITOR
- **SASL PLAIN & EXTERNAL** authentication
- Multi-network support -- connect to as many networks as you want simultaneously
- **Nick monitoring** -- track when users come online/offline with push notifications
- **Multi-device sync** -- messages you send on one device appear on all your other devices
- **Typing indicators** -- see when someone is typing (IRCv3 draft/typing)
- **Server-time** -- accurate timestamps from the IRC server
- Configurable join/part/quit message filtering
- **Infinite scroll** -- load older messages from encrypted server logs on demand

### Interface
- **Lounge-style layout** -- clean input bar, grouped nick list, collapsible panels
- **Mobile-first PWA** -- installable on iOS/Android with swipe gestures and safe-area support
- **iOS PWA keyboard handling** -- works perfectly with iOS keyboard accessory bar
- **Collapsible panels** -- sidebar and nick list collapse on desktop with persistent state
- **Nick list grouped by role** -- Owners, Admins, Operators, Half-Ops, Voiced, Users
- **Nick context menu** -- whois, query, slap, monitor, kick/ban/voice/op based on power level
- **Clickable nicks in messages** -- nick mentions in chat text are colored and clickable
- **@nick autocomplete** -- type `@` to search and insert channel nicks
- **Inline media previews** -- images, videos (.mp4/.webm/.mov), YouTube rich cards with title/author
- **Link previews** -- server-side metadata fetcher with admin whitelist (SSRF protected)
- **Pastebin** -- share text snippets with password protection and expiration
- **Encrypted notepad** -- private auto-saving notes, encrypted with vault key
- **mIRC color formatting** -- Ctrl+K color picker, Ctrl+B/U/I/O for bold/underline/italic/reset
- **Topic bar** with mIRC color rendering and edit/copy/view menu
- **Emoji picker** with colon autocomplete (`:wave:` style)
- **Slash command autocomplete** -- type `/` to see available commands
- **Search** -- search messages in current channel with highlighted results
- **File uploads** -- drag-and-drop or paperclip, link placed in input bar for you to send
- **Desktop & mobile push notifications** -- iOS PWA support, suppressed when app is focused
- **Smart unread badges** -- gray for regular messages, red for mentions and DMs
- **Mentions panel** -- chat bubble icon with red dot badge for unseen mentions
- **Persistent state** -- everything syncs server-side (themes, favorites, unread, mentions, etc.)
- **Channel drag-and-drop reorder** -- reorder channels in the sidebar
- **Mobile lag indicator** -- ping time shown next to channel name in topbar
- **34 fonts** -- choose from 21 monospace, 10 sans-serif, 2 serif, and 1 cursive font
- **Clear all data** -- one-click deletion of logs, notepad, and pastes with confirmation

### Themes (20+)
| Theme | Description |
|-------|-------------|
| Midnight | Deep dark blue (default) |
| Dracula | Classic purple-accented dark |
| Monokai | Warm syntax-inspired dark |
| Nord | Cool Arctic blue palette |
| Catppuccin Mocha | Pastel dark with lavender accents |
| Tokyo Night | Vibrant purple-blue cityscape |
| Cyberpunk | Neon pink and cyan |
| Matrix | Green-on-black terminal |
| Blumhouse | Horror-inspired dark red |
| Scream | Ghostface neon green |
| Solarized Dark | Ethan Schoonover's classic |
| Gruvbox Dark | Retro warm brown tones |
| One Dark | Atom editor inspired |
| Ayu Dark | Subtle warm dark |
| Palenight | Material palenight |
| Rosepine | Soft muted rose |
| Kanagawa | Japanese wave blue |
| Everforest | Natural green tones |
| Forest Rain | Animated rain with lightning flashes |
| Synthwave | Retro 80s purple gradient |
| **Separate mobile theme** | Independent colors, accents, and font sizes for phone vs desktop |

### Admin
- **Admin panel** -- user management, stats, registration settings
- **Link preview whitelist** -- admin controls which domains get metadata fetched
- **Registration modes** -- open, invite-code, or closed (persists across reboots)
- **User management** -- disable, delete, promote to admin
- **All admin settings persist** to disk (survives server restarts)

### Commands

All commands show in the `/` autocomplete dropdown. Type `/` to browse.

| Command | Description |
|---------|-------------|
| `/join` | Join a channel (auto-adds # if missing) |
| `/part` | Leave a channel |
| `/msg` | Send private message |
| `/query` | Open a DM window |
| `/me` | Send action |
| `/nick` | Change nickname |
| `/topic` | View or set channel topic |
| `/whois` | Look up user info |
| `/kick` | Kick a user |
| `/ban` | Ban a user |
| `/kickban` | Kick and ban |
| `/unban` | Remove a ban |
| `/unbanall` | Remove all bans from channel |
| `/unexemptall` | Remove all ban exempts (+e) |
| `/mode` | Set channel/user modes |
| `/op` `/deop` | Give/remove operator |
| `/voice` `/devoice` | Give/remove voice |
| `/halfop` | Give half-op |
| `/owner` | Give owner |
| `/opall` | Op everyone |
| `/voiceall` | Voice everyone |
| `/kickall` | Kick everyone except yourself |
| `/mdop` | Mass deop all ops except yourself |
| `/drop` | Strip ALL status (~&@%+) from everyone except yourself |
| `/ignore` | Ignore a user (supports wildcard masks) |
| `/unignore` | Stop ignoring a user |
| `/away` `/back` | Set/clear away status |
| `/invite` | Invite user to channel |
| `/list` | List all channels |
| `/links` | Show server links |
| `/cycle` | Part and rejoin channel |
| `/ns` `/cs` | NickServ/ChanServ commands |
| `/identify` | Identify with NickServ |
| `/encrypt` | Manage E2E encryption (keygen, add, rotate, on, off) |
| `/quote` | Send raw IRC command |
| `/clear` | Clear current buffer |
| `/help` | Show help or help for a command |

**Fun Commands:**

| Command | Output |
|---------|--------|
| `/prism text` | Rainbow mIRC colored text |
| `/shrug` | ¯\\\_(ツ)\_/¯ |
| `/tableflip` | (╯°□°)╯︵ ┻━┻ |
| `/unflip` | ┬─┬ノ( º \_ ºノ) |
| `/lenny` | ( ͡° ͜ʖ ͡°) |
| `/disapprove` | ಠ\_ಠ |
| `/rage` | (ノಠ益ಠ)ノ彡┻━┻ |
| `/bear` | ʕ•ᴥ•ʔ |
| `/sparkle text` | ✧･ﾟ: \*✧･ﾟ:\* text \*:･ﾟ✧\*:･ﾟ✧ |
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
| `Tab` | Nick tab completion |
| `@` | Nick autocomplete dropdown |
| `:` | Emoji autocomplete |

### Deployment
- **Single binary** -- one `cargo build` and you're done
- Interactive deploy script for Debian/Ubuntu with Caddy, Postfix, and systemd
- Automatic HTTPS via Caddy + Let's Encrypt
- Hardened systemd unit with full sandboxing

## Quick Start

```bash
# Clone
git clone https://github.com/gh0st68/CryptIRC.git
cd CryptIRC

# Deploy (Debian/Ubuntu)
sudo bash deploy/deploy.sh yourdomain.com admin@yourdomain.com
```

Visit `https://yourdomain.com`, register an account, unlock your vault, and connect.

## Install as a PWA

CryptIRC is a Progressive Web App -- install it and it runs like a native app with push notifications.

- **iPhone/iPad**: Safari > Share > Add to Home Screen
- **Android**: Chrome > Menu > Add to Home Screen
- **Desktop**: Chrome/Edge > Install icon in address bar

## Architecture

```
Browser (PWA)
  |-- E2E encryption (Signal protocol, Web Crypto API)
  |-- Per-user vault unlock (Argon2id KDF -> AES-256-GCM)
  '-- WebSocket --> CryptIRC Server (Rust/Axum)
                      |-- IRC connections (TLS + IRCv3)
                      |-- Per-user encrypted log storage
                      |-- Push notifications (Web Push / VAPID)
                      |-- Pastebin with password protection
                      |-- File uploads
                      '-- Email verification (Postfix)
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Rust, Tokio, Axum |
| Encryption | AES-256-GCM, Argon2id, HKDF-SHA256, Signal Protocol (X3DH + Double Ratchet) |
| TLS | OpenSSL (client certs), native-tls (server connections) |
| Frontend | Vanilla JS, Web Crypto API, SVG icons, CSS custom properties |
| Push | Web Push with VAPID (RFC 8292), iOS PWA support |
| IRC | IRCv3.2 with CAP negotiation (20+ capabilities) |
| Reverse Proxy | Caddy or Nginx (automatic HTTPS) |
| Mail | Postfix (local relay) |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYPTIRC_DATA` | `./data` | Path to the data directory |
| `CRYPTIRC_BASE_URL` | `http://localhost:9000` | Public URL of your instance |
| `CRYPTIRC_BASE_PATH` | `/cryptirc` | URL path prefix |
| `CRYPTIRC_PORT` | `9001` | Port the server listens on |
| `CRYPTIRC_FROM_EMAIL` | `noreply@cryptirc.local` | Sender address for emails |
| `CRYPTIRC_REGISTRATION` | `open` | Registration mode: `open`, `closed` |
| `CRYPTIRC_REG_CODE` | (none) | Invite code required for registration |
| `RUST_LOG` | `info` | Log level |

## Requirements

- Rust 1.78+
- Linux (Debian 12 / Ubuntu 22.04+ recommended)
- A domain name with an A record pointing to your server
- Ports 80 and 443 open

## License

Private. All rights reserved.
