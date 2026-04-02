<p align="center">
  <img src="static/icon.svg" width="120" height="120" alt="CryptIRC">
</p>

<h1 align="center">CryptIRC</h1>

<p align="center">
  <strong>End-to-end encrypted IRC client for the web</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.78+-orange?logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/encryption-AES--256--GCM-green?logo=letsencrypt" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/protocol-Signal%20E2E-blue?logo=signal" alt="Signal Protocol">
  <img src="https://img.shields.io/badge/version-0.7.0-brightgreen" alt="Version">
  <img src="https://img.shields.io/badge/license-private-lightgrey" alt="License">
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
- **iOS PWA keyboard handling** -- input bar works correctly with iOS keyboard accessory bar
- **Collapsible panels** -- sidebar and nick list collapse on desktop with persistent state
- **Nick list grouped by role** -- Owners, Admins, Operators, Half-Ops, Voiced, Users
- **Nick context menu** -- whois, query, slap, monitor, kick/ban/voice/op based on your power level
- **Inline media previews** -- images, videos (.mp4/.webm/.mov), and YouTube thumbnails
- **Pastebin** -- share text snippets with optional password protection and expiration
- **Encrypted notepad** -- private notes accessible from Settings, auto-saved and encrypted
- **Topic bar** with mIRC color rendering and edit/copy/view menu
- **Emoji picker** with colon autocomplete (`:wave:` style)
- **Slash command autocomplete** -- type `/` to see available commands
- **Search** -- search messages in current channel with highlighted results
- **File uploads** -- drag-and-drop or paperclip button, link placed in input bar for you to send
- **Desktop & mobile push notifications** -- works on iOS PWA, suppressed when app is open
- **Persistent state** -- open DMs, unread counts, mentions, input history all sync server-side
- **Channel drag-and-drop reorder** -- reorder channels in the sidebar

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

### Deployment
- **Single binary** -- one `cargo build` and you're done
- Interactive deploy script for Debian/Ubuntu with Caddy, Postfix, and systemd
- Automatic HTTPS via Caddy + Let's Encrypt
- Hardened systemd unit with full sandboxing
- Registration modes: open, invite-code, or closed
- Admin panel with user management

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
