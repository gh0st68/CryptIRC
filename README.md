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
  <img src="https://img.shields.io/badge/license-private-lightgrey" alt="License">
</p>

---

CryptIRC is a self-hosted, privacy-first IRC client that runs in the browser. Every message, log, and credential is encrypted before it ever touches disk. Connect to any IRC network through a clean, modern interface — no plugins, no Electron, no telemetry.

## Features

### Encryption & Security
- **AES-256-GCM** encrypted logs — every line encrypted at rest with a per-vault key derived via Argon2id
- **Signal-protocol E2E** for direct messages — X3DH key agreement + Double Ratchet
- **Encrypted credential storage** — IRC passwords and SASL secrets are never stored in plaintext
- **Vault system** — all data locked behind a passphrase; nothing is readable without it
- **Client TLS certificates** — generate and manage certs for SASL EXTERNAL auth
- **Zero-knowledge architecture** — the server cannot read your messages or credentials

### IRC
- Full IRC protocol support — channels, DMs, modes, kicks, bans, CTCP, the works
- **SASL PLAIN & EXTERNAL** authentication
- Multi-network support — connect to as many networks as you want simultaneously
- Channel and user modes, `/op`, `/voice`, `/kick`, `/ban`, `/topic`, `/ignore`, and more
- Configurable join/part/quit message filtering

### Interface
- **Three-panel layout** — collapsible sidebar, chat area, nick list
- **Mobile-first PWA** — installable on iOS/Android with swipe gestures and safe-area support
- **Multiple themes** — Midnight, Dracula, Monokai, Nord, Solarized, and more
- Adjustable font size, sidebar width, and timestamp formatting
- Desktop & mobile push notifications with per-channel granularity
- File uploads — share images and videos directly in channels

### Deployment
- **Single binary** — one `cargo build` and you're done
- Automated deploy script for Debian/Ubuntu with Caddy, Postfix, and systemd
- Automatic HTTPS via Caddy + Let's Encrypt
- Hardened systemd unit with full sandboxing (`ProtectSystem=strict`, `MemoryDenyWriteExecute`, etc.)
- Hot-swap updates with under 1 second of downtime

## Quick Start

```bash
# Clone
git clone https://github.com/gh0st68/cryptirc.git
cd cryptirc

# Deploy (Debian/Ubuntu)
sudo bash deploy/deploy.sh yourdomain.com admin@yourdomain.com
```

That's it. Visit `https://yourdomain.com`, register an account, and connect.

### Adding Users Manually

To create a user from the command line (skips email verification):

```bash
sudo bash adduser.sh <username> <email> <password>
```

The user will be pre-verified and can log in immediately.

See [`deploy/README.md`](deploy/README.md) for detailed deployment docs, backup instructions, and troubleshooting.

## Architecture

```
Browser (PWA)
  ├── E2E encryption (Signal protocol, Web Crypto API)
  ├── Vault unlock (Argon2id KDF → AES-256-GCM)
  └── WebSocket ──► CryptIRC Server (Rust/Axum)
                      ├── IRC connections (TLS)
                      ├── Encrypted log storage
                      ├── Push notifications (Web Push / VAPID)
                      ├── File uploads
                      └── Email verification (Postfix)
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Rust, Tokio, Axum |
| Encryption | AES-256-GCM, Argon2id, Signal Protocol (X3DH + Double Ratchet) |
| TLS | OpenSSL, rcgen (client cert generation) |
| Frontend | Vanilla JS, Web Crypto API, CSS custom properties |
| Push | Web Push with VAPID (RFC 8292) |
| Reverse Proxy | Caddy (automatic HTTPS) |
| Mail | Postfix (local relay) |

## Project Structure

```
src/
├── main.rs           # Axum server, routes, WebSocket handler
├── auth.rs           # Account creation, login, email verification
├── crypto.rs         # AES-256-GCM encrypt/decrypt, Argon2id KDF
├── e2e.rs            # Signal protocol key exchange endpoints
├── irc.rs            # IRC protocol client, message parsing
├── certs.rs          # Client TLS certificate generation
├── logs.rs           # Encrypted log read/write
├── notifications.rs  # Web Push / VAPID notification delivery
├── upload.rs         # File upload handling
└── email.rs          # Verification email dispatch
static/
├── index.html        # Single-page application
├── e2e.js            # Client-side E2E encryption (Signal)
├── sw.js             # Service worker for PWA + push
├── icon.svg          # App icon
└── manifest.json     # PWA manifest
deploy/
├── deploy.sh         # One-command deployment script
├── update.sh         # Hot-swap update script
├── Caddyfile         # Reverse proxy config
├── cryptirc.service  # Systemd unit file
└── README.md         # Deployment documentation
```

## Requirements

- Rust 1.78+ (installed automatically by deploy script)
- Linux (Debian 12 / Ubuntu 22.04+ recommended)
- A domain name with an A record pointing to your server
- Ports 80 and 443 open

## License

Private. All rights reserved.
