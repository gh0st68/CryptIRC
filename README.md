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

## User Registration & Email Verification

CryptIRC uses email verification to authenticate new accounts. Here's how registration works:

1. A user visits the web UI and fills in a **username**, **email**, and **password** (minimum 10 characters)
2. The server creates the account (with `verified: false`) and generates a unique verification token
3. A verification email is sent to the user via **Postfix** running on `localhost:25`
4. The email contains a link: `https://yourdomain.com/auth/verify?token=<uuid>`
5. Clicking the link sets `verified: true` — the user can now log in
6. Verification tokens expire after **24 hours**

### Configuring the From Address

The sender address for verification emails is controlled by the `CRYPTIRC_FROM_EMAIL` environment variable. Set it in your systemd unit or environment:

```ini
Environment=CRYPTIRC_FROM_EMAIL=noreply@yourdomain.com
```

If not set, it defaults to `noreply@cryptirc.local`. The deploy script automatically sets this to the admin email you provide.

Emails are sent through Postfix running on `localhost:25` as a local relay. The deploy script configures this automatically.

### Getting Email Delivery Working

Out of the box, Postfix sends email directly from your server with no relay or external service required. **This works fine** — emails will be sent and delivered, but they'll most likely land in the recipient's **spam/junk folder** since your server probably doesn't have proper SPF, DKIM, or DMARC records set up and the IP may not have a good sending reputation. If you're running a small private instance, just tell your users to check their spam folder for the verification email.

If you want emails to land in the inbox reliably, you can relay through an external SMTP provider. Here are two options:

#### Option A: Gmail SMTP Relay

1. Enable [2-Step Verification](https://myaccount.google.com/security) on your Google account
2. Generate an [App Password](https://myaccount.google.com/apppasswords) (select "Mail")
3. Configure Postfix to relay through Gmail:

```ini
# Add to /etc/postfix/main.cf
relayhost = [smtp.gmail.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_security_level = encrypt
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
```

4. Create the credentials file:

```bash
echo "[smtp.gmail.com]:587 youremail@gmail.com:your-app-password" | sudo tee /etc/postfix/sasl_passwd
sudo postmap /etc/postfix/sasl_passwd
sudo chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
sudo systemctl restart postfix
```

5. Set your from address to match:

```ini
Environment=CRYPTIRC_FROM_EMAIL=youremail@gmail.com
```

#### Option B: Transactional Mail Service (Mailgun, Brevo, etc.)

```ini
# Add to /etc/postfix/main.cf (example: Mailgun)
relayhost = [smtp.mailgun.org]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_security_level = encrypt
```

```bash
echo "[smtp.mailgun.org]:587 postmaster@yourdomain.com:your-smtp-password" | sudo tee /etc/postfix/sasl_passwd
sudo postmap /etc/postfix/sasl_passwd
sudo chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
sudo systemctl restart postfix
```

Free tiers on **Mailgun** (100 emails/day) or **Brevo** (300/day) are more than enough for a self-hosted IRC client.

### Password Reset

Users can reset their password from the login page by clicking **"Forgot password?"**. This sends a reset link to their registered email address. Reset links expire after **1 hour**.

The reset page lets them set a new password (minimum 10 characters) and redirects them back to the login screen.

To reset a user's password manually from the command line:

```bash
sudo bash resetpass.sh <username> <new_password>
```

### Adding Users Manually (No Email Required)

If you don't want to set up email at all, you can create pre-verified users from the command line:

```bash
sudo bash adduser.sh <username> <email> <password>
```

This creates the user with `verified: true` so they can log in immediately — no email sent, no verification needed. Useful for small private instances where you know everyone.

See [`deploy/README.md`](deploy/README.md) for detailed deployment docs, backup instructions, and troubleshooting.

## Install as a PWA (Mobile & Desktop)

CryptIRC is a Progressive Web App — you can install it to your home screen and it runs like a native app with its own window, push notifications, and offline splash screen. No app store needed.

### iPhone / iPad (Safari)

1. Open your CryptIRC URL in **Safari** (this only works in Safari on iOS)
2. Tap the **Share** button (the square with an arrow at the bottom of the screen)
3. Scroll down and tap **Add to Home Screen**
4. Name it whatever you want (defaults to "CryptIRC") and tap **Add**
5. The CryptIRC icon appears on your home screen — tap it to launch in full-screen mode

### Android (Chrome)

1. Open your CryptIRC URL in **Chrome**
2. Tap the **three-dot menu** (top right)
3. Tap **Add to Home screen** (or **Install app** if Chrome shows it)
4. Tap **Install** on the confirmation dialog
5. CryptIRC is now in your app drawer and home screen

### Desktop (Chrome / Edge)

1. Open your CryptIRC URL in Chrome or Edge
2. Click the **install icon** in the address bar (looks like a monitor with a down arrow), or go to the three-dot menu and click **Install CryptIRC**
3. Click **Install** — it opens in its own window, separate from your browser

### What you get with the PWA

- **Full-screen mode** — no browser chrome, looks and feels like a native app
- **Push notifications** — get alerts for mentions, DMs, or all messages even when the app is closed
- **Home screen icon** — quick access with the CryptIRC icon
- **Safe-area support** — properly handles iPhone notch and home indicator
- **Swipe gestures** — swipe to open/close the sidebar on mobile

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

## Configuration

CryptIRC is configured entirely through environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYPTIRC_DATA` | `./data` | Path to the data directory (users, logs, certs, etc.) |
| `CRYPTIRC_BASE_URL` | `http://localhost:9000` | Public URL of your CryptIRC instance |
| `CRYPTIRC_BASE_PATH` | `/cryptirc` | URL path prefix (for running behind a reverse proxy at a subpath) |
| `CRYPTIRC_PORT` | `9001` | Port the server listens on |
| `CRYPTIRC_FROM_EMAIL` | `noreply@cryptirc.local` | Sender address for verification and password reset emails |
| `RUST_LOG` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

### If installed via systemd (deploy script)

Edit the service file:

```bash
sudo nano /etc/systemd/system/cryptirc.service
```

Change or add environment lines:

```ini
Environment=CRYPTIRC_PORT=9001
Environment=CRYPTIRC_BASE_URL=https://yourdomain.com/cryptirc
Environment=CRYPTIRC_FROM_EMAIL=noreply@yourdomain.com
```

Then reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart cryptirc
```

### If running manually (no systemd)

Set the environment variables before running the binary:

```bash
export CRYPTIRC_PORT=8080
export CRYPTIRC_DATA=/var/lib/cryptirc
export CRYPTIRC_BASE_URL=https://yourdomain.com/cryptirc
export CRYPTIRC_FROM_EMAIL=noreply@yourdomain.com
/opt/cryptirc/cryptirc
```

Or inline on one line:

```bash
CRYPTIRC_PORT=8080 CRYPTIRC_DATA=./data /opt/cryptirc/cryptirc
```

## Reverse Proxy Setup

CryptIRC listens on `127.0.0.1:9001` by default and should never be exposed directly to the internet. Put it behind a reverse proxy that handles TLS.

### Nginx

If you're serving CryptIRC at a **subpath** (e.g. `https://yourdomain.com/cryptirc`):

```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location /cryptirc/ {
        proxy_pass http://127.0.0.1:9001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 26m;
    }
}

server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$host$request_uri;
}
```

If you're serving CryptIRC at the **root** of a domain (e.g. `https://cryptirc.yourdomain.com`):

```nginx
server {
    listen 443 ssl;
    server_name cryptirc.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/cryptirc.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cryptirc.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:9001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 26m;
    }
}

server {
    listen 80;
    server_name cryptirc.yourdomain.com;
    return 301 https://$host$request_uri;
}
```

Set `CRYPTIRC_BASE_PATH=/` in your environment when serving from the root.

After editing, test and reload:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

**Important:** The `proxy_http_version 1.1`, `Upgrade`, and `Connection "upgrade"` headers are required for WebSocket support. Without them, IRC connections won't work.

### Caddy

Caddy handles TLS automatically via Let's Encrypt — no certificate configuration needed.

If you're serving CryptIRC at a **subpath**:

```caddyfile
yourdomain.com {
    handle_path /cryptirc/* {
        reverse_proxy localhost:9001 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-For {remote_host}
            header_up X-Forwarded-Proto {scheme}
        }
    }
}
```

If you're serving CryptIRC at the **root** of a dedicated domain:

```caddyfile
cryptirc.yourdomain.com {
    reverse_proxy localhost:9001 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }

    encode zstd gzip

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Robots-Tag "noindex, nofollow"
        -Server
    }
}
```

Set `CRYPTIRC_BASE_PATH=/` in your environment when serving from the root.

After editing, validate and reload:

```bash
caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Caddy automatically handles WebSocket upgrades — no extra headers needed.

### TLS Certificates

- **Caddy**: Automatic. Caddy obtains and renews Let's Encrypt certs with zero configuration.
- **Nginx + Let's Encrypt**: Use [certbot](https://certbot.eff.org/) to obtain certs:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

Certbot auto-renews via a systemd timer. Verify with:

```bash
sudo certbot renew --dry-run
```

## Requirements

- Rust 1.78+ (installed automatically by deploy script)
- Linux (Debian 12 / Ubuntu 22.04+ recommended)
- A domain name with an A record pointing to your server
- Ports 80 and 443 open

## License

Private. All rights reserved.
