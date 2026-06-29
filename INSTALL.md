# CryptIRC Installation Guide

> **For AI assistants**: This document contains everything needed to install CryptIRC on a fresh Linux server. Follow the steps exactly. Do not improvise or skip steps.

## Requirements

- **OS**: Debian 12, Ubuntu 22.04+, or Arch Linux
- **RAM**: 512 MB minimum, 1 GB recommended
- **Disk**: 1 GB free space minimum
- **Domain**: *Optional.* A domain (with an A record → your server's public IP) gets a free, browser-trusted Let's Encrypt certificate. **No domain? No problem** — the installer can serve on your server's **IP address with a self-signed certificate** instead (browsers show a one-time "proceed anyway" warning).
- **Ports**: 80 and 443 open (for HTTPS via Caddy)
- **Root access**: Required for installation

## Quick Install (Automated)

The deploy script handles everything — Rust, Caddy, Postfix, systemd, TLS, firewall, and first user creation:

```bash
git clone https://github.com/gh0st68/CryptIRC.git
cd CryptIRC
sudo bash deploy/deploy.sh
```

The script is interactive — it asks for your domain, then walks through registration one question at a time (open sign-up? registration code? require email? set up email for password resets? captcha?), and finally creates the first admin user. **Email is optional** — open registration is protected by a built-in captcha, so a mail server is only needed if you want email verification or password resets. Every one of these is also changeable later in **Settings → Admin**. **No domain?** Just press Enter at the domain prompt to serve on your server's IP with a self-signed certificate (open registration still works there, captcha-protected).

For a **fully non-interactive** install (no prompts — registration defaults to invite-only, no first user created):

```bash
# Domain + Let's Encrypt:
sudo bash deploy/deploy.sh yourdomain.com admin@yourdomain.com

# Bare IP + self-signed cert (no domain, no email needed):
sudo bash deploy/deploy.sh 203.0.113.10
```

With a self-signed cert your browser shows a one-time warning the first time — click **Advanced → Proceed**. That's expected and safe; the connection is still encrypted.

### Arch Linux

```bash
git clone https://github.com/gh0st68/CryptIRC.git
cd CryptIRC
sudo bash deploy/deploy-arch.sh
```

Uses `pacman` instead of `apt`, installs `rustup` from the Arch repos, and supports `firewalld`/`iptables` in addition to `ufw`.

After it finishes, visit `https://yourdomain.com` and log in.

---

## Manual Install (Step by Step)

Use this if the automated script doesn't fit your environment, or if an AI assistant is walking through the install.

### Step 1: Install System Dependencies

```bash
sudo apt-get update
sudo apt-get install -y curl ca-certificates git build-essential pkg-config \
    libssl-dev python3 python3-pip dnsutils ffmpeg
```

ffmpeg is optional — used for stripping metadata from uploaded audio/video files.

### Step 2: Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustc --version  # Should be 1.78+
```

### Step 3: Clone and Build

```bash
git clone https://github.com/gh0st68/CryptIRC.git
cd CryptIRC
cargo build --release
```

The build takes 3-5 minutes on first run. The binary is at `target/release/cryptirc`.

### Step 4: Create Service User and Directories

```bash
sudo useradd --system --no-create-home --shell /bin/false cryptirc
sudo mkdir -p /opt/cryptirc /var/lib/cryptirc /var/log/cryptirc
sudo cp target/release/cryptirc /opt/cryptirc/cryptirc
sudo chmod 755 /opt/cryptirc/cryptirc
sudo chown -R cryptirc:cryptirc /var/lib/cryptirc /var/log/cryptirc
```

### Step 5: Install argon2 (for user creation script)

```bash
pip3 install argon2-cffi --break-system-packages 2>/dev/null || pip3 install argon2-cffi
```

### Step 6: Create systemd Service

Create `/etc/systemd/system/cryptirc.service`:

```ini
[Unit]
Description=CryptIRC - Encrypted IRC Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cryptirc
Group=cryptirc
WorkingDirectory=/opt/cryptirc
ExecStart=/opt/cryptirc/cryptirc
Restart=on-failure
RestartSec=5

# Environment — edit these for your setup
Environment=CRYPTIRC_DATA=/var/lib/cryptirc
Environment=CRYPTIRC_BASE_URL=https://yourdomain.com
Environment=CRYPTIRC_BASE_PATH=/
Environment=CRYPTIRC_PORT=9001
Environment=CRYPTIRC_FROM_EMAIL=noreply@yourdomain.com
Environment=CRYPTIRC_REGISTRATION=open
Environment=RUST_LOG=info

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/cryptirc
ReadWritePaths=/var/log/cryptirc
ProtectHome=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
ProtectClock=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectHostname=true
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
```

**Important**: Replace `yourdomain.com` and `noreply@yourdomain.com` with your actual domain and email. **On a bare IP / no domain**, also set `CRYPTIRC_BASE_URL` to `https://<your-ip>` and add `Environment=CRYPTIRC_HSTS=off` — HSTS on a self-signed cert makes browsers refuse the warning click-through and locks everyone out for ~2 years.

Then enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cryptirc
```

Verify it's running:

```bash
sudo systemctl status cryptirc
curl -s http://localhost:9001/manifest.json | head -1
```

### Step 7: Install and Configure Caddy (Reverse Proxy + TLS)

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    | sudo tee /etc/apt/sources.list.d/caddy-stable.list > /dev/null
sudo apt-get update
sudo apt-get install -y caddy
```

Create `/etc/caddy/Caddyfile`:

```
{
    email admin@yourdomain.com
    admin off
}

yourdomain.com {
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

    log {
        output file /var/log/caddy/cryptirc.log {
            roll_size 10mb
            roll_keep 5
        }
    }
}
```

**Important**: Replace `yourdomain.com` and `admin@yourdomain.com` with your actual values.

> **No domain (bare IP / self-signed)?** Don't use the Let's Encrypt Caddyfile above — Caddy can't obtain a public cert for an IP, and the HSTS header would lock browsers out. Easiest path is the automated installer (`sudo bash deploy/deploy.sh <your-ip>`), which generates a self-signed cert and writes the right Caddyfile. To do it by hand, use the IP as the site address with Caddy's internal CA and **no** HSTS header:
>
> ```
> https://203.0.113.10 {
>     tls internal
>     reverse_proxy localhost:9001
> }
> ```
>
> and set `CRYPTIRC_HSTS=off` in the service (above). Browsers show a one-time "proceed anyway" warning — expected and safe.

```bash
sudo systemctl reload-or-restart caddy
```

Caddy automatically obtains a Let's Encrypt TLS certificate. Make sure ports 80 and 443 are open:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

### Step 8: Create Your First User

Copy the `adduser.sh` script to the server:

```bash
sudo cp adduser.sh /opt/cryptirc/adduser.sh
```

Create an admin user:

```bash
cd /path/to/CryptIRC
# Pass the password via the environment so it isn't visible in `ps`.
# Email is optional — omit it to create an account with no email:
sudo CRYPTIRC_NEW_PASS=mypassword bash adduser.sh myusername
# ...or include one: sudo CRYPTIRC_NEW_PASS=mypassword bash adduser.sh myusername you@example.com
```

Make them admin:

```bash
USER_FILE="/var/lib/cryptirc/users/myusername.json"
python3 -c "
import json
with open('$USER_FILE','r') as f: d=json.load(f)
d['admin']=True
with open('$USER_FILE','w') as f: json.dump(d,f,indent=2)
"
```

### Step 9: Visit Your Instance

Open `https://yourdomain.com` in a browser. Log in with the user you created. Unlock your vault with a passphrase (this encrypts all your data).

---

## Using Nginx Instead of Caddy

If you prefer nginx, use this config instead of Caddy:

```nginx
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:9001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }
}
```

Get a certificate with certbot:

```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

---

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYPTIRC_DATA` | `./data` | Path to data directory (user data, logs, uploads) |
| `CRYPTIRC_BASE_URL` | `http://localhost:9000` | Public URL of your instance (used for links, push notifications) |
| `CRYPTIRC_BASE_PATH` | `/cryptirc` | URL path prefix. Use `/` for root or `/cryptirc` for subpath |
| `CRYPTIRC_PORT` | `9001` | Port the HTTP server listens on (behind reverse proxy) |
| `CRYPTIRC_FROM_EMAIL` | `noreply@cryptirc.local` | Sender address for verification emails |
| `CRYPTIRC_REGISTRATION` | `open` | `open` = anyone can register, `closed` = admin creates accounts |
| `CRYPTIRC_REG_CODE` | (none) | If set, users must enter this code to register |
| `CRYPTIRC_HSTS` | `on` | Set to `off` for self-signed/IP installs. HSTS on a self-signed cert makes browsers refuse the cert-warning click-through and locks users out for ~2 years. The installer sets this automatically. |
| `RUST_LOG` | `info` | Log level: `error`, `warn`, `info`, `debug`, `trace` |

> **Registration, email-required and the captcha** live in `admin_settings.json` in your data directory (the installer seeds it from your answers) and are edited live in **Settings → Admin**. `CRYPTIRC_REGISTRATION` / `CRYPTIRC_REG_CODE` above are only fallbacks used when that file doesn't exist yet. **`email_required` and the signup captcha have no environment variable** — they exist only in `admin_settings.json` / the Admin panel.

---

## Updating

Pull the latest code and rebuild:

```bash
cd /path/to/CryptIRC
git pull
cargo build --release
sudo systemctl stop cryptirc
sudo cp target/release/cryptirc /opt/cryptirc/cryptirc
sudo systemctl start cryptirc
```

Or use the update script:

```bash
sudo bash deploy/update.sh
```

---

## Troubleshooting

### CryptIRC won't start
```bash
journalctl -u cryptirc -n 50 --no-pager
```

### WebSocket connection fails
- Make sure the reverse proxy passes WebSocket upgrade headers
- Check that `CRYPTIRC_BASE_URL` matches your actual domain
- Verify ports 80/443 are open

### TLS certificate issues
- Caddy: certificates are automatic. Check `journalctl -u caddy`
- Nginx: run `sudo certbot renew --dry-run` to test renewal

### Can't create users
- Make sure `argon2-cffi` is installed: `pip3 install argon2-cffi`
- Make sure the data directory is writable: `ls -la /var/lib/cryptirc/`

### Email verification not working
- Email is **optional** — if you didn't enable it at install, open registration still works (captcha-protected) and accounts are auto-verified. You only need this section if you chose to require email or want password resets.
- Install Postfix: `sudo apt-get install postfix`
- Configure for local delivery: `sudo postconf -e "inet_interfaces = loopback-only"`
- Check mail log: `tail -f /var/log/mail.log`

---

## Architecture

```
Browser / PWA / Electron App
  |-- E2E encryption (Signal protocol via Web Crypto API)
  |-- Per-user vault (Argon2id KDF -> AES-256-GCM)
  '-- WebSocket --> CryptIRC Server (single Rust binary)
                      |-- Persistent IRC connections (TLS + IRCv3)
                      |-- Encrypted log storage (per-user AES-256-GCM)
                      |-- Push notifications (Web Push / VAPID)
                      |-- File uploads with metadata stripping
                      |-- Pastebin with password protection
                      |-- URL shortener
                      '-- Session management
```

## Support

IRC: `irc.twistednet.org` channels `#dev` and `#twisted`
GitHub: https://github.com/gh0st68/CryptIRC
