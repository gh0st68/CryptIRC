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
    libssl-dev python3 python3-pip dnsutils ffmpeg libimage-exiftool-perl
```

ffmpeg is optional — used for stripping metadata from uploaded audio/video files. exiftool (`libimage-exiftool-perl`) strips metadata from GIF/WebP/AVIF/HEIC/HEIF/TIFF uploads; without it those uploads are refused. (On Arch: `perl-image-exiftool`, then `sudo ln -s /usr/bin/vendor_perl/exiftool /usr/local/bin/exiftool` so the service can find it.)

### Step 2: Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustc --version  # Must be 1.88 or newer (the locked dependencies need it)
```

### Step 3: Clone and Build

```bash
git clone https://github.com/gh0st68/CryptIRC.git
cd CryptIRC
cargo build --release
```

The build takes 3-5 minutes on first run. It produces two binaries: `target/release/cryptirc` (the web server) and `target/release/irc_core` (the IRC connection daemon — the web server hands every IRC connection to it, so you need both).

### Step 4: Create Service User and Directories

```bash
sudo useradd --system --no-create-home --shell /bin/false cryptirc
sudo mkdir -p /opt/cryptirc /var/lib/cryptirc /var/log/cryptirc
sudo install -m 755 target/release/cryptirc /opt/cryptirc/cryptirc
sudo install -m 755 target/release/irc_core /opt/cryptirc/irc_core
sudo chown -R cryptirc:cryptirc /var/lib/cryptirc /var/log/cryptirc
sudo chmod 750 /var/lib/cryptirc /var/log/cryptirc
```

### Step 5: Install argon2 (for the user scripts)

`adduser.sh` and `resetpass.sh` run as root (via `sudo`), so the Python `argon2-cffi` package must be installed system-wide — a plain `pip3 install` as your own user puts it where root's Python never looks:

```bash
sudo apt-get install -y python3-argon2
# Not packaged on your distro? Install it for root instead:
#   sudo pip3 install argon2-cffi --break-system-packages
sudo python3 -c 'import argon2; print("argon2 OK")'
```

### Step 6: Create the systemd Services

CryptIRC runs as two services: `irc-core` holds the IRC connections (so restarting or updating the web server doesn't drop anyone's IRC session) and `cryptirc` is the web server. Without `irc-core` the web UI loads but IRC never connects.

**6a. The IRC connection daemon.** The repository ships the reference unit, already set up for the paths used in this guide:

```bash
sudo install -m 644 deploy/irc-core.service /etc/systemd/system/irc-core.service
```

(If you changed the data directory or the service user, edit `CRYPTIRC_DATA`, `ReadWritePaths`, `User` and `Group` in that file to match.)

**6b. The web server.** Create `/etc/systemd/system/cryptirc.service`:

```ini
[Unit]
Description=CryptIRC - Encrypted IRC Client
After=network-online.target caddy.service irc-core.service
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=cryptirc
Group=cryptirc
WorkingDirectory=/opt/cryptirc
ExecStart=/opt/cryptirc/cryptirc
ExecStop=/bin/kill -s TERM $MAINPID
TimeoutStopSec=30
KillMode=mixed
Restart=on-failure
RestartSec=5
# Files the service creates default to 0600/0700, even where a code path forgets to chmod.
UMask=0077

# Environment — edit these for your setup
Environment=CRYPTIRC_DATA=/var/lib/cryptirc
Environment=CRYPTIRC_BASE_URL=https://yourdomain.com
Environment=CRYPTIRC_BASE_PATH=/
Environment=CRYPTIRC_PORT=9001
Environment=CRYPTIRC_FROM_EMAIL=noreply@yourdomain.com
Environment=CRYPTIRC_REGISTRATION=open
# HSTS: "on" for a domain with a real (Let's Encrypt) certificate. On a bare IP / self-signed
# certificate set it to off — HSTS there makes browsers refuse the warning click-through and
# locks everyone out for ~2 years:
Environment=CRYPTIRC_HSTS=on
Environment=RUST_LOG=info
# Secrets (a registration code) go in this root-only file, not in Environment= lines:
EnvironmentFile=-/etc/cryptirc/cryptirc.env
Environment=NO_COLOR=1
# ffmpeg + exiftool strip upload metadata; Arch installs exiftool in /usr/bin/vendor_perl.
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/bin/site_perl:/usr/bin/vendor_perl:/usr/bin/core_perl

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
CapabilityBoundingSet=
AmbientCapabilities=
LockPersonality=true
ProtectClock=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectHostname=true
LimitNOFILE=65536
TasksMax=512

[Install]
WantedBy=multi-user.target
```

Don't put a registration code (or any other secret) in an `Environment=` line: every local user can read those with `systemctl show cryptirc`, whatever the unit file's permissions are, and systemd expands `%` in them. Put it in the root-only file the unit loads instead — values there are taken literally, except that inside double quotes a backslash, double quote, backtick or dollar sign needs a backslash in front of it:

```bash
sudo install -d -m 700 /etc/cryptirc
sudo install -m 600 /dev/null /etc/cryptirc/cryptirc.env
echo 'CRYPTIRC_REG_CODE="your-code"' | sudo tee /etc/cryptirc/cryptirc.env >/dev/null
```

(Not using a code? Leave the file out — the `-` in `EnvironmentFile=-…` makes it optional.)

**Important**: Replace `yourdomain.com` and `noreply@yourdomain.com` with your actual domain and email. **On a bare IP / no domain**, also set `CRYPTIRC_BASE_URL` to `https://<your-ip>` and change the line above to `Environment=CRYPTIRC_HSTS=off` — HSTS on a self-signed cert makes browsers refuse the warning click-through and locks everyone out for ~2 years.

Then enable and start both — `irc-core` first:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now irc-core
sudo systemctl enable --now cryptirc
```

Verify they're running:

```bash
sudo systemctl status irc-core cryptirc
sudo ls -la /var/lib/cryptirc/irc-core.sock     # the daemon's socket — must exist
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

Caddy writes its access log to `/var/log/caddy/` (the Caddyfile below), and runs as the unprivileged `caddy` user, which can't create that directory itself:

```bash
sudo install -d -o caddy -g caddy -m 750 /var/log/caddy
```

Create `/etc/caddy/Caddyfile`:

```
{
    email admin@yourdomain.com
    admin off
}

yourdomain.com {
    reverse_proxy 127.0.0.1:9001 {
        header_up Host {host}
        # {client_ip}: the client's address (Caddy 2.7+; on an older Caddy write {remote_host}).
        # Behind a CDN, see "Client IP addresses behind a proxy" below.
        header_up X-Real-IP {client_ip}
        header_up X-Forwarded-For {client_ip}
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
        # Keep one-time secrets out of the access log: email-verify / password-reset tokens
        # and paste passwords travel in the query string (and the Referer of a page opened
        # from such a link would repeat them).
        format filter {
            request>uri query {
                replace token REDACTED
                replace password REDACTED
                # link / X previews: the chat URL being previewed, and the signed
                # media-fallback values (see "X post previews" below)
                replace url REDACTED
                replace sig REDACTED
                replace a REDACTED
            }
            request>headers>Referer delete
        }
    }
}
```

**Important**: Replace `yourdomain.com` and `admin@yourdomain.com` with your actual values. If you add your own `log` block anywhere else, give it the same `format filter` — without it, the access log keeps reset and verification links someone could reuse.

> **No domain (bare IP / self-signed)?** Don't use the Let's Encrypt Caddyfile above — Caddy can't obtain a public cert for an IP, and the HSTS header would lock browsers out. Easiest path is the automated installer (`sudo bash deploy/deploy.sh <your-ip>`), which generates a self-signed cert and writes the right Caddyfile. To do it by hand, use the IP as the site address with Caddy's internal CA and **no** HSTS header:
>
> ```
> https://203.0.113.10 {
>     tls internal
>     reverse_proxy 127.0.0.1:9001
> }
> ```
>
> and set `CRYPTIRC_HSTS=off` in the service (above). Browsers show a one-time "proceed anyway" warning — expected and safe.
>
> **The desktop app on a public IP:** it needs a **publicly trusted certificate** — a domain with a Let's Encrypt certificate (the Caddyfile above). On a public IP like the example it refuses a self-signed or `tls internal` certificate outright, with no prompt, unless that certificate (or Caddy's root, see below) is installed as trusted on each desktop machine. Browsers are not affected: they show the warning and let users proceed.
>
> **The desktop app on a LAN / private address** (`localhost`, `*.local`, `127.x`, `10.x`, `172.16–31.x`, `192.168.x`, `::1` — the only addresses where it accepts a certificate that isn't publicly trusted): it asks once, then remembers (pins) the certificate and refuses one that later changes without warning. `tls internal` re-issues its short-lived certificate (a 12-hour certificate, renewed every few hours) with a new key, so desktop users would get the "certificate changed" page after each renewal. To avoid that on a LAN server, either use the installer (it creates a long-lived self-signed certificate), point Caddy at a long-lived certificate of your own (`tls /etc/caddy/cert.pem /etc/caddy/key.pem` instead of `tls internal`), or install Caddy's root certificate as trusted on each desktop machine; a trusted certificate needs no pin. Caddy keeps that root in its data directory: `/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt` with the Debian/Ubuntu package, `/var/lib/caddy/pki/authorities/local/root.crt` with Arch's (its unit sets `XDG_DATA_HOME=/var/lib`).

```bash
# restart, not reload: with `admin off` (above) Caddy has no admin API, so `reload` fails
sudo systemctl restart caddy
```

Caddy automatically obtains a Let's Encrypt TLS certificate. Make sure ports 80 and 443 are open. Stock Debian has no firewall at all (and no `ufw` command); only if you run one:

```bash
sudo ufw allow 80/tcp && sudo ufw allow 443/tcp                  # ufw
sudo firewall-cmd --permanent --add-service={http,https} && sudo firewall-cmd --reload   # firewalld
```

A cloud firewall / security group must allow TCP 80 and 443 too.

### Step 8: Create Your First User

The account scripts — `adduser.sh`, `makeadmin.sh` and `resetpass.sh` — run from your CryptIRC checkout, side by side (keep the checkout: `deploy/update.sh` lives there too). There is nothing to copy.

Create a user, then make them admin:

```bash
cd /path/to/CryptIRC
# Prompts for the password twice (nothing is echoed). Email is optional:
sudo bash adduser.sh myusername
# ...or with one:  sudo bash adduser.sh myusername you@example.com
```

The password has to meet the same rules as signing up in the app: at least 10 characters, with an upper-case letter, a lower-case letter, a digit and a symbol. One account per email address.

From a script, pipe the password in on stdin instead:

```bash
printf '%s\n' "$PASSWORD" | sudo bash adduser.sh --password-stdin myusername you@example.com
```

Never put the password on the `sudo` command line — `sudo CRYPTIRC_NEW_PASS=... bash adduser.sh` (the old documented form, still accepted with a warning) shows it to every local user in `ps` and writes it to sudo's log.

Make them admin:

```bash
sudo bash makeadmin.sh myusername
```

A fresh install has no admins and there is no in-app way to create one, so this
step is what unlocks the Admin panel. It takes effect immediately — nothing to
restart — though the browser tab needs a reload before the Admin entry appears
in Settings.

Other things the script does:

```bash
sudo bash makeadmin.sh --list             # who exists, and who is an admin
sudo bash makeadmin.sh --revoke someone   # take admin away
```

It refuses to remove the last admin (that would lock everyone out of the panel
with no way back in) unless you add `--force`.

### Step 9: Visit Your Instance

Open `https://yourdomain.com` in a browser. Log in with the user you created. Unlock your vault with a passphrase (this encrypts all your data).

---

## Using Nginx Instead of Caddy

If you prefer nginx, first get the certificate, then put the full config in place: the config below names the certificate files, and `nginx -t` (which certbot runs too) refuses a config whose certificate doesn't exist yet.

**1. Bootstrap: HTTP only, then the certificate.** Create `/etc/nginx/sites-available/cryptirc` (Debian/Ubuntu; enable it with `sudo ln -s /etc/nginx/sites-available/cryptirc /etc/nginx/sites-enabled/`) with just:

```nginx
server {
    listen 80;
    server_name yourdomain.com;
    location / { return 404; }
}
```

```bash
sudo nginx -t && sudo systemctl reload nginx
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot certonly --nginx -d yourdomain.com     # gets the certificate; leaves your config alone
```

**2. The full config.** Replace the file's content with this, then `sudo nginx -t && sudo systemctl reload nginx` (certbot renews the certificate by itself through the same nginx plugin):

```nginx
# Access log WITHOUT query strings or the Referer: password-reset / email-verify links carry
# a live token in the query string (so do paste passwords), and the Referer of a page opened
# from such a link repeats it. nginx's default log line records both, so anyone who can read
# the log (or a log collector) could reuse a reset link. (log_format belongs at the http {}
# level — a file in sites-available/ or conf.d/ is included there.)
log_format cryptirc_noquery '$remote_addr - $remote_user [$time_local] "$request_method $uri $server_protocol" '
                            '$status $body_bytes_sent "$http_user_agent"';

server {
    listen 80;
    server_name yourdomain.com;
    access_log /var/log/nginx/cryptirc.access.log cryptirc_noquery;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    access_log /var/log/nginx/cryptirc.access.log cryptirc_noquery;

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

Already running nginx for CryptIRC with the default access log? Add the `log_format` and the two `access_log` lines above, `sudo nginx -t && sudo systemctl reload nginx`, and delete or restrict the old log files that hold full URLs (reset links expire after an hour). nginx's **error** log can still name a request line when CryptIRC itself is down (`upstream … request: "GET …"`), so keep that log root-only too.

---

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYPTIRC_DATA` | `./data` | Path to data directory (user data, logs, uploads) |
| `CRYPTIRC_BASE_URL` | `http://localhost:9000` | Public URL of your instance (used for links, push notifications and shared avatars — sharing avatars needs a public https URL) |
| `CRYPTIRC_BASE_PATH` | `/cryptirc` | URL path prefix. Use `/` for root or `/cryptirc` for subpath |
| `CRYPTIRC_PORT` | `9001` | Port the HTTP server listens on (behind reverse proxy) |
| `CRYPTIRC_FROM_EMAIL` | `noreply@cryptirc.local` | Sender address for verification emails |
| `CRYPTIRC_REGISTRATION` | `open` | `open` = anyone can register, `closed` = admin creates accounts |
| `CRYPTIRC_REG_CODE` | (none) | If set, users must enter this code to register |
| `CRYPTIRC_HSTS` | `on` | Set to `off` for self-signed/IP installs. HSTS on a self-signed cert makes browsers refuse the cert-warning click-through and locks users out for ~2 years. The installer sets this automatically. |
| `CRYPTIRC_IPC_SOCK` | `$CRYPTIRC_DATA/irc-core.sock` | Unix socket between the web server and the `irc-core` daemon. If you set it, set the same value in **both** units. |
| `CRYPTIRC_TRUSTED_PROXIES` | (none) | Extra reverse proxies (IPs or CIDRs, comma- or space-separated, e.g. `10.0.0.5, 2001:db8::/64`) whose forwarding headers are believed. Loopback is always trusted. See [Client IP addresses](#client-ip-addresses-behind-a-proxy). |
| `CRYPTIRC_REAL_IP_HEADER` | `auto` | Which header a trusted proxy's client address is read from: `auto`, `x-forwarded-for` (or `xff`), `x-real-ip`, or `off`. See below. |
| `CRYPTIRC_X_GUEST_ENABLED` | (off) | `1` enables the X guest-GraphQL post provider (needs `CRYPTIRC_X_GUEST_BEARER`). See [X post previews](#x-post-previews-optional). |
| `CRYPTIRC_X_GUEST_BEARER` | (none) | Operator-supplied bearer for the guest provider. A secret: put it in `/etc/cryptirc/cryptirc.env`, never in an `Environment=` line. |
| `CRYPTIRC_X_GRAPHQL_CONFIG` | (bundled snapshot) | Optional absolute path to a ≤16 KiB operation-ID/feature JSON for the guest provider. |
| `CRYPTIRC_X_FXTWITTER_ENABLED` | (off) | `1` enables the secret-free FixTweet post provider (used only when the guest provider is not configured). |
| `CRYPTIRC_X_THREADREADER_ENABLED` | (off) | `1` enables the optional published-thread viewer (ThreadReaderApp), independent of the post providers. |
| `CRYPTIRC_AI_ALLOW_PRIVATE` | (off) | `1`/`true`/`yes`/`on` lets the AI bot's **custom** provider reach private, loopback, link-local or internal-name endpoints (e.g. a self-hosted Ollama on `127.0.0.1`). Off by default. See below. |
| `RUST_LOG` | `info` | Log level: `error`, `warn`, `info`, `debug`, `trace` |

> **Registration, email-required and the captcha** live in `admin_settings.json` in your data directory (the installer seeds it from your answers) and are edited live in **Settings → Admin**. `CRYPTIRC_REGISTRATION` / `CRYPTIRC_REG_CODE` above are fallbacks: each applies only while `admin_settings.json` does not hold that setting (until it is saved in the Admin panel — saving other admin settings, such as link previews, does not save it). If the file exists but is corrupt, registration is closed until it is fixed. **`email_required` and the signup captcha have no environment variable** — they exist only in `admin_settings.json` / the Admin panel.

### Client IP addresses behind a proxy

CryptIRC rate-limits logins, sign-ups and resets per client address (IPv6 per /64). It only listens on 127.0.0.1, so the TCP peer is normally your own reverse proxy, and it decides the client's address like this:

- **A peer that is not a trusted proxy** is keyed by its own address. Forwarding headers from it are ignored, so they can't be forged.
- **Trusted proxies** are loopback (always) plus `CRYPTIRC_TRUSTED_PROXIES`. From one of them, `CRYPTIRC_REAL_IP_HEADER` picks the header:
  - `x-forwarded-for` — `X-Forwarded-For` read from the right, skipping trusted hops; the first untrusted address wins (an unparseable entry ends the walk). For proxies that append to that header and don't set `X-Real-IP` themselves (Caddy without `header_up X-Real-IP`, HAProxy, Apache).
  - `x-real-ip` — `X-Real-IP` only. For proxies that set it but pass the client's own `X-Forwarded-For` through (nginx without a `proxy_set_header X-Forwarded-For` line).
  - `off` — no headers: every request is keyed by the proxy's address, so all clients share one limit.
  - `auto` (default) — both headers are checked, ignoring any that name a trusted address. If only one names a client, or both name the same one, that is used. If they name **different** clients, one of them was written by the client, so neither is believed: those requests all share a single rate-limit bucket (`ambiguous-fwd`), and the log warns (at most hourly) that you should set `CRYPTIRC_REAL_IP_HEADER`.

The configs in this guide and the installers' Caddy config set both headers to the client address they see, so the defaults are right for them.

**Behind a CDN or a load balancer** (Cloudflare proxying, say), the address Caddy or nginx sees is the CDN's, so every user would share the CDN's rate limits. The fix belongs in **your web server**, not in CryptIRC: CryptIRC only ever talks to Caddy/nginx over loopback (always trusted), and they overwrite the forwarding headers with the address they believe. Tell them which addresses belong to the CDN:

- **Caddy** — in the global options at the top of `/etc/caddy/Caddyfile` (the installer keeps a main Caddyfile you add options to as yours):

  ```
  {
      servers {
          trusted_proxies static 173.245.48.0/20 103.21.244.0/22   # your CDN's ranges, nothing else
          trusted_proxies_strict                                    # read X-Forwarded-For from the right
      }
  }
  ```

  **Both lines are needed.** With `trusted_proxies` alone Caddy takes the client from the *left* end of `X-Forwarded-For` — the part the client writes itself (the CDN only appends the address it saw) — so anyone could send a new made-up address with every login attempt and never hit the rate limits or the captcha. `trusted_proxies_strict` (Caddy 2.8+) reads from the right and skips only your CDN's ranges. A CDN that puts the client in a header of its own, one the client can't set, works too — for Cloudflare (its ranges: https://www.cloudflare.com/ips/), instead of `trusted_proxies_strict`:

  ```
  {
      servers {
          trusted_proxies static 173.245.48.0/20 103.21.244.0/22   # Cloudflare's ranges, nothing else
          client_ip_headers CF-Connecting-IP
      }
  }
  ```

  `{client_ip}` — which the installers' CryptIRC site uses on Caddy 2.7+, as does the Caddyfile above — is then the real client. The installer checks this: if Caddy trusts proxies but would read a client-written `X-Forwarded-For` from the left, its site passes the connecting address (`{remote_host}`) instead and says why. On Caddy older than 2.7 (`caddy version`), `{client_ip}` doesn't exist and the installer writes `{remote_host}`: upgrade Caddy for this (2.8+ for `trusted_proxies_strict`).
- **nginx** — `set_real_ip_from <each CDN range>;`, `real_ip_header X-Forwarded-For;` and `real_ip_recursive on;` (module `ngx_http_realip_module`) in the `server` block (nginx then reads from the right, skipping only those ranges); `$remote_addr`, which the nginx config in [Using Nginx Instead of Caddy](#using-nginx-instead-of-caddy) above passes on, is then the client.

Leave `CRYPTIRC_TRUSTED_PROXIES` empty in these setups. It is only for a proxy that reaches CryptIRC from a non-loopback address (another container or network namespace on the same host); then set `CRYPTIRC_REAL_IP_HEADER` to match what that proxy sends.

### AI bot custom endpoints

The built-in AI bot's **custom** provider lets a user point it at any OpenAI-compatible URL. By default CryptIRC refuses URLs that resolve to a private, loopback, link-local or internal-name address, so a user can't make the server fetch from its own loopback admin APIs, the cloud metadata service or the intranet (an SSRF guard). On a multi-user server **any** account can set a custom endpoint, so this applies to everyone.

To point the bot at a self-hosted model (Ollama, LM Studio, a LAN box), set `CRYPTIRC_AI_ALLOW_PRIVATE=1` in the service environment (a `systemctl edit cryptirc` drop-in, or a line in `/etc/cryptirc/cryptirc.env` — re-running the installer keeps lines you add there) and restart `cryptirc`. Only enable it when every account on the instance is trusted. The installer never sets it.

### X post previews (optional)

CryptIRC can render X/Twitter status links as rich cards (author, text, exact counts, photo galleries, native video/GIF playback after Play, one level of quoted post, and an optional published-thread viewer). **Everything is off by default.** With none of the variables below set, the server never contacts an X preview provider (X's API, FixTweet or ThreadReaderApp); `GET <base>/tweet/config` tells browsers nothing is offered, and X links behave exactly as they did before this feature — the ordinary link, plus the generic link preview if your admin link-preview policy allows `x.com`/`twitter.com` (the default whitelist does), with the usual click-to-load step for links in encrypted messages (a recognized X status link is never fetched as an image or video, whatever it ends with). Once a provider is offered, X links switch to X cards and are never sent to the generic `/preview` fetcher.

**Providers** (read once at startup; restart the web service after a change):

| Variable | What it enables | Who learns what |
|---|---|---|
| `CRYPTIRC_X_FXTWITTER_ENABLED=1` | Post cards from the public FixTweet API (`api.fxtwitter.com`). No credential, no rotating operation IDs. Used only when the guest provider below is not configured. | FixTweet receives the post ID and your server's IP for each preview. Third-party service; its response shape is unverified live. |
| `CRYPTIRC_X_GUEST_ENABLED=1` + `CRYPTIRC_X_GUEST_BEARER` (+ optional `CRYPTIRC_X_GRAPHQL_CONFIG`) | Post cards from X's guest GraphQL endpoint on `api.x.com`. Requires a bearer you are permitted to use. The bundled operation snapshot (`src/twitter/provider-config.json`) drifts when X rotates operation IDs; point `CRYPTIRC_X_GRAPHQL_CONFIG` at an updated file (absolute path, ≤16 KiB, keys `tweet_query_id` and `tweet_features` only, no credentials). | X receives the post ID and your server's IP. |
| `CRYPTIRC_X_THREADREADER_ENABLED=1` | A separate "Read thread…" action: after the viewer confirms, one published thread document is fetched from `threadreaderapp.com`. Independent of the post providers. | ThreadReaderApp receives the post ID. |

Invalid configuration (e.g. guest enabled without a bearer, a bad config file) turns **post previews off** with one coarse log line — even if `CRYPTIRC_X_FXTWITTER_ENABLED` is also set, there is never a silent switch to another provider or host. (The thread viewer is independent.) Only enable a provider you are permitted to use; offline tests do not establish live availability.

**Secret setup.** The bearer is a secret. Put it in the root-only environment file the unit already loads (`EnvironmentFile=-/etc/cryptirc/cryptirc.env`, created as in Step 6), not in an `Environment=` line (`systemctl show` exposes those):

```bash
sudo install -d -m 700 /etc/cryptirc
sudo touch /etc/cryptirc/cryptirc.env && sudo chmod 600 /etc/cryptirc/cryptirc.env
echo 'CRYPTIRC_X_GUEST_ENABLED=1'              | sudo tee -a /etc/cryptirc/cryptirc.env >/dev/null
echo 'CRYPTIRC_X_GUEST_BEARER="<bearer text, without the Bearer prefix>"' | sudo tee -a /etc/cryptirc/cryptirc.env >/dev/null
# or, secret-free:  echo 'CRYPTIRC_X_FXTWITTER_ENABLED=1' | sudo tee -a /etc/cryptirc/cryptirc.env >/dev/null
sudo systemctl restart cryptirc        # the web service only — irc-core needs no restart
```

systemd reads that file as root, so it can stay `0600 root:root` inside the root-only `/etc/cryptirc`. A `CRYPTIRC_X_GRAPHQL_CONFIG` file is read by the **service user** instead, so it must not live in `/etc/cryptirc` (the `cryptirc` user cannot enter that `0700` directory). Give it its own directory the service group can read, and point the variable at it:

```bash
sudo install -d -m 750 -o root -g cryptirc /etc/cryptirc-x
sudo install -m 640 -o root -g cryptirc x-graphql.json /etc/cryptirc-x/x-graphql.json
echo 'CRYPTIRC_X_GRAPHQL_CONFIG=/etc/cryptirc-x/x-graphql.json' | sudo tee -a /etc/cryptirc/cryptirc.env >/dev/null
sudo -u cryptirc cat /etc/cryptirc-x/x-graphql.json >/dev/null && echo readable   # check before restarting
```

(The unit's `ProtectSystem=strict` keeps `/etc` read-only for the service, which is all it needs.) Never put a CryptIRC session token, cookies or login credentials anywhere in this configuration.

**Admin policy.** Settings → Admin → Link previews also governs X, immediately and without a restart: **Off** disables every X provider; **Whitelist** allows X only if the list contains an exact X/Twitter host (`x.com`, `twitter.com`, `www.x.com`, `mobile.x.com`, `www.twitter.com`, `mobile.twitter.com`, `m.twitter.com`); **All** allows it (the fixed provider hosts and public-address checks still apply). Changing the policy drops every cached X result.

**Limits.** All `/tweet/*` routes require the normal Bearer session and share the per-user 30 requests/minute link-preview budget (cache hits included). Retrieval shares the existing eight outbound preview permits; requests for the same post coalesce; results are cached per viewer in memory only (10 min posts, 5 min threads, 100 per user, 1,000 / 32 MiB total). Responses are `private, no-store`.

**Media.** Card media loads directly from `pbs.twimg.com` / `video.twimg.com` in the viewer's browser (the External media setting decides avatars/thumbnails/posters; video only after Play). If a privacy extension blocks those CDNs, the browser may ask for a signed same-origin copy (`POST <base>/tweet/media/sign`, then `GET <base>/tweet/media`). That fallback uses your server's bandwidth and lets it see which media is played. It only signs assets the same account just retrieved in a preview, only recognized X CDN image/MP4 paths, and only while the admin policy allows X and a provider is configured; links expire after 15 minutes and are bound to the account; responses must be raster images or MP4 (HTML, SVG and HLS playlists are refused) and are never cacheable (`private, no-store`); single byte ranges only, at most 128 MiB, 16 streams server-wide and 3 per account; DNS + connect + response headers must finish within 12 s, and a stream is cut off after 30 s without progress (either side) or 5 minutes total. Browsers batch and de-duplicate signing requests, and stop a pending fallback if External media is switched off meanwhile. No cookies, credentials or Referer are forwarded and redirects are refused.

**Reverse-proxy logs.** CryptIRC's own logs never contain preview URLs, post IDs, tokens or text (the HTML tokenizer's trace output is always filtered out, whatever `RUST_LOG` says), but your proxy's access log records query strings unless told otherwise. `/tweet/preview` and `/tweet/thread` carry the previewed post URL in `?url=`, and `/tweet/media` carries `url`, `a` (an opaque account handle) and `sig`. The nginx config above already logs `$uri` without the query string; the Caddyfile above redacts `url`, `sig` and `a` (add those three `replace` lines to an existing Caddy `format filter`, including any Caddyfile written by `deploy/deploy.sh`). Also review any CDN/WAF in front of the proxy. If you use your own nginx log format, you can instead turn logging off for these routes (adapt the prefix; keep your normal proxy headers):

```nginx
location ~ ^/cryptirc/tweet/(preview|thread|media)$ {
    access_log off;
    proxy_pass http://127.0.0.1:9001;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

**What viewers see.** On a configured server, X links in public, unencrypted channel messages load automatically near the viewport (expanded layout by default — Appearance → X preview layout). Encrypted messages, DMs, the server window and unknown contexts stay click-to-load; any row of an end-to-end-encrypted conversation counts as encrypted. Security → X preview loading offers Auto in public (default) / Click to load / Hide on this device, plus per-conversation overrides; these choices are device-local and never synced. The global Link previews switch and Hide always win. If a browser cannot reach `/tweet/config` (e.g. during a reconnect), it retries with backoff and meanwhile shows X links through the generic link preview — never less private than the viewer's X settings. Nothing X-related loads while the vault or device is locked.

**Checking it.** After enabling a provider, sign in and open `<base>/tweet/config` with your session (or watch the browser's network panel): `"preview": true` means cards are offered. One authorized request for a public post you are allowed to fetch is enough to confirm the schema; don't log credentials or response bodies. No live provider check is part of the automated tests.

**Rollback.** Set Admin → Link previews to **Off** (immediate), then remove the `CRYPTIRC_X_*` lines from `/etc/cryptirc/cryptirc.env` and `sudo systemctl restart cryptirc`. Restart clears guest tokens and every cached result; nothing is stored on disk and messages need no migration. To roll back only threads, remove `CRYPTIRC_X_THREADREADER_ENABLED`. Reverting the code itself is a normal web-binary downgrade; irc-core is unaffected.

Offline test commands and results: [docs/x-preview-verification.md](docs/x-preview-verification.md).

### Avatars

Users upload a picture in Settings → Profile → Avatar (PNG, JPEG or WebP, up to 2 MB). The server decodes it (at most 4096 × 4096, one picture at a time), applies the EXIF orientation, crops it to a square and keeps only re-encoded 128 px and 48 px PNGs — no metadata, never the original — in `<data dir>/users/<name>/` (`avatar.json`, `avatar-<version>-<size>.png`). Deleting the account removes them.

**Who sees it.** Other CryptIRC users of the same instance, next to the owner's nick in the nick list, the WHOIS view and the nick menu — only while the owner's live connection dials the same IRC server host as the viewer's (the port may differ; a network name never counts), currently holds that nick (with the user@host the viewer's server shows for it, when it showed one), and the viewer's own connection sees the nick (a shared channel or a WHOIS reply). Pictures are never sent to IRC. Each user can hide theirs ("Show my avatar to other CryptIRC users") or turn off other people's ("Show other people's avatars").

**Bouncers.** A bouncer (ZNC, soju, …) shared by several people proves only the bouncer, not the network behind each account, so avatars are never matched for a connection that shows it goes through one — the viewer's or the other user's: `soju.im/*`, `draft/bouncer-networks`, pounce's `causal.agency/*` or ZNC's `znc.in/batch` / `znc.in/server-time-iso` capabilities, CAP replies from `irc.znc.in`, or `BOUNCER_NETID`. (`znc.in/playback` and `znc.in/self-message` alone do not count: Ergo, a real IRC server, advertises them.) Both connections must have completed CAP LS; servers that ignore or reject CAP stay restricted. The daemon now retains each live IRC session's registration facts (capabilities, bouncer evidence, CLIENTTAGDENY and CASEMAPPING) and sends them on Attach. Avatars classify immediately after web-only restarts, even when registration has left the replay ring or `avatar_sessions.json` is missing. When upgrading from <=0.5.10, install the updated daemon and restart `irc-core` once to enable this; subsequent web-only restarts need no IRC reconnect. With an older daemon, the existing continuity-checked `avatar_sessions.json` fallback remains in use. Residual: a bouncer configured to hide all of that looks like a plain IRC server; on such a host the user@host check and "exactly one CryptIRC account holds the nick" still apply.

**Admin.** Admin → Avatars turns the feature off (saved pictures are kept but neither served nor shown, and uploads are refused); a user's entry has **Remove avatar**. The switch is `avatars_enabled` in `admin_settings.json` (default on). Changing this setting needs no service restart.

**Sharing with people on other CryptIRC servers.** Most people host their own CryptIRC. "Share my avatar with people on other CryptIRC servers" (Settings → Profile → Avatar; asked before a first avatar is uploaded — nothing is public without that consent — and off for ones saved before 0.5.10) makes the 128 px picture **public**: `<CRYPTIRC_BASE_URL>/avatar/pub/<random id>-<version>.png`, no login, `nosniff`, a 5-minute public cache, an ETag. It is served only while avatars are on and the owner has that avatar, keeps it visible, shares it, and the account is neither disabled nor being deleted; turning sharing off (or removing the avatar) retires the id for good. It needs `CRYPTIRC_BASE_URL` set to the instance's public **https** address (with the base path, e.g. `https://example.org/cryptirc`); otherwise sharing shows as unavailable and nothing is announced.

The link travels on IRC from whoever holds the nick right now (the IRC network routes messages to the current holder — the same guarantee any avatar system gives: the holder chooses their own picture; another server's avatar is a claim by that nick's holder, not something this server vouches for like a local one, and the nick menu shows "via <host>" for it):
- with `message-tags`: a client-only tag `+cryptirc.com/avatar=<url>` on the user's messages (first one to a target, then on a change or every 30 minutes), an invisible `TAGMSG #channel` when they join a channel, an invisible private `TAGMSG` to someone who joins a channel they are in (a few per channel per minute, once per person per 30 minutes, not during their own join burst, never to users of the same instance), and a private one back when another CryptIRC user announces themselves in a shared channel. Clients without tag support never see any of it; `CLIENTTAGDENY` is respected;
- `draft/metadata-2` where the IRC server offers it (key `avatar`, published and subscribed; requested by the web after registration);
- an answer to `CTCP AVATAR` (KVIrc's query) — never for a user who does not share. On networks without message-tags (EFnet), that is the only way: the viewer's server sends one `CTCP AVATAR` only when the user opens that nick's menu or WHOIS and nothing is known (once per nick per 15 minutes, a few per user); never for a channel's member list or for people who merely speak.

The viewer's **server** fetches the picture (only for a nick the viewer's connection sees — a shared channel or a fresh WHOIS — when the app asks): public addresses only (DNS pinned), https on port 443, no redirects, 2 MB, timeouts, the shared outbound fetch slots, at most 20 fetches a minute, 30 per remote host and 60 per user per 10 minutes, one per URL per hour (then revalidated; a picture that is gone stops showing). It is decoded and re-encoded like an upload (at most 2048 × 2048) and kept in `<data dir>/avatar_remote/` (at most 1000 pictures; emptied at startup), and the app loads it from this server only (`private, no-store`) — the viewer's browser never contacts the other server. What another server learns from a fetch: this server's IP address, and that someone here looked at that avatar. An announce is learned only from a nick the viewer's connection sees (a shared channel or a fresh WHOIS), never from bouncer or chathistory playback (inside a batch other than the server's metadata sync, or stamped more than 2 minutes before it arrived; a line without a usable stamp counts only when it is live on a connection not behind a bouncer); it is bound to the nick and the sender's user@host and dropped on NICK, QUIT, CHGHOST, and when the viewer no longer shares a channel with that nick; a URL pointing at this instance is ignored (local users are matched only by the rules above). What viewers see never depends on their own avatar or on their sharing or visibility settings — only their "Show other people's avatars" (which also stops their queries and fetches) and the admin switch turn it off. **Remote avatars aren't shown on connections through a bouncer** — nor on one not classified yet (after a web restart whose replay proved nothing, until it reconnects): a bouncer may play back old lines that look live, so, like v1's bouncer rule, such a connection learns no remote avatar at all and asks nothing. Same-instance (v1) avatars follow v1's rules, the user's own announces still go out, and such a connection never answers CTCP AVATAR. A remote avatar is shown only with a known user@host that the viewer's connection still shows for the nick (a metadata value that arrives before it is held for up to 30 seconds). Whenever metadata-2 becomes active again (negotiated, or after a web restart), the current value is synced — published, or deleted if sharing was turned off meanwhile. Debug builds only: `CRYPTIRC_AVATAR_TEST_LOOPBACK=1` lets the two-instance test (`scripts/test-avatars-remote.mjs`) use http on loopback; release builds ignore it.

---

## Updating

Use the update script — it backs up your data, pulls, builds, swaps the binaries, and checks the new version really serves (HTTP 200). If it doesn't, it puts the previous version back by itself and exits with an error — except when the update goes from before 0.5.8 to 0.5.8 or later and users' data already changed under the new version (someone unlocked their vault during the check): then it keeps the new version, exits with code 4 and says what to do (see [deploy/README.md](deploy/README.md#updating)):

```bash
cd /path/to/CryptIRC
sudo bash deploy/update.sh
```

It leaves `irc-core` (and everyone's IRC connections) running. Only when the daemon itself changed does it say so; then apply it with `sudo bash deploy/update.sh --restart-daemon` (IRC sessions drop once and reconnect). `--help` lists the options.

On an install made before 0.5.8 it also moves a registration code out of an `Environment=` line of `cryptirc.service` (where `systemctl show` reveals it to every local user) into `/etc/cryptirc/cryptirc.env`, and adds the token-redacting `format filter` (above) to a Caddy `log` block for `/var/log/caddy/cryptirc.log` that has none — each changed file is backed up first, and Caddy is reloaded (restarted, if its config has `admin off`). An nginx config is not touched: see [Using Nginx Instead of Caddy](#using-nginx-instead-of-caddy).

Going back to an older version by hand: see the rollback notes in [deploy/README.md](deploy/README.md#updating) — don't go below 0.5.8 once anyone has unlocked their vault on it.

By hand, the same steps are below. They assume the install already runs `irc-core` (every install since 0.3.24 does: `systemctl status irc-core`). Coming from an older version — one `cryptirc.service` and no `irc-core.service` — use `deploy/update.sh` instead (it moves the install over to the daemon), or first set up `irc-core.service` as in Step 6, start it, and only then the new `cryptirc`: the new web binary no longer connects to IRC itself, so without the daemon nobody's IRC connects.

```bash
cd /path/to/CryptIRC
git pull
cargo build --release
sudo install -m 755 target/release/cryptirc /opt/cryptirc/cryptirc.new
sudo install -m 755 target/release/irc_core /opt/cryptirc/irc_core.new
sudo systemctl stop cryptirc
sudo mv -f /opt/cryptirc/cryptirc.new /opt/cryptirc/cryptirc
# Renaming (not copying) works while irc-core is running; the new daemon code
# takes effect the next time irc-core restarts (sudo systemctl restart irc-core).
sudo mv -f /opt/cryptirc/irc_core.new /opt/cryptirc/irc_core
sudo systemctl start cryptirc
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
- Make sure `argon2-cffi` is installed for root: `sudo python3 -c 'import argon2'` (fix: `sudo apt-get install python3-argon2`)
- The password must have 10+ characters with upper case, lower case, a digit and a symbol, and the email must not already belong to another account
- Make sure the data directory exists: `sudo ls -la /var/lib/cryptirc/`

### IRC never connects
- `irc-core` must be running: `sudo systemctl status irc-core` and `journalctl -u irc-core -n 50 --no-pager`
- Its socket must exist: `sudo ls -la /var/lib/cryptirc/irc-core.sock`

### Email verification not working
- Email is **optional** — if you didn't enable it at install, open registration still works (captcha-protected) and accounts are auto-verified. You only need this section if you chose to require email or want password resets.
- Install Postfix: `sudo apt-get install postfix`
- Configure for local delivery: `sudo postconf -e "inet_interfaces = loopback-only"`
- On an IPv6-only server also run `sudo postconf -e "inet_protocols = all" "smtp_address_preference = ipv6"` (with `ipv4` Postfix can't send anything there), then `sudo systemctl restart postfix`. Not `inet_protocols = ipv6`: that also stops Postfix listening on 127.0.0.1, and CryptIRC always hands its mail to `127.0.0.1:25`. Check with `ss -ltn 'sport = :25'` — it must list `127.0.0.1:25`.
- Check mail log: `tail -f /var/log/mail.log`

---

## Architecture

```
Browser / PWA / Electron App
  |-- E2E encryption (Signal protocol via Web Crypto API)
  |-- Per-user vault (Argon2id KDF -> AES-256-GCM)
  '-- WebSocket --> cryptirc (web server, Rust)
                      |-- irc-core daemon over a Unix socket: holds the
                      |   persistent IRC connections (TLS + IRCv3), survives
                      |   web restarts and updates
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
