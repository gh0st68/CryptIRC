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
| `CRYPTIRC_BASE_URL` | `http://localhost:9000` | Public URL of your instance (used for links, push notifications) |
| `CRYPTIRC_BASE_PATH` | `/cryptirc` | URL path prefix. Use `/` for root or `/cryptirc` for subpath |
| `CRYPTIRC_PORT` | `9001` | Port the HTTP server listens on (behind reverse proxy) |
| `CRYPTIRC_FROM_EMAIL` | `noreply@cryptirc.local` | Sender address for verification emails |
| `CRYPTIRC_REGISTRATION` | `open` | `open` = anyone can register, `closed` = admin creates accounts |
| `CRYPTIRC_REG_CODE` | (none) | If set, users must enter this code to register |
| `CRYPTIRC_HSTS` | `on` | Set to `off` for self-signed/IP installs. HSTS on a self-signed cert makes browsers refuse the cert-warning click-through and locks users out for ~2 years. The installer sets this automatically. |
| `CRYPTIRC_IPC_SOCK` | `$CRYPTIRC_DATA/irc-core.sock` | Unix socket between the web server and the `irc-core` daemon. If you set it, set the same value in **both** units. |
| `CRYPTIRC_TRUSTED_PROXIES` | (none) | Extra reverse proxies (IPs or CIDRs, comma- or space-separated, e.g. `10.0.0.5, 2001:db8::/64`) whose forwarding headers are believed. Loopback is always trusted. See [Client IP addresses](#client-ip-addresses-behind-a-proxy). |
| `CRYPTIRC_REAL_IP_HEADER` | `auto` | Which header a trusted proxy's client address is read from: `auto`, `x-forwarded-for` (or `xff`), `x-real-ip`, or `off`. See below. |
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
