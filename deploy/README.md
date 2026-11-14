# CryptIRC Deployment

## Requirements

- Ubuntu 22.04 / 24.04 or Debian 12 (`deploy/deploy.sh`), or Arch Linux (`deploy/deploy-arch.sh`)
- A domain name pointed at your server (A / AAAA record) for a Let's Encrypt certificate —
  or no domain at all: the installer can serve your server's IP with a self-signed certificate
- Ports 80 and 443 open in your firewall (and in your cloud provider's security group)

That's it. The deploy script installs everything else.

---

## Fresh install

**Interactive (recommended)** — asks for the domain or IP, the registration options
(open sign-up, a registration code, email verification, the captcha) and creates your
first account and makes it an admin:

```bash
sudo bash deploy/deploy.sh
```

**Non-interactive** — no questions asked:

```bash
sudo bash deploy/deploy.sh cryptirc.yourdomain.com admin@yourdomain.com   # domain + Let's Encrypt
sudo bash deploy/deploy.sh 203.0.113.10                                    # bare IP + self-signed
```

A non-interactive install is **invite-only**, sets up no email, and creates **no account**,
so create the first one yourself and make it an admin — there is no way to do either from
the browser on such an install:

```bash
sudo bash adduser.sh yourname you@yourdomain.com   # asks for the password; the email is optional
sudo bash makeadmin.sh yourname
```

(Registration, email and the captcha can then be changed in **Settings → Admin**.)

This installs and configures:
- Rust (via rustup)
- Caddy (via official apt repo)
- Postfix (local mail relay for verification / reset emails) — only if you chose email
- CryptIRC binary to `/opt/cryptirc/`
- `irc-core` binary + service — a small always-on daemon that owns the raw
  IRC connections, so restarting/redeploying CryptIRC itself no longer drops
  anyone's IRC session (see "irc-core daemon" below)
- systemd service(s) with full security hardening
- Caddy config with automatic HTTPS

**Total time:** ~5 minutes, mostly waiting for Rust to compile.

---

## What happens after deploy

1. Visit `https://cryptirc.yourdomain.com` (or `https://<your-ip>` — click through the one-time
   self-signed certificate warning)
2. With a domain, Caddy gets a Let's Encrypt TLS certificate on the first request (~30 seconds)
3. Log in with the account the installer (or `adduser.sh`) created. With open registration,
   others can sign up — and if you required email verification, they get the mail via Postfix
4. Unlock the vault with a passphrase you choose
5. Add an IRC network and connect

---

## Updating

```bash
cd /path/to/cryptirc
sudo bash deploy/update.sh
```

This backs up your data, pulls the latest code (as the checkout's owner, so your clone
never gets root-owned files), rebuilds the binary and does a hot-swap restart. The
service is down for about a second — and since `irc-core` isn't restarted by an
ordinary update, **no one's IRC connection drops**, unlike CryptIRC's own brief
web restart. The script tells you when the daemon itself changed; only then pass
`--restart-daemon` — the one case where IRC connections genuinely need to
reconnect:

```bash
sudo bash deploy/update.sh --restart-daemon
```

**A box that shouldn't build** (a small production host): build the binaries elsewhere
from the same commit — for the host's distribution release, so they need no newer system
libraries (e.g. in a `rust:1-bookworm` container for Debian 12) — copy `cryptirc` (and
`irc_core`) into a directory only root can write, with the checkout at that same commit,
and install them with:

```bash
sudo install -d -m 755 -o root -g root /root/cryptirc-bin
sudo install -m 755 -o root -g root cryptirc irc_core /root/cryptirc-bin/
sudo bash deploy/update.sh --prebuilt /root/cryptirc-bin      # or CRYPTIRC_PREBUILT_DIR=…
```

That skips the pull and the build (no git pull, no cargo); everything else — backup, unit
refresh, the 0.5.8 data floor, the health check and rollback, `--restart-daemon` — runs as
usual. It first refuses, changing nothing, binaries that aren't root-owned and
non-writable, aren't executables this host can load (`ldd`), or whose version isn't the
checkout's (`Cargo.toml`).

Safety rails:
- The binaries and units an update replaces are kept in `/opt/cryptirc/.rollback`.
  If the new version doesn't come up healthy (a real HTTP 200 from the web
  server, the IPC socket from `irc-core`), the script puts the previous version
  back, restarts it and exits non-zero. Don't restore a data backup for that: your data is
  intact. (If the new build had already run a one-time data migration, the previous version
  may show some lists — e.g. uploaded files — as empty until the next successful update.)
  The health check takes up to a minute, and the new version serves users from the moment it
  starts, so someone can unlock their vault on it in that time. That is why an update from a
  version older than 0.5.8 to 0.5.8 or later is **not** rolled back automatically once users'
  data has changed under the new version — their end-to-end keys (`e2e/<user>/`), saved
  networks (`networks/`) or vaults (`vaults/`) in the data directory, compared with a snapshot
  taken just before it started. The script then leaves the new version installed and running,
  exits with code 4 and says what to do: find out why it failed (`journalctl -u cryptirc`), and
  fix it or update to a fixed version rather than going back (see the next point). If nothing
  changed, it rolls back as described above. Re-running the installer (`deploy.sh` /
  `deploy-arch.sh`) over an install older than 0.5.8 follows the same rule — and first backs up
  the data directory to `/var/lib/cryptirc-backups/` as update.sh does (`CRYPTIRC_NO_BACKUP=1`
  skips that).
- **Going back by hand: never below 0.5.8 once anyone has unlocked their vault on 0.5.8 or
  later.** From then on that user's saved channel keys and perform (on-connect) commands are
  stored encrypted (`enc:…`), and their end-to-end encryption keys in a new format (`e2e2.…`).
  An older version doesn't know either:
  - It sends the `enc:…` text to the IRC server as it is — perform commands fail (`Unknown
    command`) and keyed channels refuse the join (`+k`) on every connect. No secret leaks (the
    values are encrypted with the user's vault key), and updating to 0.5.8 again makes these work
    as before. Anything re-entered in the older version (a re-typed perform line, say) is stored
    unencrypted until the next unlock on 0.5.8.
  - It can't read the new E2E keys — and that is NOT recoverable by updating again: an older
    browser that can't decrypt a user's migrated identity makes a NEW one and overwrites the
    migrated keys on the server (see deploy/data-floor.sh). That user's encrypted conversations
    and verified identities are then lost for good. The only way back is the data backup made
    before the upgrade (update.sh and the installers make one, in `/var/lib/cryptirc-backups/`) —
    restored together with the old binary, and losing everything users did since.
  So once anyone unlocked on 0.5.8, fix forward instead of going back.
  Rolling the web back below 0.5.8 after it ran: owners' private bot notes (`/note`) are hidden by
  the older build until you roll forward again (nothing is deleted;
  `botdata/<user>.json.pre-netkey.bak` holds the pre-upgrade file).
- On an install made before 0.5.8 the update also moves a registration code out of an
  `Environment=` line of `cryptirc.service` (`systemctl show` reveals those to every local user)
  into the root-only `/etc/cryptirc/cryptirc.env`, and gives a Caddy `log` block for
  `/var/log/caddy/cryptirc.log` that has no `format` the filter that keeps reset/verification
  tokens and paste passwords out of the access log. Files are backed up first (the unit in
  `/etc/cryptirc/backups/`, a Caddyfile as `/etc/caddy/<name>.bak.<time>`); Caddy is reloaded,
  or restarted if its config has `admin off`. `irc-core` is never restarted for this.
- Once services are stopped, Ctrl-C or a dropped SSH session can no longer leave
  the site half-updated — the script finishes (or rolls back) first. Progress is
  also logged to the journal: `journalctl -t cryptirc-update`.
- Only one update runs at a time; unknown options are refused (`--help` lists them).

---

## irc-core daemon

CryptIRC's IRC connections are held by a separate always-on process,
`irc-core`, communicating with the main `cryptirc` process over a local Unix
socket (`/var/lib/cryptirc/irc-core.sock`). It only holds the raw connection
open (dial, registration, SASL, PING/PONG, reconnect) — all message parsing,
logging, encryption, and push notifications still happen entirely in the main
`cryptirc` process, unchanged. The practical effect: restarting/redeploying
CryptIRC itself (the frequent case) no longer causes a visible part/rejoin on
any channel. Both processes run as the same unprivileged `cryptirc` user —
this is a lifecycle split, not a privilege boundary.

---

## Useful commands

```bash
# Live logs
journalctl -u cryptirc -f
journalctl -u irc-core -f

# Status
systemctl status cryptirc
systemctl status irc-core
systemctl status caddy

# Restart (irc-core rarely needs it — see "Updating" above)
sudo systemctl restart cryptirc
sudo systemctl restart irc-core

# Apply a Caddyfile edit. The installer's Caddyfile gives Caddy a caddy-only admin socket,
# so reload works; on a box set up by an installer older than 0.5.8 (`admin off`) only a
# restart does — re-running the installer fixes that.
sudo systemctl reload caddy      # or: sudo systemctl restart caddy

# Check TLS cert status
caddy trust
```

---

## File layout

```
/opt/cryptirc/
├── cryptirc              ← compiled binary (web/WS process)
└── irc_core              ← compiled binary (IRC connection daemon)

/var/lib/cryptirc/
├── vault.salt            ← random salt for Argon2id key derivation
├── vault.canary          ← encrypted canary for passphrase verification
├── vapid.json            ← VAPID keys for push notifications (keep safe)
├── irc-core.sock         ← Unix socket between cryptirc and irc-core (0600)
├── admin_settings.json   ← registration / email / captcha settings (Settings → Admin)
├── users/                ← user accounts (hashed passwords)
├── pending/              ← email verification tokens
├── resets/               ← password-reset tokens (1 hour)
├── networks/             ← IRC network configs (creds AES-256-GCM encrypted)
├── logs/                 ← encrypted IRC logs (AES-256-GCM per line)
├── certs/                ← client TLS certificates for SASL EXTERNAL
├── push/                 ← push notification subscriptions
├── notif_prefs/          ← per-user notification preferences
└── uploads/              ← uploaded files

/var/log/cryptirc/        ← application logs (Rust)
/var/log/caddy/           ← Caddy access logs (tokens and passwords are redacted)

/etc/caddy/conf.d/cryptirc.caddy   ← CryptIRC's Caddy site (regenerated by the installer)
/etc/caddy/Caddyfile               ← global options + `import conf.d/*`; one with sites of
                                     your own is kept, and only gets tagged lines added
/etc/cryptirc/cryptirc.env         ← root-only fallback settings (the registration code); lines you
                                     add (e.g. CRYPTIRC_TRUSTED_PROXIES) are kept on re-runs
/etc/cryptirc/backups/             ← the previous versions of units the installer replaced
```

Put your own changes to the services in drop-ins (`sudo systemctl edit cryptirc`) — a
re-run of the installer regenerates the units themselves.

---

## Firewall

Open ports 80 (HTTP → redirected to HTTPS by Caddy) and 443 (HTTPS).
CryptIRC itself listens on port 9001 on 127.0.0.1 only (`CRYPTIRC_PORT`) — never exposed directly.

```bash
# ufw
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 443/udp   # HTTP/3 (QUIC) — optional

# iptables (-I, not -A: an appended rule never matches after a final REJECT)
sudo iptables -I INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
```

---

## Backup

Back up `/var/lib/cryptirc/` regularly. The encrypted logs are only as
recoverable as your backups. The `vapid.json` and `vault.salt` files are
especially important — losing them means losing push subscriptions and
the ability to decrypt logs respectively.

The archive holds everything a stolen copy of the data dir would: password hashes,
registration settings, reset tokens, push keys. Keep it as private as the live files
(root-only), never in a directory other users can read:

```bash
#!/bin/bash
# /etc/cron.daily/cryptirc-backup  (sudo chmod 700 /etc/cron.daily/cryptirc-backup)
set -o pipefail
umask 077                                    # the archive is created 0600, root-only
# The real data directory: a symlink (data moved to another disk) is followed — tar would
# otherwise archive just the link. Moved it with CRYPTIRC_DATA? Put that path here.
DATA=$(readlink -e /var/lib/cryptirc) || { echo "cryptirc-backup: no data directory" >&2; exit 1; }
# Links INSIDE it (a user's directory moved elsewhere) are followed too (--dereference) — so tar
# runs as the data dir's owner, the service account: a link it planted reaches nothing it can't
# already read, and it writes only into a pipe (root writes the file). A device/FIFO/socket among
# what it reaches would never end: refuse those.
OWNER=$(stat -c %U "$DATA")
cd / || exit 1
if runuser -u "$OWNER" -- find -L "$DATA" -mindepth 1 \( -type c -o -type b -o -type p -o \
       \( -type s ! -name irc-core.sock \) \) -print -quit | grep -q .; then
    echo "cryptirc-backup: a device, FIFO or socket (or a link to one) in $DATA — not archiving" >&2; exit 1
fi
install -d -m 700 /backup
runuser -u "$OWNER" -- setpriv --no-new-privs timeout 3600 tar -czf - --dereference \
    --hard-dereference --ignore-failed-read --exclude=irc-core.sock \
    -C "$(dirname "$DATA")" "$(basename "$DATA")" | cat > "/backup/cryptirc-$(date +%Y%m%d).tar.gz"
```

(A crontab line needs every `%` written as `\%`; a script file like this one doesn't.)

To restore such an archive (or one of update.sh's from `/var/lib/cryptirc-backups/`), with the services
stopped: extract it into an empty directory as root WITHOUT the owners and modes recorded in it — the
data dir belongs to the service account, so treat what came out of it as its files — then hand the result
to the service account and put it in place:

```bash
sudo systemctl stop cryptirc irc-core
sudo mkdir -m 700 /var/lib/cryptirc.restore
sudo sh -c 'umask 077; tar -xzf /var/lib/cryptirc-backups/cryptirc-backup-<time>.tar.gz \
    -C /var/lib/cryptirc.restore --no-same-owner --no-same-permissions'
sudo chown -R cryptirc:cryptirc /var/lib/cryptirc.restore/cryptirc     # (the archive's top directory)
sudo mv /var/lib/cryptirc /var/lib/cryptirc.before-restore
sudo mv /var/lib/cryptirc.restore/cryptirc /var/lib/cryptirc && sudo rmdir /var/lib/cryptirc.restore
sudo systemctl start irc-core cryptirc
```
`deploy/update.sh` makes the same kind of archive — of the directory the service really uses,
symlink followed — 0600 in a 0700 `/var/lib/cryptirc-backups/`, before every update.

---

## Email (Postfix)

The deploy script configures Postfix for **local relay only** — it sends
verification emails outbound but accepts nothing inbound. If your server's
IP is on a spam blocklist (common with cloud VMs), emails may be rejected
by recipients.

On an IPv6-only server it sends over IPv6 (`inet_protocols = all` with `smtp_address_preference = ipv6`
— IPv4 stays on because CryptIRC hands its mail to `127.0.0.1:25`); everywhere else over IPv4.

**If emails don't arrive**, the easiest fix is to route Postfix through a
transactional mail service's SMTP relay (CryptIRC itself keeps handing mail to the local
Postfix):

```
# /etc/postfix/main.cf additions
relayhost = [smtp.mailgun.org]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_security_level = encrypt
```

Free tiers on Mailgun (100 emails/day) or Brevo (300/day) are more than
enough for a self-hosted IRC client.
