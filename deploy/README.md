# CryptIRC Deployment

## Requirements

- Ubuntu 22.04 / 24.04 or Debian 12
- A domain name pointed at your server's IP (A record)
- Port 80 and 443 open in your firewall

That's it. The deploy script installs everything else.

---

## Fresh install

```bash
sudo bash deploy/deploy.sh cryptirc.yourdomain.com admin@yourdomain.com
```

This installs and configures:
- Rust (via rustup)
- Caddy (via official apt repo)
- Postfix (local mail relay for verification emails)
- CryptIRC binary to `/opt/cryptirc/`
- systemd service with full security hardening
- Caddy config with automatic HTTPS

**Total time:** ~5 minutes, mostly waiting for Rust to compile.

---

## What happens after deploy

1. Visit `https://cryptirc.yourdomain.com`
2. Caddy automatically gets a Let's Encrypt TLS certificate on first request (~30 seconds)
3. Register an account — verification email will be sent via Postfix
4. Verify your email, log in, unlock the vault with a passphrase you choose
5. Add an IRC network and connect

---

## Updating

```bash
cd /path/to/cryptirc
git pull
sudo bash deploy/update.sh
```

This rebuilds the binary and does a hot-swap restart. The service is down for under a second.

---

## Useful commands

```bash
# Live logs
journalctl -u cryptirc -f

# Status
systemctl status cryptirc
systemctl status caddy

# Restart
sudo systemctl restart cryptirc

# Caddy reload after Caddyfile edit (no downtime)
sudo systemctl reload caddy

# Check TLS cert status
caddy trust
```

---

## File layout

```
/opt/cryptirc/
└── cryptirc              ← compiled binary

/var/lib/cryptirc/
├── vault.salt            ← random salt for Argon2id key derivation
├── vault.canary          ← encrypted canary for passphrase verification
├── vapid.json            ← VAPID keys for push notifications (keep safe)
├── users/                ← user accounts (hashed passwords)
├── pending/              ← email verification tokens
├── networks/             ← IRC network configs (creds AES-256-GCM encrypted)
├── logs/                 ← encrypted IRC logs (AES-256-GCM per line)
├── certs/                ← client TLS certificates for SASL EXTERNAL
├── push/                 ← push notification subscriptions
├── notif_prefs/          ← per-user notification preferences
└── uploads/              ← uploaded files

/var/log/cryptirc/        ← application logs (Rust)
/var/log/caddy/           ← Caddy access logs
```

---

## Firewall

Open ports 80 (HTTP → redirected to HTTPS by Caddy) and 443 (HTTPS).
CryptIRC itself listens on port 9000 locally only — never exposed directly.

```bash
# ufw
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 443/udp   # HTTP/3 (QUIC) — optional

# iptables
sudo iptables -A INPUT -p tcp --dport 80  -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

---

## Backup

Back up `/var/lib/cryptirc/` regularly. The encrypted logs are only as
recoverable as your backups. The `vapid.json` and `vault.salt` files are
especially important — losing them means losing push subscriptions and
the ability to decrypt logs respectively.

```bash
# Simple backup (cron daily)
tar -czf /backup/cryptirc-$(date +%Y%m%d).tar.gz /var/lib/cryptirc/
```

---

## Email (Postfix)

The deploy script configures Postfix for **local relay only** — it sends
verification emails outbound but accepts nothing inbound. If your server's
IP is on a spam blocklist (common with cloud VMs), emails may be rejected
by recipients.

**If emails don't arrive**, the easiest fix is to route through a
transactional mail service. Change `email.rs` to use their SMTP relay:

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
