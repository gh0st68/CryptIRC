# cryptirc-tui

A terminal client for CryptIRC. Runs alongside the web app — both can be
connected at the same time, to the same account, seeing the same messages.

```
cargo build --release          # from this directory
./target/release/cryptirc-tui  # or copy it onto your $PATH
```

## Why it does not talk to the daemon

`irc-core` accepts exactly **one** IPC client: `ipc_server.rs` keeps a single
`current_client` slot and a new `Attach` *replaces* whatever was there. A client
wired straight to `irc-core.sock` would therefore kick the browser off, and be
kicked off by it in turn, forever.

So this speaks the **same WebSocket protocol the browser speaks**, to the
`cryptirc` web process. That process already owns the daemon's single slot and
already fans every event out to all of an account's sessions, so:

* web and terminal run side by side, with no changes to the daemon or the server;
* you get the same login, the same vault, the same encrypted logs, the same
  server-side bots — not a second-class client;
* nothing here can destabilise the daemon, which is the whole point of the
  daemon-split architecture.

```
   browser ─┐
            ├─ websocket ─→ cryptirc (web) ─ unix socket ─→ irc-core ─→ IRC
   TUI ─────┘                                (single IPC client)
```

## Configuration

Any of these; later ones win.

`~/.config/cryptirc-tui/config.toml`

```toml
server   = "https://frozen.gh0st.boo/cryptirc"
username = "you"
password = "…"          # optional — prompted if omitted
```

Environment: `CRYPTIRC_URL`, `CRYPTIRC_USER`, `CRYPTIRC_PASS`.
Flags: `-s/--server`, `-u/--user`, `-p/--pass`.

The password is prompted for (hidden) when not supplied, so it never has to sit
in a file or in shell history. Note that `--pass` on the command line **is**
visible in `ps` — prefer the prompt or the config file.

## Keys

| | |
|---|---|
| `Alt+1`…`Alt+9` | jump to buffer |
| `Alt+←` / `Alt+→`, `Ctrl+P` / `Ctrl+N` | previous / next buffer |
| `PgUp` / `PgDn` | scroll |
| `Ctrl+Home` / `Ctrl+End` | oldest / newest |
| `Tab` | complete nick |
| `↑` / `↓` | input history |
| `Alt+B` / `Alt+N` | toggle buffer list / nick list |
| `Ctrl+C` | quit |

Mouse: click a buffer in the list to switch, wheel to scroll.

## Commands

`/join /part /msg /query /me /close /buffer /clear /connect /disconnect /vault
/theme /quit` are handled locally.

**Your private bot commands work exactly as they do in the web app** — they are
not raw IRC, they go over the same `bot_query` channel and the answer comes back
privately to you, never to the channel:

`/w` `/ud` `/wiki` `/define` `/dict` `/crypto` `/price` `/wtime` `/cc`
`/currency` `/joke` `/qotd` `/fact` `/8ball` `/roll` `/coin` `/flip` `/q`
`/seen` `/tell` `/note` `/notes` `/bots` `/ai`, plus `/aido` for the AI agent.

(Note the aliases the web client uses to avoid clashing with real IRC verbs:
`/wtime` because `/time` is CTCP TIME, and `/qotd` because `/quote` is `/raw`.)

**Everything else is passed to IRC verbatim** — `/nick`, `/whois`, `/topic`,
`/mode`, `/kick`, `/away` and so on all work without this client needing to know
about them, the same way the web client does it.

## Themes

`/theme list` shows them all; `/theme <name>` switches instantly and saves your
choice to the config file. Also `--theme <name>` or `CRYPTIRC_THEME`.

There are 52. They are real terminal colourschemes — gruvbox, dracula, nord, solarized,
catppuccin (4), tokyo-night, rose-pine (3), everforest, kanagawa, ayu (3),
monokai, one-dark, night-owl, synthwave, matrix, the three CRT phosphors, and
more. `terminal` is special: it uses your emulator's own ANSI palette, so it
follows whatever scheme you already have configured.

## Known limits

* **No reconnect.** If the WebSocket drops (server restart, network change, an
  expired session token — the server revalidates every 30s) the client reports
  it in the status bar and stops there; you restart it. It also cannot detect a
  half-open socket instantly: it gives up after two minutes of silence, since
  neither end sends WebSocket pings.
* **No E2E.** Channel-PSK and DM ciphertext (`sd8~…`) renders as ciphertext.
  Decryption is client-side by design and is not implemented here yet; use the
  web app for encrypted conversations.
* **No mIRC colour codes.** The renderer drops zero-width control bytes, so
  `\x03`04red` shows as `04red` — the colour byte vanishes and its digits
  remain. Not rendered, and not quite literal either.
* **Read-mostly for uploads/pastes** — no file upload.
* The vault must be unlocked for IRC to connect — the client prompts for the
  passphrase as soon as the server reports it locked. Until it is open the server
  holds no live IRC connections, so your networks appear with no channels under
  them. `/vault` re-opens the prompt if you dismissed it with Esc.
