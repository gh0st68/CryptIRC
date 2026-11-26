# Auditing CryptIRC

Run the local checks, exercise the candidate on the Arch IRC testnet, and then have Claude Code repeat the testnet run and review the changes. Record the commit or worktree diff, the web and core binary hashes, the enabled test groups, and each result.

## Review the changes locally

- Trace each reported issue through the real entry point and find where the behavior differs from what users expect. Review browser controls, WebSocket messages, server handlers, and the core separately when the change crosses those boundaries.
- Check successful use and failure paths. For encryption, cover locked and unlocked vaults, new and remembered devices, legacy recovery, account isolation, and whether a draft or secret can reach the wire. For chat and navigation, cover desktop and phone input, focus, switching views, reconnects, and stale responses.
- For each finding, record the affected version and source location, the observed result, the expected result, and the practical impact. A failed harness setup should be recorded as a setup failure. Re-run the affected check after correcting the fixture.

```bash
git diff --check
bash scripts/sync-version.sh check
bash -n deploy/update.sh
node --check static/app.js
node --check static/e2e.js
node --check static/page-controls.js
cargo test --locked
node scripts/test-interactions.mjs
node scripts/test-layout.mjs
```

Run focused suites under [scripts/](../scripts/) when their feature changes. If a check fails, compare against the base revision under the same conditions and note whether the failure predates the candidate.

## Run the Arch testnet suite

Build the candidate web and IRC core binaries. Use the already deployed core as an additional compatibility case for a web-only update when appropriate.

```bash
cargo build --release --locked --bin cryptirc --bin irc_core
sha256sum target/release/cryptirc target/release/irc_core
```

Copy the binaries to a fresh staging directory on Arch over Tailscale. Copy the integration runner and its imported `*-checks.mjs` modules under `scripts/` and keep fixtures at their repo-relative paths. The translation suite uses `src/twitter/fixtures/normalized/quoted-post.json`. For legacy encryption coverage, stage a prior release binary that can create a v2 keyring. Check the transferred hashes against the build.

On Arch, use the loopback ports of the two linked IRC test servers. Set `CHROMIUM` if the local browser path differs from the runner's default. Node must provide a global WebSocket. The runner starts its own web process and core, creates throwaway accounts and browser profiles, and cleans up on exit.

```bash
set -o pipefail
CRYPTIRC_BIN="$PWD/cryptirc" \
CRYPTIRC_CORE_BIN="$PWD/irc_core" \
CRYPTIRC_LEGACY_BIN="$PWD/cryptirc-legacy" \
IRC_PORT="<testnet hub port>" \
IRC_LEAF_PORT="<testnet leaf port>" \
CRYPTIRC_TEST_E2E=1 \
CRYPTIRC_TEST_CHANNEL_LIST=1 \
CRYPTIRC_TEST_TRANSLATION=1 \
CRYPTIRC_TEST_SETTINGS_SEARCH=1 \
node scripts/test-account-integrations.mjs | tee arch-test.log
```

Check the exit status as well as the log. The suite covers real IRC delivery, passkeys, MCP authorization and account isolation, encrypted DMs and channels, recovery, browser controls, CSP, channel directory search and cache behavior, and translation. If a feature group was disabled or the legacy binary was unavailable, note the coverage gap.

## Get an independent Claude Code audit

After your own testnet run passes, give Claude Code the relevant source diff and the location of a wrapper that reruns the isolated Arch suite against the same candidate. Use `--model opus --effort high` and record the actual model reported by the CLI. Ask Claude to run the wrapper, review the normal and failure paths, and return reproducible findings with source references and the test exit status.

Use only source and synthetic fixture output in the review. Keep production chat, account data, credentials, and recovery material out of the prompt. Disable MCP for the audit and allow only the specific test wrapper if the reviewer needs Bash.

```bash
audit_wrapper=/absolute/path/to/run-arch-audit
claude --print --model opus --effort high --no-session-persistence \
  --tools Bash --allowedTools "Bash($audit_wrapper)" --permission-mode dontAsk \
  --setting-sources '' --strict-mcp-config --mcp-config '{"mcpServers":{}}' \
  -- "Run $audit_wrapper, then audit the supplied diff and report the result." < review-input.txt
```

Verify each finding yourself. Fix confirmed issues, re-run the affected suites, and have Claude follow up on fixes that change audited behavior. Save the final model, results, and any remaining limitations alongside the test evidence.

## Record the result

In the final summary, give the tested version or commit, the local and testnet results, Claude's findings, and any open issues. If a deployment was requested, also verify the served version, HTTPS and WebSocket access, both service states, and the web service's connection to the IRC core. Record whether the core was restarted and what was observed about IRC reconnects.
