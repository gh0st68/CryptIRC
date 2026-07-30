#!/usr/bin/env node
/*
 * Regression test for `/quit` (v0.4.8).
 *
 * Contract: /quit must DISCONNECT and carry the user's message, so it goes
 * through the same path as the Disconnect button — `{type:'disconnect', id,
 * reason}` — NOT a raw `QUIT` line. A raw QUIT only makes the server close the
 * socket and the daemon redials ~5s later, which is the bug this replaced.
 *
 * Per the lesson from the timestamp-format work: extract the REAL shipped code
 * out of static/app.js rather than retyping it, and run it in a bare context
 * that provides ONLY what the real page guarantees. A hand-copied duplicate
 * would keep passing after the shipped line drifted.
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const APP = fs.readFileSync(path.join(__dirname, '..', 'static', 'app.js'), 'utf8');

// Duplicate `case` labels are legal JS, so `node --check` passes and a second,
// earlier `case 'QUIT'` would shadow the real arm while this test — which
// extracts a body by name and runs it directly — stayed green. Not
// hypothetical: app.js already ships shadowed duplicate 'NOTE'/'SEEN' arms.
const labels = APP.match(/case\s*'QUIT'\s*:/g) || [];
if (labels.length !== 1) {
  console.error(`FAIL: expected exactly 1 \`case 'QUIT':\` in app.js, found ${labels.length}` +
                ' — a duplicate label would shadow the real arm (and this test would not notice).');
  process.exit(1);
}

const start = APP.indexOf("case 'QUIT': {");
if (start < 0) { console.error("FAIL: case 'QUIT' not found in app.js"); process.exit(1); }
let i = APP.indexOf('{', start), depth = 0, end = -1;
for (let p = i; p < APP.length; p++) {
  if (APP[p] === '{') depth++;
  else if (APP[p] === '}') { depth--; if (depth === 0) { end = p; break; } }
}
if (end < 0) { console.error('FAIL: could not brace-match the QUIT case'); process.exit(1); }
const BODY = APP.slice(i + 1, end);

// Structural guard: the arm must route through disconnect, never re-grow a raw
// QUIT send (the exact defect this release replaced).
if (!/type:'disconnect'/.test(BODY)) {
  console.error("FAIL: shipped QUIT case no longer sends {type:'disconnect'} — /quit would not stay disconnected");
  process.exit(1);
}
if (/QUIT/.test(BODY.replace(/\/\/[^\n]*/g, ''))) {
  console.error('FAIL: shipped QUIT case emits a raw QUIT line again — the daemon will redial ~5s later');
  process.exit(1);
}

let fails = 0, passes = 0;
function run(label, { args, conn_id = 'c1' }, expected) {
  const sent = [];
  const notices = [];
  const ctx = {
    // `conn_id`/`target` are destructured from `active` in the real handleInput
    // scope. Nothing else is provided — the real page has no extra helpers here.
    args, conn_id, target: '#chan',
    networks: [{ config: { id: 'c1', quit_message: 'CONFIGURED' } }],
    wsend: m => sent.push(m),
    sysMsg: (c, t, text) => notices.push(text),
    String,
  };
  try {
    // `break` is only legal inside a loop/switch, so wrap the verbatim body once.
    vm.createContext(ctx);
    new vm.Script(`do {${BODY}} while(false);`).runInContext(ctx);
  } catch (e) {
    console.error(`  FAIL ${label}: threw ${e.message}`);
    fails++; return;
  }
  // Exactly ONE message: sending the reason and the teardown separately would
  // race (server may close before the drop lands).
  if (sent.length !== 1) {
    console.error(`  FAIL ${label}: expected exactly 1 wsend, got ${sent.length}`);
    fails++; return;
  }
  const m = sent[0];
  if (m.type !== 'disconnect') {
    console.error(`  FAIL ${label}: type ${JSON.stringify(m.type)} (expected 'disconnect')`);
    fails++; return;
  }
  // The Rust handler keys off `id`, not `conn_id` — a mismatch here would quit
  // the wrong network on a multi-network client, or silently no-op.
  if (m.id !== conn_id) {
    console.error(`  FAIL ${label}: id ${JSON.stringify(m.id)} (expected ${JSON.stringify(conn_id)})`);
    fails++; return;
  }
  if (m.reason !== expected) {
    console.error(`  FAIL ${label}\n       expected reason ${JSON.stringify(expected)}\n       got      reason ${JSON.stringify(m.reason)}`);
    fails++; return;
  }
  if (!notices.length) {
    console.error(`  FAIL ${label}: no local confirmation shown to the user`);
    fails++; return;
  }
  passes++;
  console.log(`  ok   ${label}  ->  reason ${JSON.stringify(m.reason)}`);
}

console.log('/quit tests (real shipped code):');

// The actual ask: a typed multi-word message must survive intact.
run('typed multi-word reason', { args: ['see', 'you', 'tomorrow'] }, 'see you tomorrow');
run('typed single-word reason', { args: ['bye'] }, 'bye');

// No message typed -> send null, so the SERVER falls back to the network's
// configured Quit Message (or the default advert). Deliberately not resolved
// client-side: DEFAULT_QUIT_MESSAGE lives in Rust and a JS copy would drift.
run('bare /quit defers to server', { args: [] }, null);
run('whitespace-only reason defers', { args: ['  ', ' '] }, null);

// Injection: CR/LF/NUL must never reach the wire as a line break.
run('CRLF injection in reason', { args: ['bye\r\nJOIN', '#evil'] }, 'bye  JOIN #evil');
run('NUL in reason', { args: ['a\0b'] }, 'a b');
run('CR-only reason collapses to null', { args: ['\r\n'] }, null);

// Formatting/encoding must pass through untouched.
run('reason containing a colon', { args: ['brb:', 'dinner'] }, 'brb: dinner');
run('unicode reason', { args: ['さようなら', '👋'] }, 'さようなら 👋');
run('mIRC colour codes preserved', { args: ['\x0304red\x03', 'bye'] }, '\x0304red\x03 bye');
run('interior spaces preserved', { args: ['a', '', 'b'] }, 'a  b');

// Routing must follow the active connection, not a hardcoded value.
run('non-default conn_id', { args: ['bye'], conn_id: 'other-net' }, 'bye');

console.log(`\n${passes} passed, ${fails} failed`);
process.exit(fails ? 1 : 0);
