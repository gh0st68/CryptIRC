#!/usr/bin/env node
/*
 * Regression test for the /quit reason wire format (v0.4.7).
 *
 * Per the lesson recorded during the timestamp-format work: extract the REAL
 * shipped code out of static/app.js rather than retyping it, and run it in a
 * bare context that provides ONLY what the real page guarantees — no
 * convenience globals. A hand-copied duplicate would keep passing after the
 * shipped line drifted, which is exactly how a green suite hides a live bug.
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const APP = fs.readFileSync(path.join(__dirname, '..', 'static', 'app.js'), 'utf8');

// Duplicate `case` labels are legal JS, so `node --check` passes and a second,
// earlier `case 'QUIT'` would shadow the real arm while this test — which
// extracts a body by name and runs it directly — stayed green. That is not
// hypothetical: app.js already ships shadowed duplicate 'NOTE' and 'SEEN' arms.
// So assert the label is unique before trusting anything below.
const labels = APP.match(/case\s*'QUIT'\s*:/g) || [];
if (labels.length !== 1) {
  console.error(`FAIL: expected exactly 1 \`case 'QUIT':\` in app.js, found ${labels.length}` +
                ' — a duplicate label would shadow the real arm (and this test would not notice).');
  process.exit(1);
}

// Pull the body of `case 'QUIT': { ... break; }` verbatim out of the shipped file.
const start = APP.indexOf("case 'QUIT': {");
if (start < 0) { console.error('FAIL: case \'QUIT\' not found in app.js'); process.exit(1); }
let i = APP.indexOf('{', start), depth = 0, end = -1;
for (let p = i; p < APP.length; p++) {
  if (APP[p] === '{') depth++;
  else if (APP[p] === '}') { depth--; if (depth === 0) { end = p; break; } }
}
if (end < 0) { console.error('FAIL: could not brace-match the QUIT case'); process.exit(1); }
const BODY = APP.slice(i + 1, end);

if (!/QUIT :\$\{qreason\}/.test(BODY)) {
  console.error('FAIL: shipped QUIT case no longer emits a colon-prefixed trailing reason');
  process.exit(1);
}

let fails = 0, passes = 0;
function run(label, { args, networks, conn_id = 'c1' }, expected) {
  const sent = [];
  const ctx = {
    // `conn_id` and `target` are destructured from `active` in the real
    // handleInput scope, so the arm may legitimately use both.
    args, networks, conn_id, target: '#chan',
    wsend: m => sent.push(m),
    // The arm also emits a local confirmation. Stub it so the body runs, but do
    // NOT hand the vm anything the real page lacks beyond this.
    sysMsg: () => {},
    String,
  };
  try {
    // `break` is only legal inside a loop/switch, so wrap the verbatim body once.
    vm.createContext(ctx);
    new vm.Script(`do {${BODY}} while(false);`).runInContext(ctx);
  } catch (e) {
    console.error(`FAIL ${label}: threw ${e.message}`);
    fails++; return;
  }
  // Assert the WHOLE envelope, not just .raw. Checking raw alone let a mutation
  // that sent the right text to the wrong conn_id (or wrong message type) pass —
  // which on a multi-network client means quitting the user off another network.
  if (sent.length === 1) {
    if (sent[0].type !== 'send') {
      console.error(`  FAIL ${label}: wrong message type ${JSON.stringify(sent[0].type)} (expected 'send')`);
      fails++; return;
    }
    if (sent[0].conn_id !== conn_id) {
      console.error(`  FAIL ${label}: sent to wrong conn_id ${JSON.stringify(sent[0].conn_id)} (expected ${JSON.stringify(conn_id)})`);
      fails++; return;
    }
  }
  const got = sent.length === 1 ? sent[0].raw : `<${sent.length} sends>`;
  if (got === expected) { passes++; console.log(`  ok   ${label}  ->  ${JSON.stringify(got)}`); }
  else { fails++; console.error(`  FAIL ${label}\n       expected ${JSON.stringify(expected)}\n       got      ${JSON.stringify(got)}`); }
}

const net = qm => [{ config: { id: 'c1', quit_message: qm } }];

console.log('/quit wire-format tests (real shipped code):');

// The actual ask: a typed multi-word message must survive intact.
run('typed multi-word reason', { args: ['see', 'you', 'tomorrow'], networks: net(null) },
    'QUIT :see you tomorrow');
run('typed single-word reason', { args: ['bye'], networks: net(null) }, 'QUIT :bye');

// Typed message always wins over the configured one.
run('typed beats configured', { args: ['later'], networks: net('CONFIGURED') }, 'QUIT :later');

// No message typed -> configured network Quit Message.
run('bare /quit uses configured', { args: [], networks: net('Gone fishing') },
    'QUIT :Gone fishing');

// No message and nothing configured -> bare QUIT, server default. Must NOT
// advertise anything the user did not ask for.
run('bare /quit, no config', { args: [], networks: net(null) }, 'QUIT');
run('bare /quit, config null-ish', { args: [], networks: net(undefined) }, 'QUIT');
run('bare /quit, config blank', { args: [], networks: net('') }, 'QUIT');
run('bare /quit, config whitespace', { args: [], networks: net('   ') }, 'QUIT');
run('whitespace-only typed reason', { args: ['  ', ' '], networks: net(null) }, 'QUIT');

// Injection: CR/LF/NUL must never reach the wire as a line break.
run('CRLF injection in typed reason',
    { args: ['bye\r\nJOIN', '#evil'], networks: net(null) }, 'QUIT :bye  JOIN #evil');
run('NUL in typed reason', { args: ['a\0b'], networks: net(null) }, 'QUIT :a b');
run('CRLF injection in configured reason',
    { args: [], networks: net('x\r\nPRIVMSG #c :owned') }, 'QUIT :x  PRIVMSG #c :owned');
run('leading/trailing CR trimmed to nothing',
    { args: [], networks: net('\r\n') }, 'QUIT');

// Robustness: the network may legitimately not be found (stale conn_id, pseudo-view).
run('conn_id not in networks', { args: [], networks: [] }, 'QUIT');
run('conn_id not found but reason typed', { args: ['ok'], networks: [] }, 'QUIT :ok');
run('network entry missing config', { args: [], networks: [{}] }, 'QUIT');
run('networks empty + weird config shape', { args: [], networks: [{ config: null }] }, 'QUIT');

// Reason with a colon inside must not be re-escaped or split.
run('reason containing a colon', { args: ['brb:', 'dinner'], networks: net(null) },
    'QUIT :brb: dinner');
// Unicode / emoji must pass through untouched.
run('unicode reason', { args: ['さようなら', '👋'], networks: net(null) },
    'QUIT :さようなら 👋');

// Guard the exact defect this release fixes: a colon-less form must be
// impossible whenever a reason exists. Runs BEFORE the summary is printed so a
// failure here can never appear underneath a green "0 failed" line.
{
  const sent = [];
  const ctx = { args: ['a', 'b'], networks: net(null), conn_id: 'c1', target: '#chan',
                wsend: m => sent.push(m), sysMsg: () => {}, String };
  vm.createContext(ctx);
  new vm.Script(`do {${BODY}} while(false);`).runInContext(ctx);
  if (!sent.length || /^QUIT [^:]/.test(sent[0].raw)) {
    console.error('FAIL: regression — reason sent WITHOUT the colon prefix');
    fails++;
  }
}

console.log(`\n${passes} passed, ${fails} failed`);
process.exit(fails ? 1 : 0);
