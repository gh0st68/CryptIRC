#!/usr/bin/env node
/**
 * Regression harness for the duplicate "Channel created" lines (RPL_CREATIONTIME / 329).
 *
 * The bug: 329 arrived as an ordinary Notice, so it was neither condensed (`notice` is
 * not a status kind) nor de-duplicated (msg_id 0 skips the id-dedup; the content-dedup
 * is status-kinds-only). CryptIRC issues bare `MODE #chan` on the user's behalf — the
 * reattach resync burst, and cmRefresh() on every live mode change while the Channel
 * Modes dialog is open — and ircd-ratbox answers each one with 324 AND 329. So the
 * channel accumulated one permanent "Channel created" line per MODE, forever, while its
 * 324 twin stayed invisible the whole time. Reported by nipsey on EFNet.
 *
 * Like scripts/test-timestamp-format.js, this extracts the REAL shipped code out of
 * static/app.js — the helper block and the `irc_channel_created` case body, verbatim,
 * never a retyped copy — and runs it in a bare vm context that provides only what the
 * page actually guarantees. A `break` inside a `switch` case and inside a `do{}while(0)`
 * mean exactly the same thing, so wrapping the case body preserves its semantics.
 *
 * Run: node scripts/test-creationtime-dedup.js
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = path.join(__dirname, '..', 'static', 'app.js');
const src = fs.readFileSync(SRC, 'utf8');

function slice(startMark, endMark, what) {
  const a = src.indexOf(startMark);
  const b = src.indexOf(endMark, a + 1);
  if (a < 0 || b < 0 || b < a) {
    console.error(`FAIL: could not locate ${what} in app.js (markers moved?)`);
    process.exit(1);
  }
  return src.slice(a, b);
}

// ── Extract the shipped code verbatim ───────────────────────────────────────
const bkFn        = slice('function bk(c,t){', '\n', 'bk()');
const queryKeyFn  = slice('function _modeQueryKey(connId, chan){', '\n', '_modeQueryKey()');
const helperBlock = slice('const _modeCreatedFollow = {};',
                          '// Where to print a /mode answer.', 'the creation-time helpers');
// The case body, minus its `case ...: {` header and its trailing `}`.
const caseWhole   = slice("case 'irc_channel_created': {", "case 'irc_ban_entry':", 'the 329 handler');
const caseBody    = caseWhole
  .slice(caseWhole.indexOf('{') + 1)
  .replace(/\}\s*$/, '');

// ── A bare context: only what the real page guarantees ──────────────────────
let said = [];              // every sysMsg the handler emitted
let dialogOpenFor = null;   // what the Channel Modes dialog is showing, if anything

const sandbox = {
  Date, Number, String, Object, Math, Intl, JSON, RegExp, Array,
  sysMsg(conn_id, target, text, kind, opts) { said.push({ conn_id, target, text, kind, opts }); },
  _cmMatch(conn_id, channel) {
    return !!dialogOpenFor && dialogOpenFor.conn_id === conn_id
      && String(dialogOpenFor.channel).toLowerCase() === String(channel || '').toLowerCase();
  },
};
vm.createContext(sandbox);
vm.runInContext(
  `${bkFn}\n${queryKeyFn}\n${helperBlock}\n` +
  `function handleCreated(ev){ do { ${caseBody} } while(0); }\n` +
  // `const` bindings are lexical: they never become properties of the context
  // object, so the harness needs a door into them. Declared here rather than in
  // app.js — the shipped code stays untouched.
  `globalThis.__state = () => ({ follow: _modeCreatedFollow, seen: _chanCreatedSeen });\n` +
  `globalThis.__clear = () => {\n` +
  `  for (const k of Object.keys(_modeCreatedFollow)) delete _modeCreatedFollow[k];\n` +
  `  for (const k of Object.keys(_chanCreatedSeen)) delete _chanCreatedSeen[k];\n` +
  `};`,
  sandbox
);

// ── Assertions ──────────────────────────────────────────────────────────────
let failures = 0;
function check(name, cond, detail) {
  if (cond) { console.log(`  ok   ${name}`); return; }
  failures++;
  console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
}
function reset() { said = []; dialogOpenFor = null; sandbox.__clear(); }
const fire = (channel, created, conn_id = 'c1') =>
  sandbox.handleCreated({ type: 'irc_channel_created', conn_id, channel, created });

const TS = 1122334455;   // a real, fixed EFNet-era channel TS

console.log('\n1. the reported bug: repeated unsolicited 329s say it once, not N times');
reset();
fire('#Chan30', TS); fire('#Chan30', TS); fire('#Chan30', TS);
check('exactly one line for three identical 329s', said.length === 1, `got ${said.length}`);
check('rendered as a condensable status kind', said[0] && said[0].kind === 'mode',
  said[0] && said[0].kind);
check('landed in the channel', said[0] && said[0].target === '#Chan30', said[0] && said[0].target);
check('spells the date, not the raw epoch',
  !!said[0] && said[0].text.startsWith('Channel created: ') && !said[0].text.includes(String(TS)),
  said[0] && said[0].text);

console.log('\n2. the memo is case-folded (ratbox echoes OUR spelling in 329, not its own)');
reset();
fire('#Chan30', TS); fire('#chan30', TS); fire('#ChAn30', TS);
check('one line across three spellings of one channel', said.length === 1, `got ${said.length}`);

console.log('\n3. a genuinely RE-CREATED channel still announces its new timestamp');
reset();
fire('#Chan30', TS); fire('#Chan30', TS + 86400);
check('two lines for two different creation times', said.length === 2, `got ${said.length}`);

console.log('\n4. per-channel and per-connection, not global');
reset();
fire('#Chan30', TS); fire('#other', TS); fire('#Chan30', TS, 'c2');
check('each distinct buffer gets its own line', said.length === 3, `got ${said.length}`);

console.log('\n5. the Channel Modes dialog swallows its own refresh...');
reset();
dialogOpenFor = { conn_id: 'c1', channel: '#Chan30' };
fire('#Chan30', TS); fire('#Chan30', TS);
check('nothing printed while the dialog owns the channel', said.length === 0, `got ${said.length}`);
console.log('   ...but does not burn the one line the user has yet to see');
dialogOpenFor = null;
fire('#Chan30', TS);
check('the line appears once after the dialog closes', said.length === 1, `got ${said.length}`);

console.log('\n6. a user-typed /mode #chan gets a spelled-out answer in the asking buffer');
reset();
sandbox._modeCreatedArm('c1', '#Chan30', 'status');   // what the 324 handler arms
fire('#Chan30', TS);
check('answered where the question was asked', said.length === 1 && said[0].target === 'status',
  said[0] && said[0].target);
check('answered as a NON-condensed system line', said[0] && said[0].kind === 'system',
  said[0] && said[0].kind);
check('names the channel it is answering about',
  !!said[0] && said[0].text.startsWith('#Chan30 created '), said[0] && said[0].text);
console.log('   ...and answering does not consume the unsolicited-copy budget');
fire('#Chan30', TS);
check('a later unsolicited copy still shows once', said.length === 2, `got ${said.length}`);

console.log('\n7. a stale arm expires instead of hijacking an unrelated later 329');
reset();
sandbox._modeCreatedArm('c1', '#Chan30', 'status');
const armed = sandbox.__state().follow[sandbox._modeQueryKey('c1', '#Chan30')];
armed.ts -= 31000;                                   // older than the 30s sweep
fire('#Chan30', TS);
check('swept, so the line falls back to the condensed channel copy',
  said.length === 1 && said[0].kind === 'mode' && said[0].target === '#Chan30',
  said[0] && `${said[0].kind}/${said[0].target}`);
check('the expired entry is gone from the map',
  Object.keys(sandbox.__state().follow).length === 0,
  JSON.stringify(Object.keys(sandbox.__state().follow)));

console.log('\n8. a missing/garbage creation time is shown once, not suppressed forever');
reset();
sandbox.handleCreated({ type: 'irc_channel_created', conn_id: 'c1', channel: '#Chan30' });
check('undefined created still produces a line', said.length === 1, `got ${said.length}`);
check('and says so honestly', !!said[0] && said[0].text === 'Channel created: unknown',
  said[0] && said[0].text);
sandbox.handleCreated({ type: 'irc_channel_created', conn_id: 'c1', channel: '#Chan30' });
check('and is still memoised so it cannot repeat', said.length === 1, `got ${said.length}`);

console.log('\n9. a 329 with no channel is dropped rather than throwing');
reset();
let threw = false;
try { sandbox.handleCreated({ type: 'irc_channel_created', conn_id: 'c1', created: TS }); }
catch (e) { threw = true; }
check('no throw, no line', !threw && said.length === 0, threw ? 'threw' : `got ${said.length}`);

console.log('\n10. the formatter itself');
check('_fmtCreated(0) is honest, not "1970"', sandbox._fmtCreated(0) === 'unknown',
  sandbox._fmtCreated(0));
check('_fmtCreated(-1) is honest', sandbox._fmtCreated(-1) === 'unknown', sandbox._fmtCreated(-1));
check('_fmtCreated(TS) renders a date', /\d{4}/.test(sandbox._fmtCreated(TS)),
  sandbox._fmtCreated(TS));

console.log(failures ? `\n✗ ${failures} check(s) failed\n` : '\n✓ all checks passed\n');
process.exit(failures ? 1 : 0);
