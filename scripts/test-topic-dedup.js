#!/usr/bin/env node
/**
 * Regression harness for the duplicate "Topic: ..." line on join.
 *
 * The bug (reported by nipsey on EFNet): joining a channel printed the topic TWICE,
 * with the condensed mode block between the two copies. A channel's topic reaches the
 * client by two routes carrying identical text — the 332 the server volunteers on JOIN,
 * and the `TOPIC #chan` this client sends itself in the resync burst (ipc_client.rs
 * paces NAMES/WHO/MODE/TOPIC per channel). addMessage's status content-dedup cannot
 * collapse that pair: `_statusKey` includes the timestamp and the two copies land whole
 * seconds apart. Same shape as the "Channel created" pile-up — see
 * scripts/test-creationtime-dedup.js — and fixed the same way: a per-buffer memo
 * compared by VALUE, so an unchanged topic is said once and a real change always shows.
 *
 * Like that harness, this extracts the REAL shipped code out of static/app.js — the
 * helper block and BOTH case bodies (`irc_topic` and `irc_join`), verbatim, never a
 * retyped copy — and runs it in a bare vm context providing only what the page
 * guarantees. `break` means the same thing in a `switch` case and in a `do{}while(0)`,
 * which is what makes wrapping a case body legal.
 *
 * Run: node scripts/test-topic-dedup.js
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

// Defaults to the shipped app.js; pass a path to run the same checks against a
// deliberately-broken copy (that is how this harness was proved RED — see the
// two variants in the commit message).
const SRC = process.argv[2] || path.join(__dirname, '..', 'static', 'app.js');
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
// A case body, minus its `case ...: {` header and its trailing `}`.
function caseBody(startMark, endMark, what) {
  const whole = slice(startMark, endMark, what);
  return whole.slice(whole.indexOf('{') + 1).replace(/\}\s*$/, '');
}

// ── Extract the shipped code verbatim ───────────────────────────────────────
const helperBlock = slice('// ── "Topic:" said once', '// Is this message OUR OWN?',
                          'the topic-memo helpers');
const topicBody   = caseBody("case 'irc_topic': {", "case 'irc_names':", 'the irc_topic handler');
const joinBody    = caseBody("case 'irc_join_ex': {", "case 'irc_part': {", 'the irc_join handler');

// ── A bare context: only what the real page guarantees ──────────────────────
let said = [];              // every sysMsg the handlers emitted
let ourNick = 'nipsey';
const networks = [{ config: { id: 'c1' }, channels: [] }];

const sandbox = {
  Date, Number, String, Object, Math, Intl, JSON, RegExp, Array, networks,
  // Assigned to by the join body's one-shot auto-select guard — must pre-exist.
  active: null, _detMode: false, _didInitialAutoSelect: true,
  sysMsg(conn_id, target, text, kind, opts) { said.push({ conn_id, target, text, kind, opts }); },
  getNick() { return ourNick; },
  _sameChan(a, b) { return String(a).toLowerCase() === String(b).toLowerCase(); },
  stripPfx(n) { return String(n).replace(/^[~&@%+]/, ''); },
  isActive() { return false; },
  // Everything the join body touches that this test does not assert on.
  monitorUpdate() {}, renderSidebar() {}, refreshUserCount() {},
  blinkUserCount() {}, consumeUserJoin() { return false; },
  setActive() {}, updateTopbar() {},
};
vm.createContext(sandbox);
vm.runInContext(
  `${helperBlock}\n` +
  `function handleTopic(ev){ do { ${topicBody} } while(0); }\n` +
  `function handleJoin(ev){ do { ${joinBody} } while(0); }\n` +
  // `const` bindings are lexical: they never become properties of the context object,
  // so the harness needs a door into them. Declared here, not in app.js — the shipped
  // code stays untouched. The vm's module state also survives between cases, hence
  // __clear().
  `globalThis.__state = () => ({ seen: _topicSeen, asked: _topicAsked });\n` +
  `globalThis.__ask = (c, ch) => _topicAskArm(c, ch);\n` +
  `globalThis.__clear = () => {\n` +
  `  for (const k of Object.keys(_topicSeen)) delete _topicSeen[k];\n` +
  `  for (const k of Object.keys(_topicAsked)) delete _topicAsked[k];\n` +
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
function reset() {
  said = []; ourNick = 'nipsey';
  networks[0].channels = [];
  sandbox.__clear();
}
// 332 RPL_TOPIC — the unprompted query reply. irc.rs leaves set_by empty for it.
const reply = (channel, topic, conn_id = 'c1') =>
  sandbox.handleTopic({ type: 'irc_topic', conn_id, channel, topic, set_by: '', ts: 1 });
// A live TOPIC someone actually set.
const setBy = (channel, topic, who, conn_id = 'c1') =>
  sandbox.handleTopic({ type: 'irc_topic', conn_id, channel, topic, set_by: who, ts: 1 });
const join = (channel, nick, conn_id = 'c1') =>
  sandbox.handleJoin({ type: 'irc_join', conn_id, channel, nick, account: '', realname: '' });
const topicLines = () => said.filter(m => m.kind === 'topic');

const T = 'welcome | mail is up';   // stands in for the topic in the report

console.log('\n1. the reported bug: one join, two identical 332s → ONE line');
reset();
join('#Chan30', 'nipsey');
reply('#Chan30', T);          // the server's own 332, right behind the JOIN
reply('#Chan30', T);          // the resync burst's `TOPIC #chan`, seconds later
check('exactly one topic line', topicLines().length === 1, `got ${topicLines().length}`);
check('it is the real topic', topicLines()[0] && topicLines()[0].text === `Topic: ${T}`,
  topicLines()[0] && topicLines()[0].text);
check('landed in the channel', topicLines()[0] && topicLines()[0].target === '#Chan30',
  topicLines()[0] && topicLines()[0].target);
check('rendered as a condensable status kind', topicLines()[0] && topicLines()[0].kind === 'topic');

console.log('\n2. the burst repeats forever (30s heartbeat) — still one line');
reset();
join('#Chan30', 'nipsey');
for (let i = 0; i < 20; i++) reply('#Chan30', T);
check('one line for twenty identical replies', topicLines().length === 1, `got ${topicLines().length}`);

console.log('\n3. the memo is case-folded (a server may echo a spelling we did not send)');
reset();
join('#Chan30', 'nipsey');
reply('#Chan30', T); reply('#chan30', T); reply('#ChAn30', T);
check('one line across three spellings of one channel', topicLines().length === 1,
  `got ${topicLines().length}`);

console.log('\n4. a real topic CHANGE always announces');
reset();
join('#Chan30', 'nipsey');
reply('#Chan30', T);
setBy('#Chan30', 'a brand new topic', 'someone');
check('two lines: the original and the change', topicLines().length === 2,
  `got ${topicLines().length}`);
check('the change credits who set it',
  topicLines()[1] && topicLines()[1].text === 'Topic: a brand new topic (someone)',
  topicLines()[1] && topicLines()[1].text);

console.log('\n5. re-setting the SAME text is still an event someone caused');
reset();
join('#Chan30', 'nipsey');
reply('#Chan30', T);
setBy('#Chan30', T, 'someone');
check('a live TOPIC is never swallowed by the memo', topicLines().length === 2,
  `got ${topicLines().length}`);

console.log('\n6. changed and changed BACK — the value compare must not miss the return');
reset();
join('#Chan30', 'nipsey');
reply('#Chan30', T);
setBy('#Chan30', 'interlude', 'someone');
setBy('#Chan30', T, 'someone');
check('three lines', topicLines().length === 3, `got ${topicLines().length}`);
check('a 332 after the round trip is quiet again',
  (reply('#Chan30', T), topicLines().length === 3), `got ${topicLines().length}`);

console.log('\n7. part and REJOIN re-announces (a fresh join earns the line again)');
reset();
join('#Chan30', 'nipsey');
reply('#Chan30', T); reply('#Chan30', T);
check('one line for the first join', topicLines().length === 1, `got ${topicLines().length}`);
join('#Chan30', 'nipsey');           // our own rejoin clears the memo
reply('#Chan30', T); reply('#Chan30', T);
check('one more line for the rejoin, not zero and not two', topicLines().length === 2,
  `got ${topicLines().length}`);

console.log('\n8. someone ELSE joining must NOT re-arm the announcement');
reset();
join('#Chan30', 'nipsey');
reply('#Chan30', T);
join('#Chan30', 'gh0st');            // not us
reply('#Chan30', T);
check('still one topic line', topicLines().length === 1, `got ${topicLines().length}`);

console.log('\n9. an explicit /topic always answers, even unchanged');
reset();
join('#Chan30', 'nipsey');
reply('#Chan30', T);
sandbox.__ask('c1', '#Chan30');      // what the TOPIC command arm does
reply('#Chan30', T);
check('the question got its answer', topicLines().length === 2, `got ${topicLines().length}`);
check('the arm is one-shot',
  (reply('#Chan30', T), topicLines().length === 2), `got ${topicLines().length}`);
check('the arm map does not leak', Object.keys(sandbox.__state().asked).length === 0,
  JSON.stringify(sandbox.__state().asked));

console.log('\n10. per-channel and per-connection, not global');
reset();
networks.push({ config: { id: 'c2' }, channels: [] });
join('#Chan30', 'nipsey');
reply('#Chan30', T); reply('#other', T); reply('#Chan30', T, 'c2');
check('each distinct buffer gets its own line', topicLines().length === 3,
  `got ${topicLines().length}`);
networks.pop();

console.log('\n11. state the handler must keep doing regardless of the memo');
reset();
join('#Chan30', 'nipsey');
reply('#Chan30', T);
reply('#Chan30', T);                 // suppressed line — but the row must still track
const row = networks[0].channels.find(c => c.name.toLowerCase() === '#chan30');
check('the channel row exists', !!row);
check('its topic is recorded for the topbar', !!row && row.topic === T, row && row.topic);

console.log('\n12. an empty/absent topic cannot poison the memo');
reset();
join('#Chan30', 'nipsey');
sandbox.handleTopic({ type: 'irc_topic', conn_id: 'c1', channel: '#Chan30', set_by: '', ts: 1 });
reply('#Chan30', T);
check('the real topic still announces after an empty one', topicLines().length === 2,
  `got ${topicLines().length}`);

console.log('\n13. a topicless event is a no-op, not a throw');
reset();
let threw = null;
try { sandbox.handleTopic({ type: 'irc_topic', conn_id: 'c1', channel: '', topic: T, set_by: '' }); }
catch (e) { threw = e; }
check('no channel → nothing said, nothing thrown', !threw && said.length === 0,
  threw ? String(threw) : `said ${said.length}`);

// ── The wiring the vm cannot see: the /topic command must arm ───────────────
console.log('\n14. the shipped /topic command arms the bypass');
const cmdArm = /if\(!args\.length\)\{\s*_topicAskArm\(conn_id,\s*target\);\s*wsend\(/.test(src);
check('bare /topic calls _topicAskArm before sending', cmdArm);

console.log(failures === 0
  ? `\nAll checks passed.\n`
  : `\n${failures} check(s) FAILED.\n`);
process.exit(failures === 0 ? 0 : 1);
