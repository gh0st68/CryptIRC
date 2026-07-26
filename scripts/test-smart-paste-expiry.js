#!/usr/bin/env node
/**
 * Tests the smart-paste expiry selector by extracting the REAL functions out of
 * static/app.js (never a retyped copy) and driving them against a <select> whose
 * options are parsed out of the REAL static/index.html — so the markup stays the
 * single source of truth and a dropped/renamed option fails the test instead of
 * silently shipping.
 *
 * Checks:
 *  (1) With no stored preference the request body is byte-identical to the
 *      pre-change behaviour (expires_in 0, plain toast) — the regression oracle.
 *  (2) Every option in index.html round-trips: chosen -> sent -> persisted ->
 *      re-applied on the next dialog open.
 *  (3) Corrupt/absent stored values, and a missing #sp-expire element (stale
 *      cached index.html against a fresh app.js), fall back to 0 without throwing.
 *  (4) The prefs-sync gate adopts clean integers and IGNORES empty/garbage, so a
 *      device that never opened the dialog cannot wipe another device's choice.
 *
 * Run: node scripts/test-smart-paste-expiry.js
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const src = fs.readFileSync(path.join(ROOT, 'static', 'app.js'), 'utf8');
const html = fs.readFileSync(path.join(ROOT, 'static', 'index.html'), 'utf8');

let failures = 0, checks = 0;
function ok(cond, label, extra) {
  checks++;
  if (cond) { console.log(`  ok   ${label}`); }
  else { failures++; console.log(`  FAIL ${label}${extra ? ` — ${extra}` : ''}`); }
}
function eq(actual, expected, label) {
  ok(Object.is(actual, expected), label, `got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}`);
}

// ── Parse the real <select> out of index.html ───────────────────────────────
const selMatch = html.match(/<select id="sp-expire">([\s\S]*?)<\/select>/);
if (!selMatch) { console.error('FAIL: #sp-expire not found in static/index.html'); process.exit(1); }
const OPTIONS = [...selMatch[1].matchAll(/<option value="([^"]*)">([^<]*)<\/option>/g)]
  .map(m => ({ value: m[1], text: m[2] }));
if (!OPTIONS.length) { console.error('FAIL: #sp-expire has no <option>s'); process.exit(1); }

// ── Extract the shipped smart-paste block verbatim ──────────────────────────
const start = src.indexOf('// ─── Smart paste ');
const end = src.indexOf('// ─── KeepNick');
if (start < 0 || end < 0 || end < start) {
  console.error('FAIL: could not locate the smart-paste block in app.js'); process.exit(1);
}
const block = src.slice(start, end);

// ── Extract the two prefs-sync lines verbatim ───────────────────────────────
const gatherLine = src.split('\n').find(l => l.includes('smartPasteExpire: localStorage.getItem'));
if (!gatherLine) { console.error('FAIL: smartPasteExpire missing from gatherPreferences'); process.exit(1); }
const restoreLine = src.split('\n').find(l => l.includes('p.smartPasteExpire'));
if (!restoreLine) { console.error('FAIL: smartPasteExpire missing from restorePreferences'); process.exit(1); }

// ── Minimal fakes: only what the real page guarantees ───────────────────────
function makeSelect(options) {
  return {
    _value: options.length ? options[0].value : '',
    options,
    get value() { return this._value; },
    // Mirrors the DOM: assigning a value no <option> carries leaves value === ''.
    set value(v) { this._value = options.some(o => o.value === String(v)) ? String(v) : ''; },
    get selectedOptions() {
      const hit = options.find(o => o.value === this._value);
      return hit ? [{ textContent: hit.text }] : [];
    },
  };
}

async function run({ stored, pick, selectPresent = true, options = OPTIONS }) {
  const store = new Map();
  if (stored !== undefined) store.set('cryptirc_smartpaste_expire', stored);

  const sel = selectPresent ? makeSelect(options) : null;
  const dialog = { classList: { add() {}, remove() {} }, querySelector: () => ({ set textContent(_) {} }) };
  const input = { value: '' };
  const sent = [];
  const toasts = [];
  let prefsSaved = 0;

  const sandbox = {
    document: {
      getElementById(id) {
        if (id === 'sp-expire') return sel;
        if (id === 'smart-paste-dialog') return dialog;
        if (id === 'msg-input') return input;
        return null;
      },
    },
    localStorage: {
      getItem: k => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: k => store.delete(k),
    },
    location: { pathname: '/cryptirc/' },
    sessionToken: 'tok',
    active: { conn_id: 1, target: '#x' },
    showToast: m => toasts.push(m),
    savePrefsToServer: () => { prefsSaved++; },
    fetch: (url, opts) => {
      sent.push({ url, body: JSON.parse(opts.body) });
      // Resolve like the real route does so the .then tail (input bar + toast)
      // actually runs and can be asserted on.
      return Promise.resolve({ json: () => Promise.resolve({ url: 'https://x/paste/abc' }) });
    },
    JSON, String, Number, RegExp, Object, Array, Promise, parseInt, console,
  };
  vm.createContext(sandbox);
  vm.runInContext(
    block +
    '\n;globalThis.__open=()=>_smartPasteApplyExpire();' +
    '\n;globalThis.__setText=t=>{_smartPasteText=t};' +
    '\n;globalThis.__yes=()=>smartPasteYes();' +
    '\n;globalThis.__no=()=>smartPasteNo();',
    sandbox, { filename: 'app.js-smartpaste-extract' }
  );

  sandbox.__setText('a\nb\nc\nd\ne');
  sandbox.__open();                                   // dialog opens -> applies stored pref
  if (pick !== undefined && sel) sel.value = pick;    // user picks from the dropdown
  sandbox.__yes();
  // Let fetch -> .json() -> .then(...) settle before asserting on the toast/input.
  await Promise.resolve(); await Promise.resolve(); await Promise.resolve();

  return { sent, toasts, store, prefsSaved, sel, input };
}

async function main() {
console.log('\n# 1. Regression oracle — untouched default must match pre-change behaviour');
{
  const r = await run({});
  eq(r.sent.length, 1, 'exactly one paste request issued');
  eq(r.sent[0].body.expires_in, 0, 'expires_in is 0 (no expiry), as before the change');
  eq(r.sent[0].body.language, 'text', 'language still "text"');
  eq(r.sent[0].body.password, null, 'password still null');
  eq(r.sent[0].body.content, 'a\nb\nc\nd\ne', 'content sent verbatim');
  eq(r.sent[0].url, '/cryptirc/paste', 'posts to the base-path-relative /paste route');
  eq(r.toasts[0], 'Paste created — URL in input bar', 'toast unchanged when never-expires');
  eq(r.sel.value, '0', 'dropdown defaults to Never');
}

console.log('\n# 2. Every option in index.html round-trips');
for (const opt of OPTIONS) {
  const r = await run({ pick: opt.value });
  const want = parseInt(opt.value, 10) || 0;
  eq(r.sent[0].body.expires_in, want, `"${opt.text}" sends expires_in=${want}`);
  eq(r.store.get('cryptirc_smartpaste_expire'), String(want), `"${opt.text}" persisted`);
  ok(r.prefsSaved === 1, `"${opt.text}" triggers a prefs sync`);
  // Toast wording: expiring pastes say so, "Never" keeps the original message.
  if (want) ok(r.toasts[0] === `Paste created (expires in ${opt.text.toLowerCase()}) — URL in input bar`,
    `"${opt.text}" toast names the lifetime`, r.toasts[0]);
  else eq(r.toasts[0], 'Paste created — URL in input bar', '"Never" keeps the plain toast');
  // Reopening the dialog restores that choice.
  const r2 = await run({ stored: String(want) });
  eq(r2.sel.value, String(want), `"${opt.text}" is re-selected on the next open`);
  eq(r2.sent[0].body.expires_in, want, `"${opt.text}" survives a reopen without re-picking`);
}

console.log('\n# 3. Hostile / degraded inputs fall back to Never, never throw');
for (const bad of ['', 'abc', '-1', '99999999999999999999', '3600; DROP', '1e9', 'null', '  600  ']) {
  let r;
  try { r = await run({ stored: bad }); }
  catch (e) { ok(false, `stored ${JSON.stringify(bad)} did not throw`, e.message); continue; }
  eq(r.sent[0].body.expires_in, 0, `stored ${JSON.stringify(bad)} -> expires_in 0`);
  eq(r.sel.value, '0', `stored ${JSON.stringify(bad)} -> dropdown shows Never`);
}
{
  // Stale cached index.html (no dropdown) against a fresh app.js — the two are
  // separate network-first fetches, so this pairing really can happen.
  let r;
  try { r = await run({ selectPresent: false }); ok(true, 'missing #sp-expire does not throw'); }
  catch (e) { ok(false, 'missing #sp-expire does not throw', e.message); r = null; }
  if (r) {
    eq(r.sent.length, 1, 'paste is still created without the dropdown');
    eq(r.sent[0].body.expires_in, 0, 'falls back to no expiry');
    eq(r.toasts[0], 'Paste created — URL in input bar', 'falls back to the plain toast');
  }
}
{
  // A value that is a clean integer but no longer an offered option.
  const r = await run({ stored: '12345' });
  eq(r.sent[0].body.expires_in, 0, 'integer with no matching <option> -> 0');
}

console.log('\n# 4. "Paste as Text" is unaffected');
{
  const store = new Map();
  const sandbox2 = {
    document: { getElementById: id => (id === 'msg-input' ? { value: 'pre:' } : { classList: { remove() {} } }) },
    localStorage: { getItem: k => store.get(k) ?? null, setItem: (k, v) => store.set(k, v), removeItem: k => store.delete(k) },
    location: { pathname: '/cryptirc/' }, sessionToken: 't', active: {}, showToast() {}, savePrefsToServer() {},
    fetch: () => { throw new Error('smartPasteNo must not hit the network'); },
    JSON, String, Number, RegExp, Object, Array, Promise, parseInt, console,
  };
  vm.createContext(sandbox2);
  vm.runInContext(block + '\n;globalThis.__setText=t=>{_smartPasteText=t};globalThis.__no=()=>smartPasteNo();', sandbox2);
  sandbox2.__setText('x\ny');
  try { sandbox2.__no(); ok(true, 'smartPasteNo still inserts text without calling the paste API'); }
  catch (e) { ok(false, 'smartPasteNo still inserts text without calling the paste API', e.message); }
}

console.log('\n# 5. Prefs-sync gate: adopt clean integers, ignore empty/garbage');
{
  const gather = (val) => {
    const store = new Map();
    if (val !== undefined) store.set('cryptirc_smartpaste_expire', val);
    const sb = { localStorage: { getItem: k => store.get(k) ?? null }, out: null, String, Object };
    vm.createContext(sb);
    vm.runInContext(`out = { ${gatherLine.trim().replace(/,\s*$/, '')} };`, sb);
    return sb.out.smartPasteExpire;
  };
  eq(gather('3600'), '3600', 'gatherPreferences exports the stored value');
  eq(gather(undefined), '', 'gatherPreferences exports "" when never set');

  const restore = (incoming, existing) => {
    const store = new Map();
    if (existing !== undefined) store.set('cryptirc_smartpaste_expire', existing);
    const sb = {
      p: incoming === undefined ? {} : { smartPasteExpire: incoming },
      localStorage: {
        getItem: k => store.get(k) ?? null,
        setItem: (k, v) => store.set(k, String(v)),
        removeItem: k => store.delete(k),
      },
      String, RegExp, Object,
    };
    vm.createContext(sb);
    vm.runInContext(restoreLine.trim(), sb);
    return store.has('cryptirc_smartpaste_expire') ? store.get('cryptirc_smartpaste_expire') : null;
  };
  eq(restore('86400', '0'), '86400', 'a synced integer is adopted');
  eq(restore(0, undefined), '0', 'a synced numeric 0 (never) is adopted');
  eq(restore('', '3600'), '3600', 'an EMPTY sync does NOT wipe an existing choice');
  eq(restore(undefined, '3600'), '3600', 'an ABSENT field does NOT wipe an existing choice');
  eq(restore('abc', '3600'), '3600', 'a garbage sync does NOT wipe an existing choice');
  eq(restore('-5', '3600'), '3600', 'a negative sync is rejected');
  eq(restore('', undefined), null, 'an empty sync on a fresh device stores nothing');
}

console.log(`\n${failures ? 'FAILED' : 'PASSED'} — ${checks - failures}/${checks} checks`);
process.exit(failures ? 1 : 0);
}
main().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
