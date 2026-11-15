#!/usr/bin/env node
/**
 * Regression harness for the avatar client code in static/app.js (codex astra re-check of
 * remote avatars):
 *  - L app.js:4969 — while "Show other people's avatars" is off, an avatar_hint must still
 *    invalidate the cached answers (turning avatars back on must not show a withdrawn one);
 *  - L app.js:4880 — a rate-limited (429) lookup must keep the user's explicit look (probe)
 *    for its retry, so the server can still ask IRC about that nick.
 *
 * Like the other harnesses, it extracts the REAL shipped avatar block from app.js verbatim
 * and runs it in a bare vm context with only what the page guarantees (stubbed DOM, fetch).
 * Pass a path to run the same checks against a deliberately broken copy (how it was proved
 * RED).
 *
 * Run: node scripts/test-avatars-client.js [path/to/app.js]
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = process.argv[2] || path.join(__dirname, '..', 'static', 'app.js');
const src = fs.readFileSync(SRC, 'utf8');
const a = src.indexOf('// ─── Avatars (other CryptIRC users of this server)');
const b = src.indexOf('setInterval(()=>{ try{ _avApplyAll(); avatarRefreshActive(); _avPrunePictures(); }catch(_){} },60000);', a);
if (a < 0 || b < 0) { console.error('FAIL: could not locate the avatar block in app.js (markers moved?)'); process.exit(1); }
const block = src.slice(a, b);

let failed = 0;
const ok = (name, cond, extra) => { console.log((cond ? 'ok   ' : 'FAIL ') + name + (cond || extra == null ? '' : ' :: ' + extra)); if (!cond) failed++; };

function context() {
  const calls = [];
  const replies = [];
  const timers = [];
  const appearance = { avatars: true };
  const sandbox = {
    Date, Math, JSON, Object, Array, String, Number, Map, Set, Promise, RegExp, Error,
    console,
    sessionToken: 'tok',
    networks: [{ config: { id: 'c1' }, channels: [{ name: '#x', names: ['alice', 'bob', 'me'] }] }],
    active: { conn_id: 'c1', target: '#x' },
    nickCtx: null,
    loadAppearance: () => appearance,
    stripPfx: (n) => String(n).replace(/^[~&@%+]+/, ''),
    isMessagesConn: () => false,
    isUploadsConn: () => false,
    _sameChan: (x, y) => String(x).toLowerCase() === String(y).toLowerCase(),
    document: { getElementById: () => null, querySelector: () => null, querySelectorAll: () => [] },
    URL: { revokeObjectURL() {}, createObjectURL() { return 'blob:x'; } },
    setTimeout: (fn, ms) => { timers.push(fn); return timers.length; },
    clearTimeout: () => {},
    fetch: async (url, opts) => {
      calls.push({ url: String(url), body: opts && opts.body ? JSON.parse(opts.body) : null });
      const r = replies.shift() || { status: 200, body: { enabled: true, avatars: {}, pending: [], ttl: 180 } };
      return { status: r.status, ok: r.status === 200, json: async () => r.body, headers: { get: () => null } };
    },
  };
  vm.createContext(sandbox);
  vm.runInContext(block + '\n;globalThis.__AV=_AV;', sandbox, { filename: 'app.js (avatar block)' });
  const tick = async () => { for (let i = 0; i < 30; i++) await new Promise((r) => setImmediate(r)); };
  const runTimers = async () => {
    for (let i = 0; i < 20; i++) {
      await tick();
      if (!timers.length) break;
      const fn = timers.shift();
      await fn();
    }
    await tick();
  };
  return { sandbox, calls, replies, appearance, runTimers };
}

(async () => {
  // ── hidden: invalidations still apply ──
  {
    const { sandbox, calls, appearance } = context();
    const now = Date.now();
    sandbox.__AV.token = 'tok';
    sandbox.__AV.cache.set('c1\nalice', { r: 'a'.repeat(32), v: 'b'.repeat(16), h: 'remote.example', at: now, until: now + 180000, refreshAt: now + 100000 });
    appearance.avatars = false;
    sandbox.avatarHint('c1', ['alice']);
    ok('hidden: an avatar_hint still drops the cached answer', !sandbox.__AV.cache.has('c1\nalice'));
    ok('hidden: …and asks the server nothing', calls.length === 0, JSON.stringify(calls));
    appearance.avatars = true;
    ok('shown again: the withdrawn answer is gone (avatarFor returns null)', sandbox.avatarFor('c1', 'alice') === null);
  }
  // ── a 429 keeps the explicit look for the retry ──
  {
    const { sandbox, calls, replies, runTimers } = context();
    replies.push({ status: 429, body: {} });
    sandbox.avatarRequest('c1', ['bob'], 0, true);
    await runTimers();
    ok('the first lookup carried the explicit look', calls[0] && JSON.stringify(calls[0].body.probe) === '["bob"]', JSON.stringify(calls));
    ok('after the 429 the explicit look is kept', sandbox.__AV.probe.has('c1\nbob'));
    sandbox.__AV.backoffUntil = 0;
    sandbox.__AV.lastSent.clear();
    await sandbox._avFlush();
    await runTimers();
    const retry = calls.find((c, i) => i > 0 && c.body && c.body.nicks.includes('bob'));
    ok('the retry still asks for discovery (probe)', retry && JSON.stringify(retry.body.probe) === '["bob"]', JSON.stringify(calls));
  }
  console.log(failed ? `${failed} FAILED` : 'all passed');
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('FAIL:', e && e.stack || e); process.exit(1); });
