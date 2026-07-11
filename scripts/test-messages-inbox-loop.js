#!/usr/bin/env node
'use strict';
/*
 * Regression harness: Messages-inbox get_logs fetch↔render loop.
 *
 * Reproduces deterministically (no timers, no network) the production bug where
 * opening the unified "Messages" inbox with a conversation whose server-side DM
 * log returns ZERO lines (e.g. a cross-device union-merged row whose lowercased
 * display misses the case-sensitive log file, or a /query with no messages yet)
 * caused an infinite loop:
 *
 *   renderMessagesView → wsend get_logs(limit:1)     [_pendingLogs key set]
 *   server → log_lines {lines: []}                    (main.rs always replies)
 *   handler → _pendingLogs.delete → prependLogs
 *   prependLogs → renderMessagesView                  (inbox active)
 *   renderMessagesView → conversation still empty, pending key gone → re-send…
 *
 * Every cycle rebuilt the whole inbox DOM (#chat-area innerHTML=''), so on a
 * macOS installed PWA the window flickered heavily and row clicks died (the
 * node was replaced between pointerdown and pointerup).
 *
 * The harness evaluates the REAL static/app.js (unmodified) inside a stubbed
 * browser sandbox, then drives the real handleEvent/renderMessagesView with a
 * simulated server that mirrors src/main.rs GetLogs semantics exactly:
 * always reply; case-sensitive log lookup; [] when the log is missing;
 * pseudo conn_ids (__msgs/__uploads) dropped with NO reply (owns_network fails);
 * vault locked → reply arrives but with EMPTY lines (read_logs can't decrypt →
 * unwrap_or_default).
 *
 * Also covers the two audit follow-ups:
 *   - Phase 4: the 'state' handler's PM-fallback get_logs must skip pseudo-views
 *     (__msgs/__messages would strand a _pendingLogs key until reconnect).
 *   - Phases 5/6: preview attempts burned by empty replies while the vault was
 *     LOCKED must retry after unlock — via the vault_unlocked event on the
 *     unlocking socket (5) and via State{vault_unlocked:true} on every other
 *     session (6), which is the only unlock signal those sockets receive.
 *
 * Run: node scripts/test-messages-inbox-loop.js   (exit 0 = pass, 1 = fail)
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const APP_JS = path.join(__dirname, '..', 'static', 'app.js');
const SRC = fs.readFileSync(APP_JS, 'utf8');

/* ─── Minimal permissive DOM stubs ──────────────────────────────────────────── */

function makeClassList() {
  const s = new Set();
  return {
    add: (...c) => c.forEach(x => s.add(x)),
    remove: (...c) => c.forEach(x => s.delete(x)),
    toggle: (c, force) => { const want = force === undefined ? !s.has(c) : !!force; want ? s.add(c) : s.delete(c); return want; },
    contains: c => s.has(c),
  };
}

let elSeq = 0;
function makeEl(tag) {
  const el = {
    __el: true, __id: ++elSeq,
    tagName: String(tag || 'div').toUpperCase(),
    children: [],
    style: { setProperty() {}, removeProperty() {}, getPropertyValue() { return ''; } },
    dataset: {},
    classList: makeClassList(),
    attributes: {},
    parentNode: null,
    textContent: '',
    value: '', checked: false, disabled: false, hidden: false,
    id: '', className: '', title: '', placeholder: '', type: '', name: '',
    tabIndex: 0, selectedIndex: 0, scrollTop: 0, scrollLeft: 0,
    scrollHeight: 0, scrollWidth: 0, clientHeight: 0, clientWidth: 0,
    offsetHeight: 0, offsetWidth: 0, offsetTop: 0, offsetLeft: 0, offsetParent: null,
    naturalWidth: 0, naturalHeight: 0, videoWidth: 0, videoHeight: 0,
    files: [], options: [], selectionStart: 0, selectionEnd: 0,
    firstChild: null, lastChild: null, nextSibling: null, previousSibling: null,
    _listeners: {},
    _innerHTML: '',
    get innerHTML() { return this._innerHTML; },
    set innerHTML(v) { this._innerHTML = String(v); this.children = []; },
    get innerText() { return this.textContent; },
    set innerText(v) { this.textContent = String(v); },
    get childNodes() { return this.children; },
    get parentElement() { return this.parentNode; },
    get firstElementChild() { return this.children[0] || null; },
    appendChild(c) { this.children.push(c); if (c && typeof c === 'object') c.parentNode = this; return c; },
    append(...cs) { cs.forEach(c => { if (c && c.__el) this.appendChild(c); }); },
    prepend(...cs) { cs.reverse().forEach(c => { if (c && c.__el) { this.children.unshift(c); c.parentNode = this; } }); },
    insertBefore(c, ref) { const i = this.children.indexOf(ref); if (i < 0) this.children.push(c); else this.children.splice(i, 0, c); if (c) c.parentNode = this; return c; },
    removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); return c; },
    replaceChildren(...cs) { this.children = []; this.append(...cs); },
    remove() { if (this.parentNode) this.parentNode.removeChild(this); },
    cloneNode() { return makeEl(this.tagName); },
    setAttribute(k, v) { this.attributes[k] = String(v); },
    getAttribute(k) { return k in this.attributes ? this.attributes[k] : null; },
    removeAttribute(k) { delete this.attributes[k]; },
    hasAttribute(k) { return k in this.attributes; },
    addEventListener(t, fn) { (this._listeners[t] = this._listeners[t] || []).push(fn); },
    removeEventListener(t, fn) { const l = this._listeners[t]; if (l) { const i = l.indexOf(fn); if (i >= 0) l.splice(i, 1); } },
    dispatchEvent() { return true; },
    click() {}, focus() {}, blur() {}, select() {}, setSelectionRange() {},
    scrollTo() {}, scrollIntoView() {}, setPointerCapture() {}, releasePointerCapture() {},
    getBoundingClientRect() { return { top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0, x: 0, y: 0 }; },
    closest() { return makeEl('div'); },   // truthy: top-level wiring dereferences it (nothing in exercised paths branches on it)
    contains() { return false; },
    matches() { return false; },
    querySelector() { return makeEl('div'); },
    querySelectorAll() { return []; },
    getContext() { return makeCtx(this); },
    play() { return Promise.resolve(); }, pause() {}, load() {},
    animate() { return { cancel() {}, finished: Promise.resolve() }; },
    requestFullscreen() { return Promise.resolve(); },
    showModal() {}, close() {},
    get content() { return makeEl('div'); },
    get valueAsNumber() { return Number(this.value) || 0; },
    getClientRects() { return []; },
    insertAdjacentHTML() {}, insertAdjacentElement(_, e) { return e; },
    before() {}, after() {}, replaceWith() {},
  };
  return el;
}

function makeCtx(canvasEl) {
  return new Proxy({}, {
    get(_, k) {
      if (k === 'canvas') return canvasEl;
      return () => undefined; // any method call is a no-op; property reads used as fns work
    },
    set() { return true; }, // fillStyle = ... etc.
  });
}

function makeStorage() {
  const m = new Map();
  return {
    getItem: k => (m.has(String(k)) ? m.get(String(k)) : null),
    setItem: (k, v) => m.set(String(k), String(v)),
    removeItem: k => m.delete(String(k)),
    clear: () => m.clear(),
    key: i => [...m.keys()][i] ?? null,
    get length() { return m.size; },
  };
}

/* ─── Sandbox ───────────────────────────────────────────────────────────────── */

const byId = new Map();
const documentStub = {
  title: 'harness',
  hidden: false,
  visibilityState: 'visible',
  cookie: '',
  readyState: 'complete',
  body: makeEl('body'),
  documentElement: makeEl('html'),
  head: makeEl('head'),
  activeElement: makeEl('input'),
  fonts: { ready: Promise.resolve(), add() {}, load: () => Promise.resolve([]) },
  getElementById(id) {
    if (!byId.has(id)) {
      const e = makeEl('div'); e.id = id;
      makeEl('div').appendChild(e);   // top-level code dereferences .parentNode
      byId.set(id, e);
    }
    return byId.get(id);
  },
  createElement(tag) { return makeEl(tag); },
  createTextNode(t) { const e = makeEl('#text'); e.textContent = String(t); return e; },
  createDocumentFragment() { return makeEl('#fragment'); },
  querySelector() { return makeEl('div'); },
  querySelectorAll() { return []; },
  addEventListener() {}, removeEventListener() {},
  dispatchEvent() { return true; },
  hasFocus() { return true; },
  elementFromPoint() { return null; },
  execCommand() { return false; },
  createEvent() { return { initEvent() {} }; },
};

const rafQueue = [];
const sandbox = {
  console,
  setTimeout, clearTimeout,           // real: needed for async settling + coalesced render
  setInterval: () => 0, clearInterval: () => {},   // neutered: no watchdogs in the harness
  requestAnimationFrame: cb => { rafQueue.push(cb); return rafQueue.length; },
  cancelAnimationFrame: () => {},
  queueMicrotask: fn => queueMicrotask(fn),
  document: documentStub,
  localStorage: makeStorage(),
  sessionStorage: makeStorage(),
  location: {
    protocol: 'https:', host: 'harness.test', hostname: 'harness.test',
    pathname: '/cryptirc/', search: '', hash: '', port: '',
    origin: 'https://harness.test', href: 'https://harness.test/cryptirc/',
    reload() {}, assign() {}, replace() {},
  },
  navigator: {
    userAgent: 'CryptIRC-harness', platform: 'MacIntel', language: 'en-US', languages: ['en-US'],
    onLine: true, maxTouchPoints: 0, hardwareConcurrency: 4,
    clipboard: { writeText: async () => {}, readText: async () => '' },
    serviceWorker: { register: async () => ({}), addEventListener() {}, controller: null, ready: new Promise(() => {}), getRegistration: async () => undefined, getRegistrations: async () => [] },
    mediaDevices: { getUserMedia: async () => { throw new Error('no media'); }, enumerateDevices: async () => [] },
    vibrate() { return false; }, sendBeacon() { return true; },
    storage: { persist: async () => false, persisted: async () => false, estimate: async () => ({ usage: 0, quota: 0 }) },
    permissions: { query: async () => ({ state: 'denied', addEventListener() {} }) },
    credentials: { create: async () => null, get: async () => null },
    userAgentData: { platform: 'macOS', brands: [] },
    wakeLock: { request: async () => ({ release: async () => {} }) },
  },
  history: { replaceState() {}, pushState() {}, back() {}, state: null },
  screen: { width: 1440, height: 900, availWidth: 1440, availHeight: 900, orientation: { type: 'landscape-primary', addEventListener() {} } },
  innerWidth: 1440, innerHeight: 900, devicePixelRatio: 2,
  matchMedia: q => ({ matches: false, media: String(q), addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }),
  getComputedStyle: () => ({ getPropertyValue: () => '', display: 'block' }),
  alert() {}, confirm() { return true; }, prompt() { return null; },
  open() { return null; },
  scrollTo() {},
  fetch: async () => ({ ok: false, status: 503, json: async () => ({}), text: async () => '', blob: async () => null, arrayBuffer: async () => new ArrayBuffer(0) }),
  WebSocket: class { constructor() { this.readyState = 0; } send() {} close() {} },
  Audio: class { constructor() { this.volume = 1; } play() { return Promise.resolve(); } pause() {} load() {} cloneNode() { return new sandbox.Audio(); } addEventListener() {} },
  AudioContext: class { constructor() { this.state = 'suspended'; this.destination = {}; } resume() { return Promise.resolve(); } createOscillator() { return { connect() {}, start() {}, stop() {}, frequency: { value: 0 } }; } createGain() { return { connect() {}, gain: { value: 0, setValueAtTime() {}, exponentialRampToValueAtTime() {} } }; } },
  Notification: class { static requestPermission() { return Promise.resolve('denied'); } constructor() {} close() {} },
  MutationObserver: class { observe() {} disconnect() {} takeRecords() { return []; } },
  ResizeObserver: class { observe() {} disconnect() {} unobserve() {} },
  IntersectionObserver: class { observe() {} disconnect() {} unobserve() {} },
  PerformanceObserver: class { observe() {} disconnect() {} },
  Event: class { constructor(t) { this.type = t; } preventDefault() {} stopPropagation() {} },
  CustomEvent: class { constructor(t, o) { this.type = t; this.detail = o && o.detail; } preventDefault() {} stopPropagation() {} },
  KeyboardEvent: class { constructor(t, o) { Object.assign(this, o || {}); this.type = t; } },
  URL, URLSearchParams, TextEncoder, TextDecoder, Blob: class { constructor(parts, opts) { this.parts = parts; this.type = (opts && opts.type) || ''; } },
  File: class {}, FileReader: class { readAsDataURL() {} readAsArrayBuffer() {} addEventListener() {} },
  FormData: class { append() {} },
  XMLHttpRequest: class { open() {} send() {} setRequestHeader() {} addEventListener() {} abort() {} upload = { addEventListener() {} }; },
  Image: class { constructor() { this.onload = null; this.onerror = null; } set src(_) {} },
  crypto: require('crypto').webcrypto,
  performance: { now: () => Date.now(), mark() {}, measure() {} },
  structuredClone: v => JSON.parse(JSON.stringify(v)),
  requestIdleCallback: cb => { rafQueue.push(cb); return 0; },
  cancelIdleCallback: () => {},
  getSelection: () => ({ toString: () => '', removeAllRanges() {}, rangeCount: 0 }),
  speechSynthesis: { speak() {}, cancel() {}, getVoices: () => [] },
  CSS: { escape: s => String(s), supports: () => false },
  DOMParser: class { parseFromString() { return documentStub; } },
  Worker: class { postMessage() {} terminate() {} addEventListener() {} },
  btoa: s => Buffer.from(String(s), 'binary').toString('base64'),
  atob: s => Buffer.from(String(s), 'base64').toString('binary'),
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
sandbox.self = sandbox;
sandbox.top = sandbox;
sandbox.parent = sandbox;
sandbox.addEventListener = () => {};
sandbox.removeEventListener = () => {};
sandbox.dispatchEvent = () => true;

vm.createContext(sandbox);

/* Epilogue runs in the SAME script as app.js, so it can reach top-level let/const
 * bindings (ws, active, networks, …) that never land on globalThis. */
const EPILOGUE = `
;globalThis.__t = {
  setWs(v){ ws = v; },
  setSession(v){ sessionToken = v; },
  setUser(v){ currentUser = v; },
  setNetworks(v){ networks = v; },
  setActiveRaw(v){ active = v; },
  getActiveRaw(){ return active; },
  setQueryBufs(v){ queryBufs = v; },
  getBuffers(){ return buffers; },
  getPendingLogs(){ return _pendingLogs; },
  getPreviewAsked(){ return _msgsPreviewAsked; },
  wrapRender(counter){
    const orig = renderMessagesView;
    renderMessagesView = function(){ counter.n++; return orig.apply(this, arguments); };
  },
};
`;

try {
  vm.runInContext(SRC + '\n' + EPILOGUE, sandbox, { filename: 'app.js' });
} catch (e) {
  console.error('FATAL: app.js failed to evaluate in the harness sandbox:');
  console.error(e && e.stack || e);
  process.exit(1);
}

/* ─── Simulated server (mirrors src/main.rs ClientMessage::GetLogs exactly):
 *     always replies LogLines; case-sensitive log lookup; [] when missing. ── */

const NOW = Math.floor(Date.now() / 1000) - 120;
const serverLogs = {
  // Log files are keyed by the sender's ORIGINAL-CASE nick (read is case-sensitive).
  'net1|Frank': [],                                                              // no log file → read_logs → [] (union-merged lowercase row will miss anyway)
  'net1|Dave': [{ id: 9, ts: NOW, from: 'Dave', text: 'hello there', kind: 'privmsg' }],
};

const sends = Object.create(null);   // get_logs sends per conn/target
const replyQueue = [];               // log_lines events waiting to be delivered
let serverEnabled = true;
let vaultLocked = false;             // read_logs fails while locked → EMPTY reply

const fakeWs = {
  readyState: 1,
  send(s) {
    let o; try { o = JSON.parse(s); } catch { return; }
    if (o.type !== 'get_logs') return;   // preference flushes etc. are irrelevant here
    const key = o.conn_id + '/' + o.target;
    sends[key] = (sends[key] || 0) + 1;
    if (!serverEnabled) return;
    // Pseudo conn_ids fail owns_network → main.rs returns WITHOUT replying, which
    // is exactly what strands the client's _pendingLogs key.
    if (o.conn_id.startsWith('__')) return;
    // Vault locked: the reply still arrives, but read_logs can't decrypt →
    // unwrap_or_default → lines: [].
    const lines = vaultLocked ? [] : (serverLogs[o.conn_id + '|' + o.target] || []).slice(-(o.limit || 200));
    replyQueue.push({ type: 'log_lines', conn_id: o.conn_id, target: o.target, lines });
  },
  close() {},
};

const flush = async () => { for (let i = 0; i < 4; i++) await new Promise(r => setTimeout(r, 1)); };

/* ─── Scenario ──────────────────────────────────────────────────────────────── */

const renders = { n: 0 };
const failures = [];
const ok = (cond, name, detail) => {
  const line = `${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`;
  console.log(line);
  if (!cond) failures.push(name);
};

// Deliver queued log_lines replies through the REAL handleEvent until quiescence.
// Each pump asserts convergence: if any phase re-introduces the fetch↔render loop,
// its pump hits MAX_CYCLES and fails here.
async function pump(tag, maxCycles = 40) {
  let c = 0;
  while (replyQueue.length && c < maxCycles) {
    c++;
    sandbox.handleEvent(replyQueue.shift());
    await flush();
  }
  ok(c < maxCycles && replyQueue.length === 0,
    `Q(${tag}) request/response pump reaches quiescence`,
    `cycles=${c}/${maxCycles}, queue=${replyQueue.length}`);
  return c;
}

(async () => {
  const t = sandbox.__t;
  t.wrapRender(renders);
  t.setSession('harness-token');
  t.setUser('me');
  t.setWs(fakeWs);
  t.setNetworks([{ config: { id: 'net1', label: 'TestNet', server: 'irc.test' }, channels: [], connected: true, nick: 'me' }]);
  // frank: union-merged row (lowercased display — v0.4.2 restorePreferences fallback
  //        queryBufs[c].set(e[0], e[0])); its case-sensitive log read returns [].
  // Dave : normal row with a server-side log line → preview must load.
  t.setQueryBufs({ net1: new Map([['frank', 'frank'], ['dave', 'Dave']]) });
  t.setActiveRaw({ conn_id: '__msgs', target: '__messages' });   // Messages inbox open

  // ── Phase 1: open the inbox, then pump request→response cycles to quiescence ──
  sandbox.renderMessagesView();
  await flush();

  const MAX_CYCLES = 40;
  let cycles = 0;
  while (replyQueue.length && cycles < MAX_CYCLES) {
    cycles++;
    const ev = replyQueue.shift();
    sandbox.handleEvent(ev);       // the REAL 'log_lines' switch case → prependLogs
    await flush();
  }
  const frankSends = sends['net1/frank'] || 0;
  const daveSends = sends['net1/Dave'] || 0;   // fetched by original-case display (matches server log filename)

  ok(cycles < MAX_CYCLES && replyQueue.length === 0,
    'R0 fetch/render pump reaches quiescence',
    `cycles=${cycles}/${MAX_CYCLES}, queue=${replyQueue.length}`);
  ok(frankSends <= 3,
    'R1 empty-log conversation is not re-fetched in a loop',
    `get_logs sends for net1/frank = ${frankSends}`);
  ok(renders.n <= 8,
    'R2 inbox renders are bounded (no flicker storm)',
    `renderMessagesView invocations = ${renders.n}`);

  // ── Phase 2: green guards — previews must still work after any fix ──
  const daveBuf = t.getBuffers()['net1/dave'] || [];
  ok(daveBuf.length === 1 && daveBuf[0].text === 'hello there',
    'G1 preview fetch fills the conversation buffer',
    `net1/dave buffer len=${daveBuf.length}`);
  ok(daveSends === 1,
    'G2 logged conversation fetched exactly once',
    `get_logs sends for net1/dave = ${daveSends}`);

  // Render once more (as the preferences-sync handler does) and inspect the DOM.
  const rendersBefore = renders.n;
  sandbox.renderMessagesView();
  await flush();
  const chatArea = documentStub.getElementById('chat-area');
  const previews = [];
  (function walk(el) {
    if (!el || !el.__el) return;
    if (el.className === 'msgs-preview') previews.push(el.textContent);
    (el.children || []).forEach(walk);
  })(chatArea);
  ok(previews.some(p => p.includes('hello there')),
    'G3 rendered inbox shows the fetched preview text',
    `previews=${JSON.stringify(previews)}`);
  ok(previews.length === 2,
    'G4 both conversations render as rows',
    `row previews found = ${previews.length}`);

  // External re-renders (preferences sync storms) must not grow fetch traffic
  // without bound: the answered-empty conversation stays answered.
  const frankBefore = sends['net1/frank'] || 0;
  sandbox.renderMessagesView(); await flush();
  sandbox.renderMessagesView(); await flush();
  const frankGrowth = (sends['net1/frank'] || 0) - frankBefore;
  ok(frankGrowth <= 1,
    'G5 external re-renders do not refetch an answered-empty conversation unboundedly',
    `extra frank sends across 2 external renders = ${frankGrowth} (renders after G3: ${renders.n - rendersBefore})`);

  // ── Phase 3: pseudo-view targets must not leak into IRC-buffer plumbing ──
  const junkBefore = sends['__msgs/__messages'] || 0;
  sandbox._syncActiveChannel();          // fires every 5s + on every click in prod
  await flush();
  ok((sends['__msgs/__messages'] || 0) === junkBefore,
    'R3 _syncActiveChannel sends no get_logs for the __msgs pseudo-view',
    `junk sends = ${(sends['__msgs/__messages'] || 0)}`);

  const junkBefore2 = sends['__msgs/__messages'] || 0;
  sandbox._onResume();                   // fires on every focus/visibility/pageshow
  await flush();
  ok((sends['__msgs/__messages'] || 0) === junkBefore2,
    'R4 _onResume sends no get_logs for the __msgs pseudo-view',
    `junk sends = ${(sends['__msgs/__messages'] || 0)}`);

  // ── Phase 4: 'state' handler PM-fallback must skip pseudo-views (follow-up 1) ──
  // With the inbox active, the state handler's "load active PM" fallback used to
  // fire get_logs {__msgs/__messages}; main.rs drops it (owns_network fails) with
  // NO reply, stranding the _pendingLogs key until the next reconnect.
  const stateNetworks = [{ config: { id: 'net1', label: 'TestNet', server: 'irc.test' }, channels: [], connected: true, nick: 'me' }];
  const junkBefore3 = sends['__msgs/__messages'] || 0;
  sandbox.handleEvent({ type: 'state', networks: stateNetworks, vault_unlocked: true });
  await flush(); await pump('state-inbox-active');
  ok((sends['__msgs/__messages'] || 0) === junkBefore3,
    'R5 state-handler PM fallback sends no get_logs for the __msgs pseudo-view',
    `junk sends = ${(sends['__msgs/__messages'] || 0)}`);
  ok(!t.getPendingLogs().has('__msgs/__messages'),
    'R6 no stranded __msgs/__messages key in _pendingLogs after a state event',
    `pending keys = ${JSON.stringify([...t.getPendingLogs().keys()])}`);

  // Green guard: a REAL PM with an empty buffer must still get the fallback load
  // (the pseudo-view guard must not swallow it).
  t.setActiveRaw({ conn_id: 'net1', target: 'Zoe' });
  sandbox.handleEvent({ type: 'state', networks: stateNetworks, vault_unlocked: true });
  await flush(); await pump('state-real-pm');
  ok((sends['net1/Zoe'] || 0) === 1,
    'G6 state-handler PM fallback still loads a real PM buffer',
    `get_logs sends for net1/Zoe = ${sends['net1/Zoe'] || 0}`);
  t.setActiveRaw({ conn_id: '__msgs', target: '__messages' });   // back to the inbox

  // ── Phase 5: previews burned while the vault was LOCKED retry after unlock
  //    (follow-up 2, unlocking socket: vault_unlocked event) ──
  // Locked-vault GetLogs still replies, but read_logs can't decrypt →
  // unwrap_or_default → EMPTY lines: the reply consumes the _pendingLogs key and
  // burns the once-per-connection _msgsPreviewAsked slot.
  serverLogs['net1|Grace'] = [{ id: 11, ts: NOW + 60, from: 'Grace', text: 'vault says hi', kind: 'privmsg' }];
  t.setQueryBufs({ net1: new Map([['frank', 'frank'], ['dave', 'Dave'], ['grace', 'Grace']]) });
  sandbox.handleEvent({ type: 'state', networks: stateNetworks, vault_unlocked: false });   // overlay up
  await flush();
  vaultLocked = true;
  const frankAtLock = sends['net1/frank'] || 0;
  sandbox.renderMessagesView();                    // inbox rendered behind the overlay
  await flush(); await pump('locked-previews');
  ok((sends['net1/Grace'] || 0) === 1
      && (t.getBuffers()['net1/grace'] || []).length === 0
      && t.getPreviewAsked().has('net1/Grace'),
    'R7 locked-vault preview asked once, got empty reply, burned its slot (no loop)',
    `Grace sends=${sends['net1/Grace'] || 0}, buf=${(t.getBuffers()['net1/grace'] || []).length}`);

  vaultLocked = false;                             // server-side unlock happens…
  sandbox.handleEvent({ type: 'vault_unlocked', e2e_enc_key: '' });   // …and THIS socket gets the event
  const clearedOnUnlock = t.getPreviewAsked().size === 0;             // synchronous reset, before the repaint re-asks
  await flush(); await pump('unlock-refetch');
  const graceBuf = t.getBuffers()['net1/grace'] || [];
  ok(clearedOnUnlock && (sends['net1/Grace'] || 0) === 2 && graceBuf.length === 1 && graceBuf[0].text === 'vault says hi',
    'G7 vault_unlocked clears the preview guard and the preview refetches + fills',
    `cleared=${clearedOnUnlock}, Grace sends=${sends['net1/Grace'] || 0}, buf=${graceBuf.length}`);
  ok(((sends['net1/frank'] || 0) - frankAtLock) <= 1,
    'R8 unlock retries a still-empty conversation at most ONCE (no loop resumes)',
    `extra frank sends across lock+unlock = ${(sends['net1/frank'] || 0) - frankAtLock}`);

  // ── Phase 6: cross-session unlock arrives as State{vault_unlocked:true} only
  //    (main.rs sends vault_unlocked solely to the unlocking socket) ──
  serverLogs['net1|Heidi'] = [{ id: 12, ts: NOW + 90, from: 'Heidi', text: 'cross-device hello', kind: 'privmsg' }];
  t.setQueryBufs({ net1: new Map([['frank', 'frank'], ['dave', 'Dave'], ['grace', 'Grace'], ['heidi', 'Heidi']]) });
  sandbox.handleEvent({ type: 'state', networks: stateNetworks, vault_unlocked: false });   // locked again
  await flush();
  vaultLocked = true;
  sandbox.renderMessagesView();
  await flush(); await pump('locked-previews-2');
  const heidiAskedLocked = sends['net1/Heidi'] || 0;
  vaultLocked = false;
  sandbox.handleEvent({ type: 'state', networks: stateNetworks, vault_unlocked: true });    // the ONLY unlock signal here
  const clearedOnState = t.getPreviewAsked().size === 0;
  await flush(); await pump('state-unlock-refetch');
  const heidiBuf = t.getBuffers()['net1/heidi'] || [];
  ok(heidiAskedLocked === 1 && clearedOnState && (sends['net1/Heidi'] || 0) === 2 && heidiBuf.length === 1,
    'G8 cross-session unlock via state event also resets the guard and refetches',
    `lockedAsks=${heidiAskedLocked}, cleared=${clearedOnState}, Heidi sends=${sends['net1/Heidi'] || 0}, buf=${heidiBuf.length}`);

  console.log('');
  if (failures.length) {
    console.log(`RESULT: FAIL (${failures.length} failing: ${failures.join(', ')})`);
    process.exit(1);
  } else {
    console.log('RESULT: PASS (all assertions green)');
    process.exit(0);
  }
})().catch(e => {
  console.error('FATAL: harness scenario crashed:');
  console.error(e && e.stack || e);
  process.exit(1);
});
