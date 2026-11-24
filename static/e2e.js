/**
 * CryptIRC E2E Encryption Engine  (e2e.js)
 *
 * DMs:      X3DH key agreement → Double Ratchet (Signal protocol)
 * Channels: Pre-shared key (AES-256-GCM)
 *
 * All crypto runs in the browser via WebCrypto (SubtleCrypto).
 *
 * 2026-11-01 audit fix pass (C1/C2/H5/H6 + MEDIUMs):
 *   C1 — the browser wraps its storage master key with a generated recovery code.
 *        Only the wrapped keyring is synced. Vault credentials are used solely to
 *        open pre-upgrade keyrings. The browser caches non-extractable CryptoKeys
 *        in IndexedDB and binds stored blobs to their slots with AEAD.
 *   C2 — a changed identity key never overwrites the pin; the peer stays "changed"
 *        (warned on every message, new key not used for encrypt or decrypt) until
 *        the user runs /encrypt accept (fingerprints shown) or /encrypt reject.
 *   H5 — nothing unauthenticated can delete a live session; whenever E2E is on for a
 *        target but no usable key/session exists, sends are BLOCKED (never cleartext)
 *        and the lock icon shows the blocked state.
 *   H6 — every E2E PRIVMSG fits the 512-byte IRC line (incl. the server-added
 *        :nick!user@host prefix): the X3DH header is relayed by the server AND sent
 *        inline split into [e2ex3dh]~id~i~n~ fragments (reassembled with caps/TTL);
 *        long messages are split into independently-encrypted pieces. The old
 *        single-line header is still accepted.
 *   M  — sessions + trust pins are restored on reload from an authenticated state
 *        blob; epochs are persistent (rollback/replay of stale blobs refused); PSK
 *        blobs carry a generation (no post-rotation resurrection) and a server can't
 *        delete keys by pushing a short channel list; unsolicited identity blobs are
 *        ignored and a failed identity load never silently regenerates; lookups are
 *        case-insensitive everywhere; /encrypt trust needs a live session + confirm;
 *        simultaneous /encrypt on (glare) resolves deterministically.
 */

'use strict';

// ─── Constants ────────────────────────────────────────────────────────────────

// E2E protocol v2 marker (audit #26/#81/#3/#24/#25/#29). v2 changes the message-key
// KDF to the Signal-spec KDF_CK (HMAC(CK,0x01)/HMAC(CK,0x02)) and prepends the X3DH F
// constant, so v1 ([e2edm1]) sessions cannot continue and peers transparently
// re-establish a fresh session on first contact (a one-time re-encrypt).
const E2E_DM_PREFIX     = '[e2edm2]';   // ASCII-only — safe through all IRC servers
const E2E_CHAN_PREFIX    = 'sd8~';       // ASCII-only
const E2E_HDR_PREFIX    = '[e2ex3dh]';  // single-line X3DH header (legacy senders)
const E2E_HDR_FRAG      = '[e2ex3dh]~'; // H6: fragmented header ([e2ex3dh]~id~i~n~data)
const E2E_MAX_SKIP      = 100;   // max buffered out-of-order message keys per session
const OTPK_REFILL_BELOW = 10;   // replenish when server reports fewer than this (L5)
const OTPK_BATCH_SIZE   = 20;   // keys generated per replenishment batch
// C1: blob / keyring format + browser KDF.
const E2E_STORAGE_VERSION = 3;
const E2E_BLOB_PREFIX    = 'e2e3.';
const E2E_KEYRING_PREFIX = 'e2k3.';
const E2E_V2_BLOB       = 'e2e2.';
const E2E_V2_KEYRING    = 'e2k2.';
const E2E_KDF_ITER      = 600000;    // legacy v2 PBKDF2-SHA256 iterations
const E2E_IDB_NAME       = 'cryptirc-e2e';  // IndexedDB db (wiped with other cryptirc* storage on logout)
const E2E_IDB_STORE      = 'keys';
// H6: IRC line budget. 512 bytes incl. CRLF; the server prepends ":nick!user@host
// PRIVMSG <target> :" when relaying. Fixed part = ':' '!' user(<=11) '@' host(<=64)
// ' PRIVMSG ' ' :' CRLF = 91 bytes, plus 62 bytes of slack for oversized cloaks/idents.
// Our nick and the target are added per message.
// r9 (astra-p2 irc.rs:945): the server now refuses an encrypted line that does not fit what
// the recipients receive, counting the user@host it learned (up to 128 bytes) plus a 10-byte
// margin — the slack (50 before) covers that, so a line sized here is never refused for it.
const E2E_IRC_LINE_MAX         = 512;
const E2E_LINE_FIXED_OVERHEAD  = 153;
// #F4: distinguished return from e2eEncryptOutgoing meaning "E2E is ON for this target
// but it cannot be used right now" (no send chain yet, session lost, key changed and
// unaccepted, PSK removed remotely, E2E locked on this device...). Callers MUST treat
// this as BLOCKED: drop the outbound message and warn — NEVER fall back to sending
// plaintext. It is a frozen sentinel so it can never collide with a real (string) wire
// payload or the null "no E2E → plaintext" result; identify it by strict === or the
// duck-typed marker `.e2eBlocked === true`. The human-readable reason for the latest
// block is in E2E.lastBlockReason.
const E2E_ENCRYPT_BLOCKED = Object.freeze({ e2eBlocked: true });
// #81: X3DH "F" domain-separation constant — 32 bytes of 0xFF prepended to the IKM
// before the X3DH KDF, per the Signal X3DH spec. Applied at both X3DH call sites.
const X3DH_F_CONSTANT   = new Uint8Array(32).fill(0xFF);

// ─── Case-insensitive maps ────────────────────────────────────────────────────
// IRC nicks/channels are case-insensitive. Every E2E map is keyed by the lowercased
// name and these Proxies lowercase on every access, so `E2E.channelKeys['#Secret']`
// and `E2E.dmSessions.Alice` (incl. app.js's direct lookups) hit the same entry the
// lock icon reports — the encrypt path can no longer miss a key the icon shows.
function _e2eK(name) { return String(name == null ? '' : name).toLowerCase(); }
function _e2eIsChan(t) { return /^[#&+!]/.test(String(t || '')); }
function _e2eCiMap() {
  const n = (k) => (typeof k === 'string' ? k.toLowerCase() : k);
  return new Proxy(Object.create(null), {
    get: (o, k) => o[n(k)],
    set: (o, k, v) => { o[n(k)] = v; return true; },
    has: (o, k) => n(k) in o,
    deleteProperty: (o, k) => { delete o[n(k)]; return true; },
    getOwnPropertyDescriptor: (o, k) => Object.getOwnPropertyDescriptor(o, n(k)),
    defineProperty: (o, k, d) => Reflect.defineProperty(o, n(k), d),
  });
}

// ─── r3 (codex-p3 HIGH e2e.js:2816): other spellings of an E2E target ─────────
// The maps above fold case with toLowerCase only, but an IRC network folds names
// under its CASEMAPPING (RFC1459: `[]\~` are the upper case of `{}|^`, so #foo[ and
// #foo{ are ONE channel), and a message can reach a conversation under another name:
// STATUSMSG (`@#chan` = the ops of #chan) or `nick!user@host` / `nick@server`. Such a
// spelling used to find no E2E state and went out in cleartext. Now every E2E decision
// first resolves the target: the exact (lowercased) name when E2E knows it, else the
// ONE known name equal to it under RFC1459 rules (the widest fold); a STATUSMSG /
// nick!user@host form of an E2E target is BLOCKED (it can't be encrypted for a part of
// the channel / that form). CASEMAPPING and STATUSMSG come from the network's 005
// (app.js _sniffIsupport) — i.e. from the server, so they may only ever make this
// STRICTER (security review of r3): a mapping narrower than RFC1459 never lets a
// fold-sibling of an E2E name through as cleartext (it is blocked as ambiguous), and
// the server's STATUSMSG only ADDS prefix characters to the default set.
function _e2eIsupport(cid) {
  try { if (cid && typeof _isupport !== 'undefined' && _isupport && typeof _isupport === 'object') return _isupport[cid] || null; } catch (_) {}
  return null;
}
// 'ascii' / 'strict-rfc1459' only when the network explicitly says so; anything else —
// rfc1459, unknown values (rfc7613, precis, …), empty, not seen yet — is RFC1459.
function _e2eCaseMap(cid) {
  const i = _e2eIsupport(cid);
  const c = i && typeof i.casemapping === 'string' ? i.casemapping.trim().toLowerCase() : '';
  if (c === 'ascii' || c === 'strict-rfc1459') return c;
  return 'rfc1459';
}
function _e2eFold(name, cm) {
  let s = _e2eK(name);
  if (cm === 'ascii') return s;
  s = s.replace(/\[/g, '{').replace(/\]/g, '}').replace(/\\/g, '|');
  return cm === 'strict-rfc1459' ? s : s.replace(/~/g, '^');
}
// The PSK sender binding's channel fold (r3 wire form — kept as is, so r3-era bindings
// keep verifying).
function _e2eFoldAll(name) { return _e2eFold(name, 'rfc1459'); }
// r4 (verifier w3-web N2, integrator decision: fail closed): "RFC1459 is the widest fold"
// is false on CASEMAPPING=rfc8265 / precis networks (e.g. Ergo `casemapping: precis`),
// which also equate fullwidth letters (ｓｅｃ = sec), compatibility characters and
// decomposed accents (NFD café = NFC café). Deciding "which E2E name does this target
// stand for" therefore compares under NFKC + Unicode lowercase + the RFC1459 specials.
// Over-matching here only ever leads to an encrypted send or a refusal (see _e2eCanon),
// never to cleartext. Exact fold — the server's outdated-tab guard (main.rs e2e_fold_all
// = irc_lower(to_lowercase(NFKC(s)))) applies the same, so both sides agree:
//   NFKC → Unicode lowercase → [ { , ] } , \ | , ~ ^
// This fold is for OUTGOING / "is this an E2E target" decisions only. Incoming senders
// are resolved under the network's real casemapping (_e2eRecvName, SEC-HOOK-W1).
function _e2eNfkc(s) { try { return String(s).normalize('NFKC'); } catch (_) { return String(s); } }
function _e2eFoldWide(name) {
  return _e2eNfkc(name == null ? '' : name).toLowerCase()
    .replace(/\[/g, '{').replace(/\]/g, '}').replace(/\\/g, '|').replace(/~/g, '^');
}
const E2E_STATUSMSG_DEFAULT = '~&@%+';
function _e2eStatusMsgChars(cid) {
  const i = _e2eIsupport(cid);
  const v = i && typeof i.statusmsg === 'string' ? i.statusmsg.replace(/[\s#]/g, '').slice(0, 32) : '';
  let out = E2E_STATUSMSG_DEFAULT;
  for (const ch of v) if (!out.includes(ch)) out += ch;
  return out;
}
// Every name E2E holds any state for (keys, sessions, on/off entries, hints, pending).
function _e2eKnownNames() {
  const out = new Set();
  const add = (a) => { for (const n of (a || [])) if (n) out.add(_e2eK(n)); };
  try {
    add(Object.keys(E2E.channelKeys)); add(Object.keys(E2E.dmSessions)); add(Object.keys(E2E.chanRemoved));
    if (E2E.state) { add(Object.keys(E2E.state.dm || {})); add(Object.keys(E2E.state.ch || {})); }
    const h = _e2eHints(); add(h.dm); add(h.ch);
    const sh = E2E._serverHints; if (sh) { add(sh.peers); add(sh.channels); }
    if (E2E._pendingOn) add(Object.keys(E2E._pendingOn));
  } catch (_) {}
  return out;
}
// The E2E name `target` stands for on connection `cid` (lowercased), or null = BLOCK:
// it is RFC1459-fold-equal to several E2E names, or to one that the network's
// advertised (narrower) CASEMAPPING says is a different name — the client can't verify
// the server's casemapping, and refusing is cheaper than a leak.
function _e2eCanon(target, cid) {
  const t = _e2eK(target);
  const known = _e2eKnownNames();
  if (known.has(t)) return t;                  // the exact name wins
  // r4 (N2): the widest fold (_e2eFoldWide), also for names without RFC1459 specials —
  // a fullwidth / NFD / compatibility spelling of an E2E name is that name too.
  const fr = _e2eFoldWide(t);
  const sib = [...known].filter(n => _e2eFoldWide(n) === fr);
  if (!sib.length) return t;                   // no E2E name it could be
  if (sib.length > 1) return null;
  const cm = _e2eCaseMap(cid);
  if (cm !== 'rfc1459' && _e2eFold(sib[0], cm) !== _e2eFold(t, cm)) return null;
  return sib[0];
}
// The E2E conversations a target reaches under ANOTHER form: the channel behind
// STATUSMSG prefix(es), the nick of nick!user@host / nick@server / nick%host.
function _e2eAliasesOf(target, cid) {
  // r4 (N2): NFKC first, so a fullwidth ＠ / ！ etc. is recognised like @ / ! (over-
  // matching only refuses more).
  const t = _e2eNfkc(String(target || '')), out = [];
  const sm = _e2eStatusMsgChars(cid);
  let s = t;
  while (s.length > 1 && sm.includes(s[0])) { s = s.slice(1); if (_e2eIsChan(s)) out.push(s); }
  if (!_e2eIsChan(t) && t[0] !== '$') { const m = /^([^!@%]+)[!@%]/.exec(t); if (m) out.push(m[1]); }
  return out;
}

// r4 (SEC-HOOK-W1, integrator decision): the resolution rule is ASYMMETRIC.
//  - OUTGOING / "is this an E2E target" / input-history filter: the WIDEST fold
//    (_e2eCanon / _e2eFoldWide, ISUPPORT may only make it stricter) — over-matching there
//    only means refusing or encrypting more, never cleartext.
//  - INCOMING sender (or channel) → E2E name: only the network's REAL casemapping as
//    learned from its 005 (app.js _sniffIsupport): rfc1459 / strict-rfc1459 as stated,
//    NFKC + Unicode lowercase only on a network that advertises rfc8265 (PRECIS), and
//    ascii (case only) when the mapping is unknown or anything else. Over-matching here
//    would be identity confusion: on an ascii network `bob{x}` and `bob[x]`, and on a
//    non-PRECIS network `ｂｏｂ` and `bob`, are DIFFERENT users. A remapped sender is
//    still displayed under the nick it actually used, and may only use the EXISTING
//    session of the peer it maps to: it never starts or replaces a session (X3DH headers
//    are always handled under the exact spelling, so a new identity goes through the
//    normal TOFU question for that exact nick and a pinned identity is never replaced
//    silently).
// r4 (verifier w3-web N2): Ergo with `casemapping: precis` advertises CASEMAPPING=ascii
// PLUS UTF8MAPPING=rfc8265 (the IRCv3 UTF8MAPPING token): it enforces nick/channel
// uniqueness under PRECIS, so that is the network's real rule → 'precis' (NFKC +
// lowercase) when CASEMAPPING is ascii or not stated and UTF8MAPPING is rfc8265/rfc7613.
// An unknown UTF8MAPPING value changes nothing (stays ascii).
function _e2eRecvCaseMap(cid) {
  const i = _e2eIsupport(cid);
  const c = i && typeof i.casemapping === 'string' ? i.casemapping.trim().toLowerCase() : '';
  const u = i && typeof i.utf8mapping === 'string' ? i.utf8mapping.trim().toLowerCase() : '';
  if (c === 'rfc1459') return 'rfc1459';
  if (c === 'strict-rfc1459' || c === 'rfc1459-strict') return 'strict-rfc1459';
  if (c === 'rfc8265' || c === 'rfc7613' || c === 'precis') return 'precis';
  if ((c === '' || c === 'ascii') && (u === 'rfc8265' || u === 'rfc7613')) return 'precis';
  return 'ascii';
}
function _e2eRecvFold(name, cm) {
  const s0 = String(name == null ? '' : name);
  if (cm === 'precis') return _e2eNfkc(s0).toLowerCase();
  let s = s0.replace(/[A-Z]/g, (c) => c.toLowerCase());
  if (cm === 'ascii') return s;
  s = s.replace(/\[/g, '{').replace(/\]/g, '}').replace(/\\/g, '|');
  return cm === 'strict-rfc1459' ? s : s.replace(/~/g, '^');
}
// The E2E name an INCOMING sender / channel `name` is on connection `cid`: the exact
// (lowercased) name when E2E knows it, else the ONE known name equal to it under the
// network's real casemapping, else the exact name (a different peer — never a block).
function _e2eRecvName(name, cid) {
  const t = _e2eK(name);
  const known = _e2eKnownNames();
  if (known.has(t)) return t;
  const cm = _e2eRecvCaseMap(cid);
  const f = _e2eRecvFold(name, cm);
  const sib = [...known].filter((n) => _e2eRecvFold(n, cm) === f);
  return sib.length === 1 ? sib[0] : t;
}
// r5 (security review of r5/web): the E2E name a KEY COMMAND acts on — /encrypt keygen /
// add / rotate / off / share and the encryption panel's Copy Key. These write, delete or
// disclose a key, so they resolve under the network's REAL rule (_e2eRecvCaseMap, as for
// incoming senders), never under the wide send-path fold: on an ascii / rfc1459 network
// #ｓｅｃ is a different channel than #sec and must not overwrite, remove or hand out
// #sec's key. (The send path keeps the wide fold: there it can only encrypt or refuse.)
//   { name }       act on `name` (the window's own spelling, lowercased)
//   { name, ask }  `name` is stored under ANOTHER spelling (the same conversation under
//                  the network's rule), or E2E's lowercased key slot may stand for a
//                  different conversation here — the caller asks the user first
//   { refuse }     another E2E name looks alike but is a different conversation under
//                  the network's rule (or several names match) — nothing is done
function _e2eKeyCmdName(target, cid) {
  const raw = String(target == null ? '' : target);
  const t = _e2eK(raw);
  const known = _e2eKnownNames();
  const cm = _e2eRecvCaseMap(cid);
  const f = _e2eRecvFold(raw, cm);
  const rules = cm === 'precis' ? 'PRECIS' : cm;
  if (known.has(t)) {
    if (_e2eRecvFold(t, cm) === f) return { name: t };
    // E2E's maps fold with toLowerCase, which also merges non-ASCII letter case
    // (#École / #école) — different conversations on a non-PRECIS network.
    return { name: t, ask: `🔐 ${raw} and ${t} share one E2E key slot, but under this network's case rules (${rules}) they can be DIFFERENT conversations.` };
  }
  const real = [...known].filter((n) => _e2eRecvFold(n, cm) === f);
  if (real.length > 1) return { refuse: `🔐 ${raw} matches several E2E conversations (${real.join(', ')}) under this network's case rules (${rules}) — nothing was done; use the exact name.` };
  if (real.length === 1) return { name: real[0], ask: `🔐 Under this network's case rules (${rules}) ${raw} is the same conversation as ${real[0]}, whose E2E key is stored under that spelling.` };
  const fw = _e2eFoldWide(t);
  const wide = [...known].filter((n) => _e2eFoldWide(n) === fw);
  if (wide.length) return { refuse: `🔐 ${raw} looks like ${wide.join(', ')} but is a DIFFERENT conversation under this network's case rules (${rules}) — nothing was done for ${raw}, and the key of ${wide.join(', ')} was not used.` };
  return { name: t };
}
// The question for { ask } above (the in-app dialog when app.js is there).
async function _e2eKeyCmdConfirm(msg, okLabel) {
  try {
    if (typeof customConfirm === 'function' && typeof document !== 'undefined' && document && document.body) return !!(await customConfirm(msg, okLabel || 'Continue', 'Cancel'));
    if (typeof confirm === 'function') return !!confirm(msg);
  } catch (_) {}
  return false;
}

// ─── State ────────────────────────────────────────────────────────────────────

window.E2E = {
  storageVersion: E2E_STORAGE_VERSION,
  // app.js gates every send on `E2E.ready || E2E.channelKeys[target]` before calling
  // e2eEncryptOutgoing. That gate used to let sends to an E2E target go out in
  // cleartext whenever the identity wasn't loaded yet. e2eEncryptOutgoing must see
  // every outgoing message so it can BLOCK those (it returns null — plaintext — for
  // targets that never had E2E), so `ready` is now always true for that gate. The
  // real readiness flags are keyReady / identityReady.
  get ready() { return true; },
  keyReady:      false,     // C1: the E2E master key (e2eEncKey) is available on this device
  identityReady: false,     // identity keys loaded/created (was `ready`, C6)
  e2eEncKey:    null,       // CryptoKey (AES-256-GCM, non-extractable): client-held master key
  _legacyKey:   null,       // CryptoKey: pre-upgrade server-derived key (read + re-wrap only)
  _pepper:      null,       // base64 pepper from the last passphrase-proven unlock (memory only)
  identityKeys: null,       // { dhKeyPair, signKeyPair }
  dmSessions:   _e2eCiMap(),   // nick → DoubleRatchetSession
  channelKeys:  _e2eCiMap(),   // channel/nick → CryptoKey (AES-256-GCM PSK)
  trustStore:   _e2eCiMap(),   // nick → { fingerprint, verified, keyChanged, pendingFingerprint, server_seeded }
  chanRemoved:  _e2eCiMap(),   // channel → true when the server's key list dropped a key we hold
  _spkBlob:     null,       // raw encrypted SPK blob (set when server sends it)
  _encryptLock: Object.create(null),  // nick → Promise chain (S3: serialise ALL per-session ratchet ops)
  _sessionEpoch: Object.create(null), // nick → monotonic epoch high-water mark (persisted, see saveSession)
  _chanGen:     Object.create(null),  // channel → PSK generation in use
  state: null,              // authenticated state blob (trust pins, enabled targets, PSK gens)
  lastBlockReason: null,
  _bootChain: Promise.resolve(),
  _pageStart: Date.now(),   // r2: see the "recent" message keys (_ratchetDecryptInner)
  // r4 (C3-1): set true by the LAST statement of this file. While false, app.js treats
  // the engine as not loaded (fail closed: no e2e:2, no chat sends) — a top-level
  // exception between here and the end left it half set up.
  _engineLoaded: false,
  _lockGen: 0,              // r4 (N7): +1 on every lock / session end (see _e2eLockedMeanwhile)
  _serverLocked: false,     // r4 (N6): the SERVER vault is locked (not just this device)
  _chanKeyGen:  Object.create(null),  // r6: channel → generation of the key INSTALLED here
  _resyncPending: false,    // r6: reconnected — E2E state not re-checked with the server yet
};

// ─── Small helpers ────────────────────────────────────────────────────────────

function _e2eUser() {
  try { if (typeof currentUser !== 'undefined' && currentUser) return String(currentUser); } catch (_) {}
  return E2E._user || '';
}
function _e2eLsGet(key) {
  try { if (typeof localStorage === 'undefined') return null; const v = localStorage.getItem(key); return v ? JSON.parse(v) : null; }
  catch (_) { return null; }
}
function _e2eLsSet(key, val) {
  try { if (typeof localStorage !== 'undefined') localStorage.setItem(key, JSON.stringify(val)); } catch (_) {}
}
function _e2eLsDel(key) { try { if (typeof localStorage !== 'undefined') localStorage.removeItem(key); } catch (_) {} }
// Per-device, per-user local E2E bookkeeping (localStorage key starts with "cryptirc").
// Holds NO secrets: epoch / PSK-generation high-water marks and the latest encrypted
// state blob, so a server can't roll this device back to an older state.
function _e2eDevKey()  { return 'cryptirc_e2e_dev_'  + _e2eUser(); }
function _e2eHintKey() { return 'cryptirc_e2e_hint_' + _e2eUser(); }
// r2 (v-e2e NEW-2): this record is shared by every tab of the browser. It used to be
// read ONCE per page and written back whole, so a tab that booted earlier overwrote a
// newer tab's high-water marks / state copy (last writer wins). Now every read merges
// in what other tabs stored (monotonic: max per mark; the state copy with the higher
// seq), and every write merges again right before storing.
function _e2eDevMerge(dst, d) {
  if (!d || typeof d !== 'object') return dst;
  for (const [k, v] of Object.entries(d.ep || {})) if ((v | 0) > (dst.ep[k] | 0)) dst.ep[k] = v | 0;
  for (const [k, v] of Object.entries(d.gen || {})) if ((v | 0) > (dst.gen[k] | 0)) dst.gen[k] = v | 0;
  if ((d.seq | 0) > (dst.seq | 0)) { dst.seq = d.seq | 0; if (typeof d.st === 'string' && d.st) dst.st = d.st; }
  else if (!dst.st && typeof d.st === 'string') dst.st = d.st;
  return dst;
}
function _e2eDev() {
  if (!E2E._devCache || E2E._devCacheUser !== _e2eUser()) {
    E2E._devCache = { seq: 0, ep: Object.create(null), gen: Object.create(null), st: '' };
    E2E._devCacheUser = _e2eUser();
  }
  return _e2eDevMerge(E2E._devCache, _e2eLsGet(_e2eDevKey()));
}
function _e2eDevSave() { const d = _e2eDev(); _e2eLsSet(_e2eDevKey(), { seq: d.seq, ep: d.ep, gen: d.gen, st: d.st }); }
// Targets with E2E on (names only — so a page that can't unlock E2E yet still
// BLOCKS sends to them instead of leaking cleartext).
function _e2eHints() {
  const h = _e2eLsGet(_e2eHintKey()) || {};
  return { dm: Array.isArray(h.dm) ? h.dm : [], ch: Array.isArray(h.ch) ? h.ch : [] };
}
// r2 (NEW-2): union with what other tabs recorded; a name is only dropped when THIS
// state explicitly turned it off (tombstone) — never because another tab's (older)
// state simply did not know it.
function _e2eHintsRefresh() {
  const st = E2E.state; if (!st) return;
  const h = _e2eHints();
  const isOff = (m, k) => !!(m[k] && !m[k].on);
  const dm = new Set(h.dm.filter(k => !isOff(st.dm || {}, k)));
  const ch = new Set(h.ch.filter(k => !isOff(st.ch || {}, k)));
  for (const k of Object.keys(st.dm || {})) if (st.dm[k] && st.dm[k].on) dm.add(k);
  for (const k of Object.keys(st.ch || {})) if (st.ch[k] && st.ch[k].on) ch.add(k);
  _e2eLsSet(_e2eHintKey(), { dm: [...dm], ch: [...ch] });
}

// ─── r2: same-browser tab coordination (v-e2e NEW-7, codex-p3 MED e2e.js:1264) ────
// Every tab / pop-out window of one browser restores and uses the SAME DM ratchet. Each
// used to keep its own in-memory copy, so when two tabs sent, the second one's messages
// were undecryptable (the send chains forked) and whichever tab saved last decided
// what the next reload restored. Now:
//  - every ratchet operation runs under a browser-wide Web Lock per peer
//    (navigator.locks; same-origin tabs and windows share it), and
//  - starts by adopting the newest copy of that session another tab wrote to this
//    browser's IndexedDB (wrapped under the E2E master key, never sent anywhere), and
//    writes its own result there before the lock is released;
//  - the copy keeps the message keys of the last few decrypted messages, so a tab that
//    receives the same incoming line after another tab already advanced the ratchet
//    still shows it (once per tab — a re-sent copy is still refused as a replay).
// Without Web Locks (very old browsers) each tab still adopts a newer copy before
// every operation, which narrows but cannot close the race.
function _e2eDeviceId() {
  if (E2E._dv) return E2E._dv;
  let d = null;
  try { if (typeof localStorage !== 'undefined') d = localStorage.getItem('cryptirc_e2e_dv'); } catch (_) {}
  if (!d || !/^[a-z0-9]{12}$/.test(d)) {
    d = Array.from(crypto.getRandomValues(new Uint8Array(12)), b => 'abcdefghijklmnopqrstuvwxyz0123456789'[b % 36]).join('');
    try { if (typeof localStorage !== 'undefined') localStorage.setItem('cryptirc_e2e_dv', d); } catch (_) {}
  }
  return (E2E._dv = d);
}
function _e2eXLock(name, fn) {
  let L = null;
  try { if (typeof navigator !== 'undefined' && navigator && navigator.locks && typeof navigator.locks.request === 'function') L = navigator.locks; } catch (_) {}
  if (!L) return fn();
  return L.request('cryptirc-e2e:' + _e2eUser() + ':' + name, () => fn());
}
function _e2eDevSlot(nk) { return 'devsession\n' + nk; }
async function _e2eIdbGet(key) {
  try { const rec = await _e2eIdbOp('readonly', s => s.get(key)); return rec || null; } catch (_) { return null; }
}
async function _e2eIdbPut(key, val) {
  try { await _e2eIdbOp('readwrite', s => s.put(val, key)); return true; } catch (_) { return false; }
}
async function _e2eIdbDel(key) { try { await _e2eIdbOp('readwrite', s => s.delete(key)); } catch (_) {} }
// Device copy of one session: { ep, blob } (blob = e2e2. under the master key, slot
// "devsession\n<peer>", INCLUDING skipped/recent message keys), or { ep, del: 1 } after
// /encrypt off / a key change so other tabs drop theirs too.
async function _e2eDevSessPut(nk, rec) {
  const user = _e2eUser();
  if (!user || !E2E.keyReady) return;
  await _e2eIdbPut('s:' + user + ':' + nk, rec);
  E2E._devIdx = E2E._devIdx || new Set();
  if (!E2E._devIdx.has(nk)) {
    const idx = (await _e2eIdbGet('si:' + user)) || {};
    const names = new Set(Array.isArray(idx.n) ? idx.n : []);
    if (!names.has(nk)) { names.add(nk); await _e2eIdbPut('si:' + user, { n: [...names].slice(-4096) }); }
    E2E._devIdx.add(nk);
  }
}
async function _e2eDevSessWipe(user) {
  if (!user) return;
  const idx = await _e2eIdbGet('si:' + user);
  for (const nk of (idx && Array.isArray(idx.n) ? idx.n : [])) await _e2eIdbDel('s:' + user + ':' + nk);
  await _e2eIdbDel('si:' + user);
  E2E._devIdx = new Set();
}
// Adopt the newest copy of `nk`'s session written by another tab of this browser.
// Runs at the start of every ratchet-locked operation.
async function _e2eSyncFromDevice(nk) {
  if (!E2E.keyReady || !E2E.e2eEncKey) return;
  const rec = await _e2eIdbGet('s:' + _e2eUser() + ':' + nk);
  if (!rec || !Number.isInteger(rec.ep)) return;
  const cur = E2E.dmSessions[nk];
  const curEp = cur ? (cur.epoch | 0) : -1;
  if (rec.ep <= curEp) return;
  if (rec.del) {
    if (cur) { delete E2E.dmSessions[nk]; E2E._sessionEpoch[nk] = Math.max(E2E._sessionEpoch[nk] || 0, rec.ep); }
    return;
  }
  try {
    const o = JSON.parse(new TextDecoder().decode(await aesDecryptBlob(rec.blob, _e2eDevSlot(nk))));
    if (!o || typeof o !== 'object' || !o.RK || (o.epoch | 0) !== rec.ep) return;
    o.nick = nk; o.skipped = o.skipped || {}; o.recent = o.recent || {};
    E2E.dmSessions[nk] = o;
    E2E._sessionEpoch[nk] = Math.max(E2E._sessionEpoch[nk] || 0, rec.ep);
  } catch (e) { console.warn('[E2E] device session copy unreadable:', nk, e && e.message); }
}
// Browser-wide notices between tabs (no secrets): "E2E key is now cached".
function _e2eBc() {
  if (E2E._bc !== undefined) return E2E._bc;
  E2E._bc = null;
  try {
    if (typeof BroadcastChannel === 'function') {
      E2E._bc = new BroadcastChannel('cryptirc-e2e');
      E2E._bc.onmessage = (m) => { try { _e2eOnBc(m && m.data); } catch (_) {} };
    }
  } catch (_) { E2E._bc = null; }
  return E2E._bc;
}
function _e2eBcPost(msg) { try { const bc = _e2eBc(); if (bc) bc.postMessage({ ...msg, u: _e2eUser() }); } catch (_) {} }
function _e2eUtf8len(s) { return new TextEncoder().encode(String(s || '')).length; }
function _e2eSys(target, text) { try { e2eSysMsg(target, text); } catch (_) {} }
function _e2eToast(text) { try { if (typeof showToast === 'function') showToast(text); } catch (_) {} }
function _e2eStatusTarget() { try { return (active && active.target) || 'status'; } catch (_) { return 'status'; } }
function _e2eCmpBytes(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) { if (a[i] !== b[i]) return a[i] - b[i]; }
  return a.length - b.length;
}

// Paced sender for E2E protocol messages. The server drops (silently) any command
// beyond 40/s on one socket (WS_MAX_CMDS_PER_SEC), and E2E bursts — publishing a
// bundle (20 OTPK blobs + SPK + bundle), refilling prekeys, the one-time migration,
// loading N channel keys — would otherwise lose messages. FIFO, ≤12/s sustained (burst
// 12), leaving most of the budget to normal app traffic (which bursts at boot too).
// Resolves true once the message was handed to the open socket, false if it was down.
const E2E_TX_RATE = 12;
E2E._txq = []; E2E._txTokens = E2E_TX_RATE; E2E._txLast = Date.now(); E2E._txTimer = null;
function _e2eWs(msg) {
  return new Promise(resolve => { E2E._txq.push({ msg, resolve }); _e2eTxPump(); });
}
function _e2eTxPump() {
  const now = Date.now();
  E2E._txTokens = Math.min(E2E_TX_RATE, E2E._txTokens + (now - E2E._txLast) * E2E_TX_RATE / 1000);
  E2E._txLast = now;
  while (E2E._txq.length && E2E._txTokens >= 1) {
    const { msg, resolve } = E2E._txq.shift();
    // r3 (w-web INFO): after a vault lock the server refuses every E2E write ("Vault must
    // be unlocked …" errors); one still queued from a boot the lock interrupted is an
    // expected cancel — not sent. r4 (verifier w3-web N6): only after a SERVER vault lock.
    // A device-only lock (auto-lock of this browser) leaves the server vault unlocked, so a
    // write already queued — e.g. the ratchet state of a message just sent — is still
    // stored, as before r3 (dropping it let this device later restore an older session
    // and reuse message keys the peer had already consumed).
    if (E2E._serverLocked === true && msg && /^(e2e_store_|e2e_publish_bundle$|e2e_add_otpks$)/.test(String(msg.type))) { resolve(false); continue; }
    E2E._txTokens -= 1;
    let ok = false;
    try { ok = wsend(msg) !== false; } catch (_) {}
    resolve(ok);
  }
  if (E2E._txq.length && !E2E._txTimer) E2E._txTimer = setTimeout(() => { E2E._txTimer = null; _e2eTxPump(); }, 60);
}

// Generic request → reply waiter for the request/response style E2E events. The
// timeout starts once the request actually left (it may wait in the paced queue). All
// E2E requests are idempotent, so an unanswered one (the server sheds commands above
// its per-socket budget) is re-sent up to `retries` times before giving up.
E2E._waiters = Object.create(null);
function _e2eReq(msg, replyType, timeoutMs = 6000, match = null, retries = 2) {
  return new Promise(resolve => {
    const list = E2E._waiters[replyType] || (E2E._waiters[replyType] = []);
    const entry = { match, done: null };
    let t = null, left = retries;
    entry.done = (ev) => { if (t) clearTimeout(t); resolve(ev); };
    list.push(entry);
    const drop = () => { const i = list.indexOf(entry); if (i >= 0) list.splice(i, 1); resolve(null); };
    const attempt = () => _e2eWs(msg).then(ok => {
      if (!ok) { drop(); return; }
      if (!list.includes(entry)) return;   // already answered
      t = setTimeout(() => { if (left-- > 0 && list.includes(entry)) attempt(); else drop(); }, timeoutMs);
    });
    attempt();
  });
}
// Returns true if a waiter consumed the event.
function _e2eResolveWaiter(ev) {
  const list = E2E._waiters[ev.type];
  if (!list || !list.length) return false;
  const i = list.findIndex(w => !w.match || w.match(ev));
  if (i < 0) return false;
  const [w] = list.splice(i, 1);
  try { w.done(ev); } catch (_) {}
  return true;
}

// ─── C1: client-held key management ───────────────────────────────────────────

function _e2eBlobAAD(ctx, version = 3) { return new TextEncoder().encode('CryptIRC-E2E-BLOB-v' + version + '\n' + ctx); }
function _e2eWrappedBlob(blob) { return blob.startsWith(E2E_BLOB_PREFIX) || blob.startsWith(E2E_V2_BLOB); }
function _e2eCtxSession(partner) { return 'session\n' + partner; }
function _e2eCtxChan(channel)    { return 'chan\n' + _e2eK(channel); }

async function _e2eImportAesKey(raw, extractable = false) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, extractable, ['encrypt', 'decrypt']);
}

// Read-only support for the old keyring during migration.
async function _e2eDeriveV2Kek(pass, saltB64, iter, pepperB64, user) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']);
  const pb = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: base64ToBytes(saltB64), iterations: iter }, base, 256));
  const ikm = concat(pb, base64ToBytes(pepperB64));
  pb.fill(0);
  const hk = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  ikm.fill(0);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('CryptIRC-E2E-KEK-v2\n' + user) },
    hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
// r2 (agy-p3 HIGH e2e.js:269/295): the keyring is stored by the server, so every field
// is untrusted. The PBKDF2 iteration count must be EXACTLY the one this design uses —
// a tampered `it` could hang every client (2e9 iterations) or make offline guessing
// cheap (it:1) — and salt / wrapped key / check value must have their real sizes.
// Anything else is refused (fail closed: E2E stays locked, nothing is re-wrapped).
function _e2eKringParse(blob) {
  if (typeof blob !== 'string' || blob.length > 4096) throw new Error('bad keyring');
  const v = blob.startsWith(E2E_KEYRING_PREFIX) ? 3 : blob.startsWith(E2E_V2_KEYRING) ? 2 : 0;
  if (!v) throw new Error('bad keyring');
  const o = JSON.parse(atob(blob.slice(E2E_KEYRING_PREFIX.length)));
  if (!o || o.v !== v || typeof o.s !== 'string' || typeof o.w !== 'string') throw new Error('bad keyring');
  if (v === 3) {
    const w = base64ToBytes(o.w).length;
    if (base64ToBytes(o.s).length !== 16 || (w !== 60 && w !== 92) ||
        typeof o.c !== 'string' || base64ToBytes(o.c).length !== 52) throw new Error('bad keyring (field sizes)');
    return o;
  }
  if (o.it !== E2E_KDF_ITER || (o.kdf !== undefined && o.kdf !== 'pbkdf2-sha256')) throw new Error('bad keyring (unexpected KDF parameters)');
  let sl = 0, wl = 0, cl = 0;
  try { sl = base64ToBytes(o.s).length; wl = base64ToBytes(o.w).length; cl = typeof o.c === 'string' ? base64ToBytes(o.c).length : 0; } catch (_) { throw new Error('bad keyring'); }
  if (sl !== 16 || wl !== 12 + 32 + 16 || (typeof o.c === 'string' && cl !== 12 + 24 + 16)) throw new Error('bad keyring (field sizes)');
  return o;
}
function _e2eKringValid(blob) { try { _e2eKringParse(blob); return true; } catch (_) { return false; } }
async function _e2eGcmEnc(key, pt, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, pt));
  return concat(iv, ct);
}
async function _e2eGcmDec(key, data, aad) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12), additionalData: aad }, key, data.slice(12)));
}
// Wrap raw master-key bytes under a fresh salt. Also stores a key-check value (a
// constant encrypted under the master key itself) so a browser's cached key can be
// validated against the current keyring without the passphrase.
async function _e2eRecoveryKek(code, salt, user) {
  const normalized = String(code).trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(normalized)) throw new Error('invalid recovery code');
  const raw = base64ToBytes(normalized.replace(/-/g, '+').replace(/_/g, '/') + '=');
  try {
    const key = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
    return await crypto.subtle.deriveKey({
      name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('CryptIRC-E2E-KEK-v3\n' + user),
    }, key, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally { raw.fill(0); }
}
async function _e2eWrapKeyring(rawM, previous, code, user) {
  const salt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
  const kek = await _e2eRecoveryKek(code, base64ToBytes(salt), user);
  const enc = new TextEncoder();
  const keys = previous ? concat(rawM, previous) : rawM;
  let w;
  try { w = await _e2eGcmEnc(kek, keys, enc.encode('CryptIRC-E2E-KEYRING-v3\n' + user)); }
  finally { if (previous) keys.fill(0); }
  const M = await _e2eImportAesKey(rawM);
  const c = await _e2eGcmEnc(M, enc.encode('CryptIRC-E2E-KEYCHECK-v3'), enc.encode(user));
  const o = { v: 3, s: salt, w: bytesToBase64(w), c: bytesToBase64(c) };
  return E2E_KEYRING_PREFIX + btoa(JSON.stringify(o));
}
async function _e2eUnwrapV2Keyring(blob, pass, pepperB64, user) {
  const o = _e2eKringParse(blob);
  if (o.v !== 2) throw new Error('expected v2 keyring');
  const kek = await _e2eDeriveV2Kek(pass, o.s, o.it, pepperB64, user);
  return _e2eGcmDec(kek, base64ToBytes(o.w), new TextEncoder().encode('CryptIRC-E2E-KEYRING-v2\n' + user));
}
async function _e2eUnwrapKeyring(blob, code, user) {
  const o = _e2eKringParse(blob);
  if (o.v !== 3) throw new Error('expected v3 keyring');
  const kek = await _e2eRecoveryKek(code, base64ToBytes(o.s), user);
  const raw = await _e2eGcmDec(kek, base64ToBytes(o.w), new TextEncoder().encode('CryptIRC-E2E-KEYRING-v3\n' + user));
  try {
    const k = await _e2eImportAesKey(raw.subarray(0, 32));
    if (!(await _e2eKeyringCheck(blob, k, user))) throw new Error('invalid key check');
    const previous = raw.length === 64 ? await _e2eImportAesKey(raw.subarray(32)) : null;
    const finalized = previous
      ? await _e2eWrapKeyring(raw.subarray(0, 32), null, code, user)
      : null;
    return { k, previous, finalized };
  } finally { raw.fill(0); }
}
async function _e2eKeyringCheck(blob, M, user) {
  try {
    const o = _e2eKringParse(blob);
    const pt = await _e2eGcmDec(M, base64ToBytes(o.c), new TextEncoder().encode(user));
    return new TextDecoder().decode(pt) === 'CryptIRC-E2E-KEYCHECK-v' + o.v;
  } catch (_) { return false; }
}

// IndexedDB cache of the NON-EXTRACTABLE master CryptoKey (structured-clonable; script
// can use it but never read its bytes). Best effort: no IndexedDB → passphrase per load.
// Opens (creating/upgrading as needed) the E2E key DB. Robust against a DB that exists
// without our store (an earlier build, or anything else that created the name): the
// version is bumped once and every store we need is created in onupgradeneeded. After
// app.js's logout wipe deletes cryptirc* DBs, the next open simply recreates it.
function _e2eIdbOpen(version) {
  return new Promise((resolve, reject) => {
    try {
      if (typeof indexedDB === 'undefined' || !indexedDB) { reject(new Error('no indexedDB')); return; }
      const r = version ? indexedDB.open(E2E_IDB_NAME, version) : indexedDB.open(E2E_IDB_NAME);
      r.onupgradeneeded = () => {
        try { const db = r.result; if (!db.objectStoreNames || !db.objectStoreNames.contains(E2E_IDB_STORE)) db.createObjectStore(E2E_IDB_STORE); } catch (_) {}
      };
      r.onsuccess = () => {
        const db = r.result;
        if (db.objectStoreNames && !db.objectStoreNames.contains(E2E_IDB_STORE)) {
          const v = (db.version || 1) + 1;
          try { db.close(); } catch (_) {}
          if (version) { reject(new Error('idb store missing after upgrade')); return; }
          _e2eIdbOpen(v).then(resolve, reject);
          return;
        }
        db.onversionchange = () => { try { db.close(); } catch (_) {} };
        resolve(db);
      };
      r.onerror = () => reject(r.error || new Error('idb open failed'));
      r.onblocked = () => reject(new Error('idb open blocked'));
    } catch (e) { reject(e); }
  });
}
async function _e2eIdbOp(mode, fn) {
  const db = await _e2eIdbOpen();
  try {
    return await new Promise((resolve, reject) => {
      let tx;
      try { tx = db.transaction(E2E_IDB_STORE, mode); } catch (e) { reject(e); return; }
      const req = fn(tx.objectStore(E2E_IDB_STORE));
      tx.oncomplete = () => resolve(req ? req.result : undefined);
      tx.onerror = () => reject(tx.error || new Error('idb tx failed'));
      tx.onabort = () => reject(tx.error || new Error('idb tx aborted'));
    });
  } finally { try { db.close(); } catch (_) {} }
}
async function _e2eIdbGetKey(user) {
  try { const rec = await _e2eIdbOp('readonly', s => s.get('m:' + user)); return rec && rec.v === 3 && rec.k ? rec : null; } catch (_) { return null; }
}
async function _e2eIdbPutKey(user, keys) {
  try { await _e2eIdbOp('readwrite', s => s.put({ ...keys, v: 3 }, 'm:' + user)); return true; } catch (_) { return false; }
}
async function _e2eIdbDelKey(user) {
  try { await _e2eIdbOp('readwrite', s => s.delete('m:' + user)); } catch (_) {}
}
// Forget this browser's E2E key (vault locked, or explicit). Logout additionally wipes
// all cryptirc* IndexedDB/localStorage (app.js doLogout).
async function e2eForgetDevice() { await _e2eIdbDelKey(_e2eUser()); }

// ─── Blob encrypt / decrypt ───────────────────────────────────────────────────

// Versioned blob: prefix + base64(nonce || AES-GCM(masterKey, plain, AAD)).
// The context binds a blob to its slot (identity / session:<partner> / chan:<#chan>),
// so a server serving one channel's key blob under another name, or one peer's session
// under another peer, fails authentication instead of being silently used.
E2E._v2Slots = new Set();   // slots seen/written as v2 this page: a legacy blob for them is refused
async function aesEncryptBlob(plainBytes, ctx) {
  if (!E2E.e2eEncKey) throw new Error('E2E key not available on this device');
  if (typeof ctx !== 'string') throw new Error('E2E blob context required');
  E2E._v2Slots.add(ctx);
  return E2E_BLOB_PREFIX + bytesToBase64(await _e2eGcmEnc(E2E.e2eEncKey, plainBytes, _e2eBlobAAD(ctx)));
}
// Returns { pt, legacy }. Legacy (pre-upgrade, bare base64, no AAD) blobs are only
// readable while the legacy key is in memory (passphrase-proven unlock or unmigrated
// account) — callers re-wrap them as v2 immediately.
async function aesDecryptBlobEx(blob, ctx) {
  if (typeof blob !== 'string' || !blob) throw new Error('empty E2E blob');
  if (blob.startsWith(E2E_BLOB_PREFIX)) {
    if (!E2E.e2eEncKey) throw new Error('E2E key not available on this device');
    const pt = await _e2eGcmDec(E2E.e2eEncKey, base64ToBytes(blob.slice(E2E_BLOB_PREFIX.length)), _e2eBlobAAD(ctx));
    E2E._v2Slots.add(ctx);
    return { pt, legacy: false };
  }
  if (blob.startsWith(E2E_V2_BLOB)) {
    if (!E2E._previousKey) throw new Error('E2E v2 migration key unavailable');
    const pt = await _e2eGcmDec(E2E._previousKey, base64ToBytes(blob.slice(E2E_V2_BLOB.length)), _e2eBlobAAD(ctx, 2));
    return { pt, legacy: false };
  }
  // Legacy (server-key) blobs are only ever read during the one-time migration. Once
  // the account is migrated the legacy key is gone and every non-v2 blob is refused —
  // a server (or an old backup) can't feed an old identity / ratchet / PSK back in —
  // and even before that, a slot already seen as v2 never accepts a legacy blob again.
  if (E2E._migrated) throw new Error('refusing legacy-format E2E blob (account already upgraded)');
  if (E2E._v2Slots.has(ctx)) throw new Error('refusing legacy-format E2E blob for an upgraded slot');
  if (!E2E._legacyKey) throw new Error('legacy-format E2E blob and no legacy key');
  const data = base64ToBytes(blob);
  return { pt: new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12) }, E2E._legacyKey, data.slice(12))), legacy: true };
}
async function aesDecryptBlob(blob, ctx) { return (await aesDecryptBlobEx(blob, ctx)).pt; }

// ─── Vault hooks (called from app.js) ─────────────────────────────────────────

// The vault passphrase is retained briefly to migrate a pre-upgrade keyring.
function e2eNotePassphrase(pass) {
  E2E._pendingPass = pass || null;
  clearTimeout(E2E._passTimer);
  if (pass) E2E._passTimer = setTimeout(() => { E2E._pendingPass = null; E2E._devicePromptPending = false; }, 60000);
}
function e2eOnVaultError(message) {
  if (E2E._devicePromptPending) {
    E2E._lockReason = 'declined';
    E2E._devicePromptPending = false;
    _e2eSys(_e2eStatusTarget(), '🔐 ' + (message || 'Incorrect vault passphrase') + ' — run /encrypt unlock to retry');
  }
  e2eNotePassphrase(null);
}
// r3 (w-web INFO "console noise on vault lock"): a vault lock (any device) wipes the E2E
// key while a boot / identity setup may still be running; what fails after that is an
// expected cancel, not an error.
// r4 (verifier w3-web N7): "locked meanwhile" = a lock / session end really happened
// since `gen` was taken (E2E._lockGen), or the vault is locked now — no longer "the key
// is not ready", which labelled every early boot failure (a parse error, a refused
// request, a bug) as a lock and hid it from the console.
function _e2eLockedMeanwhile(gen) { return E2E._vaultUp === false || (gen !== undefined && gen !== E2E._lockGen); }
// The E2E key is gone (lock) — nothing more may be published with it.
function _e2eKeyGone() { return E2E._vaultUp === false || !E2E.keyReady || !E2E.e2eEncKey; }
function _e2eRun(fn) {
  const gen = E2E._lockGen;
  E2E._bootChain = E2E._bootChain.then(fn).catch(e => {
    try {
      if (_e2eLockedMeanwhile(gen)) console.log('[E2E] boot step stopped: the vault was locked meanwhile (' + (e && (e.message || e.name) || e) + ')');
      else console.error('[E2E] boot step failed:', e);
    } catch (_) {}
  });
  return E2E._bootChain;
}
// app.js 'vault_unlocked' event. ev = { e2e_enc_key, e2e_legacy_key?, e2e_pepper?, e2e_migrated }.
async function e2eOnVaultUnlocked(ev) {
  ev = ev || {};
  E2E._user = _e2eUser();
  E2E._vaultUp = true; E2E._serverLocked = false;
  // r3 (w-web MED e2e.js:1657): this arrives on every (re)connected socket. "Session
  // moved" notices sent while the socket was down are lost, so compare each live DM
  // session with the server copy before its next send.
  if (E2E.keyReady) for (const k of Object.keys(E2E.dmSessions)) _e2eMarkMaybeMoved(k);
  _e2eBc();
  if (ev.e2e_migrated) { E2E._migrated = true; E2E._legacyKey = null; }
  const legacy = ev.e2e_legacy_key || ev.e2e_enc_key || '';
  if (legacy && !E2E._legacyKey && !E2E._migrated) { try { E2E._legacyKey = await _e2eImportAesKey(base64ToBytes(legacy)); } catch (_) {} }
  if (ev.e2e_pepper) E2E._pepper = ev.e2e_pepper;
  const pass = ev.e2e_pepper ? E2E._pendingPass : null;
  const verified = ev.vault_verified || ev.e2e_pepper || ev.e2e_legacy_key;
  const resumeSetup = !!(verified && E2E._devicePromptPending);
  if (verified) {
    e2eNotePassphrase(null);
    E2E._devicePromptPending = false;
  }
  return _e2eRun(() => _e2eBoot(pass, resumeSetup));
}
// Back-compat entry point (an app.js from before this change called e2eInit(key)).
function e2eInit(e2eEncKeyB64) { return e2eOnVaultUnlocked({ e2e_enc_key: e2eEncKeyB64 || '' }); }
// app.js 'state' event with vault_unlocked:true (e.g. another device unlocked).
function e2eOnVaultStateUnlocked() {
  E2E._vaultUp = true; E2E._serverLocked = false;
  _e2eBc();
  if (E2E.keyReady || E2E._booting) return E2E._bootChain;
  // r2 (v-e2e NEW-6): after a vault lock (any device) every tab used to stay E2E-off
  // for good when the vault was unlocked elsewhere ('locked' short-circuit) — no
  // prompt, and incoming E2E DMs were lost there. Now a tab locked BY THE VAULT retries:
  // it picks up the key another tab of this browser cached (that tab announces it on a
  // BroadcastChannel; the short delay covers the race) and otherwise asks once for the
  // passphrase. A tab whose user declined the prompt keeps quiet until /encrypt unlock.
  if (E2E._bootPhase === 'locked' && E2E._lockReason !== 'vault') return E2E._bootChain;
  clearTimeout(E2E._stateBootTimer);
  E2E._stateBootTimer = setTimeout(() => {
    if (!E2E.keyReady && !E2E._booting && E2E._vaultUp) _e2eRun(() => _e2eBoot(null));
  }, E2E._bootPhase === 'locked' ? 1500 : 0);
  return E2E._bootChain;
}
// r6 (codex-p3 HIGH e2e.js:1007): app.js calls this on EVERY auth_ok — before it flushes
// the lines queued during an outage. Changes made on other devices while this socket was
// down (E2E turned on for a channel / peer, a channel key rotated or removed) were only
// broadcast to the sockets connected at the time, and a ready device never asked again
// (_e2eBoot returned at once): it kept treating such a target as unencrypted (cleartext)
// or kept the old key. Now every reconnect re-runs discovery, and until it completed
// every outgoing target is BLOCKED (like a fresh load: _krReceived / the r5 F1 guard).
function e2eOnSocketAuthed() {
  E2E._krReceived = false;                 // locked device: its hints may be stale too
  if (E2E.keyReady) E2E._resyncPending = true;
}
function _e2eResyncDone() {
  E2E._resyncPending = false;
  const w = E2E._resyncWaiters || []; E2E._resyncWaiters = [];
  for (const f of w) { try { f(); } catch (_) {} }
}
// Resolves when the re-sync finished (or after `ms`); at once when none is pending.
function _e2eResyncWait(ms) {
  if (!E2E._resyncPending || !E2E.keyReady) return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => { clearTimeout(t); const i = (E2E._resyncWaiters || []).indexOf(done); if (i >= 0) E2E._resyncWaiters.splice(i, 1); resolve(); };
    const t = setTimeout(done, ms);
    (E2E._resyncWaiters = E2E._resyncWaiters || []).push(done);
  });
}
// A failed / stalled re-sync is retried (at most every 5 s) while something wants to send.
function _e2eKickResync() {
  if (!E2E._resyncPending || !E2E.keyReady || !E2E._vaultUp || E2E._resyncRunning || E2E._booting) return;
  const now = Date.now();
  if (now - (E2E._resyncKickAt || 0) < 5000) return;
  E2E._resyncKickAt = now;
  _e2eRun(() => _e2eBoot(null));
}
// The re-sync of a READY device (keys + identity in memory): the keyring's target
// inventory, the E2E state other devices saved (channels / peers turned on or off, key
// generations), trust pins, every channel key (new / rotated / removed elsewhere) and the
// stored DM sessions of peers this page has none for. Every await re-checks the lock
// generation (a lock meanwhile → nothing installed, still pending until the next unlock).
async function _e2eResync() {
  if (E2E._resyncRunning) return;
  const gen = E2E._lockGen;
  E2E._resyncRunning = true;
  try {
    const user = _e2eUser();
    const kr = await _e2eReq({ type: 'e2e_load_keyring' }, 'e2e_keyring');
    if (_e2eBootStale(gen) || !kr) return;             // no answer: stays blocked, retried
    if (!kr.blob || !kr.blob.startsWith(E2E_KEYRING_PREFIX) || !_e2eKringValid(kr.blob)) {
      if (!E2E._resyncBadNotice) { E2E._resyncBadNotice = true; _e2eSys(_e2eStatusTarget(), '⚠️ E2E: the server returned an INVALID E2E keyring after the reconnect — messages stay blocked here until it is fixed (reload to retry).'); }
      return;
    }
    if (!(await _e2eKeyringCheck(kr.blob, E2E.e2eEncKey, user))) {
      // The keyring was replaced elsewhere: this device's key no longer opens it. Same as
      // a stale cached key at boot — drop it and boot again (asks for the passphrase).
      if (_e2eBootStale(gen)) return;
      console.warn('[E2E] the E2E keyring was replaced on another device — re-unlocking');
      _e2eWipeMemory();
      try { await _e2eIdbDelKey(user); } catch (_) {}
      E2E._bootPhase = undefined;
      E2E._resyncRunning = false;
      return _e2eBoot(null);
    }
    E2E._krReceived = true;
    if (kr.migrated) { E2E._migrated = true; E2E._legacyKey = null; }
    E2E._serverHints = { peers: (kr.peers || []).map(_e2eK), channels: (kr.channels || []).map(_e2eK), hasIdentity: !!kr.has_identity, migrated: !!kr.migrated };
    // What other devices saved meanwhile (merged the way e2eSaveState merges).
    const sb = await _e2eFetchSession('__state__');
    if (_e2eBootStale(gen)) return;
    const srv = sb ? await _e2eDecodeState(sb) : null;
    if (_e2eBootStale(gen)) return;
    if (srv && E2E.state && _e2eMergeStateInto(E2E.state, srv)) _e2eApplyMergedState();
    for (const s of Object.values(E2E.dmSessions)) { try { await _e2eSessFp(s); } catch (_) {} }   // r7: pin comparison
    _e2eWs({ type: 'e2e_load_trust' });
    // Channel keys: the list (a key missing from it → blocked, see e2e_channel_list), then
    // every listed key, waiting (bounded) until each one was processed.
    const list = await _e2eReq({ type: 'e2e_list_channel_keys' }, 'e2e_channel_list');
    if (_e2eBootStale(gen) || !list) return;
    const names = (Array.isArray(list.channels) ? list.channels : []).map(String);
    await Promise.all(names.map((ch) => new Promise((resolve) => {
      const wl = E2E._waiters.e2e_channel_key_done || (E2E._waiters.e2e_channel_key_done = []);
      const entry = { match: (e) => _e2eK(e.channel) === _e2eK(ch), done: () => { clearTimeout(t); resolve(); } };
      const t = setTimeout(() => { const i = wl.indexOf(entry); if (i >= 0) wl.splice(i, 1); resolve(); }, 20000);
      wl.push(entry);
    })));
    if (_e2eBootStale(gen)) return;
    await _e2eRestoreSessions(gen);
    if (_e2eBootStale(gen)) return;
    _e2eResyncDone();
    E2E._resyncBadNotice = false;
    console.log('[E2E] re-synced after the reconnect');
  } finally {
    E2E._resyncRunning = false;
    try { updateE2EIndicator(_e2eStatusTarget()); } catch (_) {}
  }
}
// Another tab of this browser cached the E2E key (r2, NEW-6): use it instead of asking.
function _e2eOnBc(m) {
  if (!m || m.u !== _e2eUser()) return;
  if (m.t === 'key' && !E2E.keyReady && !E2E._booting && E2E._vaultUp) {
    clearTimeout(E2E._stateBootTimer);
    _e2eRun(() => _e2eBoot(null));
  }
}
// app.js 'vault_locked' event / state with vault_unlocked:false: drop every key.
// r4: opts.deviceOnly — app.js's device-local lock (the server vault stays unlocked).
async function e2eOnVaultLocked(opts) {
  const had = E2E.keyReady || E2E.identityReady || E2E._legacyKey;
  const user = _e2eUser();
  E2E._vaultUp = false;
  E2E._lockGen++;
  if (!(opts && opts.deviceOnly)) E2E._serverLocked = true;
  _e2eCancelPrompt();
  _e2eCloseIdentityQuestions();   // r4 (N3)
  clearTimeout(E2E._stateBootTimer);
  _e2eWipeMemory();
  E2E._bootPhase = 'locked';
  E2E._lockReason = 'vault';
  E2E._autoPrompted = false;          // one prompt again after the next unlock elsewhere
  E2E._lockedNoticeShown = false;
  if (had) { await e2eForgetDevice(); await _e2eDevSessWipe(user); }
  try { updateE2EIndicator(_e2eStatusTarget()); } catch (_) {}
}
// Every key / session / pending request out of memory (vault lock, session end).
function _e2eWipeMemory() {
  E2E.keyReady = false; E2E.identityReady = false;
  E2E._v2Slots = new Set();
  E2E.e2eEncKey = null; E2E._previousKey = null; E2E._finalKeyring = null; E2E._legacyKey = null; E2E._pepper = null; E2E.identityKeys = null;
  e2eNotePassphrase(null);
  E2E._devicePromptPending = false;
  for (const k of Object.keys(E2E.dmSessions)) delete E2E.dmSessions[k];
  for (const k of Object.keys(E2E.channelKeys)) delete E2E.channelKeys[k];
  E2E._chanKeyGen = Object.create(null);
  _e2eResyncDone();               // r6: nothing to re-sync without keys (waiters re-check → locked)
  E2E._spkBlob = null; E2E._sessionCache = Object.create(null); E2E._glareAlt = Object.create(null);
  E2E._pendingOn = Object.create(null); E2E._moved = Object.create(null); E2E._maybeMoved = Object.create(null); E2E._devIdx = new Set();
  E2E._orphans = Object.create(null); E2E._hdrWait = Object.create(null); E2E._lazyTried = Object.create(null);   // r8
}
// r2 (v-fe-a NEW-1): the session ended (auth_failed / sign-out): close our passphrase
// prompt — it used to stay on top of the login screen, intercepting clicks and asking
// the next person for "your vault passphrase" — and drop keys from memory. The cached
// device key stays (same user, same browser); sign-out wipes it with the rest.
function e2eOnSessionEnd() {
  _e2eCancelPrompt();
  _e2eCloseIdentityQuestions();   // r4 (verifier w3-web N3)
  E2E._vaultUp = false;
  E2E._lockGen++;
  clearTimeout(E2E._stateBootTimer);
  _e2eWipeMemory();
  E2E._bootPhase = undefined; E2E._krReceived = false; E2E._serverHints = null; E2E._migrated = false;
  E2E._autoPrompted = false; E2E._lockedNoticeShown = false; E2E._lockedHold = [];
}
function _e2eCancelPrompt() {
  if (!E2E._promptText) return;
  try {
    const msg = document.getElementById('custom-prompt-msg');
    const cancel = document.getElementById('custom-prompt-cancel');
    if (msg && cancel && msg.textContent === E2E._promptText && typeof cancel.onclick === 'function') cancel.onclick();
  } catch (_) {}
}
async function _e2ePrompt(message, value = '', masked = true) {
  E2E._promptText = message;
  try {
    return await customPrompt(message, value, masked, true);
  } finally { E2E._promptText = null; }
}
async function _e2eShowSharedKey(words) {
  if (E2E.keyReady && !E2E._promptText) {
    await _e2ePrompt('Copy this key and share it over a trusted, encrypted connection.', words, false);
  }
}
function _e2eDiscardSetupCode() {
  _e2eSys(_e2eStatusTarget(), '🔐 The recovery code just shown was not saved. Discard it and run /encrypt unlock.');
}
async function _e2eSetupCode(gen) {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const code = bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  bytes.fill(0);
  const saved = await _e2ePrompt('Copy this E2E recovery code and save it somewhere safe. The app will confirm when it is active. You’ll need it on other devices and after clearing browser data.', code, false);
  if (saved === code && !_e2eBootStale(gen)) {
    const confirm = await _e2ePrompt('Paste your saved E2E recovery code to confirm.');
    if (!_e2eBootStale(gen) && confirm?.trim() === code) return code;
  }
  _e2eDiscardSetupCode();
  return null;
}
async function e2ePromptDeviceUnlock() {
  if (E2E.keyReady || E2E._promptText || E2E._devicePromptPending) return;
  if (E2E._vaultUp !== true) {
    _e2eSys(_e2eStatusTarget(), '🔐 Unlock the vault before unlocking encrypted chats.');
    return;
  }
  E2E._autoPrompted = true;
  return _e2eRun(() => _e2eBoot(null, true));
}

// r2: server 'error' events about E2E (app.js routes them here first). Returns true
// when handled. "No E2E key bundle for X" used to reach only the console, so a user
// who typed /encrypt on X saw "Fetching key bundle…" and nothing else.
function e2eOnServerError(message) {
  const m = String(message || '');
  const mm = /^No E2E key bundle for (\S+)/.exec(m);
  if (mm) {
    const k = _e2eK(mm[1]);
    const p = E2E._pendingOn && E2E._pendingOn[k];
    if (p && !p.answered) {
      delete E2E._pendingOn[k];
      _e2eSys(p.target, `🔓 ${m}. Encryption with ${mm[1]} was NOT started — messages to ${mm[1]} are not encrypted.`);
      try { updateE2EIndicator(p.target); } catch (_) {}
    } else _e2eSys(mm[1], '🔐 ' + m);
    return true;
  }
  if (/^Too many key-bundle requests/.test(m)) {
    for (const [k, p] of Object.entries(E2E._pendingOn || {})) {
      if (p && p.answered) continue;                    // r6: already answered, being set up
      delete E2E._pendingOn[k];
      _e2eSys(p.target, `🔓 ${m}. Encryption with ${k} was NOT started — try /encrypt on ${k} again in a minute.`);
    }
    return true;
  }
  if (/^E2E\b/.test(m)) {
    const now = Date.now();
    if (now - (E2E._errToastAt || 0) > 5000) { E2E._errToastAt = now; _e2eToast('🔐 ' + m); }
    return true;
  }
  return false;
}

// r2 (codex-p1/p3 HIGH): compare-and-swap keyring store. `expect` = the keyring this
// client believes is current ('' = none yet). Returns null (no reply), {ok:true,
// migrated} or {ok:false, blob} — another device's keyring won and must be adopted.
async function _e2eStoreKeyring(blob, migrated, expect) {
  const r = await _e2eReq({ type: 'e2e_store_keyring', blob, migrated: !!migrated, expect: expect || '' }, 'e2e_keyring_stored');
  if (!r) return null;
  if (r.conflict) return { ok: false, migrated: !!r.migrated, blob: typeof r.blob === 'string' ? r.blob : '' };
  return { ok: true, migrated: !!r.migrated };
}

async function _e2eProveVault(gen, message) {
  const pass = await _e2ePrompt(message);
  if (!pass || _e2eBootStale(gen)) return;
  e2eNotePassphrase(pass);
  E2E._devicePromptPending = true;
  if (wsend({ type: 'unlock_vault', passphrase: pass }) === false) e2eOnVaultError('Connection unavailable');
}
async function _e2eOpenKeys(kr, user, gen, vaultPass, interactive) {
  if (kr.needs_legacy && !E2E._legacyKey) {
    if (interactive) await _e2eProveVault(gen, 'Enter your vault passphrase to unlock your pre-upgrade E2E data.');
    return null;
  }
  const isV3 = kr.blob && kr.blob.startsWith(E2E_KEYRING_PREFIX);
  if (isV3) {
    const cached = await _e2eIdbGetKey(user);
    if (cached && await _e2eKeyringCheck(kr.blob, cached.k, user)) {
      if (cached.previous && base64ToBytes(_e2eKringParse(kr.blob).w).length === 60) {
        return { keys: { k: cached.k }, remember: true };
      }
      return { keys: cached, remember: false };
    }
    if (_e2eBootStale(gen) || !interactive) return null;
    const code = await _e2ePrompt('Enter your E2E recovery code to unlock encrypted chats on this device.');
    if (!code || _e2eBootStale(gen)) return null;
    try { return { keys: await _e2eUnwrapKeyring(kr.blob, code, user), remember: true }; }
    catch (_) { _e2eSys(_e2eStatusTarget(), '🔐 That recovery code did not open your E2E keyring. Run /encrypt unlock to retry.'); return null; }
  }

  const upgrade = !!kr.blob;
  if (upgrade && !vaultPass) {
    if (!interactive) return null;
    await _e2eProveVault(gen, 'Enter your vault passphrase to upgrade your existing E2E keyring.');
    return null;
  }
  if (!upgrade && !interactive) return null;

  return _e2eXLock('keyring-setup', async () => {
    let previous = null;
    let raw = null;
    try {
      if (upgrade) {
        if (!E2E._pepper) return null;
        try { previous = await _e2eUnwrapV2Keyring(kr.blob, vaultPass, E2E._pepper, user); }
        catch (_) {
          const oldPass = await _e2ePrompt('Enter the previous vault passphrase that protected your old E2E keyring.');
          if (!oldPass || _e2eBootStale(gen)) return null;
          try { previous = await _e2eUnwrapV2Keyring(kr.blob, oldPass, E2E._pepper, user); }
          catch (_) { _e2eSys(_e2eStatusTarget(), '🔐 That passphrase did not open the old E2E keyring.'); return null; }
        }
      }
      if (_e2eBootStale(gen)) return null;
      const latest = await _e2eReq({ type: 'e2e_load_keyring' }, 'e2e_keyring');
      if (!latest || _e2eBootStale(gen)) return null;
      if (latest.blob !== kr.blob) {
        Object.assign(kr, latest);
        if (latest.blob?.startsWith(E2E_KEYRING_PREFIX) && _e2eKringValid(latest.blob)) {
          return _e2eOpenKeys(kr, user, gen, null, true);
        }
        _e2eSys(_e2eStatusTarget(), '🔐 E2E setup changed on another device. Run /encrypt unlock to retry.');
        return null;
      }
      const code = await _e2eSetupCode(gen);
      if (!code) return null;
      raw = crypto.getRandomValues(new Uint8Array(32));
      const blob = await _e2eWrapKeyring(raw, previous, code, user);
      if (_e2eBootStale(gen)) { _e2eDiscardSetupCode(); return null; }
      let result = await _e2eStoreKeyring(blob, !!kr.migrated, kr.blob);
      if (!result && !_e2eBootStale(gen)) {
        const saved = await _e2eReq({ type: 'e2e_load_keyring' }, 'e2e_keyring');
        if (saved?.blob === blob) result = { ok: true, migrated: saved.migrated };
      }
      if (!result) {
        _e2eSys(_e2eStatusTarget(), '🔐 Could not confirm setup. Keep the recovery code and run /encrypt unlock to check.');
        return null;
      }
      if (!result.ok) { _e2eDiscardSetupCode(); return null; }
      _e2eSys(_e2eStatusTarget(), '🔐 Your saved E2E recovery code is now active.');
      kr.blob = blob;
      kr.migrated = !!result.migrated;
      return { keys: await _e2eUnwrapKeyring(blob, code, user), remember: true };
    } finally {
      if (previous) previous.fill(0);
      if (raw) raw.fill(0);
    }
  });
}

// ─── Boot ─────────────────────────────────────────────────────────────────────

// r5 (codex-p3 e2e.js:1030): a lock (any device / this device) during a boot step must
// win: e2eOnVaultLocked wipes memory and the cached key, but cannot cancel a boot that
// is awaiting (a KDF, a server reply). The boot therefore re-checks the lock generation
// after every await that precedes installing or persisting a secret, and drops its
// results if a lock happened meanwhile. Boots are serialized (_e2eRun), so the next
// boot after an unlock starts only once this one has returned.
function _e2eBootStale(gen) { return gen !== E2E._lockGen; }
async function _e2eBoot(vaultPass, interactive = false) {
  // r6: a ready device does not boot again — after a reconnect it re-syncs instead.
  if (E2E.keyReady && E2E.identityReady) return E2E._resyncPending ? _e2eResync() : undefined;
  const gen = E2E._lockGen;
  E2E._booting = true;
  E2E._bootPhase = 'loading';
  E2E._bootStarted = Date.now();
  try {
    const user = _e2eUser();
    const kr = await _e2eReq({ type: 'e2e_load_keyring' }, 'e2e_keyring');
    if (_e2eBootStale(gen)) return;
    if (!kr) { E2E._bootPhase = 'failed'; return; }
    kr.peers = Array.isArray(kr.peers) ? kr.peers : [];
    kr.channels = Array.isArray(kr.channels) ? kr.channels : [];
    if (vaultPass) E2E._autoPrompted = true;
    E2E._krReceived = true;
    E2E._lockReason = null;
    if (kr.migrated) { E2E._migrated = true; E2E._legacyKey = null; }
    E2E._serverHints = { peers: (kr.peers || []).map(_e2eK), channels: (kr.channels || []).map(_e2eK), hasIdentity: !!kr.has_identity, migrated: !!kr.migrated };
    if (kr.blob && !_e2eKringValid(kr.blob)) {
      // r2: a malformed / tampered keyring is never unwrapped (no KDF run on server-chosen
      // parameters), never replaced, and does not cost this browser its cached key.
      E2E._bootPhase = 'locked'; E2E._lockReason = 'badkeyring';
      console.warn('[E2E] refusing an invalid E2E keyring from the server');
      _e2eSys(_e2eStatusTarget(), '⚠️ E2E: the server returned an INVALID E2E keyring (corrupted or tampered) — it was not used and E2E stays locked on this device. Nothing was changed.');
      _e2eToast('⚠️ E2E: the server returned an invalid E2E keyring — E2E stays locked on this device');
      try { updateE2EIndicator(_e2eStatusTarget()); } catch (_) {}
      return;
    }
    const opened = E2E.e2eEncKey
      ? { keys: { k: E2E.e2eEncKey, previous: E2E._previousKey, finalized: E2E._finalKeyring }, remember: false }
      : await _e2eOpenKeys(kr, user, gen, vaultPass, interactive);
    if (_e2eBootStale(gen)) return;
    if (!opened) {
      E2E._bootPhase = 'locked';
      if (!E2E._lockReason) E2E._lockReason = 'nokey';
      const h = E2E._serverHints;
      const inUse = kr.blob || h.hasIdentity || h.migrated || h.peers.length || h.channels.length || _e2eHints().dm.length || _e2eHints().ch.length;
      if (inUse && !E2E._autoPrompted && !vaultPass) {
        E2E._autoPrompted = true;
        setTimeout(() => { if (!E2E.keyReady && E2E._vaultUp !== false) e2ePromptDeviceUnlock(); }, 1200);
      } else if ((h.hasIdentity || kr.blob) && !E2E._lockedNoticeShown) {
        E2E._lockedNoticeShown = true;
        _e2eSys(_e2eStatusTarget(), '🔐 E2E is locked on this device — run /encrypt unlock to enable it');
      }
      try { updateE2EIndicator(_e2eStatusTarget()); } catch (_) {}
      return;
    }
    if (_e2eBootStale(gen)) return;
    E2E.e2eEncKey = opened.keys.k;
    E2E._previousKey = opened.keys.previous;
    E2E._finalKeyring = opened.keys.finalized;
    E2E._pepper = null;
    E2E.keyReady = true;
    if (opened.remember) {
      await _e2eIdbPutKey(user, opened.keys);
      // A lock during the write: the lock's forget may have run before it — remove it.
      if (_e2eBootStale(gen)) { try { await _e2eIdbDelKey(user); } catch (_) {} _e2eWipeMemory(); return; }
      _e2eBcPost({ t: 'key' });
    }
    _e2eCancelPrompt();   // the key arrived (e.g. from another tab) while we were asking
    if (!kr.migrated) {
      const ok = await _e2eMigrate(kr);
      if (_e2eBootStale(gen)) { _e2eWipeMemory(); return; }
      if (ok) {
        // r2: CAS on the keyring we migrated under — if it was replaced meanwhile, the
        // account is NOT marked migrated (the next unlock re-checks everything).
        const r = await _e2eStoreKeyring(kr.blob, true, kr.blob);
        if (r && r.ok && r.migrated) {
          kr.migrated = true; E2E._serverHints.migrated = true; E2E._migrated = true; E2E._legacyKey = null;
          console.log('[E2E] blobs re-wrapped under the client-held key (migration complete)');
        } else if (r && !r.ok) console.warn('[E2E] keyring changed during migration — not marking migrated');
      }
    }
    if (kr.migrated && E2E._previousKey && E2E._finalKeyring) {
      const done = await _e2eRewrapV2(gen, kr);
      if (_e2eBootStale(gen)) { _e2eWipeMemory(); return; }
      if (done) {
        E2E._previousKey = null;
        E2E._finalKeyring = null;
        E2E._spkBlob = null;
        E2E._sessionCache = Object.create(null);
        await _e2eIdbPutKey(user, { k: E2E.e2eEncKey });
        if (_e2eBootStale(gen)) { await _e2eIdbDelKey(user); _e2eWipeMemory(); return; }
      } else {
        _e2eSys(_e2eStatusTarget(), '🔐 Some E2E data still needs to be upgraded. CryptIRC will retry next time you unlock.');
      }
    }
    await _e2eLoadState();
    if (_e2eBootStale(gen)) { _e2eWipeMemory(); return; }
    await _e2eLoadIdentity(kr, gen);
    if (_e2eBootStale(gen)) { _e2eWipeMemory(); return; }
    _e2eWs({ type: 'e2e_load_trust' });
    _e2eWs({ type: 'e2e_list_channel_keys' });
    _e2eWs({ type: 'e2e_load_session', partner: '__spk__' });
    await _e2eRestoreSessions(gen);
    if (_e2eBootStale(gen)) { _e2eWipeMemory(); return; }
    if (E2E.identityReady) await e2eEnsureOTPKs();
    if (_e2eBootStale(gen)) { _e2eWipeMemory(); return; }
    E2E._bootPhase = 'ready';
    _e2eResyncDone();     // r6: a full boot loaded everything a re-sync would
    _e2eReleaseLockedHold();
    if (typeof showEncryptPanel === 'function' && document.getElementById('encrypt-overlay')?.classList.contains('show')) {
      showEncryptPanel();
    }
  } finally {
    E2E._booting = false;
    if (E2E._bootPhase === 'loading') E2E._bootPhase = 'failed';
    try { updateE2EIndicator(_e2eStatusTarget()); } catch (_) {}
  }
}

// One-time re-wrap of every legacy (server-key) blob under the client-held key.
// Idempotent + crash-safe: already-v2 blobs are skipped; the keyring was stored first;
// the server keeps accepting legacy writes and offering the legacy key until the
// caller marks the keyring migrated. Returns false if a legacy blob couldn't be read
// (so migration is retried on a later unlock instead of stranding it).
async function _e2eMigrate(kr) {
  let allOk = true;
  const L = E2E._legacyKey;
  // Identity
  const idEv = await _e2eReq({ type: 'e2e_load_identity' }, 'e2e_identity_blob');
  if (!idEv) allOk = false;
  if (idEv && idEv.blob && !_e2eWrappedBlob(idEv.blob)) {
    if (!L) allOk = false;
    else {
      try {
        const { pt } = await aesDecryptBlobEx(idEv.blob, 'identity');
        _e2eWs({ type: 'e2e_store_identity', blob: await aesEncryptBlob(pt, 'identity') });
      } catch (e) { console.warn('[E2E] migrate identity failed:', e); allOk = false; }
    }
  }
  // Session blobs: SPK/OTPK private halves and peer ratchets. Pre-upgrade peer ratchets
  // were never reloaded by the old client (write-only data); they are re-wrapped into
  // a reserved "__legacy__<nick>" slot — so the server's list of peer sessions only
  // names sessions that are really on — and restored lazily if that peer continues
  // the old ratchet.
  const sl = await _e2eReq({ type: 'e2e_list_sessions' }, 'e2e_session_list');
  if (!sl) allOk = false;
  for (const p of (sl && Array.isArray(sl.partners) ? sl.partners : [])) {
    const sev = await _e2eReq({ type: 'e2e_load_session', partner: p }, 'e2e_session', 6000, e => e.partner === p);
    if (!sev) { allOk = false; continue; }   // no reply (dropped/timeout): retry migration later
    const blob = sev.blob || '';
    if (!blob || _e2eWrappedBlob(blob)) continue;
    if (!L) { allOk = false; continue; }
    try {
      const { pt } = await aesDecryptBlobEx(blob, _e2eCtxSession(p));
      const name = p.startsWith('__') ? p : '__legacy__' + _e2eK(p);
      const nb = await aesEncryptBlob(pt, _e2eCtxSession(name));
      _e2eWs({ type: 'e2e_store_session', partner: name, blob: nb });
      if (name !== p) { _e2eWs({ type: 'e2e_delete_session', v: E2E_STORAGE_VERSION, partner: p }); delete E2E._sessionCache[p]; }
      else E2E._sessionCache[name] = nb;
      if (name === '__spk__') E2E._spkBlob = null;
    } catch (e) { console.warn('[E2E] migrate session failed:', p, e); allOk = false; }
  }
  // Channel PSKs: the e2e_channel_key handler re-wraps a legacy blob as soon as it reads
  // one; request each and wait for it to be processed.
  for (const ch of (kr.channels || [])) {
    const r = await _e2eReq({ type: 'e2e_load_channel_key', channel: ch }, 'e2e_channel_key_done', 8000, ev => ev.channel === ch);
    if (!r || r.legacyUnreadable) allOk = false;
  }
  if (!allOk) return false;
  // Verify before declaring the account migrated: every slot must now read back as v2
  // (a store can be shed by the server's per-socket budget; marking migrated with a
  // legacy blob left behind would make that blob unreadable for good).
  // r2 (codex-p1 HIGH): and every one must OPEN under the master key we hold — a v2
  // blob wrapped under some other key (a racing device) is not "migrated".
  const opens = async (blob, ctx) => { try { await aesDecryptBlobEx(blob, ctx); return true; } catch (_) { return false; } };
  const unreadable = [];
  const v1 = await _e2eReq({ type: 'e2e_load_identity' }, 'e2e_identity_blob');
  if (!v1 || (v1.blob && !_e2eWrappedBlob(v1.blob))) return false;
  if (v1.blob && !(await opens(v1.blob, 'identity'))) unreadable.push('identity');
  const sl2 = await _e2eReq({ type: 'e2e_list_sessions' }, 'e2e_session_list');
  if (!sl2) return false;
  for (const p of (Array.isArray(sl2.partners) ? sl2.partners : [])) {
    const sev = await _e2eReq({ type: 'e2e_load_session', partner: p }, 'e2e_session', 6000, e => e.partner === p);
    if (!sev || (sev.blob && !_e2eWrappedBlob(sev.blob))) return false;
    if (sev.blob && !(await opens(sev.blob, _e2eCtxSession(p)))) unreadable.push(p);
  }
  const kr2 = await _e2eReq({ type: 'e2e_load_keyring' }, 'e2e_keyring');
  if (!kr2 || kr2.blob !== kr.blob) return false;
  for (const ch of (kr2.channels || [])) {
    const r = await _e2eReq({ type: 'e2e_load_channel_key', channel: ch }, 'e2e_channel_key_done', 8000, ev => ev.channel === ch);
    if (!r || !r.v2) return false;
    if (r.ok === false) unreadable.push(ch);
  }
  if (unreadable.length) {
    console.warn('[E2E] migration check: blobs that do not open under this keyring:', unreadable.length);
    _e2eSys(_e2eStatusTarget(), '⚠️ E2E: some of your stored E2E data does not open with your current E2E key (written by another device during the upgrade?) — not finishing the upgrade yet; it is retried on the next unlock.');
    return false;
  }
  return true;
}

// Re-encrypt legacy v2 slots under the new master. Exact ciphertext matching lets
// one device finish the upgrade while another advances a session or rotates a PSK.
async function _e2eRewrapV2(gen, kr) {
  const rewrap = async (slot, name, ctx, event) => {
    if (!event || _e2eBootStale(gen)) return false;
    const expect = event.blob || '';
    if (!expect.startsWith(E2E_V2_BLOB)) return !expect || expect.startsWith(E2E_BLOB_PREFIX);
    try {
      const pt = await aesDecryptBlob(expect, ctx);
      let blob;
      try { blob = await aesEncryptBlob(pt, ctx); }
      finally { pt.fill(0); }
      if (_e2eBootStale(gen)) return false;
      const r = await _e2eReq({ type: 'e2e_rewrap_blob', slot, name, expect, blob },
        'e2e_blob_rewrapped', 6000, ev => ev.slot === slot && ev.name === name);
      return !!(r && r.ok);
    } catch (_) { return false; }
  };
  const identity = await _e2eReq({ type: 'e2e_load_identity' }, 'e2e_identity_blob');
  if (!(await rewrap('identity', '', 'identity', identity))) return false;
  const list = await _e2eReq({ type: 'e2e_list_sessions' }, 'e2e_session_list');
  if (!list || _e2eBootStale(gen)) return false;
  for (const name of list.partners || []) {
    const event = await _e2eReq({ type: 'e2e_load_session', partner: name }, 'e2e_session', 6000, ev => ev.partner === name);
    if (!(await rewrap('session', name, _e2eCtxSession(name), event))) return false;
  }
  const keyring = await _e2eReq({ type: 'e2e_load_keyring' }, 'e2e_keyring');
  if (!keyring || _e2eBootStale(gen)) return false;
  for (const name of keyring.channels || []) {
    const req = crypto.randomUUID();
    const event = await _e2eReq({ type: 'e2e_load_channel_key', channel: name, req }, 'e2e_channel_key', 6000, ev => ev.req === req);
    if (!(await rewrap('channel', name, _e2eCtxChan(name), event))) return false;
  }
  if (_e2eBootStale(gen)) return false;
  const result = await _e2eStoreKeyring(E2E._finalKeyring, true, kr.blob);
  const current = result && !result.ok ? result.blob : E2E._finalKeyring;
  if (!result || !current || _e2eBootStale(gen)) return false;
  if (!result.ok) {
    try {
      if (base64ToBytes(_e2eKringParse(current).w).length !== 60 ||
          !(await _e2eKeyringCheck(current, E2E.e2eEncKey, _e2eUser()))) return false;
    } catch (_) { return false; }
  }
  kr.blob = current;
  return true;
}

async function _e2eFetchSession(partner) {
  const ev = await _e2eReq({ type: 'e2e_load_session', partner }, 'e2e_session', 6000, e => e.partner === partner);
  return ev && ev.blob ? ev.blob : null;
}

// Authenticated state blob ("__state__" session slot): trust pins, which DM peers /
// channels have E2E on, PSK generations, own identity fingerprint, and a sequence
// number. The latest copy is ALSO kept on this device so the server can't roll it back.
function _e2eEmptyState() { return { v: 1, seq: 0, idfp: '', trust: {}, dm: {}, ch: {} }; }
async function _e2eDecodeState(blob) {
  try {
    const o = JSON.parse(new TextDecoder().decode(await aesDecryptBlob(blob, _e2eCtxSession('__state__'))));
    if (!o || o.v !== 1) return null;
    o.trust = o.trust || {}; o.dm = o.dm || {}; o.ch = o.ch || {};
    return o;
  } catch (_) { return null; }
}
// r2 (v-e2e NEW-2): the state blob used to be last-writer-wins: a tab or device that
// booted earlier (stale seq, no merge) uploaded its whole state and DROPPED the "E2E on"
// peers another tab had added, so after a reload those DMs went out in cleartext. Now
// every entry carries a version `n` and the state is MERGED (union, per entry the
// higher version; on a tie "on" wins — the safe side) on load and before every save,
// from this device's copy and the server's. Turning E2E off writes a tombstone
// ({on:0}) instead of deleting the entry, so only an explicit /encrypt off removes a
// peer. Local changes are kept as intents and re-applied on top of the merged state.
function _e2eMergeStateInto(dst, src) {
  if (!dst || !src || typeof src !== 'object') return false;
  let changed = false;
  const pick = (a, b, preferOn) => {
    const na = a ? (a.n | 0) : -1, nb = b ? (b.n | 0) : -1;
    if (nb > na) return b;
    if (na > nb) return a;
    if (preferOn && a && b && !a.on && b.on) return b;
    return a;
  };
  for (const sec of ['dm', 'ch']) {
    dst[sec] = dst[sec] || {};
    for (const [k, e] of Object.entries(src[sec] || {})) {
      if (!e || typeof e !== 'object') continue;
      const cur = dst[sec][k];
      let w = pick(cur, e, true);
      if (sec === 'ch') {
        const g = Math.max((cur && cur.g) | 0, e.g | 0);
        if (g && (w.g | 0) !== g) w = { ...w, g };
      }
      if (w !== cur) { dst[sec][k] = { ...w }; changed = true; }
    }
  }
  dst.trust = dst.trust || {};
  for (const [k, e] of Object.entries(src.trust || {})) {
    if (!e || typeof e !== 'object' || typeof e.fp !== 'string') continue;
    const cur = dst.trust[k];
    const w = pick(cur, e, false);
    if (w !== cur) { dst.trust[k] = { ...w }; changed = true; }
  }
  if (!dst.idfp && src.idfp) { dst.idfp = src.idfp; changed = true; }
  if ((src.seq | 0) > (dst.seq | 0)) dst.seq = src.seq | 0;
  return changed;
}
// Make in-memory views follow a merged state (pins accepted / made in another tab).
function _e2eApplyMergedState() {
  const st = E2E.state; if (!st) return;
  for (const [nick, t] of Object.entries(st.trust || {})) {
    if (!t || typeof t.fp !== 'string') continue;
    const ts = E2E.trustStore[nick];
    if (!ts || ts.server_seeded || ts.fingerprint !== t.fp) {
      const pending = ts && ts.pendingFingerprint && ts.pendingFingerprint !== t.fp ? ts.pendingFingerprint : null;
      E2E.trustStore[nick] = { fingerprint: t.fp, verified: !!t.ver, keyChanged: !!pending, pendingFingerprint: pending };
    } else if (!!ts.verified !== !!t.ver) ts.verified = !!t.ver;
  }
  for (const [ch, c] of Object.entries(st.ch || {})) { if (c && Number.isInteger(c.g)) E2E._chanGen[ch] = Math.max(E2E._chanGen[ch] || 0, c.g); }
  _e2eHintsRefresh();
}
// Record a local change: applied now, and again on top of whatever the next save merges in.
function _e2eStateOp(sec, k, fn) {
  if (!E2E.state) return;
  E2E.state[sec] = E2E.state[sec] || {};
  E2E.state[sec][k] = fn(E2E.state[sec][k]);
  (E2E._stateOps = E2E._stateOps || []).push({ sec, k, fn });
  e2eSaveState();
}
async function _e2eLoadState() {
  const srvBlob = await _e2eFetchSession('__state__');
  const srv = srvBlob ? await _e2eDecodeState(srvBlob) : null;
  const dev = _e2eDev();
  const loc = dev.st ? await _e2eDecodeState(dev.st) : null;
  const st = _e2eEmptyState();
  if (srv) _e2eMergeStateInto(st, srv);
  let upload = false;
  if (loc) {
    const grew = _e2eMergeStateInto(st, loc);
    if (!srv || grew || (loc.seq | 0) > (srv.seq | 0)) {
      upload = true;
      if (srv || srvBlob) console.warn('[E2E] this device has E2E state the server copy lacks — merged and re-uploading');
    }
  }
  E2E.state = st;
  if ((st.seq | 0) > (dev.seq | 0)) { dev.seq = st.seq | 0; _e2eDevSave(); }
  // Pins from the authenticated state are locally owned (not server_seeded).
  for (const [nick, t] of Object.entries(st.trust)) {
    if (!t || typeof t.fp !== 'string') continue;
    E2E.trustStore[nick] = { fingerprint: t.fp, verified: !!t.ver, keyChanged: false, pendingFingerprint: null };
  }
  _e2eApplyMergedState();
  if (upload) await e2eSaveState();
}
async function e2eSaveState() {
  if (!E2E.state || !E2E.keyReady) return;
  // Coalesce concurrent saves; each actual write gets a strictly larger seq.
  E2E._stateDirty = true;
  if (E2E._stateSaving) return E2E._stateSaving;
  E2E._stateSaving = (async () => {
    try {
      while (E2E._stateDirty) {
        E2E._stateDirty = false;
        await _e2eXLock('state', async () => {
          // Merge what other tabs (device copy) and devices (server copy) saved since.
          let grew = false;
          const dev = _e2eDev();
          if (dev.st) { const loc = await _e2eDecodeState(dev.st); if (loc) grew = _e2eMergeStateInto(E2E.state, loc) || grew; }
          const sb = await _e2eFetchSession('__state__');
          const srv = sb ? await _e2eDecodeState(sb) : null;
          if (srv) grew = _e2eMergeStateInto(E2E.state, srv) || grew;
          // Local intents win over what was merged in (version above it).
          const ops = E2E._stateOps || []; E2E._stateOps = [];
          for (const op of ops) { E2E.state[op.sec] = E2E.state[op.sec] || {}; E2E.state[op.sec][op.k] = op.fn(E2E.state[op.sec][op.k]); }
          if (grew) _e2eApplyMergedState();
          E2E.state.seq = Math.max(E2E.state.seq | 0, dev.seq | 0, (srv && srv.seq) | 0) + 1;
          const blob = await aesEncryptBlob(new TextEncoder().encode(JSON.stringify(E2E.state)), _e2eCtxSession('__state__'));
          _e2eWs({ type: 'e2e_store_session', partner: '__state__', blob });
          const d2 = _e2eDev(); d2.seq = E2E.state.seq; d2.st = blob; _e2eDevSave();
        });
      }
    } finally { E2E._stateSaving = null; }
  })();
  _e2eHintsRefresh();
  return E2E._stateSaving;
}
function _e2eStateSetDm(k, on, force = false) {
  if (!E2E.state) return;
  const cur = E2E.state.dm[k];
  if (!force && (on ? (cur && cur.on) : !(cur && cur.on))) return;
  _e2eStateOp('dm', k, (c) => ({ on: on ? 1 : 0, n: ((c && c.n) | 0) + 1 }));
}
function _e2eStateSetChan(k, on, g) {
  if (!E2E.state) return;
  _e2eStateOp('ch', k, (c) => ({ on: on ? 1 : 0, g: Math.max((c && c.g) | 0, g | 0), n: ((c && c.n) | 0) + 1 }));
}
function _e2eStateSetTrust(k) {
  if (!E2E.state) return;
  const t = E2E.trustStore[k];
  if (!t || t.server_seeded) return;
  const cur = E2E.state.trust[k];
  if (cur && cur.fp === t.fingerprint && !!cur.ver === !!t.verified) return;
  const fp = t.fingerprint, ver = !!t.verified;
  _e2eStateOp('trust', k, (c) => ({ fp, ver, t: (c && c.fp === fp && c.t) || Math.floor(Date.now() / 1000), n: ((c && c.n) | 0) + 1 }));
}

// ─── Identity keys ────────────────────────────────────────────────────────────

async function _e2eOwnFingerprint() {
  const dh = await exportPub(E2E.identityKeys.dhKeyPair.publicKey, 'ECDH');
  const sg = await exportPub(E2E.identityKeys.signKeyPair.publicKey, 'ECDSA');
  return computeIdentityFingerprint(dh, sg);
}

// Only ever runs for the reply to OUR e2e_load_identity (an unsolicited
// e2e_identity_blob pushed by the server is ignored), and NEVER regenerates the
// identity because a blob failed to decrypt or the server claimed there is none while
// we know one exists — that would let the server force a global re-TOFU at will.
async function _e2eLoadIdentity(kr, gen) {
  const ev = await _e2eReq({ type: 'e2e_load_identity' }, 'e2e_identity_blob');
  if (gen !== undefined && _e2eBootStale(gen)) return;
  if (!ev) { _e2eSys(_e2eStatusTarget(), '🔐 E2E identity did not load (timeout) — reload to retry'); return; }
  const blob = ev.blob || '';
  if (!blob) {
    if ((kr && kr.has_identity) || (E2E.state && E2E.state.idfp)) {
      _e2eSys(_e2eStatusTarget(), '⚠️ E2E: the server returned NO identity although this account has one — not generating a new one automatically. If your keys are really gone, run /encrypt reset-identity (peers will see a key change).');
      return;
    }
    console.log('[E2E] No identity blob — generating fresh keys');
    await e2eGenerateAndPublishIdentity();
    return;
  }
  try {
    const { pt, legacy } = await aesDecryptBlobEx(blob, 'identity');
    const obj = JSON.parse(new TextDecoder().decode(pt));
    const keys = await importIdentityKeys(obj);
    const fp = await computeIdentityFingerprint(await exportPub(keys.dhKeyPair.publicKey, 'ECDH'), await exportPub(keys.signKeyPair.publicKey, 'ECDSA'));
    if (gen !== undefined && _e2eBootStale(gen)) return;
    // r5 (codex-p3 e2e.js:1333): an identity whose fingerprint differs from the one
    // this account's authenticated E2E state says it uses now is NOT adopted silently —
    // that is what an old identity restored from a backup or replayed by the server
    // looks like (it still decrypts: same master key and context), and adopting it
    // reversed an identity reset. A reset on another device stores the new identity
    // and then the state with its fingerprint, so the normal cross-device and
    // new-device paths match (a device with no remembered fingerprint adopts as
    // before). The user is asked; until they accept, the identity is not used.
    const known = E2E.state && E2E.state.idfp;
    if (known && known !== fp && E2E._idAcceptFp !== fp) {
      const short = (x) => String(x).slice(0, 19);
      _e2eSys(_e2eStatusTarget(), `⚠️ E2E: the identity the server returned (fingerprint ${short(fp)}…) is NOT the one this account uses now (${short(known)}…). It was not used — answer the question to continue, or run /encrypt reset-identity.`);
      const msg = `⚠️ Your E2E identity changed back?\n\nThe server returned an identity with fingerprint:\n${fp}\n\nbut this account's encrypted state says your current identity is:\n${known}\n\nThis is what an OLD identity restored from a backup — or replayed by a compromised server — looks like. It can also happen if an identity reset on another device did not finish.\n\nUse the identity the server returned?`;
      _e2eAskDialog(msg).then((ok) => {
        if (!ok || (gen !== undefined && _e2eBootStale(gen)) || E2E.identityReady) return;
        E2E._idAcceptFp = fp;
        if (E2E.state) { E2E.state.idfp = fp; e2eSaveState(); }
        _e2eRun(() => _e2eBoot(null));       // load it now (and the steps that need it)
      }, () => {});
      return;
    }
    E2E.identityKeys = keys;
    if (legacy) _e2eWs({ type: 'e2e_store_identity', blob: await aesEncryptBlob(pt, 'identity') });
    if (E2E.state && E2E.state.idfp !== fp) { E2E.state.idfp = fp; e2eSaveState(); }
    E2E.identityReady = true;
    console.log('[E2E] Identity keys loaded');
  } catch (e) {
    console.error('[E2E] identity blob did not decrypt:', e);
    _e2eSys(_e2eStatusTarget(), '⚠️ E2E: your identity keys could not be decrypted — E2E is disabled on this device (NOT regenerating automatically). If they are really lost, run /encrypt reset-identity.');
  }
}

// r3 (codex-p3 MED e2e.js:1129): store a NEW identity only if none is stored yet, then
// read back what the server holds (same socket, so after the store): our blob → we won;
// another blob → another device's first unlock won the race. A store the server shed
// (per-socket budget) is retried once. → { state: 'won'|'lost'|'failed'|'noreply', blob }
async function _e2eStoreIdentityIfAbsent(blob) {
  for (let i = 0; i < 2; i++) {
    _e2eWs({ type: 'e2e_store_identity', blob, expect: '' });
    const ev = await _e2eReq({ type: 'e2e_load_identity' }, 'e2e_identity_blob');
    if (!ev) return { state: 'noreply' };
    if (ev.blob === blob) return { state: 'won' };
    if (ev.blob) return { state: 'lost', blob: ev.blob };
  }
  return { state: 'failed' };
}
async function _e2eSha256Hex(str) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)));
  return Array.from(d, b => b.toString(16).padStart(2, '0')).join('');
}
// opts.replace: /encrypt reset-identity (replaces the stored identity on purpose).
async function e2eGenerateAndPublishIdentity(opts = null) {
  const replace = !!(opts && opts.replace);
  const gen = E2E._lockGen;
  try {
    const dhKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
    );
    const signKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    const exported = await exportIdentityKeys({ dhKeyPair, signKeyPair });
    const blob     = await aesEncryptBlob(new TextEncoder().encode(JSON.stringify(exported)), 'identity');
    if (replace) {
      _e2eWs({ type: 'e2e_store_identity', blob });
    } else {
      // Two devices doing their first unlock at once used to BOTH install (and keep
      // using) their own identity and publish their own bundle; whichever wrote last
      // won on the server and the other one's sessions broke after a reload.
      const r = await _e2eStoreIdentityIfAbsent(blob);
      if (r.state === 'lost') {
        // The loser adopts the stored identity (same master key — the keyring is
        // compare-and-swapped too) and publishes NOTHING (no SPK/prekeys/bundle):
        // the winner's bundle is the one that matches the stored identity.
        try {
          const { pt } = await aesDecryptBlobEx(r.blob, 'identity');
          E2E.identityKeys = await importIdentityKeys(JSON.parse(new TextDecoder().decode(pt)));
        } catch (e) {
          E2E.identityKeys = null;
          _e2eSys(_e2eStatusTarget(), '⚠️ E2E: another device created your E2E identity at the same time and it does not open here — reload this page to retry.');
          return;
        }
        const fp = await _e2eOwnFingerprint();
        if (E2E.state && E2E.state.idfp !== fp) { E2E.state.idfp = fp; e2eSaveState(); }
        E2E.identityReady = true;
        console.log('[E2E] another device created the E2E identity first — using it');
        return;
      }
      if (r.state !== 'won') {
        E2E.identityKeys = null;
        if (_e2eLockedMeanwhile(gen)) { console.log('[E2E] identity setup stopped: the vault was locked meanwhile'); return; }
        _e2eSys(_e2eStatusTarget(), '🔐 E2E: your new E2E identity could not be saved on the server (' + (r.state === 'noreply' ? 'no answer' : 'refused') + ') — E2E is not available yet; reload to retry.');
        return;
      }
    }
    E2E.identityKeys = { dhKeyPair, signKeyPair };
    await e2ePublishBundle(await _e2eSha256Hex(blob));
    if (E2E.state) { E2E.state.idfp = await _e2eOwnFingerprint(); await e2eSaveState(); }
    E2E.identityReady = true;
    console.log('[E2E] Generated and published fresh identity keys');
  } catch(e) {
    if (_e2eLockedMeanwhile(gen)) console.log('[E2E] identity setup stopped: the vault was locked meanwhile (' + (e && (e.message || e.name) || e) + ')');
    else console.error('[E2E] Key generation failed:', e);
    E2E.identityKeys = null;
  }
}

// idHash (r3): SHA-256 hex of the identity blob this bundle belongs to — the server
// refuses the bundle if a different identity is stored.
async function e2ePublishBundle(idHash = null) {
  if (!E2E.identityKeys) return;
  const { dhKeyPair, signKeyPair } = E2E.identityKeys;

  const dhPub   = await exportPub(dhKeyPair.publicKey,   'ECDH');
  const signPub = await exportPub(signKeyPair.publicKey, 'ECDSA');

  // Signed prekey
  const spkPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
  );
  const spkPub      = await exportPub(spkPair.publicKey, 'ECDH');
  const spkPubBytes = base64ToBytes(spkPub);
  const spkSig      = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, signKeyPair.privateKey, spkPubBytes
  );

  // #25/#84: persist the SPK private key keyed by a stable spk_id, and select it by
  // the header's spk_id on respond. The id-keyed blob (`__spk__<id>`) lets us retain
  // prior SPKs; the `__spk__` alias is the current SPK. (C1: each slot is its own blob
  // because the AAD binds the slot name.)
  let spkId = 1;
  if (E2E._spkBlob) {
    try { const o = JSON.parse(new TextDecoder().decode(await aesDecryptBlob(E2E._spkBlob, _e2eCtxSession('__spk__')))); if (Number.isInteger(o.spk_id)) spkId = o.spk_id + 1; } catch(_) {}
  }
  const spkPrivJwk = await crypto.subtle.exportKey('jwk', spkPair.privateKey);
  const spkPlain   = new TextEncoder().encode(JSON.stringify({ spk_priv: spkPrivJwk, spk_pub: spkPub, spk_id: spkId }));
  const spkBlob    = await aesEncryptBlob(spkPlain, _e2eCtxSession('__spk__'));
  const spkBlobId  = await aesEncryptBlob(spkPlain, _e2eCtxSession(`__spk__${spkId}`));
  _e2eWs({ type: 'e2e_store_session', partner: '__spk__', blob: spkBlob });
  _e2eWs({ type: 'e2e_store_session', partner: `__spk__${spkId}`, blob: spkBlobId });
  E2E._spkBlob = spkBlob;
  E2E._sessionCache[`__spk__${spkId}`] = spkBlobId;

  // One-time prekeys — generate and store private halves (C7)
  const otpks = [];
  for (let i = 0; i < OTPK_BATCH_SIZE; i++) {
    const opkPair   = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
    );
    // L8: use crypto.getRandomValues for key_id instead of Date.now()
    const keyIdBytes = crypto.getRandomValues(new Uint8Array(4));
    const keyId      = new DataView(keyIdBytes.buffer).getUint32(0, false);
    const opkPub     = await exportPub(opkPair.publicKey, 'ECDH');
    const opkPrivJwk = await crypto.subtle.exportKey('jwk', opkPair.privateKey);
    const opkBlob    = await aesEncryptBlob(
      new TextEncoder().encode(JSON.stringify({ opk_priv: opkPrivJwk, key_id: keyId })), _e2eCtxSession(`__otpk__${keyId}`)
    );
    otpks.push({ key_id: keyId, public_key: opkPub });
    // Store each OTPK private key as a separate session blob keyed by id
    _e2eWs({ type: 'e2e_store_session', partner: `__otpk__${keyId}`, blob: opkBlob });
  }

  if (_e2eKeyGone()) { console.log('[E2E] key bundle not published: the vault was locked meanwhile'); return; }
  _e2eWs({
    type: 'e2e_publish_bundle',
    v: 3,
    ...(idHash ? { id_hash: idHash } : {}),
    bundle: {
      identity_dh_key:   dhPub,
      identity_sign_key: signPub,
      signed_prekey: {
        key_id:     spkId,
        public_key: spkPub,
        signature:  bytesToBase64(new Uint8Array(spkSig)),
      },
      one_time_prekeys: otpks,
    },
  });
  E2E._spkId = spkId;
}

// L7: Fix — query OTPK count directly via a dedicated message type instead
// of piggybacking on e2e_list_channel_keys which doesn't check OTPK count.
async function e2eEnsureOTPKs() {
  _e2eWs({ type: 'e2e_check_otpk_count' });
}

// ─── X3DH: Initiate (sender) ──────────────────────────────────────────────────

async function x3dhInitiate(bundle) {
  const { dhKeyPair, signKeyPair } = E2E.identityKeys;

  // Verify SPK signature
  const spkPubBytes = base64ToBytes(bundle.signed_prekey.public_key);
  const spkSigBytes = base64ToBytes(bundle.signed_prekey.signature);
  const theirSignPub = await importPub(bundle.identity_sign_key, 'ECDSA');
  const valid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' }, theirSignPub, spkSigBytes, spkPubBytes
  );
  if (!valid) throw new Error('SPK signature invalid — possible MITM');

  const ephPair  = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
  );
  const theirIK  = await importPub(bundle.identity_dh_key,         'ECDH');
  const theirSPK = await importPub(bundle.signed_prekey.public_key, 'ECDH');

  // X3DH: DH1=DH(IK_A,SPK_B), DH2=DH(EK_A,IK_B), DH3=DH(EK_A,SPK_B)
  const dh1 = await ecdh(dhKeyPair.privateKey, theirSPK);
  const dh2 = await ecdh(ephPair.privateKey,   theirIK);
  const dh3 = await ecdh(ephPair.privateKey,   theirSPK);

  let dh4 = new Uint8Array(0);
  let usedOTPKId = null;
  if (bundle.one_time_prekey) {
    const theirOPK = await importPub(bundle.one_time_prekey.public_key, 'ECDH');
    dh4 = await ecdh(ephPair.privateKey, theirOPK);
    usedOTPKId = bundle.one_time_prekey.key_id;
  }

  // #12: cryptographically bind BOTH identities into the X3DH root key by
  // folding the canonical (initiator, responder) identity encoding into the
  // HKDF info. We are the initiator (A); the bundle owner is the responder (B).
  // The responder reconstructs the byte-identical AD in x3dhRespond, so both
  // derive the same root key. identityAD is also pinned on the session and
  // reused as the per-message AEAD AD.
  const myDhPub   = await exportPub(dhKeyPair.publicKey,   'ECDH');
  const mySignPub = await exportPub(signKeyPair.publicKey, 'ECDSA');
  const identAD   = e2eIdentityAD(
    myDhPub, mySignPub,                                  // initiator (us)
    bundle.identity_dh_key, bundle.identity_sign_key      // responder (them)
  );

  // #81: prepend the X3DH F constant (32 bytes of 0xFF) to the IKM as the spec
  // mandates for the Curve25519/P-256 X3DH KDF. #26 version marker: info is now v2.
  const ikm          = concat(X3DH_F_CONSTANT, dh1, dh2, dh3, dh4);
  const sharedSecret = await hkdf(ikm, concat(new TextEncoder().encode('X3DH-CryptIRC-v2'), identAD), 64);
  const ephPub       = await exportPub(ephPair.publicKey, 'ECDH');
  return { sharedSecret, ephemeralPub: ephPub, usedOTPKId, identityAD: bytesToBase64(identAD) };
}

// ─── X3DH: Respond (receiver) ─────────────────────────────────────────────────

async function x3dhRespond(x3dhHeader) {
  const { dhKeyPair, signKeyPair } = E2E.identityKeys;

  // #25: select the SPK private half named by the header's spk_id, not "whatever the
  // current SPK is". Try the id-keyed blob first (so a rotated/retained prior SPK still
  // resolves); fall back to the current __spk__ blob (covers the single-SPK case and
  // headers that omit spk_id). Refuse if neither resolves rather than guessing.
  let spkRaw = null, spkSlot = '__spk__';
  const wantId = (x3dhHeader.spk_id != null && Number.isInteger(x3dhHeader.spk_id)) ? x3dhHeader.spk_id : null;
  if (x3dhHeader.spk_id != null && wantId === null) throw new Error('bad spk_id');
  if (wantId !== null) {
    spkRaw = await loadSessionBlobFromCache(`__spk__${wantId}`);
    if (!spkRaw) { delete E2E._sessionCache[`__spk__${wantId}`]; spkRaw = await loadSessionBlobFromCache(`__spk__${wantId}`); }  // one retry (transient miss)
    if (spkRaw) spkSlot = `__spk__${wantId}`;
  }
  if (!spkRaw) {
    if (!E2E._spkBlob) {
      console.warn('[E2E] SPK blob not in memory, requesting...');
      // #48: event-driven wait (see loadSessionBlobFromCache) instead of a 3s
      // spin-poll. The __spk__ e2e_session reply sets E2E._spkBlob and wakes this
      // waiter; a miss resolves immediately rather than blocking the pipeline 3s.
      await loadSessionBlobFromCache('__spk__');
    }
    spkRaw = E2E._spkBlob;
  }
  if (!spkRaw) throw new Error('SPK blob not loaded — cannot respond to X3DH');
  const spkObj  = JSON.parse(new TextDecoder().decode(await aesDecryptBlob(spkRaw, _e2eCtxSession(spkSlot))));
  // r2 (agy-p3 MED e2e.js:964): the fallback to the CURRENT signed prekey is only right
  // when it IS the one the initiator used. Otherwise the root keys would silently
  // diverge (generic "decryption failed" on both sides): abort distinctly instead, like
  // a missing one-time prekey. (Every SPK this device published is kept under its id,
  // so this means its blob is gone from the server, or the header is not ours.)
  if (wantId !== null && Number.isInteger(spkObj.spk_id) && spkObj.spk_id !== wantId) {
    throw new Error(`E2E_SPK_MISSING: the signed prekey #${wantId} this key exchange used is not available on this account`);
  }
  const spkPriv = await crypto.subtle.importKey(
    'jwk', spkObj.spk_priv, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']
  );

  const theirIK  = await importPub(x3dhHeader.sender_ik,    'ECDH');
  const theirEph = await importPub(x3dhHeader.ephemeral_pub, 'ECDH');

  const dh1 = await ecdh(spkPriv,              theirIK);
  const dh2 = await ecdh(dhKeyPair.privateKey, theirEph);
  const dh3 = await ecdh(spkPriv,              theirEph);

  // C7/#29: load OTPK private key from server if one was used. If the initiator
  // committed to a DH4 (used_otpk_id present) but we CANNOT load that OTPK blob, the
  // root keys would diverge → a generic "[decryption failed]" indistinguishable from
  // tampering. Instead ABORT with a distinct error. Crucially, we do NOT delete the
  // OTPK here — deletion happens only after the first message authenticates (the
  // caller marks it consumed), so a transient load miss / multi-device race doesn't
  // permanently destroy a still-needed OTPK.
  let dh4 = new Uint8Array(0);
  let consumedOtpkId = null;
  if (x3dhHeader.used_otpk_id != null) {
    if (!Number.isInteger(x3dhHeader.used_otpk_id)) throw new Error('bad used_otpk_id');
    const otpkBlob = await loadSessionBlobFromCache(`__otpk__${x3dhHeader.used_otpk_id}`);  // now async
    if (!otpkBlob) {
      throw new Error('E2E_OTPK_MISSING: consumed one-time prekey blob unavailable — cannot complete X3DH (try re-establishing)');
    }
    const otpkObj  = JSON.parse(new TextDecoder().decode(await aesDecryptBlob(otpkBlob, _e2eCtxSession(`__otpk__${x3dhHeader.used_otpk_id}`))));
    const otpkPriv = await crypto.subtle.importKey(
      'jwk', otpkObj.opk_priv, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']
    );
    dh4 = await ecdh(otpkPriv, theirEph);
    consumedOtpkId = x3dhHeader.used_otpk_id;
  }

  // #12: reconstruct the byte-identical identity AD the initiator used. We are
  // the responder; the header's sender is the initiator. The initiator's dh
  // identity is x3dhHeader.sender_ik and its sign identity is
  // x3dhHeader.sender_sign_ik (added to the header so this binding is mutual).
  // e2eIdentityAD sorts the two identity pairs canonically, so passing the same
  // four keys (regardless of which we call "ours") yields the same bytes the
  // initiator computed. This folds into the HKDF info so both peers derive the
  // same root key, and is pinned on the session for the per-message AEAD AD.
  // #25: a non-empty signing identity key is mandatory (the establishment helper
  // already enforces this; guard here too so no responder path can derive an AD
  // over a dh-only identity).
  if (!x3dhHeader.sender_sign_ik) throw new Error('X3DH header missing sender_sign_ik');
  const myDhPub   = await exportPub(dhKeyPair.publicKey,   'ECDH');
  const mySignPub = await exportPub(signKeyPair.publicKey, 'ECDSA');
  const identAD   = e2eIdentityAD(
    x3dhHeader.sender_ik, x3dhHeader.sender_sign_ik,        // initiator (them)
    myDhPub, mySignPub                                      // responder (us)
  );

  // #81/#26: F constant + v2 info, byte-identical to x3dhInitiate so both peers
  // derive the same root key.
  const ikm = concat(X3DH_F_CONSTANT, dh1, dh2, dh3, dh4);
  const ss = await hkdf(ikm, concat(new TextEncoder().encode('X3DH-CryptIRC-v2'), identAD), 64);
  // #29: report which OTPK we consumed; the caller deletes it only AFTER the session
  // is successfully established (not mid-derivation), so a transient failure can't
  // destroy a still-needed OTPK and leave the root keys diverged.
  // P4 (#25/#84): return the SPK material we actually selected by spk_id so the
  // ratchet seeds its initial DHs from THIS SPK (the one the initiator pinned as
  // DHr), not whatever the current _spkBlob happens to be. With SPK rotation
  // disabled these coincide; once #84 is enabled a non-current SPK would otherwise
  // make the responder's first reply undecryptable.
  return {
    sharedSecret: ss,
    identityAD: bytesToBase64(identAD),
    consumedOtpkId,
    selectedSpk: { pub: spkObj.spk_pub, priv: spkObj.spk_priv },
  };
}

// ─── Responder establishment (shared by all 3 X3DH responder paths) ──────────
//
// #1: Every responder path (inline [e2ex3dh] — single-line or fragmented —, relayed
// e2e_x3dh_header, and the header-with-envelope path) MUST authenticate the claimed
// sender identity BEFORE establishing — otherwise the server (which distributes bundles
// AND relays X3DH headers) can substitute its own identity_ik and silently MITM the
// responder direction while the user sees "session established".
//
// This single helper is used by all of them so they cannot drift apart:
//   * computes the TOFU fingerprint over BOTH identity keys (dh + sign, #11),
//   * on a CHANGED key: shows the key-change warning and REFUSES to establish — and
//     (C2/H5) leaves the pin AND any live session untouched,
//   * on first-use (tofu): records the pin exactly like the initiator side,
//   * runs x3dhRespond + ratchetInitRecv, pinning theirIdentityPub (#2) and the
//     identity-binding AD (#12) on the session.
// Returns { ok, why } — why ∈ replay | changed | rejected | deferred | invalid | ratelimited.
// True if `name` SANITIZES (the server's exact filter: keep [A-Za-z0-9_-]) to a key
// in the reserved internal namespace ('__spk__' / '__otpk__<id>' / '__state__'). Used
// to refuse a peer nick that would collide with the user's own private-key blob
// filenames. The ASCII keep-set is a subset of the server's, so this can never
// UNDER-reject a real collision; a legit peer nick never sanitizes to a '__' prefix.
function _e2eReservedNamespace(name){
  return String(name).replace(/[^A-Za-z0-9_-]/g, '').startsWith('__');
}
// #47: canonical byte-encoding of the X3DH header fields the sender signs with its
// ECDSA identity (sender_sign_ik) and the responder verifies BEFORE pinning, so a relay
// cannot flip the sign-key half of the TOFU pin on first contact. Sender and verifier
// build this from the SAME four header fields; '\n' is a safe separator (base64 pubkeys
// never contain it, spk_id/used_otpk_id are integers or null). Domain-separated.
function _x3dhHeaderSigMsg(senderIk, ephemeralPub, spkId, usedOtpkId) {
  return new TextEncoder().encode(
    'CryptIRC-X3DH-HDR-v1\n' +
    String(senderIk || '') + '\n' +
    String(ephemeralPub || '') + '\n' +
    (spkId == null ? '' : String(spkId)) + '\n' +
    (usedOtpkId == null ? '' : String(usedOtpkId))
  );
}
// Serialised per peer (same lock as the ratchet), so the relayed copy and the IRC copy
// of one header can't both run the X3DH respond (double OTPK use / double prompt).
async function e2eEstablishResponderSession(from, header, opts = {}) {
  return _withRatchetLock(_e2eK(from), () => _e2eEstablishInner(from, header, opts));
}
async function _e2eEstablishInner(from, header, opts = {}) {
  const nk = _e2eK(from);
  // SECURITY: peer ratchet sessions share the server-side e2e/sessions namespace with
  // the user's OWN internal key blobs ('__spk__', '__otpk__<id>', '__state__'). Test
  // the SERVER-SANITIZED form (see _e2eReservedNamespace). (saveSession enforces too.)
  if (_e2eReservedNamespace(nk)) {
    console.warn('[E2E] refusing reserved-namespace peer:', from);
    return { ok: false, why: 'invalid' };
  }
  if (!header || typeof header !== 'object' || !header.sender_ik) {
    console.warn('[E2E] responder establish: missing sender_ik');
    return { ok: false, why: 'invalid' };
  }
  // REPLAY GUARD: a header that already established the live session (same ephemeral —
  // x3dhInitiate generates a new ephemeral every time, a replay/duplicate reuses it) is
  // an idempotent no-op instead of resetting the receive chain. The initiator re-sends
  // its header (relay + inline) until it hears back, so duplicates are normal.
  const _existing = opts.alt ? null : E2E.dmSessions[nk];
  if (_existing && header.ephemeral_pub
      && (_existing.establishEph === header.ephemeral_pub
          || (Array.isArray(_existing.priorEstablishEphs)
              && _existing.priorEstablishEphs.includes(header.ephemeral_pub)))) {
    return { ok: true, why: 'replay' };
  }
  // #25: REQUIRE a non-empty signing identity key so the pin always covers BOTH keys.
  if (!header.sender_sign_ik || !header.sender_ik) {
    console.warn('[E2E] refusing X3DH from', from, '— missing identity key(s)');
    return { ok: false, why: 'invalid' };
  }
  // #47: verify the ECDSA signature over sender_ik||ephemeral_pub||spk_id||used_otpk_id
  // BEFORE pinning; refuse on any missing/invalid/error.
  if (!header.sender_sign_sig) {
    console.warn('[E2E] refusing X3DH from', from, '— missing header signature');
    return { ok: false, why: 'invalid' };
  }
  try {
    const _signPub = await importPub(header.sender_sign_ik, 'ECDSA');
    const _sigOk = await crypto.subtle.verify(
      { name:'ECDSA', hash:'SHA-256' }, _signPub,
      base64ToBytes(header.sender_sign_sig),
      _x3dhHeaderSigMsg(header.sender_ik, header.ephemeral_pub, header.spk_id, header.used_otpk_id)
    );
    if (!_sigOk) {
      console.warn('[E2E] refusing X3DH from', from, '— header signature invalid (possible relay tamper)');
      return { ok: false, why: 'invalid' };
    }
  } catch (e) {
    console.warn('[E2E] refusing X3DH from', from, '— header signature verify error:', e && e.message);
    return { ok: false, why: 'invalid' };
  }
  // #11/#25: pin BOTH identity keys (dh + sign).
  const fp    = await computeIdentityFingerprint(header.sender_ik, header.sender_sign_ik);
  const trust = await e2eCheckTrust(from, fp);

  // #1/C2: a changed identity must NOT silently re-establish. Warn and refuse; the pin
  // and the live session (if any) stay exactly as they were.
  if (trust.keyChanged) {
    e2eShowKeyChangeWarning(from, fp, trust.firstWarning);
    return { ok: false, why: 'changed' };
  }
  if (trust.status === 'rejected') {
    console.warn('[E2E] responder establish refused — unconfirmed identity:', from);
    return { ok: false, why: 'rejected' };
  }

  // #3: DoS hardening for X3DH RE-establishment over an ALREADY-LIVE session. A header
  // that arrives ALONE cannot be authenticated (only its first message can), so it must
  // NOT overwrite a live session: defer to the header+envelope path, which commits the
  // new session only if its first message decrypts. Envelope-driven re-establishment is
  // rate-limited per peer.
  if (_existing && !_existing._unusable) {
    if (!opts.withEnvelope) {
      console.warn('[E2E] deferring header-only X3DH re-establishment for live session:', from);
      return { ok: false, why: 'deferred' };
    }
    const _now = Date.now();
    E2E._reestablishLog = E2E._reestablishLog || Object.create(null);
    const _log = (E2E._reestablishLog[nk] || []).filter(t => _now - t < 60000);
    if (_log.length >= 10) {
      console.warn('[E2E] refusing X3DH re-establishment — rate limit exceeded for', from);
      E2E._reestablishLog[nk] = _log;
      return { ok: false, why: 'ratelimited' };
    }
    _log.push(_now);
    E2E._reestablishLog[nk] = _log;
  }

  const { sharedSecret, identityAD, consumedOtpkId, selectedSpk } = await x3dhRespond(header);
  // #2: pin the initiator's long-term identity DH pub (header.sender_ik). Pin the
  // establishing ephemeral for the replay guard. P4: seed the ratchet's initial DHs from
  // the spk_id-selected SPK. opts.alt: build the session WITHOUT installing it (glare).
  const sess = await ratchetInitRecv(nk, sharedSecret, header.sender_ik, identityAD, header.ephemeral_pub, selectedSpk,
                                     { noInstall: !!opts.alt, theirSignPub: header.sender_sign_ik });
  if (opts.alt) { E2E._glareAlt = E2E._glareAlt || Object.create(null); E2E._glareAlt[nk] = sess; }
  // #29: now that the session is established (and x3dhRespond didn't abort on a
  // missing OTPK), it's safe to consume the one-time prekey.
  if (consumedOtpkId != null) {
    _e2eWs({ type: 'e2e_delete_session', v: E2E_STORAGE_VERSION, partner: `__otpk__${consumedOtpkId}` });
    delete E2E._sessionCache[`__otpk__${consumedOtpkId}`];
  }
  if (!opts.alt) _e2eStateSetDm(nk, true);
  return { ok: true, why: '' };
}

// ─── Session blob cache (for SPK and OTPKs loaded async) ─────────────────────

E2E._sessionCache = Object.create(null);  // partner → raw blob string (null prototype)

async function loadSessionBlobFromCache(partner) {
  if (E2E._sessionCache[partner]) return E2E._sessionCache[partner];
  // #48: event-driven, not a 3s spin-poll. The server ALWAYS replies to
  // e2e_load_session with an e2e_session event (the blob on a hit, an empty
  // string on a miss), so resolve the instant that reply is handled. The timeout is
  // only a dead-connection backstop.
  _e2eWs({ type: 'e2e_load_session', partner });
  return await new Promise(resolve => {
    if (E2E._sessionCache[partner]) { resolve(E2E._sessionCache[partner]); return; }
    if (!E2E._sessionBlobWaiters) E2E._sessionBlobWaiters = Object.create(null);
    const list = E2E._sessionBlobWaiters[partner] || (E2E._sessionBlobWaiters[partner] = []);
    let entry;
    const timeout = setTimeout(() => {
      const arr = E2E._sessionBlobWaiters[partner];
      if (arr) {
        const idx = arr.indexOf(entry);
        if (idx >= 0) arr.splice(idx, 1);
        if (arr.length === 0) delete E2E._sessionBlobWaiters[partner];
      }
      resolve(E2E._sessionCache[partner] || null);
    }, 3000);
    entry = (blob) => { clearTimeout(timeout); resolve(blob || null); };
    list.push(entry);
  });
}

// #48: resolve every pending loadSessionBlobFromCache waiter for `partner` as
// soon as the server's e2e_session reply is handled (hit -> blob, miss -> null).
function _e2eResolveBlobWaiters(partner, blob) {
  const arr = E2E._sessionBlobWaiters && E2E._sessionBlobWaiters[partner];
  if (!arr) return;
  delete E2E._sessionBlobWaiters[partner];
  for (const cb of arr) { try { cb(blob); } catch (_) {} }
}

// ─── Session restore (reload) ─────────────────────────────────────────────────

// Install a stored ratchet session for `nk` (lowercased) if it is not older than what
// this device has already seen (persistent epoch high-water mark) — a server can't
// roll a session back to replay old ciphertexts. Returns the installed session or null.
async function _e2eInstallStoredSession(nk, blob, slot = null, opts = null) {
  if (!blob) return null;
  return _withRatchetLock(nk, () => _e2eInstallStoredInner(nk, blob, slot, opts));
}
// opts.hint (r2 security review — e2e_session_moved): the server merely SAYS another
// device moved this session on. Its blob is installed only if its epoch is STRICTLY
// newer than everything this device has seen for the peer (live session, page and
// device high-water marks) and it continues the same identity binding; the epoch is
// never raised and nothing is re-saved, so a replayed older blob can't be laundered.
// The buffered skipped / recent message keys of the live session are kept.
// opts.quiet (r3): a check after a reload / reconnect, not a server notice — no
// console noise when the stored copy is not newer, no "used on two devices" warning.
async function _e2eInstallStoredInner(nk, blob, slot = null, opts = null) {
    const hint = !!(opts && opts.hint);
    const quiet = !!(opts && opts.quiet);
    try {
      const { pt, legacy } = await aesDecryptBlobEx(blob, _e2eCtxSession(slot || nk));
      const session = JSON.parse(new TextDecoder().decode(pt));
      if (!session || typeof session !== 'object' || !session.RK) return null;
      const hwm = Math.max(E2E._sessionEpoch[nk] || 0, _e2eDev().ep[nk] || 0);
      if (hint) {
        const cur = E2E.dmSessions[nk];
        const curEp = cur ? (cur.epoch || 0) : 0;
        if (legacy || !((session.epoch || 0) > Math.max(hwm, curEp))) {
          if (!quiet) console.warn('[E2E] ignoring a "session moved" hint: the stored copy for', nk, 'is not newer (epoch', session.epoch, '≤', Math.max(hwm, curEp), ')');
          return null;
        }
        let replaced = false;
        if (cur && !cur._unusable && (cur.theirIdentityPub !== session.theirIdentityPub || cur.identityAD !== session.identityAD)) {
          // r7 (codex-p3 e2e.js:1375): a different identity binding is taken only when the
          // stored copy is bound to the identity this account pins NOW and the live session
          // is not — the peer's replacement identity was accepted on another device, which
          // then set up this session with it.
          const tr = E2E.trustStore[nk];
          const pinNow = tr && !tr.server_seeded ? tr.fingerprint : null;
          const newFp = await _e2eSessFp(session), curFp = await _e2eSessFp(cur);
          // r8 (agy-flash e2e.js:2076): a pre-#11 pin hashes the DH key only — the same
          // fallback as _e2eSessPinMismatch.
          const dhFp = async (x) => x && x.theirIdentityPub ? computeIdentityFingerprint(x.theirIdentityPub, null) : null;
          const newOk = !!pinNow && (newFp === pinNow || await dhFp(session) === pinNow);
          const curOk = !!pinNow && (curFp === pinNow || await dhFp(cur) === pinNow);
          if (!(newOk && !curOk)) {
            console.warn('[E2E] ignoring a "session moved" hint: different identity binding for', nk);
            return null;
          }
          replaced = true;
          console.log('[E2E] taking over the session with', nk, 'bound to its accepted replacement identity');
        }
        if (!replaced && !quiet && cur && !cur._unusable && (cur.DHr !== session.DHr || cur.CKr !== session.CKr || (cur.Nr | 0) !== (session.Nr | 0))) {
          _e2eSys(nk, `⚠️ Your encrypted conversation with ${nk} is also active on another device — a message may not decrypt on one of them (using two devices at once in one E2E conversation is not fully supported).`);
        }
        session.nick = nk;
        // (a replaced session's buffered keys belong to the previous identity — not kept)
        session.skipped = Object.assign({}, session.skipped || {}, (!replaced && cur && cur.skipped) || {});
        session.recent = Object.assign({}, (!replaced && cur && cur.recent) || {});
        E2E.dmSessions[nk] = session;
        E2E._sessionEpoch[nk] = Math.max(E2E._sessionEpoch[nk] || 0, session.epoch || 0);
        return session;
      }
      if ((session.epoch || 0) < hwm) {
        console.warn('[E2E] refusing stale session blob for', nk, '(epoch', session.epoch, '<', hwm, ')');
        _e2eSys(nk, `⚠️ E2E: the server returned an OLD copy of your session with ${nk} (possible replay) — refused. /encrypt on ${nk} to start a fresh session.`);
        const live = E2E.dmSessions[nk];
        if (!live) E2E.dmSessions[nk] = { nick: nk, _unusable: 'session state was rolled back — re-establish with /encrypt on', epoch: hwm };
        return null;
      }
      const live = E2E.dmSessions[nk];
      if (live && !live._unusable && (live.epoch || 0) >= (session.epoch || 0)) return live;
      session.nick = nk;
      session.skipped = session.skipped || {};
      E2E.dmSessions[nk] = session;
      E2E._sessionEpoch[nk] = Math.max(E2E._sessionEpoch[nk] || 0, session.epoch || 0);
      if (legacy) await saveSession(nk, session);
      return session;
    } catch (e) { console.warn('[E2E] Failed to load session:', nk, e); return null; }
}
async function _e2eRestoreSessions(gen) {
  const dm = (E2E.state && E2E.state.dm) || {};
  // r2 (NEW-2): also peers with a stored session on the server that the state does not
  // explicitly turn off (a state written by an older/stale tab may lack them).
  const names = new Set(Object.keys(dm).filter(nk => dm[nk] && dm[nk].on));
  for (const nk of ((E2E._serverHints && E2E._serverHints.peers) || [])) if (!dm[nk]) names.add(nk);
  for (const nk of names) {
    if (gen !== undefined && _e2eBootStale(gen)) return;   // r5: locked meanwhile
    if (E2E.dmSessions[nk]) { _e2eMarkMaybeMoved(nk); continue; }
    await _withRatchetLock(nk, async () => {});        // a newer copy from another tab?
    const blob = await _e2eFetchSession(nk);
    if (!blob) continue;
    if (gen !== undefined && _e2eBootStale(gen)) return;
    if (E2E.dmSessions[nk]) {
      // r3 (w-web MED e2e.js:1657): this browser's own copy was adopted, but another
      // DEVICE may have sent since (its "session moved" notice was lost with the
      // reload) — then the server holds a NEWER copy and sending on ours reuses a
      // message number the peer already consumed ("decryption failed"). Install the
      // server copy only under the strict hint rules: epoch strictly newer than
      // anything this device has seen, same identity binding, nothing re-saved — so an
      // old copy replayed by the server is never accepted.
      await _withRatchetLock(nk, () => _e2eInstallStoredInner(nk, blob, null, { hint: true, quiet: true }));
    } else await _e2eInstallStoredSession(nk, blob);
  }
}
// r2: before sending to a DM peer this page has no session for although E2E is on for
// it (merged in from another tab/device, or restored late): load it (throttled).
async function _e2eLazyRestore(k) {
  await _withRatchetLock(k, async () => {});           // adopt another tab's newer copy
  if (E2E.dmSessions[k]) { _e2eMarkMaybeMoved(k); return; }   // r3: compare with the server copy before sending
  E2E._lazyRestoreAt = E2E._lazyRestoreAt || Object.create(null);
  if (Date.now() - (E2E._lazyRestoreAt[k] || 0) < 15000) return;
  E2E._lazyRestoreAt[k] = Date.now();
  const blob = await _e2eFetchSession(k);
  if (blob && !E2E.dmSessions[k]) await _e2eInstallStoredSession(k, blob);
}
// r3 (w-web MED e2e.js:1657): "another device may have sent on this session while this
// page could not hear about it" (reload, socket reconnect). The next send (or a failed
// decrypt) first compares with the server copy, quietly, under the hint rules.
function _e2eMarkMaybeMoved(k) {
  if (!k || k.startsWith('__')) return;
  E2E._maybeMoved = E2E._maybeMoved || Object.create(null);
  E2E._maybeMoved[k] = Date.now();
}
function _e2eMovedPending(k) { return !!((E2E._moved && E2E._moved[k]) || (E2E._maybeMoved && E2E._maybeMoved[k])); }
// r7 (codex-p3 e2e.js:1375): the identity a DM session is bound to vs the identity this
// account pins for the peer NOW. Accepting a peer's replacement identity on another
// device reaches this one as a new pin (re-sync / state merge) — but the old session
// stayed and kept encrypting to (and authenticating) the previous identity.
E2E._fpCache = new Map();
function _e2eSessFpKey(s) { return s && s.theirIdentityPub && s.theirSignPub ? s.theirIdentityPub + '|' + s.theirSignPub : null; }
function _e2eSessFpCached(s) { const key = _e2eSessFpKey(s); return key ? E2E._fpCache.get(key) : undefined; }
async function _e2eSessFp(s) {
  const key = _e2eSessFpKey(s);
  if (!key) return null;
  let fp = E2E._fpCache.get(key);
  if (fp === undefined) {
    // (also the pre-#11 dh-only form of the same identity: a pin made before both keys
    // were pinned matches it — never a false "replaced")
    E2E._fpCache.set('dh|' + s.theirIdentityPub, await computeIdentityFingerprint(s.theirIdentityPub, null));
    fp = await computeIdentityFingerprint(s.theirIdentityPub, s.theirSignPub);
    E2E._fpCache.set(key, fp);
    while (E2E._fpCache.size > 1000) E2E._fpCache.delete(E2E._fpCache.keys().next().value);
  }
  return fp;
}
// true = the session is bound to ANOTHER identity than the current (locally owned) pin;
// null = not known yet (being computed); false = same, or nothing to compare (no pin, a
// server-seeded pin, a legacy session without the signing key).
function _e2eSessPinMismatch(k, s) {
  const tr = E2E.trustStore[k];
  if (!s || s._unusable || !tr || tr.server_seeded || !tr.fingerprint || !_e2eSessFpKey(s)) return false;
  const fp = _e2eSessFpCached(s);
  if (fp === undefined) { _e2eSessFp(s).catch(() => {}); return null; }
  return fp !== tr.fingerprint && E2E._fpCache.get('dh|' + s.theirIdentityPub) !== tr.fingerprint;
}
// r2 (NEW-7, cross-device): another device of this account SENT on the session with
// `k`, so its send chain moved past ours. The server's "session moved" event is only a
// HINT: the stored copy is installed under the strict rules of _e2eInstallStoredInner
// (strictly newer epoch, same identity binding, epoch never raised, no re-save).
async function _e2eAdoptMoved(k) {
  if (!E2E.keyReady || !_e2eMovedPending(k)) return true;
  return _withRatchetLock(k, async () => {
    if (!_e2eMovedPending(k)) return true;
    const quiet = !(E2E._moved && E2E._moved[k]);
    if (E2E._moved) delete E2E._moved[k];
    if (E2E._maybeMoved) delete E2E._maybeMoved[k];
    const blob = await _e2eFetchSession(k);
    if (!blob) return false;
    return !!(await _e2eInstallStoredInner(k, blob, null, { hint: true, quiet }));
  });
}

// ─── Double Ratchet ───────────────────────────────────────────────────────────

async function ratchetInitSend(nick, sharedSecret, theirSPKPub, theirIdentityPub, identityAD, extra = {}) {
  nick = _e2eK(nick);
  // L1: DHr = their SIGNED PREKEY (not identity key)
  const RK  = sharedSecret.slice(0, 32);
  const CKs = sharedSecret.slice(32, 64);

  const dhRatchet    = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
  );
  const dhRatchetPub = await exportPub(dhRatchet.publicKey, 'ECDH');

  const session = {
    nick,
    RK:          bytesToBase64(RK),
    CKs:         bytesToBase64(CKs),
    CKr:         null,
    Ns:          0,
    Nr:          0,
    PN:          0,
    DHs:         { pub: dhRatchetPub, priv: await exportPriv(dhRatchet.privateKey) },
    DHr:         theirSPKPub,   // L1: SPK pub, not identity key
    // #2: pin the partner's LONG-TERM identity DH pubkey so /encrypt verify
    // hashes the stable identity (not the ratchet key) — matches the responder.
    theirIdentityPub: theirIdentityPub || null,
    theirSignPub: extra.theirSignPub || null,
    // #12: pin the canonical identity-binding AD for the per-message AEAD.
    identityAD:  identityAD || null,
    skipped:     {},
    isInitiator: true,
    // H6/reload: the X3DH header travels with the session until the peer answers
    // (public values only), so it survives a reload and can be re-sent.
    x3dhPending: extra.x3dhHeader || null,
  };

  E2E.dmSessions[nick] = session;
  await saveSession(nick, session);
  _e2eStateSetDm(nick, true);
  return session;
}

async function ratchetInitRecv(nick, sharedSecret, theirIdentityPub, identityAD, establishEph, selectedSpk, opts = {}) {
  nick = _e2eK(nick);
  const RK  = sharedSecret.slice(0, 32);
  const CKr = sharedSecret.slice(32, 64);

  // Carry forward EVERY ephemeral that has previously established this session so the
  // replay guard recognises a re-delivered OLDER genuine header. Bounded to 32 + deduped.
  const _old = opts.noInstall ? null : E2E.dmSessions[nick];
  const _prior = [];
  if (_old) {
    if (_old.establishEph) _prior.push(_old.establishEph);
    if (Array.isArray(_old.priorEstablishEphs)) for (const e of _old.priorEstablishEphs) _prior.push(e);
  }
  const _priorDedup = [...new Set(_prior.filter(e => e && e !== establishEph))].slice(-32);

  // Use SPK keypair as initial DHs so initiator can match the first ratchet step.
  // P4 (#25/#84): prefer the spk_id-selected SPK the caller resolved in x3dhRespond.
  let dhRatchetPub, dhRatchetPriv;
  if (selectedSpk && selectedSpk.pub && selectedSpk.priv) {
    dhRatchetPub = selectedSpk.pub;
    dhRatchetPriv = JSON.stringify(selectedSpk.priv);
  } else {
    const spkObj = JSON.parse(new TextDecoder().decode(await aesDecryptBlob(E2E._spkBlob, _e2eCtxSession('__spk__'))));
    dhRatchetPub = spkObj.spk_pub;
    dhRatchetPriv = JSON.stringify(spkObj.spk_priv);
  }

  const session = {
    nick,
    RK:          bytesToBase64(RK),
    CKs:         null,
    CKr:         bytesToBase64(CKr),
    Ns:          0,
    Nr:          0,
    PN:          0,
    DHs:         { pub: dhRatchetPub, priv: dhRatchetPriv },
    DHr:         null,
    theirIdentityPub: theirIdentityPub || null,
    theirSignPub: opts.theirSignPub || null,
    identityAD:  identityAD || null,
    establishEph: establishEph || null,
    priorEstablishEphs: _priorDedup,
    skipped:     {},
    isInitiator: false,
  };

  if (opts.noInstall) return session;
  E2E.dmSessions[nick] = session;
  await saveSession(nick, session);
  return session;
}

// S3: serialise ALL ratchet operations (encrypt AND decrypt) per session. Both paths
// mutate the same session object, so they must never interleave at an await boundary:
// an encrypt advancing the send chain (CKs/Ns) while a decrypt is mid-flight would be
// silently lost when the decrypt commits — ratchetDecrypt clones the session and swaps
// the whole object back on a successful decrypt, reverting any send-chain progress made
// in the meantime (→ message-key reuse / send-chain desync / a dropped outbound msg).
// Two concurrent decrypts would clobber each other the same way. One shared per-nick
// promise chain guarantees strict FIFO serialisation across both directions. Sequential
// (non-overlapping) calls are completely unaffected — behavior is identical.
function _withRatchetLock(nick, fn) {
  // Chain each call behind the previous one for the same nick. The stored promise only
  // ever resolves (resolve() in finally, never rejected), so `await prev` never throws.
  // r2: and, browser-wide, behind every other tab's operation on this peer (Web Lock),
  // starting from the newest copy any tab of this browser saved (_e2eSyncFromDevice).
  const prev = E2E._encryptLock[nick] || Promise.resolve();
  let resolve;
  const mine = new Promise(r => resolve = r);
  E2E._encryptLock[nick] = mine;
  return (async () => {
    try {
      await prev;
      return await _e2eXLock('r:' + nick, async () => { await _e2eSyncFromDevice(nick); return await fn(); });
    } finally {
      resolve();
      // r8 (codex-p3 e2e.js:4039): nobody queued behind → the entry goes (one per nick
      // that ever sent anything used to stay for good).
      if (E2E._encryptLock[nick] === mine) delete E2E._encryptLock[nick];
    }
  })();
}
// r8 (codex-p3 e2e.js:4039): per-nick state an UNAUTHENTICATED sender can create (held
// envelopes waiting for a key exchange, header waits, lazy-restore attempts) is pruned
// across all nicks — expired entries of senders who stopped, and the oldest beyond a
// global bound — instead of only for the nick currently sending.
const E2E_STRANGER_MAX = 200;
// r9 (astra-p3 e2e.js:3453): when each pending X3DH header arrived (keyed by the header
// object, so the stored value keeps its shape).
const _e2ePendHdrAt = new WeakMap();
function _e2eSweepStrangerState() {
  const now = Date.now();
  // r9 (astra-p3 e2e.js:3453): headers that arrived alone and were not used (malformed,
  // refused, or never followed by a message) — any IRC sender can leave one per nick. They
  // expire after 10 minutes and at most E2E_STRANGER_MAX are kept (oldest dropped first).
  // A header of a PINNED contact whose key change waits for /encrypt accept (it uses the
  // header) does not expire and is counted separately: a flood of one-off headers from new
  // nicks never evicts it (only the oldest of those beyond their own bound go).
  if (E2E._pendingIncomingX3DH) {
    const P = E2E._pendingIncomingX3DH, live = [], held = [];
    for (const [k, h] of Object.entries(P)) {
      if (!h || typeof h !== 'object') { delete P[k]; continue; }
      let t = _e2ePendHdrAt.get(h);
      if (t === undefined) { t = now; _e2ePendHdrAt.set(h, t); }
      const tr = E2E.trustStore && E2E.trustStore[k];
      if (tr && tr.pendingFingerprint) held.push([k, t]);
      else if (now - t < 600000) live.push([k, t]); else delete P[k];
    }
    for (const a of [live, held]) {
      if (a.length < E2E_STRANGER_MAX) continue;
      a.sort((x, y) => x[1] - y[1]);
      for (const [k] of a.slice(0, a.length - E2E_STRANGER_MAX + 1)) delete P[k];
    }
  }
  if (E2E._orphans) {
    for (const [k, a] of Object.entries(E2E._orphans)) {
      const live = (a || []).filter(o => now - o.t < 600000);
      if (live.length) E2E._orphans[k] = live; else delete E2E._orphans[k];
    }
    const ks = Object.keys(E2E._orphans);
    if (ks.length >= E2E_STRANGER_MAX) {
      ks.sort((x, y) => (E2E._orphans[x][0].t) - (E2E._orphans[y][0].t));
      for (const k of ks.slice(0, ks.length - E2E_STRANGER_MAX + 1)) delete E2E._orphans[k];
    }
  }
  if (E2E._hdrWait) {
    for (const [k, h] of Object.entries(E2E._hdrWait)) if (!h.busy && !(h.fails || []).some(t => now - t < 60000)) delete E2E._hdrWait[k];
  }
}
// Message keys of the last decrypted messages, kept ONLY in this browser's copy of the
// session (never on the server): another tab that receives the same line after this
// one advanced the ratchet can still read it — once (E2E._consumed, per tab).
const E2E_RECENT_KEYS = 32, E2E_RECENT_MS = 10 * 60 * 1000;
function _e2eNoteRecent(session, skipKey, mk) {
  const now = Date.now();
  const r = session.recent = session.recent || {};
  r[skipKey] = { k: bytesToBase64(mk), t: now };
  const ks = Object.keys(r).filter(x => r[x] && now - (r[x].t || 0) < E2E_RECENT_MS).sort((a, b) => r[a].t - r[b].t);
  const keep = new Set(ks.slice(-E2E_RECENT_KEYS));
  for (const x of Object.keys(r)) if (!keep.has(x)) delete r[x];
}
function _e2eMarkConsumed(skipKey) {
  const c = E2E._consumed = E2E._consumed || new Set();
  c.add(skipKey);
  if (c.size > 1024) c.delete(c.values().next().value);
}

async function ratchetEncrypt(nick, plaintext) {
  return _withRatchetLock(_e2eK(nick), () => _ratchetEncryptInner(_e2eK(nick), plaintext));
}

async function _ratchetEncryptInner(nick, plaintext) {
  const session = E2E.dmSessions[nick];
  if (!session) throw new Error(`No ratchet session with ${nick}`);
  if (session._unusable) throw new Error(session._unusable);

  // L8: As the receiver (Bob), we have no sending chain yet and cannot send
  // until we receive at least one message from Alice (to get her ratchet pub key).
  // Attempting dhRatchetStep with DHr=null would crash. Give a clear error.
  if (!session.CKs) {
    if (!session.DHr) {
      throw new Error(
        `Cannot send yet — waiting for ${nick} to send the first message to establish the ratchet.`
      );
    }
    // Responder's FIRST send. We must open a sending chain WITHOUT disturbing the LIVE
    // receive chain (CKr/Nr/DHr) that is still decrypting the initiator's initial chain.
    // A full dhRatchetStep() here is WRONG: its step 1 overwrites session.CKr and resets
    // session.Nr, so the initiator's later initial-chain messages (n=1,2,… on DHr) would
    // fail AES-GCM. Instead mirror the initiator's step-0 (see ~line 800): advance ONLY
    // the root key via ECDH(our initial DHs = SPK, their DHr = initiator's ratchet pub) —
    // discarding the receive half — then derive ONLY a fresh sending chain exactly like
    // dhRatchetStep()'s step 2. The KDF inputs/order are byte-identical to what the old
    // dhRatchetStep produced, so the initiator still derives a matching CKr; we simply no
    // longer clobber our receive state.
    const ourPrivR0  = await importPriv(session.DHs.priv);   // our SPK priv (initial DHs)
    const theirPubR  = await importPub(session.DHr, 'ECDH'); // initiator's ratchet pub
    const dhR0       = await ecdh(ourPrivR0, theirPubR);
    const dR0        = await hkdf(concat(base64ToBytes(session.RK), dhR0), 'DR-Ratchet-v1', 64);
    session.RK       = bytesToBase64(dR0.slice(0, 32));       // advance RK only; DISCARD dR0[32:64] (that would clobber CKr)
    // Step 2 (mirrors dhRatchetStep): fresh DHs → ECDH → derive new RK + our sending chain.
    const newDHsR    = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
    );
    const newDHsRPub = await exportPub(newDHsR.publicKey, 'ECDH');
    const dhR2       = await ecdh(newDHsR.privateKey, theirPubR);
    const derivedR2  = await hkdf(concat(base64ToBytes(session.RK), dhR2), 'DR-Ratchet-v1', 64);
    session.RK       = bytesToBase64(derivedR2.slice(0, 32));
    session.CKs      = bytesToBase64(derivedR2.slice(32, 64));
    session.PN       = session.Ns;   // no prior sending chain → 0
    session.Ns       = 0;
    session.DHs      = { pub: newDHsRPub, priv: await exportPriv(newDHsR.privateKey) };
    // NOTE: intentionally leave session.CKr / session.Nr / session.DHr / session.rgen
    // untouched — the initiator's initial receive chain must stay live.
    await saveSession(nick, session, { snd: true });
  }

  const [mk, newCKs] = await chainKeyStep(base64ToBytes(session.CKs));
  session.CKs        = bytesToBase64(newCKs);

  const header = {
    dh: session.DHs.pub,
    pn: session.PN,
    n:  session.Ns,
  };
  session.Ns++;

  // #12: bind both identities into the AEAD via the session-pinned AD.
  const identAD = sessionIdentityAD(session);
  const ct = await messageEncrypt(mk, new TextEncoder().encode(plaintext), header, identAD);
  await saveSession(nick, session, { snd: true });

  return { h: { d: header.dh, p: header.pn, n: header.n }, c: bytesToBase64(ct) };
}

async function ratchetDecrypt(nick, envelope, useAlt = false) {
  // Serialise with the send path (and other decrypts) per nick — see _withRatchetLock.
  return _withRatchetLock(_e2eK(nick), () => _ratchetDecryptInner(_e2eK(nick), envelope, useAlt));
}

async function _ratchetDecryptInner(nick, envelope, useAlt = false) {
  // L2: null-check session BEFORE any property access
  // useAlt: decrypt with the glare-loser's responder session held aside (not installed).
  const live = useAlt ? (E2E._glareAlt && E2E._glareAlt[nick]) : E2E.dmSessions[nick];
  if (!live) throw new Error(`No ratchet session with ${nick} — key exchange needed`);
  if (live._unusable) throw new Error(live._unusable);
  // ATOMICITY (Signal spec §decrypt): operate on a deep CLONE and commit only after the
  // ciphertext is authenticated. The sole authentication is messageDecrypt (AES-GCM tag)
  // below, which throws on any forged/tampered [e2edm1] envelope — and the server relays
  // every PRIVMSG, so any peer who can DM the victim can inject one. Every mutation in
  // this function (skipped-key delete, skipMessageKeys, CKr/Nr advance, dhRatchetStep)
  // therefore runs on `session` (the clone); the live ratchet in E2E.dmSessions[nick] is
  // untouched until saveSession() reassigns it AFTER a successful decrypt. A forgery now
  // leaves Nr/CKr/CKs/RK/DHs/DHr and the buffered skipped keys fully intact (the next
  // genuine message still decrypts) instead of desyncing the session until reload, and it
  // can no longer destroy a buffered out-of-order key. The session is pure-JSON
  // (saveSession does JSON.stringify), so structuredClone is a faithful deep copy; for
  // honest peers the committed state, plaintext and wire output are byte-identical to before.
  const session = structuredClone(live);

  // Support both compact (h/c) and legacy (header/ciphertext) formats
  const header = envelope.h ? { dh: envelope.h.d, pn: envelope.h.p, n: envelope.h.n } : envelope.header;
  const ct = base64ToBytes(envelope.c || envelope.ciphertext);

  // Check skipped keys
  // #12: same session-pinned identity AD as the encrypt path.
  const identAD = sessionIdentityAD(session);

  const skipKey = `${nick}/${header.dh}/${header.n}`;
  const commit = async (mk) => {
    // First authenticated message from the peer: they have our X3DH header, stop resending it.
    if (session.x3dhPending) delete session.x3dhPending;
    if (mk) _e2eNoteRecent(session, skipKey, mk);
    _e2eMarkConsumed(skipKey);
    if (useAlt) E2E._glareAlt[nick] = session;
    else await saveSession(nick, session);
  };
  // r2: another tab of this browser already decrypted this very message (and advanced
  // the shared ratchet): read it with the key it left behind — once per tab, no state
  // change. A replay to the same tab is still refused (consumed).
  // Only for a message another tab decrypted while THIS page was already open (it
  // received the same live line): a page loaded later is shown a re-sent old line as
  // what it is — a replay — exactly as before.
  const rk = session.recent && session.recent[skipKey];
  if (rk && !useAlt && (rk.t || 0) >= E2E._pageStart && !(E2E._consumed && E2E._consumed.has(skipKey))) {
    try {
      const pt = await messageDecrypt(base64ToBytes(rk.k), ct, header, identAD);
      _e2eMarkConsumed(skipKey);
      return new TextDecoder().decode(pt);
    } catch (_) { /* not that message */ }
  }
  if (session.skipped[skipKey]) {
    const mk = base64ToBytes(session.skipped[skipKey]);
    delete session.skipped[skipKey];
    if (session.skippedMeta) delete session.skippedMeta[skipKey];  // #39: keep eviction side-table in sync
    const pt = await messageDecrypt(mk, ct, header, identAD);
    await commit(mk);
    return new TextDecoder().decode(pt);
  }

  // DH ratchet step if new ratchet key
  if (header.dh !== session.DHr) {
    if (session.DHr === null) {
      // First message received by responder — just record sender's DH pub
      session.DHr = header.dh;
    } else if (session.isInitiator && session.CKr === null) {
      // Initiator receiving first reply: need to advance RK first
      // Step 0: ECDH(our DHs, old DHr=SPK) to advance RK (matching responder's step1)
      const ourPriv0 = await importPriv(session.DHs.priv);
      const oldPub = await importPub(session.DHr, 'ECDH');
      const dh0 = await ecdh(ourPriv0, oldPub);
      const d0 = await hkdf(concat(base64ToBytes(session.RK), dh0), 'DR-Ratchet-v1', 64);
      session.RK = bytesToBase64(d0.slice(0, 32));
      // Now do normal ratchet step with the new DH pub
      await skipMessageKeys(session, nick, header.pn);
      await dhRatchetStep(session, header.dh);
    } else {
      await skipMessageKeys(session, nick, header.pn);
      await dhRatchetStep(session, header.dh);
    }
  }

  await skipMessageKeys(session, nick, header.n);

  const [mk, newCKr] = await chainKeyStep(base64ToBytes(session.CKr));
  session.CKr = bytesToBase64(newCKr);
  session.Nr++;

  const pt = await messageDecrypt(mk, ct, header, identAD);
  await commit(mk);
  return new TextDecoder().decode(pt);
}

async function dhRatchetStep(session, theirNewDHPub) {
  // Signal spec: when receiving a new DH ratchet pub from peer
  // Step 1: ECDH(our current DHs, their NEW DH pub) → KDF → new RK, CKr
  const ourPriv   = await importPriv(session.DHs.priv);
  const theirPub  = await importPub(theirNewDHPub, 'ECDH');
  const dhOut     = await ecdh(ourPriv, theirPub);

  const derived   = await hkdf(concat(base64ToBytes(session.RK), dhOut), 'DR-Ratchet-v1', 64);
  session.RK      = bytesToBase64(derived.slice(0, 32));
  session.CKr     = bytesToBase64(derived.slice(32, 64));
  session.PN      = session.Ns;
  session.Ns      = 0;
  session.Nr      = 0;
  session.DHr     = theirNewDHPub;
  // #39: advance the receive-generation counter so skipped keys buffered AFTER this
  // step sort (by generation) strictly after keys from the prior generation, making
  // eviction a true (generation, n) LRU instead of raw insertion order.
  session.rgen    = (session.rgen || 0) + 1;

  // Step 2: Generate new DHs, ECDH(new DHs, their DH pub) → KDF → new RK, CKs
  const newDHs    = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
  );
  const newDHsPub = await exportPub(newDHs.publicKey, 'ECDH');
  const dhOut2    = await ecdh(newDHs.privateKey, theirPub);
  const derived2  = await hkdf(concat(base64ToBytes(session.RK), dhOut2), 'DR-Ratchet-v1', 64);
  session.RK      = bytesToBase64(derived2.slice(0, 32));
  session.CKs     = bytesToBase64(derived2.slice(32, 64));
  session.DHs     = { pub: newDHsPub, priv: await exportPriv(newDHs.privateKey) };
}

async function skipMessageKeys(session, nick, until) {
  if (session.Nr >= until) return;
  if (until - session.Nr > E2E_MAX_SKIP) throw new Error('Too many skipped messages');
  if (!session.CKr) return;

  // #39: stamp each buffered key with its (generation, n) so eviction below is by true
  // sequence, not raw Object.keys insertion order. session.rgen advances on every DH
  // ratchet step, so old-generation skips (stamped before the step) always sort before
  // new-generation skips (stamped after), regardless of insertion timing.
  const _gen = session.rgen || 0;
  session.skippedMeta = session.skippedMeta || {};

  while (session.Nr < until) {
    const [mk, newCKr] = await chainKeyStep(base64ToBytes(session.CKr));
    session.CKr = bytesToBase64(newCKr);
    const sk = `${nick}/${session.DHr}/${session.Nr}`;
    session.skipped[sk] = bytesToBase64(mk);
    session.skippedMeta[sk] = { g: _gen, n: session.Nr };
    session.Nr++;
  }

  // S4/#39: evict by true (generation, message-number) LRU when over the cap — NOT raw
  // insertion order. Across a DH-ratchet step the DHr prefix changes, so insertion order
  // no longer tracks sequence and a skip burst in a newer generation could otherwise
  // evict a newer, still-needed key before a stale one. Sorting by the stamped (g, n)
  // ascending and dropping the front keeps the most-recent MAX_SKIP keys.
  const keys = Object.keys(session.skipped);
  if (keys.length > E2E_MAX_SKIP) {
    const meta = session.skippedMeta || {};
    keys.sort((a, b) => {
      const ma = meta[a] || { g: 0, n: 0 }, mb = meta[b] || { g: 0, n: 0 };
      return (ma.g - mb.g) || (ma.n - mb.n);
    });
    for (const k of keys.slice(0, keys.length - E2E_MAX_SKIP)) {
      delete session.skipped[k];
      delete session.skippedMeta[k];
    }
  }
}

// #26: spec-compliant Double Ratchet KDF_CK. The message key is HMAC-SHA256(CK, 0x01)
// and the next chain key is HMAC-SHA256(CK, 0x02) — the chain key keys an HMAC over a
// single constant byte, exactly as the Signal spec defines (not a re-extract-then-expand
// approximation). Both peers run this identical derivation.
async function chainKeyStep(ck) {
  const key = await crypto.subtle.importKey('raw', ck, { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const mk  = new Uint8Array(await crypto.subtle.sign('HMAC', key, new Uint8Array([0x01])));
  const nck = new Uint8Array(await crypto.subtle.sign('HMAC', key, new Uint8Array([0x02])));
  return [mk, nck];
}

// #12: retrieve the identity-binding AD pinned on the session at establishment.
// Stored as base64 on the session object (so it survives JSON persistence). When
// absent (legacy/in-flight session predating this change) returns null, which
// makes messageEncrypt/Decrypt fall back to header-only AD — those old sessions
// stay self-consistent with their own peer but are intentionally incompatible
// with upgraded fresh sessions (#12).
function sessionIdentityAD(session) {
  return session && session.identityAD ? base64ToBytes(session.identityAD) : null;
}

// ─── Message encrypt / decrypt ────────────────────────────────────────────────

// #12: identAD (Uint8Array) is the canonical encoding of both peer identities
// (e2eIdentityAD), pinned on the session at establishment. Folding it into the
// AEAD additionalData cryptographically binds every ratchet message to the two
// identities, so a substituted identity key produces an AEAD authentication
// failure instead of a silently-working session. It MUST be supplied
// identically on encrypt and decrypt — both pull it from session.identityAD.
async function messageEncrypt(keyBytes, plaintext, header, identAD) {
  const key   = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  // Include header (anti-tamper) AND the bound identity AD (#12) as Associated Data.
  // #24: identity AD is MANDATORY for v2 sessions — refuse to encrypt without it rather
  // than silently degrading to header-only AD (which would drop the identity binding).
  if (!identAD) throw new Error('E2E identity AD missing — refusing to encrypt without identity binding');
  const headerAD = header ? new TextEncoder().encode(JSON.stringify(header)) : new Uint8Array(0);
  const ad = concat(headerAD, identAD);
  const ct    = await crypto.subtle.encrypt({ name:'AES-GCM', iv:nonce, additionalData:ad }, key, plaintext);
  return concat(nonce, new Uint8Array(ct));
}

async function messageDecrypt(keyBytes, ctWithNonce, header, identAD) {
  const key   = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  const nonce = ctWithNonce.slice(0, 12);
  const ct    = ctWithNonce.slice(12);
  // #24: identity AD is MANDATORY for v2 — never authenticate under the weaker
  // header-only AD. A v2 session always pins identityAD; its absence is a setup/
  // downgrade error, not a fallback.
  if (!identAD) throw new Error('E2E identity AD missing — refusing to decrypt without identity binding');
  const headerAD = header ? new TextEncoder().encode(JSON.stringify(header)) : new Uint8Array(0);
  const ad = concat(headerAD, identAD);
  return new Uint8Array(await crypto.subtle.decrypt({ name:'AES-GCM', iv:nonce, additionalData:ad }, key, ct));
}

// ─── Channel PSK ─────────────────────────────────────────────────────────────

// r2 (codex-p3 MED e2e.js:1681): sender + conversation binding and replay detection.
// The ciphertext itself stays exactly as before (AES-GCM, no AAD), so every CryptIRC
// version — including other people's older clients on other servers — still reads it.
// New senders ADD three envelope fields that older clients ignore:
//   i = random message id, t = send time (unix s),
//   m = HMAC-SHA256(HKDF(PSK, "CryptIRC-PSK-BIND-v1"), binding|i|t|n|c)[0..16]
// where binding = channel + sender nick (or, for a DM key, the sender nick). A relay
// re-sending a captured line under another nick, or in another channel sharing the
// key, now FAILS verification (the message is refused); a repeat of a live message id
// is a replay (dropped); a live message older than an hour is flagged. Lines without
// `m` (older senders, or a relay that stripped it) still decrypt but are shown as
// "(unverified sender)".
const E2E_PSK_BIND_INFO = 'CryptIRC-PSK-BIND-v1';
const E2E_PSK_OLD_SECS  = 3600;
E2E._pskMacKeys = new WeakMap();
E2E._pskSeen = new Map();
async function _e2ePskMacKey(key) {
  let mk = E2E._pskMacKeys.get(key);
  if (!mk) {
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    const h = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
    raw.fill(0);
    mk = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode(E2E_PSK_BIND_INFO) },
                                       h, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign']);
    E2E._pskMacKeys.set(key, mk);
  }
  return mk;
}
// r3: the channel part is folded with the widest IRC case-fold, so the binding is the
// same however sender and receiver spell the channel (#foo[ vs #foo{ — the server
// relays its own spelling). The sender part stays the exact (lowercased) nick the
// server prefixes the line with. `v1` = the round-2 form (lowercase channel), still
// accepted on receive.
function _e2ePskBinding(channel, sender, v1 = false) {
  const c = v1 ? _e2eK(channel) : _e2eFoldAll(channel), s = _e2eK(sender);
  return _e2eIsChan(c) ? 'c\n' + c + '\n' + s : 'd\n' + s;
}
async function _e2ePskMac(key, binding, env) {
  const msg = new TextEncoder().encode(E2E_PSK_BIND_INFO + '\n' + binding + '\n' + env.i + '\n' + env.t + '\n' + env.n + '\n' + env.c);
  return new Uint8Array(await crypto.subtle.sign('HMAC', await _e2ePskMacKey(key), msg)).slice(0, 16);
}
// `sender` = our own nick on the connection the line goes out on (null: unbound line).
async function channelEncrypt(channel, plaintext, sender = null) {
  const key = E2E.channelKeys[_e2eK(channel)];
  if (!key) throw new Error(`No E2E key for ${channel}`);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct    = await crypto.subtle.encrypt({ name:'AES-GCM', iv:nonce }, key,
                  new TextEncoder().encode(plaintext));
  const env   = { v:1, n:bytesToBase64(nonce), c:bytesToBase64(new Uint8Array(ct)) };
  if (sender) {
    env.i = bytesToBase64(crypto.getRandomValues(new Uint8Array(9)));
    env.t = Math.floor(Date.now() / 1000);
    env.m = bytesToBase64(await _e2ePskMac(key, _e2ePskBinding(channel, sender), env));
  }
  return E2E_CHAN_PREFIX + btoa(JSON.stringify(env));
}
// → null (not ours / no key / does not decrypt) or { pt, verified, bad, replay, old }.
// opts.live: a message arriving now (replay window + age checks); opts.self: our own line.
async function channelDecryptEx(channel, wireText, sender = null, opts = {}) {
  if (typeof wireText !== 'string' || !wireText.startsWith(E2E_CHAN_PREFIX)) return null;
  const key = E2E.channelKeys[_e2eK(channel)];
  if (!key) return null;
  let env, pt;
  try {
    env = JSON.parse(atob(wireText.slice(E2E_CHAN_PREFIX.length)));
    pt = new TextDecoder().decode(await crypto.subtle.decrypt({ name:'AES-GCM', iv: base64ToBytes(env.n) }, key, base64ToBytes(env.c)));
  } catch { return null; }
  const r = { pt, verified: false, bad: false, replay: false, old: false, ts: 0 };
  if (typeof env.m === 'string' && typeof env.i === 'string' && Number.isInteger(env.t)) {
    if (!sender) return r;
    const binding = _e2ePskBinding(channel, sender);
    const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
    let ok = false;
    try {
      const got = base64ToBytes(env.m);
      ok = same(await _e2ePskMac(key, binding, env), got);
      const b1 = _e2ePskBinding(channel, sender, true);
      if (!ok && b1 !== binding) ok = same(await _e2ePskMac(key, b1, env), got);
    } catch (_) { ok = false; }
    if (!ok) { r.bad = true; return r; }
    r.verified = true; r.ts = env.t;
    if (opts.live) {
      if (Math.abs(Date.now() / 1000 - env.t) > E2E_PSK_OLD_SECS) r.old = true;
      if (!opts.self) {
        let seen = E2E._pskSeen.get(binding);
        if (!seen) { seen = new Map(); E2E._pskSeen.set(binding, seen); if (E2E._pskSeen.size > 512) E2E._pskSeen.delete(E2E._pskSeen.keys().next().value); }
        if (seen.has(env.i)) r.replay = true;
        else { seen.set(env.i, env.t); if (seen.size > 2000) seen.delete(seen.keys().next().value); }
      }
    }
  }
  return r;
}
function _e2ePskShown(r, sender) {
  if (r.bad) return `🔐 [encrypted message REFUSED — it was not sent by ${sender || 'this sender'} here (re-sent under another name or in another channel)]`;
  if (!r.verified) return '⚠️ (unverified sender) ' + r.pt;
  if (r.old) { let when = ''; try { when = new Date(r.ts * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC'; } catch (_) {} return `⚠️ (sent ${when} — delayed or replayed) ` + r.pt; }
  return r.pt;
}
// String API kept for app.js (history / echo paths): plaintext with a marker, or null.
async function channelDecrypt(channel, wireText, sender = null) {
  const r = await channelDecryptEx(channel, wireText, sender);
  return r ? _e2ePskShown(r, sender) : null;
}

async function generateChannelKey() {
  const raw   = crypto.getRandomValues(new Uint8Array(32));
  const key   = await crypto.subtle.importKey('raw', raw, { name:'AES-GCM' }, true, ['encrypt','decrypt']);
  const words = bytesToMnemonic(raw);
  return { keyWords: words.join(' '), keyB64: bytesToBase64(raw), key };
}

async function importChannelKeyFromWords(wordsStr) {
  const words = wordsStr.trim().toLowerCase().split(/\s+/);
  if (words.length !== 32) throw new Error('Expected 32 words, got ' + words.length);
  const raw   = mnemonicToBytes(words);
  // Verify round-trip: any unrecognised word is an error
  for (const w of words) {
    if (!WORDLIST.includes(w)) throw new Error(`Unrecognised word: "${w}"`);
  }
  const key = await crypto.subtle.importKey('raw', raw, { name:'AES-GCM' }, true, ['encrypt','decrypt']);
  return { key, keyB64: bytesToBase64(raw) };
}

// PSK blobs (v2) hold {k: base64 key, g: generation}. The generation only ever goes up
// (keygen / add / rotate) and is remembered in the authenticated state blob and on this
// device, so a server re-serving a PRE-rotation blob is refused (a removed member can't
// be let back in), and the AAD binds the blob to its channel name.
function _e2eKnownChanGen(k) {
  return Math.max(E2E._chanGen[k] || 0, (E2E.state && E2E.state.ch[k] && E2E.state.ch[k].g) || 0, _e2eDev().gen[k] || 0);
}
async function storeChannelKey(channel, key, keyB64) {
  const k = _e2eK(channel);
  const g = _e2eKnownChanGen(k) + 1;
  E2E.channelKeys[k] = key;
  E2E._chanGen[k] = g;
  E2E._chanKeyGen[k] = g;
  delete E2E.chanRemoved[k];
  const blob = await aesEncryptBlob(new TextEncoder().encode(JSON.stringify({ k: keyB64, g })), _e2eCtxChan(k));
  _e2eWs({ type:'e2e_store_channel_key', channel: k, blob });
  const dev = _e2eDev(); dev.gen[k] = g; _e2eDevSave();
  _e2eStateSetChan(k, true, g);
}

async function _e2eDeleteSlot(msg) {
  const req = crypto.randomUUID();
  const gen = E2E._lockGen;
  // Retrying a delete could remove a replacement key saved after a lost reply.
  const event = await _e2eReq({ ...msg, req, v: E2E_STORAGE_VERSION }, 'e2e_key_deleted', 6000, e => e.req === req, 0);
  return !!event?.ok && !_e2eBootStale(gen);
}
async function removeChannelKey(k, storedNames) {
  for (const channel of new Set([k, ...storedNames.filter(name => _e2eK(name) === k)])) {
    if (!(await _e2eDeleteSlot({ type:'e2e_delete_channel_key', channel }))) return false;
  }
  delete E2E.channelKeys[k];
  delete E2E._chanKeyGen[k];
  delete E2E.chanRemoved[k];
  if (E2E.state && E2E.state.ch[k]) _e2eStateSetChan(k, false, E2E.state.ch[k].g);
  return true;
}

// Decode a channel-key blob for `k`. Returns { raw, g, legacy }.
async function _e2eDecodeChanBlob(blob, k) {
  const { pt, legacy } = await aesDecryptBlobEx(blob, _e2eCtxChan(k));
  if (legacy) {
    if (pt.length !== 32) throw new Error('bad legacy channel key');
    return { raw: pt, g: 0, legacy: true };
  }
  const o = JSON.parse(new TextDecoder().decode(pt));
  const raw = base64ToBytes(o.k);
  if (raw.length !== 32 || !Number.isInteger(o.g)) throw new Error('bad channel key blob');
  return { raw, g: o.g, legacy: false };
}

async function loadChannelKeyFromBlob(channel, blob) {
  const k = _e2eK(channel);
  const rec = await _e2eDecodeChanBlob(blob, k);
  const key = await crypto.subtle.importKey('raw', rec.raw, { name:'AES-GCM' }, true, ['encrypt','decrypt']);
  E2E.channelKeys[k] = key;
  return rec;
}

// ─── Session persistence ──────────────────────────────────────────────────────

async function saveSession(nick, session, opts = null) {
  nick = _e2eK(nick);
  // SECURITY chokepoint: never persist a PEER session under the reserved internal
  // namespace ('__spk__' / '__otpk__<id>' / '__state__'). Test the SERVER-SANITIZED form.
  if (_e2eReservedNamespace(nick)) {
    console.warn('[E2E] refusing to store peer session under reserved name:', nick);
    return;
  }
  // #12 / MEDIUM (epoch rollback): stamp a per-nick MONOTONIC epoch that survives
  // reloads — it continues from the highest epoch this device has seen (the loaded
  // blob's and the device high-water mark), so a stored blob from an earlier page can
  // never out-rank a newer session, and an older blob is refused on load.
  const dev = _e2eDev();
  const epoch = Math.max(E2E._sessionEpoch[nick] || 0, dev.ep[nick] || 0, session.epoch || 0) + 1;
  E2E._sessionEpoch[nick] = epoch;
  session.epoch = epoch;
  E2E.dmSessions[nick] = session;
  if (!E2E.keyReady) return;
  // r2: this browser's copy (incl. skipped/recent message keys — device-local only,
  // wrapped under the master key) is written before the ratchet lock is released, so
  // the next tab to take the lock continues from exactly this state.
  try {
    const devBlob = await aesEncryptBlob(new TextEncoder().encode(JSON.stringify(session)), _e2eDevSlot(nick));
    await _e2eDevSessPut(nick, { ep: epoch, blob: devBlob });
  } catch (e) { console.warn('[E2E] device session copy not written:', e && e.message); }
  // #39: never persist buffered skipped message keys (session.skipped) to the untrusted
  // server — keep them in memory only; the persisted blob carries an EMPTY skipped map.
  const { skipped, skippedMeta, recent, ...persist } = session;
  const blob = await aesEncryptBlob(new TextEncoder().encode(JSON.stringify({ ...persist, skipped: {} })), _e2eCtxSession(nick));
  // Only advance this device's high-water mark if the write actually went out, so a
  // dropped write can't make the (older) stored copy look like a rollback later.
  // r2: dv/snd tell this account's OTHER devices that this device sent (NEW-7).
  _e2eWs({ type:'e2e_store_session', partner:nick, blob, dv: _e2eDeviceId(), snd: !!(opts && opts.snd) }).then(ok => {
    if (ok) { const d = _e2eDev(); if ((d.ep[nick] || 0) < epoch) { d.ep[nick] = epoch; _e2eDevSave(); } }
  });
}
// Drop the session with `k` everywhere: memory, server, and every tab of this browser
// (device tombstone) — /encrypt off, an accepted key change.
function _e2eDropSession(k, removeStored = true) {
  delete E2E.dmSessions[k];
  if (E2E._glareAlt) delete E2E._glareAlt[k];
  if (E2E._moved) delete E2E._moved[k];
  if (removeStored) _e2eWs({ type:'e2e_delete_session', v: E2E_STORAGE_VERSION, partner:k });
  const ep = Math.max(E2E._sessionEpoch[k] || 0, _e2eDev().ep[k] || 0) + 1;
  E2E._sessionEpoch[k] = ep;
  return _e2eDevSessPut(k, { ep, del: 1 });
}

// ─── TOFU / trust ─────────────────────────────────────────────────────────────

// #1: explicit out-of-band confirmation for a BRAND-NEW (first-contact) identity.
// An IRC nick is unauthenticated and the server bridges nick→key-bundle via a global
// connection map, so the first party to grab a peer's nick can offer its own key.
// Never silently auto-pin — force the local user to eyeball the fingerprint and confirm
// it out-of-band before it is pinned and used. Returns true iff the user approves.
// `seededFp`: a fingerprint the SERVER has on record for this nick (trust.json — not
// authenticated). The prompt says whether the presented key matches it, so a
// post-upgrade re-confirmation can't look identical to an attacker's new key.
//
// r3 (agy-flash P3 HIGH e2e.js:2355): this used to be a synchronous confirm(). Any IRC
// user (even an /ignore'd one — decryption runs before the ignore check) could DM an
// [e2ex3dh] header from a fresh nick and freeze the whole page in a modal dialog (no
// input, no WebSocket keep-alive), and again after every Cancel. Now (_e2eAskIdentity):
//  - the dialog is a NON-blocking in-app dialog (_e2eIdentityDialog) when there is a page;
//  - one question per peer at a time — more headers from that peer share its answer, a
//    DIFFERENT key offered while it is open is refused;
//  - one dialog on screen at a time, at most 8 waiting; unsolicited ones beyond that are
//    refused;
//  - after the user declines a peer, UNSOLICITED prompts for it are refused for 10 min
//    (the user's own /encrypt on <peer> still asks);
//  - fail closed throughout: nothing is pinned and no session exists until "Accept".
// opts.solicited: the user asked for this (the bundle reply to their /encrypt on).
async function e2eConfirmNewIdentity(nick, fingerprint, seededFp = null, opts = null) {
  try {
    let msg;
    if (seededFp && seededFp !== fingerprint) {
      msg =
        `⚠️ KEY CHANGE for ${nick}\n\n` +
        `The server's record for ${nick} has fingerprint:\n${seededFp}\n\n` +
        `but the identity presented now is:\n${fingerprint}\n\n` +
        `This may be a man-in-the-middle or a new device. Accept the NEW key only after ` +
        `confirming it with ${nick} over a trusted channel (voice/in person).\n\n` +
        `Accept the new key and start encrypting with ${nick}?`;
    } else if (seededFp) {
      msg =
        `🔐 Confirm encryption identity for ${nick}\n\n` +
        `Fingerprint:\n${fingerprint}\n\n` +
        `This matches the fingerprint the server has on record for ${nick}, but that record ` +
        `is not authenticated and was not confirmed on this device.\n\n` +
        `Accept and start encrypting with ${nick}?`;
    } else {
      msg =
        `🔐 New encryption identity for ${nick}\n\n` +
        `Fingerprint:\n${fingerprint}\n\n` +
        `Anyone can claim this IRC nick. Confirm this fingerprint with ${nick} over a ` +
        `trusted channel (voice/in person) BEFORE accepting.\n\n` +
        `Accept and start encrypting with ${nick}?`;
    }
    return await _e2eAskIdentity(_e2eK(nick), fingerprint, msg, !!(opts && opts.solicited));
  } catch (e) { console.warn('[E2E] identity confirmation unavailable:', e); return false; }
}
E2E._idAsk = Object.create(null);       // peer → { fp, p } (open question)
E2E._idDeclined = Object.create(null);  // peer → ms of the last "Cancel"
E2E._idQueue = Promise.resolve(); E2E._idWaiting = 0;
const E2E_ID_DECLINE_MS = 10 * 60 * 1000, E2E_ID_MAX_WAITING = 8;
// r4 (verifier w3-web N5): the limits above are per peer; a sender who keeps changing
// nicks (each header only needs a fresh self-signed identity) could still present one
// full-screen question after another. UNSOLICITED questions are now also capped overall:
// at most E2E_ID_UNSOLICITED_MAX per E2E_ID_UNSOLICITED_WINDOW_MS; the excess is dropped
// (nothing pinned, no session; the sender can try again later, its envelopes stay held
// for a while as before) with ONE system line per window. The user's own /encrypt on
// always asks. An /ignore'd sender never raises one (decryption runs before app.js's
// ignore check, so the check is made here, with the sender's prefix when known).
const E2E_ID_UNSOLICITED_MAX = 4, E2E_ID_UNSOLICITED_WINDOW_MS = 10 * 60 * 1000;
E2E._idUnsol = []; E2E._idUnsolNoted = 0; E2E._idGen = 0;
E2E._senderPfx = new Map();             // lowercased nick → last nick!user@host seen (≤256)
function _e2eNoteSenderPrefix(k, prefix) {
  if (!k || typeof prefix !== 'string' || !prefix) return;
  E2E._senderPfx.delete(k); E2E._senderPfx.set(k, prefix.slice(0, 512));
  while (E2E._senderPfx.size > 256) E2E._senderPfx.delete(E2E._senderPfx.keys().next().value);
}
function _e2eSenderIgnored(k) {
  try { return typeof isIgnored === 'function' && !!isIgnored(k, E2E._senderPfx.get(k) || null); } catch (_) { return false; }
}
// r4 (verifier w3-web N3): session end (auth_failed / sign-out) and vault lock (server or
// this device) close the open identity question and drop the queued ones — as Cancel
// for the caller (nothing pinned), WITHOUT recording a decline. It used to stay over the
// login screen, and the queued questions kept appearing one after another.
function _e2eCloseIdentityQuestions() {
  E2E._idGen++;
  E2E._idAsk = Object.create(null);
  try { if (typeof E2E._idDialogClose === 'function') E2E._idDialogClose(); } catch (_) {}
  try { const d = (typeof document !== 'undefined' && document && document.getElementById) ? document.getElementById('e2e-id-dialog') : null; if (d) d.remove(); } catch (_) {}
}
const E2E_BUNDLE_REPLY_MS = 60 * 1000;   // a bundle reply must come ≤60 s after the request went out
async function _e2eAskDialog(msg) {
  // In the app (app.js's dialogs exist) → the in-app dialog; e2e.js alone (the protocol
  // test harness, which stubs confirm) → confirm.
  if (typeof customConfirm === 'function' && typeof document !== 'undefined' && document && document.body) return _e2eIdentityDialog(msg);
  if (typeof confirm === 'function') return !!confirm(msg);
  return false;
}
// The in-app identity question. Unlike a generic confirm it can't be answered by a
// stray keystroke: Cancel has the focus, Enter does nothing unless "Accept" itself is
// focused, and "Accept" only works after the dialog was visible for a moment (a
// remote peer decides WHEN it pops up — e.g. while the user is typing).
function _e2eIdentityDialog(msg) {
  return new Promise((resolve) => {
    const ov = document.createElement('div');
    ov.id = 'e2e-id-dialog';
    ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:10002;display:flex;align-items:center;justify-content:center;padding:20px;';
    const box = document.createElement('div');
    box.style.cssText = 'background:var(--bg2);border:1px solid var(--border2);border-radius:10px;padding:20px;width:min(440px,92vw);max-height:min(80vh,80dvh);overflow-y:auto;box-shadow:0 8px 30px rgba(0,0,0,.5);';
    const txt = document.createElement('div');
    txt.style.cssText = 'color:var(--text);font-size:13px;white-space:pre-wrap;line-height:1.5;margin-bottom:14px;word-break:break-word;';
    txt.textContent = msg;
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;';
    const mk = (id, label, primary) => { const b = document.createElement('button'); b.id = id; b.type = 'button'; b.textContent = label;
      b.style.cssText = 'padding:8px 20px;border-radius:8px;border:none;cursor:pointer;font-size:12px;font-weight:500;font-family:var(--mono);min-height:36px;' + (primary ? 'background:var(--accent);color:#000;' : 'background:var(--bg4);color:var(--text2);'); return b; };
    const no = mk('e2e-id-cancel', 'Cancel', false), yes = mk('e2e-id-accept', 'Accept', true);
    yes.disabled = true; yes.style.opacity = '.5';
    row.appendChild(no); row.appendChild(yes); box.appendChild(txt); box.appendChild(row); ov.appendChild(box);
    const opened = Date.now();
    const key = (e) => {
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); done(false); }
      else if (e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); if (document.activeElement === no) done(false); else if (document.activeElement === yes && !yes.disabled) done(true); }
    };
    function done(v) { document.removeEventListener('keydown', key, true); try { ov.remove(); } catch (_) {} if (E2E._idDialogClose === closeMe) E2E._idDialogClose = null; resolve(!!v); }
    const closeMe = () => done(false);
    E2E._idDialogClose = closeMe;
    no.onclick = () => done(false);
    yes.onclick = () => { if (!yes.disabled && Date.now() - opened >= 800) done(true); };
    document.addEventListener('keydown', key, true);
    document.body.appendChild(ov);
    setTimeout(() => { try { no.focus(); } catch (_) {} }, 0);
    setTimeout(() => { yes.disabled = false; yes.style.opacity = ''; }, 800);
  });
}
function _e2eAskIdentity(k, fp, msg, solicited) {
  if (!solicited) {
    const d = E2E._idDeclined[k];
    if (d && Date.now() - d < E2E_ID_DECLINE_MS) return Promise.resolve(false);
    if (_e2eSenderIgnored(k)) return Promise.resolve(false);   // r4 (N5): /ignore'd sender
  }
  const open = E2E._idAsk[k];
  if (open) return open.fp === fp ? open.p : Promise.resolve(false);
  if (!solicited && E2E._idWaiting >= E2E_ID_MAX_WAITING) return Promise.resolve(false);
  if (!solicited) {
    // r4 (N5): overall cap on unsolicited questions per window.
    const now = Date.now();
    E2E._idUnsol = E2E._idUnsol.filter(t => now - t < E2E_ID_UNSOLICITED_WINDOW_MS);
    if (E2E._idUnsol.length >= E2E_ID_UNSOLICITED_MAX) {
      if (now - E2E._idUnsolNoted >= E2E_ID_UNSOLICITED_WINDOW_MS) {
        E2E._idUnsolNoted = now;
        _e2eSys(_e2eStatusTarget(), '🔐 More people than usual asked to start end-to-end encryption with you just now — further requests are ignored for a few minutes (nothing was accepted). To start one yourself: /encrypt on <nick>');
      }
      return Promise.resolve(false);
    }
    E2E._idUnsol.push(now);
  }
  E2E._idWaiting++;
  const gen = E2E._idGen;
  const entry = { fp, p: null };
  // A question still waiting when the session ended / the vault locked (gen changed) is
  // never shown.
  const run = E2E._idQueue.then(() => (gen === E2E._idGen ? _e2eAskDialog(msg) : false));
  E2E._idQueue = run.catch(() => false);
  entry.p = run.then((ok) => !!ok, () => false).then((ok) => {
    E2E._idWaiting--;
    if (E2E._idAsk[k] === entry) delete E2E._idAsk[k];
    if (gen !== E2E._idGen) return false;              // closed by session end / lock: no decline recorded, never "accepted"
    if (ok) delete E2E._idDeclined[k]; else E2E._idDeclined[k] = Date.now();
    return ok;
  });
  E2E._idAsk[k] = entry;
  return entry.p;
}

// C2: the pinned fingerprint is NEVER overwritten by a key change. A different key puts
// the peer in the 'changed' state (pendingFingerprint) — establishment under it is
// refused and every message warns — until the user explicitly accepts (/encrypt accept,
// fingerprints shown) or rejects it. The old code overwrote the pin on the first
// (header) PRIVMSG, so the second (envelope) PRIVMSG "matched" and was silently trusted.
async function e2eCheckTrust(nick, fingerprint, opts = null) {
  const k = _e2eK(nick);
  const existing = E2E.trustStore[k];
  // #F1: a server_seeded pin (delivered via e2e_trust with NO local confirmation) must
  // never stand in for a user-confirmed pin — treat it like first contact, but tell the
  // user whether the presented key matches the server's record.
  if (!existing || existing.server_seeded) {
    const seeded = existing && existing.server_seeded ? existing.fingerprint : null;
    const confirmed = await e2eConfirmNewIdentity(nick, fingerprint, seeded, opts);
    if (!confirmed) return { status:'rejected', keyChanged:false };
    E2E.trustStore[k] = { fingerprint, verified:false, keyChanged:false, pendingFingerprint:null };
    _e2eWs({ type:'e2e_update_trust', nick:k, fingerprint, verified:false });
    _e2eStateSetTrust(k);
    return { status:'tofu', keyChanged:false };
  }
  if (existing.fingerprint !== fingerprint) {
    const firstWarning = existing.pendingFingerprint !== fingerprint;
    existing.keyChanged = true;
    existing.pendingFingerprint = fingerprint;
    return { status:'changed', keyChanged:true, firstWarning };
  }
  // The PINNED key is presented again: any pending (unaccepted) change is moot.
  if (existing.keyChanged || existing.pendingFingerprint) { existing.keyChanged = false; existing.pendingFingerprint = null; }
  return { status: existing.verified ? 'verified' : 'trusted', keyChanged:false };
}

function e2eMarkVerified(nick) {
  const k = _e2eK(nick);
  const t = E2E.trustStore[k];
  if (!t || t.server_seeded || t.keyChanged) return false;
  t.verified = true;
  _e2eWs({ type:'e2e_update_trust', nick:k, fingerprint:t.fingerprint, verified:true });
  _e2eStateSetTrust(k);
  return true;
}

async function computeFingerprint(b64PubKey) {
  const digest = await crypto.subtle.digest('SHA-256', base64ToBytes(b64PubKey));
  const hex    = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2,'0')).join('');
  return hex.match(/.{1,4}/g).join(' ').toUpperCase();
}

// #11: TOFU must pin BOTH identity keys (sign + dh) so that swapping the sign
// key (while keeping the dh key) also trips the key-change warning. The pinned
// fingerprint hashes the canonical concatenation dhKey||signKey of the raw key
// bytes. Both the pin-creation and compare paths call this so they stay in sync.
// Inputs are base64 raw EC public keys.
async function computeIdentityFingerprint(b64DhKey, b64SignKey) {
  const dh   = base64ToBytes(b64DhKey);
  const sign = b64SignKey ? base64ToBytes(b64SignKey) : new Uint8Array(0);
  const digest = await crypto.subtle.digest('SHA-256', concat(dh, sign));
  const hex    = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2,'0')).join('');
  return hex.match(/.{1,4}/g).join(' ').toUpperCase();
}

// #12: Canonical encoding of BOTH peer identities (initiator + responder), used
// identically on initiator and responder to (a) fold into the X3DH HKDF info so
// the derived root key is bound to the two identities, and (b) feed the
// per-message AEAD additionalData so a substituted identity yields an AEAD
// failure rather than a silently-established session. Sorted canonically (by the raw
// dh key bytes), each component 4-byte big-endian length-prefixed.
function e2eIdentityAD(aDhB64, aSignB64, bDhB64, bSignB64) {
  const aDh = base64ToBytes(aDhB64 || ''), aSign = base64ToBytes(aSignB64 || '');
  const bDh = base64ToBytes(bDhB64 || ''), bSign = base64ToBytes(bSignB64 || '');
  let aFirst = true;
  for (let i = 0; i < Math.min(aDh.length, bDh.length); i++) {
    if (aDh[i] < bDh[i]) { aFirst = true;  break; }
    if (aDh[i] > bDh[i]) { aFirst = false; break; }
  }
  const first  = aFirst ? [aDh, aSign] : [bDh, bSign];
  const second = aFirst ? [bDh, bSign] : [aDh, aSign];
  const parts = [
    new TextEncoder().encode('CryptIRC-IDBIND-v1'),
    first[0], first[1], second[0], second[1],
  ];
  const chunks = [];
  for (const p of parts) {
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, p.length, false);
    chunks.push(len, p);
  }
  return concat(...chunks);
}

// C5: sort keys before hashing so output is identical on both sides
async function safetyPhrase(pubKeyA, pubKeyB) {
  const a   = base64ToBytes(pubKeyA);
  const b   = base64ToBytes(pubKeyB);
  let cmp = false;
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] < b[i]) { cmp = true; break; }
    if (a[i] > b[i]) { cmp = false; break; }
  }
  const ikm = cmp ? concat(a, b) : concat(b, a);
  const digest = await crypto.subtle.digest('SHA-256', ikm);
  return bytesToMnemonic(new Uint8Array(digest).slice(0, 16)).slice(0, 12).join(' ');
}

// ─── Event router ─────────────────────────────────────────────────────────────

async function e2eHandleEvent(ev) {
  switch (ev.type) {

    case 'e2e_keyring':
    case 'e2e_keyring_stored':
    case 'e2e_blob_rewrapped':
    case 'e2e_key_deleted':
    case 'e2e_session_list':
      _e2eResolveWaiter(ev);
      break;

    case 'e2e_identity_blob':
      // Only the reply to OUR load request is used; an unsolicited push is ignored
      // (MEDIUM: a server could otherwise force an identity reset at will).
      if (!_e2eResolveWaiter(ev)) console.warn('[E2E] ignoring unsolicited e2e_identity_blob');
      break;

    case 'e2e_session': {
      const partner = String(ev.partner || '');
      const blob = ev.blob || '';
      if (partner === '__spk__') {
        // C2: store blob so x3dhRespond can read it
        if (blob) E2E._spkBlob = blob;
      } else if (partner.startsWith('__') && blob) {
        E2E._sessionCache[partner] = blob;   // SPK-by-id / OTPK private halves
      }
      // Peer ratchet sessions are installed ONLY by the code that asked for them
      // (reload restore / lazy load), under the ratchet lock and the epoch check. A
      // server-pushed session blob is never authoritative (rollback / replay / DoS).
      _e2eResolveWaiter(ev);
      _e2eResolveBlobWaiters(partner, blob || null);  // #48: wake blob waiters (hit or miss)
      break;
    }

    case 'e2e_bundle': {
      const nick   = String(ev.username || '');
      const k      = _e2eK(nick);
      const bundle = ev.bundle;
      // r2 (NEW-3): the /encrypt on request is answered (whatever happens below).
      // r3 (security review of bff53f9): a bundle is only used as the answer to THIS
      // page's own recent /encrypt on (the only sender of e2e_fetch_bundle is
      // _e2eFetchBundleQueued, which registers _pendingOn and stamps when the request
      // went out). Anything else — a bundle the server pushed unasked, or one arriving
      // after the request expired — is dropped: no identity question, no pin, no session
      // (same rule as an unsolicited e2e_identity_blob).
      const pend = E2E._pendingOn && E2E._pendingOn[k];
      const sentAt = pend ? (pend.sentAt || pend.t) : 0;
      if (!pend || pend.answered || Date.now() - sentAt > E2E_BUNDLE_REPLY_MS) {
        console.warn('[E2E] ignoring an e2e_bundle nobody on this page asked for (or a late one):', nick);
        if (pend && !pend.answered) delete E2E._pendingOn[k];
        break;
      }
      // r6 (codex-p3 e2e.js:3042): the pending entry is what keeps sends to `nick` BLOCKED
      // — it used to be deleted here, BEFORE the awaits below (ratchet lock, fingerprint,
      // the first-contact identity question, session creation), so a previously plain peer
      // was 'none' (cleartext, e.g. an upload link auto-sent) while the question was open.
      // It now stays (marked answered: a second bundle is ignored) until setup finished or
      // was cancelled, whatever way this handler ends (finally below).
      pend.answered = Date.now();
      try {
        if (!E2E.identityReady) { _e2eSys(nick, '🔐 E2E not ready on this device — /encrypt unlock'); break; }
        await _withRatchetLock(k, async () => {});    // another tab may have set it up already
        // Guard: if a usable session already exists (e.g. both users initiated simultaneously), skip
        // (r7: unless it is bound to a replaced identity — then this bundle replaces it)
        const cur = E2E.dmSessions[k];
        if (cur && !cur._unusable) { try { await _e2eSessFp(cur); } catch (_) {} }
        if (cur && !cur._unusable && _e2eSessPinMismatch(k, cur) !== true) {
          e2eSysMsg(nick, `🔐 Session with ${nick} already active — skipping duplicate initiation`);
          break;
        }

        // #11: TOFU pins BOTH identity keys (dh + sign).
        const fp    = await computeIdentityFingerprint(bundle.identity_dh_key, bundle.identity_sign_key);
        const trust = await e2eCheckTrust(nick, fp, { solicited: true });   // the reply to the user's own /encrypt on (checked above)

        if (trust.keyChanged) {
          e2eShowKeyChangeWarning(nick, fp, trust.firstWarning);
          return;
        }
        // #1: first-contact identity was not confirmed out-of-band — abort with no
        // pin/session (e2eCheckTrust already recorded nothing on a 'rejected' return).
        if (trust.status === 'rejected') {
          e2eSysMsg(nick, `🔐 Encryption with ${nick} cancelled — identity not confirmed`);
          return;
        }

        const { sharedSecret, ephemeralPub, usedOTPKId, identityAD } = await x3dhInitiate(bundle);
        const myIKPub     = await exportPub(E2E.identityKeys.dhKeyPair.publicKey,   'ECDH');
        const mySignIKPub = await exportPub(E2E.identityKeys.signKeyPair.publicKey, 'ECDSA');

        // #47: sign sender_ik||ephemeral_pub||spk_id||used_otpk_id with our ECDSA identity
        // so the responder can verify sender_sign_ik has integrity before pinning.
        const _hdrSig = new Uint8Array(await crypto.subtle.sign(
          { name:'ECDSA', hash:'SHA-256' }, E2E.identityKeys.signKeyPair.privateKey,
          _x3dhHeaderSigMsg(myIKPub, ephemeralPub, bundle.signed_prekey.key_id, usedOTPKId)
        ));
        const x3dhHeader = {
          sender_ik:      myIKPub,
          sender_sign_ik: mySignIKPub,
          sender_sign_sig: bytesToBase64(_hdrSig),
          ephemeral_pub:  ephemeralPub,
          used_otpk_id:   usedOTPKId,
          spk_id:         bundle.signed_prekey.key_id,
        };
        // L1: pass SPK pub (not identity key) as DHr seed. #2/#12: pin identity + AD.
        // r2: under the (browser-wide) ratchet lock, like every other session write.
        await _withRatchetLock(k, () => ratchetInitSend(nick, sharedSecret, bundle.signed_prekey.public_key, bundle.identity_dh_key, identityAD,
                              { x3dhHeader, theirSignPub: bundle.identity_sign_key }));
        if (E2E._hdrSent) delete E2E._hdrSent[k];

        updateE2EIndicator(nick);
        e2eSysMsg(nick, '🔐 E2E session established with ' + nick);
        // Refresh encryption panel if it's open for this nick
        if (typeof showEncryptPanel === 'function' && active && _e2eK(active.target) === k) {
          const overlay = document.getElementById('encrypt-overlay');
          if (overlay && overlay.classList.contains('show')) showEncryptPanel();
        }
      } catch(e) {
        console.warn('[E2E] Failed to process bundle:', nick, e);
        e2eSysMsg(nick, '🔐 Failed to establish E2E session with ' + nick + ' (invalid key bundle)');
      } finally {
        if (E2E._pendingOn && E2E._pendingOn[k] === pend) delete E2E._pendingOn[k];
        try { updateE2EIndicator(pend.target || nick); } catch (_) {}
      }
      break;
    }

    case 'e2e_channel_key': {
      if (ev.req) { _e2eResolveWaiter(ev); break; }
      const k = _e2eK(ev.channel);
      // r6 (codex-p3 e2e.js:3129): a lock (vault / device) while this reply is being
      // decrypted or imported wipes memory; the key must not be installed after that.
      const gen = E2E._lockGen;
      const lockedMeanwhile = () => gen !== E2E._lockGen || !E2E.keyReady;
      // Was this key part of the bulk reload that fires on every (re)connect?
      const wasBulk = E2E._bulkKeyLoad && E2E._bulkKeyLoad.has(k);
      if (E2E._bulkKeyLoad) E2E._bulkKeyLoad.delete(k);
      const hadKey = !!E2E.channelKeys[k];
      let rec = null, legacyUnreadable = false;
      try {
        rec = await _e2eDecodeChanBlob(ev.blob, k);
        if (lockedMeanwhile()) { rec.raw && rec.raw.fill && rec.raw.fill(0); rec = null; _e2eResolveWaiter({ type: 'e2e_channel_key_done', channel: ev.channel, ok: false, locked: true }); break; }
      } catch (e) {
        legacyUnreadable = typeof ev.blob === 'string' && !_e2eWrappedBlob(ev.blob);
        console.warn('[E2E] channel key blob for', k, 'did not authenticate:', e && e.message);
        if (!legacyUnreadable) _e2eSys(ev.channel, `⚠️ E2E: the server sent an invalid key for ${ev.channel} (not the key stored for this channel) — ignored`);
        else if (E2E._migrated) _e2eSys(ev.channel, `⚠️ E2E: the server sent an outdated pre-upgrade key blob for ${ev.channel} — refused`);
      }
      if (rec) {
        const known = _e2eKnownChanGen(k);
        if (rec.g < known || (rec.legacy && known > 0)) {
          // MEDIUM: a pre-rotation key re-served by the server must not come back.
          _e2eSys(ev.channel, `⚠️ E2E: the server re-sent an OLDER key for ${ev.channel} than the one in use — ignored`);
        } else {
          const key = await crypto.subtle.importKey('raw', rec.raw, { name:'AES-GCM' }, true, ['encrypt','decrypt']);
          if (lockedMeanwhile()) { _e2eResolveWaiter({ type: 'e2e_channel_key_done', channel: ev.channel, ok: false, locked: true }); break; }
          E2E.channelKeys[k] = key;
          delete E2E.chanRemoved[k];
          let g = rec.g;
          if (rec.legacy && E2E.keyReady) {
            // Re-wrap a pre-upgrade blob as v2 (generation 1), stored under the
            // lowercased name; drop the differently-cased original.
            g = 1;
            const blob = await aesEncryptBlob(new TextEncoder().encode(JSON.stringify({ k: bytesToBase64(rec.raw), g })), _e2eCtxChan(k));
            if (lockedMeanwhile()) { _e2eResolveWaiter({ type: 'e2e_channel_key_done', channel: ev.channel, ok: false, locked: true }); break; }
            _e2eWs({ type:'e2e_store_channel_key', channel: k, blob });
            if (ev.channel !== k) _e2eWs({ type:'e2e_delete_channel_key', v: E2E_STORAGE_VERSION, channel: ev.channel });
          }
          E2E._chanGen[k] = Math.max(E2E._chanGen[k] || 0, g);
          E2E._chanKeyGen[k] = g;
          const dev = _e2eDev(); if ((dev.gen[k] || 0) < g) { dev.gen[k] = g; _e2eDevSave(); }
          if (E2E.state && E2E.keyReady) {
            const c = E2E.state.ch[k];
            if (!c || !c.on || (c.g || 0) < g) _e2eStateSetChan(k, true, g);
          }
          updateE2EIndicator(ev.channel);
          // History may have replayed from logs as ciphertext before this key arrived.
          if (typeof redecryptChannelHistory === 'function') {
            try { await redecryptChannelHistory(ev.channel); }
            catch(e) { console.error('[E2E] history re-decrypt failed', e); }
          }
          // Announce ONLY for a genuinely new key learned during a live session.
          if (!wasBulk && !hadKey && !rec.legacy) {
            const chLabel = _e2eIsChan(ev.channel) ? 'Channel' : 'DM';
            e2eSysMsg(ev.channel, `🔐 ${chLabel} encryption active for ${ev.channel}`);
          }
        }
      }
      _e2eResolveWaiter({ type: 'e2e_channel_key_done', channel: ev.channel, legacyUnreadable, ok: !!rec,
                          v2: typeof ev.blob === 'string' && _e2eWrappedBlob(ev.blob) });
      break;
    }

    case 'e2e_channel_list': {
      const listed = new Set((Array.isArray(ev.channels) ? ev.channels : []).map(_e2eK));
      // MEDIUM: the server's list can no longer DELETE keys. A key we hold that is
      // missing from the list (deleted on another device — or a server lying) keeps the
      // channel in the BLOCKED state until the user confirms with /encrypt off here.
      for (const ch of Object.keys(E2E.channelKeys)) {
        if (!listed.has(ch) && !E2E.chanRemoved[ch]) {
          E2E.chanRemoved[ch] = true;
          _e2eSys(ch, `⚠️ The encryption key for ${ch} was removed on another device (or by the server). Messages to ${ch} are BLOCKED here — run /encrypt off to send unencrypted, or re-add the key.`);
          updateE2EIndicator(ch);
        }
      }
      // Bulk (re)load: no "encryption active" announcement per channel.
      E2E._bulkKeyLoad = new Set(listed);
      for (const ch of (ev.channels || [])) _e2eWs({ type:'e2e_load_channel_key', channel:ch });
      _e2eResolveWaiter(ev);   // r6: the reconnect re-sync waits for the list
      break;
    }

    case 'e2e_trust': {
      // #3/#46: the local pin is AUTHORITATIVE. The server can't re-pin, can't flip
      // keyChanged, can't mark verified. A nick with no local pin gets a server_seeded
      // record (confirmation still required before use, F1).
      const k = _e2eK(ev.nick);
      if (!k) break;
      if (!E2E.trustStore[k]) {
        E2E.trustStore[k] = {
          fingerprint: String(ev.fingerprint || ''),
          verified:    false,
          keyChanged:  false,
          pendingFingerprint: null,
          server_seeded: true,
        };
      }
      updateE2EIndicator(ev.nick);
      break;
    }

    case 'e2e_otpk_low':
      if (!E2E.identityReady) break;
      console.warn('[E2E] OTPKs low:', ev.remaining, '— replenishing');
      await e2eReplenishOTPKs();
      break;

    case 'e2e_x3dh_header': {
      const nick = String(ev.from_nick || '');
      if (!nick) break;
      if (!E2E.identityReady || !E2E.identityKeys) { _e2eHoldLocked({ kind: 'relay', from: nick, header: ev.header }); break; }
      await _e2eHandleHeader(nick, ev.header, 'relay');
      break;
    }

    case 'e2e_session_moved': {
      // r2 (NEW-7): another DEVICE of this account sent on this session. Tabs of this
      // browser share one device id and coordinate through IndexedDB instead.
      const k = _e2eK(ev.partner);
      if (!k || k.startsWith('__') || ev.dv === _e2eDeviceId()) break;
      E2E._moved = E2E._moved || Object.create(null);
      E2E._moved[k] = Date.now();
      if (E2E.dmSessions[k]) _e2eAdoptMoved(k).catch(() => {});
      break;
    }
  }
}

async function e2eReplenishOTPKs() {
  const keys = [];
  for (let i = 0; i < OTPK_BATCH_SIZE; i++) {
    const pair  = await crypto.subtle.generateKey(
      { name:'ECDH', namedCurve:'P-256' }, true, ['deriveKey','deriveBits']
    );
    // L8: random key_id
    const idBytes = crypto.getRandomValues(new Uint8Array(4));
    const keyId   = new DataView(idBytes.buffer).getUint32(0, false);
    const opkPub  = await exportPub(pair.publicKey, 'ECDH');
    const opkPriv = await crypto.subtle.exportKey('jwk', pair.privateKey);
    const blob    = await aesEncryptBlob(
      new TextEncoder().encode(JSON.stringify({ opk_priv: opkPriv, key_id: keyId })), _e2eCtxSession(`__otpk__${keyId}`)
    );
    _e2eWs({ type:'e2e_store_session', partner:`__otpk__${keyId}`, blob });
    keys.push({ key_id: keyId, public_key: opkPub });
  }
  _e2eWs({ type:'e2e_add_otpks', v: 3, keys });
}

// A header that arrived alone (relayed by the server, or inline/fragmented via IRC):
// remember it for the envelope that follows and pre-establish the responder session
// when that is safe (first contact / no usable session).
async function _e2eHandleHeader(nick, hdr, via) {
  const k = _e2eK(nick);
  if (!hdr || typeof hdr !== 'object') return;
  E2E._pendingIncomingX3DH = E2E._pendingIncomingX3DH || Object.create(null);
  if (!E2E._pendingIncomingX3DH[k]) _e2eSweepStrangerState();   // r9: bounded (see the sweep)
  E2E._pendingIncomingX3DH[k] = hdr; _e2ePendHdrAt.set(hdr, Date.now());
  if (E2E._x3dhWaiters && E2E._x3dhWaiters[k]) E2E._x3dhWaiters[k](hdr);
  try {
    const r = await e2eEstablishResponderSession(nick, hdr);
    if (!r.ok) return;  // changed (warned) / deferred / invalid: header stays pending
    delete E2E._pendingIncomingX3DH[k];
    updateE2EIndicator(nick);
    if (r.why !== 'replay') e2eSysMsg(nick, '🔐 E2E session established with ' + nick);
    // Envelopes that arrived before this header (reordered / delayed header lines).
    const orphans = (E2E._orphans && E2E._orphans[k]) || [];
    if (orphans.length) {
      delete E2E._orphans[k];
      for (const o of orphans) {
        try { _e2eShowDecrypted(o.conn_id, nick, nick, await _e2eDecryptWithFallback(k, o.envelope), `🔐 The next message from ${nick} arrived before its key exchange (delayed):`); }
        catch (e) { console.warn('[E2E] held message failed:', e && e.message); }
      }
    }
  } catch (e) {
    console.error('[E2E] x3dh pre-init failed (' + via + '):', e && (e.message || e.name));
    e2eSysMsg(nick, `🔐 X3DH setup failed: ${e && (e.message || e.name || String(e))}`);
  }
}

// H6: reassembly of fragmented headers ([e2ex3dh]~id~i~n~data). Caps: ≤8 fragments of
// ≤600 chars, ≤4 KiB total, ≤4 open ids per sender, ≤64 senders, 120 s TTL; a fragment
// index seen twice with different data poisons that id.
E2E._hdrFrags = Object.create(null);
function _e2eHdrFragment(from, text) {
  const m = /^\[e2ex3dh\]~([a-z0-9]{4,12})~([1-8])~([1-8])~([A-Za-z0-9+/=]{1,600})$/.exec(text);
  if (!m) return null;
  const k = _e2eK(from), id = m[1], i = +m[2], n = +m[3], data = m[4];
  if (i > n) return null;
  const now = Date.now();
  for (const s of Object.keys(E2E._hdrFrags)) {
    for (const fid of Object.keys(E2E._hdrFrags[s])) if (now - E2E._hdrFrags[s][fid].t > 120000) delete E2E._hdrFrags[s][fid];
    if (!Object.keys(E2E._hdrFrags[s]).length) delete E2E._hdrFrags[s];
  }
  if (!E2E._hdrFrags[k]) {
    if (Object.keys(E2E._hdrFrags).length >= 64) return null;
    E2E._hdrFrags[k] = Object.create(null);
  }
  const per = E2E._hdrFrags[k];
  let e = per[id];
  if (!e) {
    if (Object.keys(per).length >= 4) return null;
    e = per[id] = { n, parts: new Array(n).fill(null), t: now, bad: false };
  }
  if (e.bad || e.n !== n) { e.bad = true; return null; }
  if (e.parts[i - 1] !== null) { if (e.parts[i - 1] !== data) e.bad = true; return null; }
  e.parts[i - 1] = data;
  if (e.parts.some(p => p === null)) return null;
  delete per[id];
  const whole = e.parts.join('');
  if (whole.length > 4096) return null;
  try { return JSON.parse(atob(whole)); } catch (_) { return null; }
}

// ─── Encrypt / decrypt intercept ─────────────────────────────────────────────

// What E2E state a target is in: 'psk' | 'dm' (usable) | 'blocked' (E2E is on but
// can't be used — sends must be dropped) | 'none' (never encrypted → plaintext).
// opts: { incoming: checking a message that ARRIVED (no discovery kick / block),
//         conn_id: the connection the target is on (its CASEMAPPING / STATUSMSG) }.
function e2eTargetState(target, opts = null) {
  const t = String(target || '');
  // r2 (codex-p3 HIGH app.js:4917): "bob,carol" is several recipients. Each one keeps
  // its own E2E state; the combined line can only go out in cleartext if NONE of them
  // has E2E on (app.js /msg sends encrypted recipients one by one).
  if (t.includes(',')) {
    const parts = t.split(',').map(x => x.trim()).filter(Boolean);
    for (const x of parts) {
      const st = e2eTargetState(x, opts);
      if (st.mode !== 'none') return { mode: 'blocked', reason: `End-to-end encryption is on for ${x} — send to each recipient separately (one /msg per nick or channel)` };
    }
    return { mode: 'none' };
  }
  // r3 (codex-p3 HIGH e2e.js:2816): resolve the network's other spellings first.
  const cid = (opts && opts.conn_id) || null;
  const canon = _e2eCanon(t, cid);
  if (canon === null) return { mode:'blocked', reason:`${t} may be another spelling of an encrypted conversation under IRC case rules (e.g. [ ] vs { }) — message not sent; use the exact name` };
  const st0 = _e2eTargetStateOf(canon, t, opts);
  if (st0.mode !== 'none' || (opts && opts._alias)) return st0;
  for (const a of _e2eAliasesOf(t, cid)) {
    if (e2eTargetState(a, { ...(opts || {}), _alias: true }).mode !== 'none') {
      return { mode:'blocked', reason:`End-to-end encryption is on for ${a} — a message to ${t} can't be encrypted; send it to ${a} itself` };
    }
  }
  return st0;
}
// The E2E state of the resolved name `k` (lowercased); `t` = the name as written.
function _e2eTargetStateOf(k, t, opts) {
  const isDM = !_e2eIsChan(k);
  const hints = _e2eHints();
  const sh = E2E._serverHints;
  const srvCh = (sh && sh.channels) || [];
  const srvPeers = (sh && sh.peers) || [];
  // r6 (codex-p3 HIGH e2e.js:1007): reconnected, not re-synced yet → nothing goes out
  // (E2E may have been turned on, or a key rotated, on another device meanwhile).
  // `discovery`: app.js holds queued lines instead of failing them; sends wait for it.
  if (E2E._resyncPending && E2E.keyReady && !(opts && opts.incoming)) {
    _e2eKickResync();
    return { mode:'blocked', discovery: true, reason:'E2E status is being re-checked after the reconnect — message not sent; try again in a moment' };
  }
  const stCh = E2E.state && E2E.state.ch[k];
  if (E2E.channelKeys[k]) {
    if (E2E.chanRemoved[k]) return { mode:'blocked', reason:`The encryption key for ${t} was removed on another device or by the server — run /encrypt off to send unencrypted, or re-add the key` };
    // r6: the E2E state says a NEWER key generation is in use (rotated on another
    // device) than the key installed here — never encrypt with the replaced key.
    const kg = E2E._chanKeyGen[k];
    if (kg !== undefined && stCh && Number.isInteger(stCh.g) && stCh.g > kg) return { mode:'blocked', reason:`The encryption key for ${t} was rotated on another device and the new key has not loaded here yet — message not sent; reload if this persists` };
    return { mode:'psk' };
  }
  const stDm = E2E.state && E2E.state.dm[k];
  const chOn = !!(stCh && stCh.on) || hints.ch.includes(k) || (srvCh.includes(k) && !(stCh && !stCh.on));
  // r2 (NEW-3): /encrypt on is in progress (bundle requested, maybe queued in an outage).
  const pend = E2E._pendingOn && E2E._pendingOn[k];
  // r6 (codex-p3 e2e.js:3042): also while the answered bundle is being set up (identity
  // question open, session being created) — for as long as that takes: the bundle
  // handler removes the entry when it ends (any way), a lock wipes it, /encrypt off too.
  if (pend && (pend.answered || Date.now() - pend.t < 120000)) {
    return { mode:'blocked', reason: pend.answered ? `Encryption with ${t} is still being set up (confirm ${t}'s identity first) — message not sent` : `Encryption with ${t} is still being set up (waiting for ${t}'s key bundle) — message not sent; try again in a moment` };
  }
  if (!E2E.keyReady) {
    const dmOn = isDM && (hints.dm.includes(k) || srvPeers.includes(k));
    if (chOn || dmOn) {
      const why = E2E._bootPhase === 'loading' ? 'E2E keys are still loading — try again in a moment'
                                               : 'E2E is locked on this device — run /encrypt unlock';
      return { mode:'blocked', reason: why };
    }
    // r2 (codex-p3 HIGH e2e.js:2261): a browser that has not yet heard from the server
    // which targets have E2E state (fresh browser: no local hints) cannot know whether
    // this one is encrypted — BLOCK until discovery succeeds. There used to be a 15 s
    // grace after which (or after a failed lookup) sends silently went out in
    // cleartext. A failed / stalled discovery is retried.
    // r5 (agy-flash e2e.js:3284): REGARDLESS of _bootPhase — on a fresh load with the
    // vault locked no boot has run yet (_bootPhase undefined), and that used to fall
    // through to 'none' (cleartext) before the server had said anything. Only the
    // server's keyring reply (_krReceived; it lists this account's E2E peers/channels)
    // can establish that a target may go out unencrypted.
    if (!E2E._krReceived && !(opts && opts.incoming)) {
      _e2eKickDiscovery();
      return { mode:'blocked', discovery: true, reason:'E2E status for this account is not known yet (the server has not answered) — message not sent; try again in a moment' };
    }
    return { mode:'none' };
  }
  if (chOn) return { mode:'blocked', reason:`Encryption is on for ${t} but its key is missing (the server did not return it) — re-add the key, or /encrypt off to send unencrypted` };
  if (!isDM) return { mode:'none' };
  const s = E2E.dmSessions[k];
  const tr = E2E.trustStore[k];
  if (s && !s._unusable) {
    if (!E2E.identityReady) return { mode:'blocked', reason:'E2E identity not loaded on this device' };
    // r7 (codex-p3 e2e.js:1375): a session bound to another identity than the current pin
    // is never used — the server copy bound to the new identity is taken over if there is
    // one (checked before the next send), else /encrypt on sets up a new session.
    const mm = _e2eSessPinMismatch(k, s);
    if (mm === null) return { mode:'blocked', waitable: true, reason:`Checking the encrypted session with ${t} — try again in a moment` };
    if (mm) {
      const now = Date.now();
      E2E._pinAdoptAt = E2E._pinAdoptAt || Object.create(null);
      if (!(now - (E2E._pinAdoptAt[k] || 0) < 30000)) { E2E._pinAdoptAt[k] = now; _e2eMarkMaybeMoved(k); }
      return { mode:'blocked', reason:`${t}'s identity was replaced (accepted on another device) and the encrypted session here still belongs to the previous identity — message not sent. Run /encrypt on ${t} to set up a session with the new identity` };
    }
    if (!s.CKs && !s.DHr) return { mode:'blocked', waitable: true, reason:`Encrypted session with ${t} not ready yet — waiting for ${t}'s first message` };
    return { mode:'dm', changed: !!(tr && tr.keyChanged) };
  }
  // r2 (NEW-2): a peer with a stored session on the server counts as "on" unless this
  // page's state explicitly turned it off.
  const on = !!(stDm && stDm.on) || (srvPeers.includes(k) && !(stDm && !stDm.on));
  if (s && s._unusable) return { mode:'blocked', reason:`E2E session with ${t} unusable (${s._unusable})` };
  if (tr && tr.keyChanged && on) return { mode:'blocked', reason:`${t}'s identity key CHANGED — verify it, then /encrypt accept ${t} (or /encrypt off ${t})` };
  if (on) return { mode:'blocked', reason:`E2E is on for ${t} but there is no session — /encrypt on ${t} to re-establish, or /encrypt off ${t} to send unencrypted` };
  return { mode:'none' };
}
// Re-run a failed / stalled E2E discovery (at most every 5 s).
function _e2eKickDiscovery() {
  if (E2E._booting || E2E.keyReady || !E2E._vaultUp) return;
  const now = Date.now();
  if (now - (E2E._kickAt || 0) < 5000) return;
  E2E._kickAt = now;
  _e2eRun(() => _e2eBoot(null));
}

// NOTE: name must not collide with app.js globals (app.js has _e2eBlocked/_idbOpen).
function _e2eBlock(reason) {
  E2E.lastBlockReason = reason || 'Encrypted session not ready';
  return E2E_ENCRYPT_BLOCKED;
}

// H6: bytes available for the PRIVMSG text so the RELAYED line still fits 512 bytes.
// r2 (NEW-8): for the connection the line goes out on, not whatever window is active.
function _e2eWireBudget(target, cid) {
  let nick = '';
  try { if (typeof getNick === 'function' && cid) nick = String(getNick(cid) || ''); } catch (_) {}
  const nb = nick ? Math.max(_e2eUtf8len(nick), 9) : 30;
  return Math.max(160, E2E_IRC_LINE_MAX - E2E_LINE_FIXED_OVERHEAD - nb - _e2eUtf8len(target));
}
function _e2eB64len(n) { return 4 * Math.ceil(n / 3); }
// Exact wire length of one encrypted line for a plaintext of L bytes (p/n counters
// assumed ≤ 6 digits). PSK lines carry the r2 binding fields (+65 JSON bytes).
function _e2eWireLen(kind, L) {
  if (kind === 'dm') return E2E_DM_PREFIX.length + _e2eB64len(131 + _e2eB64len(28 + L));
  return E2E_CHAN_PREFIX.length + _e2eB64len(102 + _e2eB64len(L + 16));
}
function _e2eMaxPlain(kind, budget) {
  for (let L = 480; L >= 8; L--) if (_e2eWireLen(kind, L) <= budget) return L;
  return 8;
}
// Split plaintext into UTF-8-safe pieces of ≤ maxBytes (prefer a space near the end;
// keep a CTCP ACTION wrapper on every piece). Each piece is encrypted separately, so
// every receiver (old clients included) can decrypt each line on its own.
function _e2eSplit(text, maxBytes) {
  const enc = new TextEncoder();
  if (enc.encode(text).length <= maxBytes) return [text];
  let pre = '', suf = '';
  if (text.startsWith('\x01ACTION ') && text.endsWith('\x01') && text.length > 9) { pre = '\x01ACTION '; suf = '\x01'; text = text.slice(8, -1); maxBytes -= 9; }
  const out = []; let cur = '', curB = 0;
  for (const ch of text) {
    const b = enc.encode(ch).length;
    if (curB + b > maxBytes && cur) {
      const cut = cur.lastIndexOf(' ');
      if (cut > cur.length * 0.6) { out.push(cur.slice(0, cut)); cur = cur.slice(cut + 1); }
      else { out.push(cur); cur = ''; }
      curB = enc.encode(cur).length;
    }
    cur += ch; curB += b;
  }
  if (cur) out.push(cur);
  return out.map(p => pre + p + suf);
}
// Encrypt every piece now (in order); return the FIRST wire line to the caller (which
// sends it), and send the rest right after the caller's own send — on the connection
// and with the verb the caller uses (r2 NEW-8: captured when the send started).
// r5 (codex-p3 e2e.js:3371): `defer` (an array) = the caller sends several recipients
// and must validate/encrypt ALL of them before anything goes out — the later pieces are
// handed back in it ({ target, cid, raw }) instead of being scheduled here.
// r7 (codex-p3 app.js:13324): `meta` = what the pieces are encrypted with (recorded per
// wire line, see e2eQueuedWireVerdict).
async function _e2eEmitPieces(target, pieces, encFn, cid, verb = 'PRIVMSG', defer = null, meta = null) {
  const wires = [];
  for (const p of pieces) wires.push(await encFn(p));
  if (meta) _e2eNoteWires(wires, meta);
  if (wires.length > 1 && cid && Array.isArray(defer)) {
    for (const w of wires.slice(1)) defer.push({ target, cid, raw: `${verb} ${target} :${w}` });
  } else if (wires.length > 1 && cid) {
    const rest = wires.slice(1);
    setTimeout(() => {
      for (const w of rest) {
        const m = { type:'send', conn_id:cid, raw:`${verb} ${target} :${w}` };
        if (typeof rateLimitedSend === 'function') rateLimitedSend(m); else wsend(m);
      }
    }, 0);
  }
  return wires[0];
}
// r7 (codex-p3 app.js:13324): a queued encrypted line used to leave as it was — also
// after a reconnect re-sync rotated or removed the channel key it was encrypted with (a
// removed member keeps reading), or replaced the peer's identity. Every wire line is
// recorded with what encrypted it; app.js's send queue asks right before it leaves:
// 'hold' (E2E status being re-checked), 'send', or { refuse, reason }.
E2E._wireMeta = new Map();
const E2E_WIRE_META_MAX = 2000;
function _e2eNoteWires(wires, meta) {
  for (const w of wires) E2E._wireMeta.set(w, meta);
  while (E2E._wireMeta.size > E2E_WIRE_META_MAX) E2E._wireMeta.delete(E2E._wireMeta.keys().next().value);
}
// r8 (codex-p3 + agy-flash e2e.js:3689): also HELD — not refused — while this device's
// E2E keys are locked or still loading (vault / device lock: they come back with the
// unlock, which re-checks the line then), and for a waitable state (the session check
// still computing, a pending handshake) for up to 2 minutes (`heldMs` = how long app.js
// has held it). E2E locked by choice with the vault up is refused (holding the head of
// the queue there would block every later line).
function e2eQueuedWireVerdict(target, cid, text, heldMs) {
  const meta = E2E._wireMeta.get(text);
  const st = e2eTargetState(target, { conn_id: cid });
  if (st.mode === 'blocked' && st.discovery) return 'hold';
  if (!E2E.keyReady && (E2E._vaultUp !== true || E2E._booting || E2E._promptOpen)) return 'hold';
  if (st.mode === 'blocked' && st.waitable && !((heldMs || 0) > 120000)) return 'hold';
  E2E._wireMeta.delete(text);
  if (!meta) return { refuse: true, reason: 'what it was encrypted with is not known on this page any more' };
  if (st.mode !== meta.mode) return { refuse: true, reason: st.mode === 'blocked' ? (st.reason || 'E2E is blocked for it now') : 'its encryption changed since it was queued' };
  if (meta.mode === 'psk') {
    // By key GENERATION (a rotation always raises it): the reconnect re-sync re-imports
    // the same key as a new CryptoKey object, which must not refuse lines encrypted
    // with it. Object identity only when a generation is not known.
    const g = E2E._chanKeyGen[meta.k];
    const changed = !E2E.channelKeys[meta.k] || (meta.gen !== undefined && g !== undefined ? g !== meta.gen : E2E.channelKeys[meta.k] !== meta.key);
    if (changed) return { refuse: true, reason: 'the channel key changed (rotated or replaced) after it was encrypted' };
  }
  if (meta.mode === 'dm' && meta.fp) {
    const cur = _e2eSessFpCached(E2E.dmSessions[meta.k]);
    if (cur && cur !== meta.fp) return { refuse: true, reason: 'the identity of the other side changed after it was encrypted' };
  }
  return 'send';
}
// H6: header → PRIVMSG lines that each fit the relayed 512-byte limit.
function _e2eHeaderLines(hdr, target, cid) {
  const b64 = btoa(JSON.stringify(hdr));
  const budget = _e2eWireBudget(target, cid);
  const idb = crypto.getRandomValues(new Uint8Array(6));
  const id = Array.from(idb, b => 'abcdefghijklmnopqrstuvwxyz0123456789'[b % 36]).join('');
  const frameLen = (E2E_HDR_FRAG + id + '~8~8~').length;
  const per = Math.min(600, budget - frameLen);
  const n = Math.ceil(b64.length / per);
  if (n > 8) throw new Error('X3DH header too large to fragment');
  const lines = [];
  for (let i = 0; i < n; i++) lines.push(`${E2E_HDR_FRAG}${id}~${i + 1}~${n}~${b64.slice(i * per, (i + 1) * per)}`);
  return lines;
}
function _e2eSendHeader(target, sess, cid) {
  const k = _e2eK(target);
  E2E._hdrSent = E2E._hdrSent || Object.create(null);
  const last = E2E._hdrSent[k] || 0;
  if (last && Date.now() - last < 5 * 60 * 1000) return;
  const hdr = sess.x3dhPending;
  // Fast path: the server relays it to the peer's CryptIRC sessions (no IRC limits).
  _e2eWs({ type:'e2e_relay_x3dh', target_nick: target, header: hdr, conn_id: cid || undefined });
  // Robust path: inline over IRC (works when the peer is offline from the web UI but
  // its IRC connection is up, and is replayed from the daemon ring), fragmented. The
  // lines go through the SAME ordered send queue as chat lines (rateLimitedSend: FIFO,
  // survives a WebSocket outage), enqueued BEFORE the message, so the parts stay in
  // order and precede the envelope even if the socket is down right now. The header
  // also stays on the session (x3dhPending) until the peer answers, and the receiver
  // holds envelopes that arrive before their header, so a lost/late header recovers.
  if (!cid) return;
  let queued = true;
  for (const line of _e2eHeaderLines(hdr, target, cid)) {
    const m = { type:'send', conn_id:cid, raw:`PRIVMSG ${target} :${line}` };
    if (typeof rateLimitedSend === 'function') rateLimitedSend(m);
    else if (wsend(m) === false) queued = false;
  }
  if (queued) E2E._hdrSent[k] = Date.now();
}

// connId: the connection the caller sends on (r2 NEW-8 — the async senders, e.g. an
// upload finishing while another window is active, pass theirs; default: the active
// one, captured BEFORE any await). opts.verb: 'NOTICE' for /notice (default PRIVMSG).
async function e2eEncryptOutgoing(target, plaintext, connId, opts) {
  E2E.lastBlockReason = null;
  let cid = connId || null;
  if (!cid) { try { cid = (active && active.conn_id) || null; } catch (_) {} }
  const verb = opts && String(opts.verb || '').toUpperCase() === 'NOTICE' ? 'NOTICE' : 'PRIVMSG';
  // r6: right after a reconnect, wait (≤ 8 s) for the E2E re-sync instead of refusing.
  if (E2E._resyncPending && E2E.keyReady) { _e2eKickResync(); await _e2eResyncWait(8000); }
  // r3 (codex-p3 HIGH e2e.js:2816): the E2E name this spelling resolves to on this
  // network (#foo{ → the key held for #foo[ on an RFC1459 network). e2eTargetState
  // blocks an ambiguous one and STATUSMSG / nick@host forms of E2E targets.
  const k = _e2eCanon(target, cid) || _e2eK(target);
  const isDM = !_e2eIsChan(k) && !String(target || '').includes(',');
  if (isDM && E2E.keyReady) {
    // Another tab of this browser / another device may have moved this session on, or
    // set it up (only for peers E2E state knows about — a plain DM costs nothing).
    const stDm = E2E.state && E2E.state.dm[k];
    const known = !!E2E.dmSessions[k] || !!(stDm && stDm.on) || _e2eHints().dm.includes(k)
               || (!!E2E._serverHints && E2E._serverHints.peers.includes(k) && !(stDm && !stDm.on))
               || !!(E2E._devIdx && E2E._devIdx.has(k));
    if (known) {
      if (!E2E.dmSessions[k]) await _e2eLazyRestore(k);
      else await _withRatchetLock(k, async () => {});
      if (_e2eMovedPending(k)) await _e2eAdoptMoved(k);
    }
  }
  if (isDM && E2E.dmSessions[k]) { try { await _e2eSessFp(E2E.dmSessions[k]); } catch (_) {} }   // r7: for the pin comparison
  let st = e2eTargetState(target, { conn_id: cid });
  // A responder session can be mid-establishment (its first incoming message being
  // decrypted under the ratchet lock): wait for in-flight ratchet work, then re-check.
  if (st.mode === 'blocked' && st.waitable) { await _withRatchetLock(k, async () => {}); st = e2eTargetState(target, { conn_id: cid }); }
  if (st.mode === 'none') return null;
  if (st.mode === 'blocked') return _e2eBlock(st.reason);
  const budget = _e2eWireBudget(target, cid);
  if (st.mode === 'psk') {
    try {
      let me = null;
      try { if (typeof getNick === 'function' && cid) me = getNick(cid) || null; } catch (_) {}
      const pieces = _e2eSplit(String(plaintext), _e2eMaxPlain('psk', budget));
      const meta = { mode: 'psk', k, key: E2E.channelKeys[k], gen: E2E._chanKeyGen[k] };
      return await _e2eEmitPieces(target, pieces, (p) => channelEncrypt(k, p, me), cid, verb, opts && opts.defer, meta);
    } catch(e) { console.error('[E2E] PSK encrypt failed:', e); return _e2eBlock('Encryption failed — message not sent'); }
  }
  // Signal-protocol DM encryption (same-server only)
  try {
    const sess = E2E.dmSessions[k];
    if (sess.x3dhPending) _e2eSendHeader(target, sess, cid);
    const pieces = _e2eSplit(String(plaintext), _e2eMaxPlain('dm', budget));
    const meta = { mode: 'dm', k, fp: _e2eSessFpCached(sess) || null };
    const wire = await _e2eEmitPieces(target, pieces, async (p) => E2E_DM_PREFIX + btoa(JSON.stringify(await ratchetEncrypt(k, p))), cid, verb, opts && opts.defer, meta);
    if (st.changed) _e2eSys(target, `⚠️ ${target} presented a DIFFERENT identity key (not accepted). This message was encrypted to the key you already trust. /encrypt accept ${target} or /encrypt reject ${target}`);
    return wire;
  } catch(e) {
    console.error('[E2E] DM encrypt failed:', e);
    // #F4: a DM session EXISTS — the encrypt failed. Never fall back to cleartext.
    return _e2eBlock(`Encrypted session with ${target} not ready — ${e && e.message ? e.message : 'encrypt failed'}`);
  }
}

// Stash for messages that arrived under an unaccepted changed key (decrypted if the
// user accepts it). ≤20 per peer.
function _e2eStashChanged(k, x3dh, envelope, connId = null) {
  E2E._changedStash = E2E._changedStash || Object.create(null);
  const a = E2E._changedStash[k] || (E2E._changedStash[k] = []);
  if (a.length < 20) a.push({ x3dh, envelope, conn_id: connId });
}

// r2 (v-e2e NEW-6): E2E DM traffic that arrives while E2E is locked on this device is
// held (≤60 items, 30 min) and processed once E2E unlocks, instead of being lost.
function _e2eHoldLocked(item) {
  const now = Date.now();
  E2E._lockedHold = (E2E._lockedHold || []).filter(x => now - x.t < 30 * 60 * 1000);
  if (E2E._lockedHold.length < 60) E2E._lockedHold.push({ ...item, t: now });
}
async function _e2eReleaseLockedHold() {
  const items = E2E._lockedHold || []; E2E._lockedHold = [];
  for (const it of items) {
    if (Date.now() - it.t > 30 * 60 * 1000) continue;
    try {
      if (it.kind === 'relay') { await _e2eHandleHeader(it.from, it.header, 'relay'); continue; }
      const r = await e2eDecryptIncoming(it.from, it.target, it.text, { conn_id: it.conn_id, live: false, held: true });
      if (r && r.encrypted && typeof r.plaintext === 'string' && !r.duplicate) {
        _e2eShowDecrypted(it.conn_id, it.from, it.from, r.plaintext, `🔐 The next message from ${it.from} arrived while E2E was locked here:`);
      }
    } catch (e) { console.warn('[E2E] held message failed:', e && e.message); }
  }
}
// INFO-3: a decrypted "\x01ACTION …\x01" is a /me — app.js renders it as an action.
function e2eSplitAction(text) {
  const t = String(text == null ? '' : text);
  if (t.length > 9 && t.startsWith('\x01ACTION ') && t.endsWith('\x01')) return { action: true, text: t.slice(8, -1) };
  return { action: false, text: t };
}
// r2 (security review): decrypted text shown LATER (held while locked, arrived before
// its key exchange, held until a key change was accepted) is a real encrypted message
// from `from`: it goes through addMessage with encrypted:true on its own connection —
// so it is badged and its links are never auto-previewed via the server — with a
// separate system note (no message text in it) saying why it is late.
function _e2eShowDecrypted(connId, peer, from, text, note) {
  const a = e2eSplitAction(text);
  let cid = connId || null;
  if (!cid) { try { cid = (active && active.conn_id) || null; } catch (_) {} }
  if (note) { try { sysMsg(cid, peer, note, 'system'); } catch (_) { _e2eSys(peer, note); } }
  try {
    if (typeof addMessage === 'function' && cid) {
      addMessage(cid, peer, { ts: Math.floor(Date.now() / 1000), from, text: a.text, kind: a.action ? 'action' : 'privmsg', encrypted: true });
      return;
    }
  } catch (e) { console.warn('[E2E] could not show a held message:', e && e.message); return; }
  _e2eSys(peer, `🔐 ${from}: ${a.text}`);   // no app.js (test harness)
}
// A structurally valid DM envelope (anything else is dropped at once, without any
// lookup or wait — codex-p3 MED e2e.js:2485).
function _e2eEnvelopeOk(env) {
  if (!env || typeof env !== 'object' || Array.isArray(env)) return false;
  const c = env.c || env.ciphertext;
  if (typeof c !== 'string' || c.length < 24 || c.length > 8192) return false;
  if (env.h) return typeof env.h === 'object' && typeof env.h.d === 'string' && env.h.d.length >= 40 && env.h.d.length <= 200
                    && Number.isInteger(env.h.n) && env.h.n >= 0 && Number.isInteger(env.h.p) && env.h.p >= 0;
  return !!(env.header && typeof env.header === 'object' && typeof env.header.dh === 'string');
}

// opts: { conn_id: the connection it arrived on, live: a message arriving now (not
// history / a daemon replay), held: re-processing something held while locked }.
// Result: { plaintext, encrypted, duplicate? } — duplicate: an exact repeat of a live
// encrypted channel message already shown (drop it).
async function e2eDecryptIncoming(from, target, text, opts = {}) {
  const isDM = !_e2eIsChan(target);
  let fk = _e2eK(from);
  let me = '';
  try { if (typeof getNick === 'function') { const cid = opts.conn_id || (active && active.conn_id); if (cid) me = _e2eK(getNick(cid)); } } catch (_) {}

  // Pre-shared key decryption — works for both channels and DMs
  if (text.startsWith(E2E_CHAN_PREFIX)) {
    // r6 (codex-p3 e2e.js:3129): never with E2E locked here — a key that slipped back
    // into memory after the wipe must not decrypt anything while the device is locked.
    if (!E2E.keyReady) return { plaintext:'🔐 [encrypted — E2E is locked on this device: /encrypt unlock]', encrypted:true };
    // For DMs, the PSK is stored under the sender's nick. r3: resolved under the
    // network's casemapping (the server relays its own spelling of the channel).
    // r4 (SEC-HOOK-W1): receive side → the network's REAL casemapping (_e2eRecvName).
    const pskTarget = _e2eRecvName(isDM ? from : target, opts.conn_id);
    const po = { live: !!opts.live, self: !!me && fk === me };
    let r = await channelDecryptEx(pskTarget, text, from, po);
    if (!r && isDM) r = await channelDecryptEx(target, text, from, po);
    if (r) {
      if (r.replay) return { plaintext: null, encrypted: true, duplicate: true };
      return { plaintext: _e2ePskShown(r, from), encrypted: !r.bad };
    }
    if (!E2E.keyReady) return { plaintext:'🔐 [encrypted — E2E is locked on this device: /encrypt unlock]', encrypted:true };
    return { plaintext:'🔐 [encrypted — wrong or missing key]', encrypted:true };
  }

  // r4 (agy-flash F3-3 + SEC-HOOK-W1): an encrypted DM from a sender who is a known E2E
  // peer under the network's REAL casemapping (`{bob}` for the session held as `[bob]` on
  // a CASEMAPPING=rfc1459 network — one nick there) is decrypted with that peer's
  // EXISTING session (it used to find no session: a 3 s header wait, then "cannot
  // decrypt", while our replies to `{bob}` used `[bob]`'s session). Only the real mapping
  // counts (see _e2eRecvName: ascii when unknown, never NFKC unless rfc8265). The sender
  // stays displayed as `from` (the nick it used); `fk` only selects the session. A
  // remapped sender never starts or replaces a session: its inline / pending / awaited
  // X3DH headers are ignored below, and its header LINES are handled under the exact
  // spelling (branch above → a separate peer with its own TOFU question).
  const fkExact = fk;
  let remapped = false;
  if (isDM && opts.prefix && (text.startsWith(E2E_HDR_PREFIX) || text.startsWith(E2E_DM_PREFIX))) _e2eNoteSenderPrefix(fkExact, opts.prefix);   // r4 (N5): /ignore check
  if (isDM && text.startsWith(E2E_DM_PREFIX)) {
    const c = _e2eRecvName(from, opts.conn_id);
    if (c && c !== fk) { fk = c; remapped = true; }
  }

  // X3DH header (sent before the first encrypted message): fragmented or single-line.
  if (isDM && text.startsWith(E2E_HDR_PREFIX)) {
    let hdr = null;
    if (text.startsWith(E2E_HDR_FRAG)) hdr = _e2eHdrFragment(from, text);
    else { try { hdr = JSON.parse(atob(text.slice(E2E_HDR_PREFIX.length))); } catch (e) { console.error('[E2E] x3dh header parse failed:', e); } }
    if (hdr && E2E.identityReady && E2E.identityKeys) await _e2eHandleHeader(from, hdr, 'irc');
    else if (hdr && !opts.held) _e2eHoldLocked({ kind: 'relay', from, header: hdr });
    return { plaintext: null, encrypted: false }; // don't display the header message
  }

  if (isDM && text.startsWith(E2E_DM_PREFIX)) {
    let envelope;
    try { envelope = JSON.parse(atob(text.slice(E2E_DM_PREFIX.length))); } catch (_) { envelope = null; }
    if (!_e2eEnvelopeOk(envelope)) return { plaintext:'🔐 [invalid encrypted message — ignored]', encrypted:true };
    if (!E2E.identityReady || !E2E.identityKeys) {
      if (!opts.held) _e2eHoldLocked({ kind: 'dm', from, target, text, conn_id: opts.conn_id });
      return { plaintext: E2E.keyReady ? '🔐 [E2E identity not loaded on this device — it will be shown when it is]' : '🔐 [encrypted — E2E is locked on this device: /encrypt unlock (it will be shown then)]', encrypted:true };
    }
    try {
      // #47: x3dh header comes inline (envelope.x3dh_header, legacy) or via a preceding
      // header line / the server relay.
      // r4 (SEC-HOOK-W1): a remapped sender may only use the existing session.
      let x3dh = remapped ? null : (envelope.x3dh_header || null);
      if (!remapped && !x3dh && E2E._pendingIncomingX3DH?.[fk]) {
        x3dh = E2E._pendingIncomingX3DH[fk];
        delete E2E._pendingIncomingX3DH[fk];
      }
      // A newer copy from another tab of this browser?
      if (!x3dh) await _withRatchetLock(fk, async () => {});
      // No header and no session: lazily try a stored session (pre-upgrade sessions are
      // not auto-restored), then wait up to 3s for a relayed header.
      if (!x3dh && !E2E.dmSessions[fk]) {
        E2E._lazyTried = E2E._lazyTried || Object.create(null);
        if (!E2E._lazyTried[fk] && Object.keys(E2E._lazyTried).length >= E2E_STRANGER_MAX) E2E._lazyTried = Object.create(null);   // r8: bounded
        if (!E2E._lazyTried[fk]) {
          E2E._lazyTried[fk] = true;
          const blob = await _e2eFetchSession(fk);
          if (blob && await _e2eInstallStoredSession(fk, blob)) _e2eStateSetDm(fk, true);
          else if (!_e2eReservedNamespace(fk)) {
            const lb = await _e2eFetchSession('__legacy__' + fk);
            if (lb && await _e2eInstallStoredSession(fk, lb, '__legacy__' + fk)) {
              _e2eStateSetDm(fk, true);
              await saveSession(fk, E2E.dmSessions[fk]);
              _e2eWs({ type:'e2e_delete_session', v: E2E_STORAGE_VERSION, partner:'__legacy__' + fk });
            }
          }
        }
      }
      // r2 (codex-p3 MED e2e.js:2485): at most ONE header wait per peer at a time, and
      // none for a minute after a wait for that peer timed out (a sender spraying
      // envelopes); those are held as orphans right away (shown if a header ever arrives
      // — a late header still decrypts them). app.js
      // now also queues per conversation, so a wait never delays anybody else's chat.
      E2E._hdrWait = E2E._hdrWait || Object.create(null);
      if (!E2E._hdrWait[fk]) _e2eSweepStrangerState();   // r8
      const hw = E2E._hdrWait[fk] || (E2E._hdrWait[fk] = { busy: false, fails: [] });
      hw.fails = hw.fails.filter(t => Date.now() - t < 60000);
      if (!remapped && !x3dh && !E2E.dmSessions[fk] && !hw.busy && hw.fails.length < 1) {
        hw.busy = true;
        try {
          x3dh = await new Promise(resolve => {
            if (E2E._pendingIncomingX3DH?.[fk]) { const h = E2E._pendingIncomingX3DH[fk]; delete E2E._pendingIncomingX3DH[fk]; resolve(h); return; }
            if (!E2E._x3dhWaiters) E2E._x3dhWaiters = Object.create(null);
            const timeout = setTimeout(() => { delete E2E._x3dhWaiters[fk]; resolve(null); }, 3000);
            E2E._x3dhWaiters[fk] = (hdr) => { clearTimeout(timeout); delete E2E._x3dhWaiters[fk]; resolve(hdr); };
          });
        } finally { hw.busy = false; }
        if (!x3dh) hw.fails.push(Date.now());
        if (x3dh && E2E._pendingIncomingX3DH) delete E2E._pendingIncomingX3DH[fk];
      }

      if (x3dh) {
        const existing = E2E.dmSessions[fk];
        // r8 (codex-p3 e2e.js:4043): a session bound to a replaced identity (accepted on
        // another device) does not authenticate anything — the header is considered.
        if (existing && !existing._unusable) { try { await _e2eSessFp(existing); } catch (_) {} }
        const existingOk = existing && !existing._unusable && _e2eSessPinMismatch(fk, existing) !== true;
        // H5: a header we hold is not necessarily related to THIS message (a forged
        // header-only [e2ex3dh] can sit pending). If the live session decrypts the
        // message (atomic: a failed attempt changes nothing) it is a continuing message
        // from the peer we already trust — the header plays no part, trust is untouched.
        if (existingOk) {
          try {
            const pt = await _e2eDecryptWithFallback(fk, envelope);
            if (!envelope.x3dh_header && x3dh.ephemeral_pub && existing.establishEph !== x3dh.ephemeral_pub) {
              E2E._pendingIncomingX3DH = E2E._pendingIncomingX3DH || Object.create(null);
              if (!E2E._pendingIncomingX3DH[fk]) E2E._pendingIncomingX3DH[fk] = x3dh;
            }
            const tr0 = E2E.trustStore[fk];
            if (tr0 && tr0.keyChanged) _e2eSys(from, `⚠️ ${from} recently presented a DIFFERENT identity key (not accepted). The message above was authenticated with the key you already trust. /encrypt accept ${from} or /encrypt reject ${from}`);
            return { plaintext:pt, encrypted:true };
          } catch (_) { /* not a continuing message — consider the header */ }
        }
        // MEDIUM (glare): both sides ran /encrypt on before seeing the other's header.
        // Deterministic tie-break — the X3DH started by the party whose identity DH key
        // sorts LOWER wins on both ends. The winner keeps its initiator session and reads
        // the loser's in-flight messages with a side session; the loser switches to
        // responder of the winner's X3DH.
        if (existingOk && existing.isInitiator && !existing.CKr && existing.x3dhPending) {   // r8: not with a replaced identity's session
          const myDh = await exportPub(E2E.identityKeys.dhKeyPair.publicKey, 'ECDH');
          const iWin = _e2eCmpBytes(base64ToBytes(myDh), base64ToBytes(String(x3dh.sender_ik || ''))) < 0;
          if (iWin) {
            const r = await _e2eEstablishAndDecrypt(from, x3dh, envelope, { withEnvelope: true, alt: true });
            if (!r.ok) return _e2eRefusedResult(fk, r, x3dh, envelope, from, opts.conn_id);
            return { plaintext:r.pt, encrypted:true };
          }
        }
        // #1: authenticate the sender identity (TOFU pin / key-change refusal) BEFORE
        // establishing and decrypting. #3: the new session is bound to this first message
        // (the prior session is restored if it doesn't decrypt), and establishment +
        // first decrypt run under ONE ratchet lock, so an outgoing message can't slip in
        // between and find a half-built (not yet send-ready) responder session.
        const r = await _e2eEstablishAndDecrypt(from, x3dh, envelope, { withEnvelope: true });
        if (!r.ok) return _e2eRefusedResult(fk, r, x3dh, envelope, from, opts.conn_id);
        if (E2E._glareAlt) delete E2E._glareAlt[fk];
        updateE2EIndicator(from);
        return { plaintext:r.pt, encrypted:true };
      }

      const live = E2E.dmSessions[fk];
      if (!live && remapped) return { plaintext:`🔐 [encrypted — cannot decrypt: no encryption session with ${from}]`, encrypted:true };
      if (!live) {
        // Header not here (yet): hold the envelope (≤20/peer, 10 min) and decrypt it as
        // soon as a header for this peer establishes a session.
        _e2eSweepStrangerState();   // r8: expired / excess entries of OTHER nicks too
        E2E._orphans = E2E._orphans || Object.create(null);
        const oa = (E2E._orphans[fk] || []).filter(o => Date.now() - o.t < 600000);
        if (oa.length < 20) oa.push({ t: Date.now(), envelope, conn_id: opts.conn_id || null });
        E2E._orphans[fk] = oa;
        return { plaintext:'🔐 [encrypted — waiting for the key exchange; it will be shown when it arrives]', encrypted:true };
      }
      // r8 (codex-p3 e2e.js:4043): the live session must belong to the identity pinned NOW
      // — after a replacement was accepted on another device the old ratchet kept
      // returning authenticated ("encrypted") plaintext. Take over the other device's
      // session for the new identity if there is one; otherwise the line is not shown.
      if (!live._unusable) {
        try { await _e2eSessFp(live); } catch (_) {}
        if (_e2eSessPinMismatch(fk, live) === true) {
          const now = Date.now();
          E2E._pinAdoptAt = E2E._pinAdoptAt || Object.create(null);
          if (!(now - (E2E._pinAdoptAt[fk] || 0) < 30000)) { E2E._pinAdoptAt[fk] = now; _e2eMarkMaybeMoved(fk); }   // at most every 30 s
          try { await _e2eAdoptMoved(fk); } catch (_) {}
          const nl = E2E.dmSessions[fk];
          if (nl) { try { await _e2eSessFp(nl); } catch (_) {} }
          if (!nl || nl._unusable || _e2eSessPinMismatch(fk, nl) === true) {
            return { plaintext:`🔐 [not shown: encrypted with the session of ${from}'s PREVIOUS identity — ${from}'s identity was replaced (accepted on another device). /encrypt on ${from} sets up a session with the new identity]`, encrypted:true };
          }
        }
      }
      let pt;
      try { pt = await _e2eDecryptWithFallback(fk, envelope); }
      catch (e) {
        // r2 (NEW-7): another device of this account answered on this session: adopt
        // its copy and try once more.
        if (_e2eMovedPending(fk) && await _e2eAdoptMoved(fk)) pt = await _e2eDecryptWithFallback(fk, envelope);
        else throw e;
      }
      const tr = E2E.trustStore[fk];
      if (tr && tr.keyChanged) _e2eSys(from, `⚠️ ${from} recently presented a DIFFERENT identity key (not accepted). The message above was authenticated with the key you already trust. /encrypt accept ${from} or /encrypt reject ${from}`);
      return { plaintext:pt, encrypted:true };
    } catch(e) {
      const errMsg = e.message || e.name || String(e);
      console.error('[E2E] DM decrypt FAILED:', errMsg, e.stack || e);
      if (/^E2E_(SPK|OTPK)_MISSING/.test(errMsg)) {
        return { plaintext:`🔐 [encrypted — ${from} started encryption with a prekey this account no longer has. Ask ${from} to restart it: /encrypt off ${me || 'you'} then /encrypt on ${me || 'you'}]`, encrypted:true };
      }
      return { plaintext:`🔐 [decryption failed: ${errMsg}]`, encrypted:true };
    }
  }

  // LOW: cleartext arriving in a DM that has E2E on is flagged, so injected plaintext
  // can't pass for part of the encrypted conversation.
  // r6 (agy-flash e2e.js:3830): CTCP-framed text too — a line starting with \x01 skipped
  // the flag and was shown (delimiters invisible) like encrypted chat. It is flagged and
  // shown as what it is ("CTCP PING: …", "CTCP VERSION reply: …"); the CTCP replies
  // themselves are produced server-side and are not affected.
  if (isDM && text && fk !== me && e2eTargetState(from, { incoming: true, conn_id: opts.conn_id }).mode !== 'none') {
    if (text.startsWith('\x01')) {
      const m = /^\x01([A-Za-z0-9_-]{1,32})(?:[ ]([^\x01]*))?\x01?$/.exec(text);
      const reply = String(opts.kind || '').toLowerCase() === 'notice';
      const shown = m ? `CTCP ${m[1].toUpperCase()}${reply ? ' reply' : ''}${m[2] ? ': ' + m[2] : ''}` : text.replace(/\x01/g, '');
      return { plaintext:'⚠️ [NOT ENCRYPTED] ' + shown, encrypted:false };
    }
    return { plaintext:'⚠️ [NOT ENCRYPTED] ' + text, encrypted:false };
  }
  return { plaintext:null, encrypted:false };
}

async function _e2eEstablishAndDecrypt(from, x3dh, envelope, opts) {
  const fk = _e2eK(from);
  return _withRatchetLock(fk, async () => {
    const savedSession = opts.alt ? null : E2E.dmSessions[fk];
    const r = await _e2eEstablishInner(from, x3dh, opts);
    if (!r.ok) return r;
    try {
      const pt = await _ratchetDecryptInner(fk, envelope, !!opts.alt);
      return { ok: true, why: r.why, pt };
    } catch (e) {
      if (!opts.alt && savedSession && E2E.dmSessions[fk] !== savedSession) {
        await saveSession(fk, savedSession);
        console.warn('[E2E] X3DH re-establishment failed to authenticate — restored prior session for', from);
      }
      if (opts.alt && E2E._glareAlt) delete E2E._glareAlt[fk];
      throw e;
    }
  });
}

// Main session first; a glare side session (if any) second. Dropping the side session
// once the main one works again.
async function _e2eDecryptWithFallback(fk, envelope) {
  try {
    const pt = await ratchetDecrypt(fk, envelope);
    if (E2E._glareAlt && E2E._glareAlt[fk]) delete E2E._glareAlt[fk];
    return pt;
  } catch (e) {
    if (E2E._glareAlt && E2E._glareAlt[fk]) return await ratchetDecrypt(fk, envelope, true);
    throw e;
  }
}

function _e2eRefusedResult(fk, r, x3dh, envelope, from, connId = null) {
  if (r.why === 'changed') {
    _e2eStashChanged(fk, x3dh, envelope, connId);
    return { plaintext:`🔐 [message under a CHANGED identity key for ${from} — not decrypted. Verify it, then /encrypt accept ${from}]`, encrypted:true };
  }
  if (r.why === 'rejected') return { plaintext:'🔐 [encrypted message — identity not accepted]', encrypted:true };
  if (r.why === 'ratelimited') return { plaintext:'🔐 [encrypted message — too many re-handshakes, ignored]', encrypted:true };
  return { plaintext:'🔐 [encrypted message — key exchange refused (invalid header)]', encrypted:true };
}

// ─── /encrypt command ─────────────────────────────────────────────────────────

// r2 (NEW-3): send the bundle request, retrying while the socket is down (≤2 min);
// once it went out, give up after 30 s without an answer (the server always answers:
// e2e_bundle or an error). The target stays BLOCKED while pending.
async function _e2eFetchBundleQueued(nick, k, cid) {
  const started = Date.now();
  for (;;) {
    const p = E2E._pendingOn && E2E._pendingOn[k];
    if (!p || p.t > started) return;                     // answered / cancelled / superseded
    if (await _e2eWs({ type:'e2e_fetch_bundle', username:nick, conn_id: cid })) { p.sentAt = Date.now(); break; }
    if (Date.now() - started > 120000) {
      delete E2E._pendingOn[k];
      _e2eSys(p.target, `🔓 Could not reach the server to set up encryption with ${nick} — NOT started (messages to ${nick} are not encrypted). Try /encrypt on ${nick} again.`);
      try { updateE2EIndicator(p.target); } catch (_) {}
      return;
    }
    await new Promise(r => setTimeout(r, 2000));
  }
  const sentAt = Date.now();
  // The pending entry blocks for up to 120 s (e2eTargetState); report a lost answer.
  setTimeout(() => {
    const p = E2E._pendingOn && E2E._pendingOn[k];
    if (!p || p.t > started || p.answered) return;     // r6: answered → being set up
    delete E2E._pendingOn[k];
    _e2eSys(p.target, `🔓 No answer from the server for ${nick}'s key bundle — encryption with ${nick} was NOT started. Try /encrypt on ${nick} again.`);
    try { updateE2EIndicator(p.target); } catch (_) {}
  }, Math.max(1000, 30000 - (Date.now() - sentAt)));
}

async function handleEncryptCommand(args, conn_id, target) {
  const sub = (args[0] || '').toLowerCase();
  const dmTarget = !_e2eIsChan(target) && target !== 'status' ? target : null;
  // r5 (agy-flash app.js:9205 + security review): the key a window's PSK operations
  // (keygen / add / share / rotate / off) act on is resolved under the network's REAL
  // case rules (_e2eKeyCmdName) — #room{ on an RFC1459 network is the key held as
  // #room[ (asked first: another spelling), while a look-alike that is a different
  // conversation there (#ｓｅｃ vs #sec on a non-PRECIS network) is refused: these
  // commands overwrite, remove or disclose a key. null = refused / cancelled.
  const keyName = async (t, verb) => {
    const r = _e2eKeyCmdName(t, conn_id || (active && active.conn_id) || null);
    if (r.refuse) { e2eSysMsg(target, r.refuse); return null; }
    const gen = E2E._lockGen;
    if (r.ask && !(await _e2eKeyCmdConfirm(`${r.ask}\n\n${verb} the E2E key held for ${r.name}?`, verb))) {
      e2eSysMsg(target, `🔐 Cancelled — nothing was changed for ${t}`); return null;
    }
    // the question may stay open for a while: a lock meanwhile cancels the command
    // (keygen / rotate / add would otherwise put a key into memory after the wipe)
    if (r.ask && (E2E._lockGen !== gen || (verb === 'Replace' && !E2E.keyReady))) {
      e2eSysMsg(target, `🔐 E2E was locked meanwhile — nothing was changed for ${t}`); return null;
    }
    return r.name;
  };

  switch(sub) {
    case 'unlock': {
      if (E2E.keyReady) { e2eSysMsg(target, '🔐 E2E is already unlocked on this device'); return; }
      await e2ePromptDeviceUnlock();
      break;
    }
    case 'on': case 'start': {
      const nick = args[1] || target;
      if (!nick || _e2eIsChan(nick) || nick === 'status') { e2eSysMsg(target,'Usage: /encrypt on <nick>'); return; }
      if (!E2E.keyReady) { e2eSysMsg(target,'🔐 E2E is locked on this device — /encrypt unlock first'); return; }
      if (!E2E.identityReady) { e2eSysMsg(target,'🔐 E2E identity not loaded yet — try again in a moment'); return; }
      const k = _e2eK(nick);
      const cur = E2E.dmSessions[k];
      // r7: a session bound to a replaced identity (accepted on another device) is replaced.
      if (cur && !cur._unusable) { try { await _e2eSessFp(cur); } catch (_) {} }
      if (cur && !cur._unusable && _e2eSessPinMismatch(k, cur) !== true) { e2eSysMsg(target,`🔐 Session with ${nick} already active`); return; }
      if (E2E.trustStore[k]?.keyChanged) { e2eSysMsg(target,`⚠️ ${nick}'s identity key changed — /encrypt accept ${nick} (after verifying) or /encrypt reject ${nick} first`); return; }
      // r2 (v-e2e NEW-3): from now until the bundle answer, messages to this nick are
      // BLOCKED (never cleartext), and the request is QUEUED if the socket is down —
      // it used to be dropped silently during an outage while the next typed line went
      // out unencrypted after the reconnect.
      const cid = conn_id || (active && active.conn_id) || undefined;
      E2E._pendingOn = E2E._pendingOn || Object.create(null);
      E2E._pendingOn[k] = { t: Date.now(), target, cid };
      updateE2EIndicator(target);
      e2eSysMsg(target,`🔐 Fetching key bundle for ${nick}… (messages to ${nick} are held back until encryption is set up)`);
      _e2eFetchBundleQueued(nick, k, cid);
      break;
    }
    case 'keygen': {
      if (!E2E.keyReady) { e2eSysMsg(target,'🔐 E2E is locked on this device — /encrypt unlock first'); return; }
      const kn = await keyName(target, 'Replace'); if (kn === null) return;
      const { keyWords, keyB64, key } = await generateChannelKey();
      if (!E2E.keyReady) { e2eSysMsg(target, '🔐 E2E was locked meanwhile — nothing was changed'); return; }   // r5: locked during the key generation
      await storeChannelKey(kn, key, keyB64);
      const label = _e2eIsChan(target) ? 'Channel' : 'DM';
      e2eSysMsg(target,`🔐 ${label} key generated for ${target}.`);
      updateE2EIndicator(target);
      await _e2eShowSharedKey(keyWords);
      break;
    }
    case 'add': {
      const words = args.slice(1);
      if (words.length !== 32) { e2eSysMsg(target,'Usage: /encrypt add <word1> … <word32>  (32 words)'); return; }
      if (!E2E.keyReady) { e2eSysMsg(target,'🔐 E2E is locked on this device — /encrypt unlock first'); return; }
      const kn = await keyName(target, 'Replace'); if (kn === null) return;
      try {
        const { key, keyB64 } = await importChannelKeyFromWords(words.join(' '));
        if (!E2E.keyReady) { e2eSysMsg(target, '🔐 E2E was locked meanwhile — nothing was changed'); return; }   // r5: locked during the key generation
        await storeChannelKey(kn, key, keyB64);
        e2eSysMsg(target,`🔐 Key added — messages now encrypted`);
        updateE2EIndicator(target);
      } catch(e) { e2eSysMsg(target,`❌ ${e.message}`); }
      break;
    }
    case 'share': {
      const kn = await keyName(target, 'Show'); if (kn === null) return;
      const key = E2E.channelKeys[kn];
      if (!key) { e2eSysMsg(target,`No key for ${target} — use /encrypt keygen first`); return; }
      const raw   = await crypto.subtle.exportKey('raw', key);
      const bytes = new Uint8Array(raw);
      const words = bytesToMnemonic(bytes).join(' ');
      bytes.fill(0);
      if (E2E.channelKeys[kn] === key) await _e2eShowSharedKey(words);
      break;
    }
    case 'rotate': {
      if (!E2E.keyReady) { e2eSysMsg(target,'🔐 E2E is locked on this device — /encrypt unlock first'); return; }
      const kn = await keyName(target, 'Replace'); if (kn === null) return;
      const { keyWords, keyB64, key } = await generateChannelKey();
      if (!E2E.keyReady) { e2eSysMsg(target, '🔐 E2E was locked meanwhile — nothing was changed'); return; }   // r5: locked during the key generation
      await storeChannelKey(kn, key, keyB64);
      e2eSysMsg(target,`🔐 Key rotated for ${target}.`);
      updateE2EIndicator(target);
      await _e2eShowSharedKey(keyWords);
      break;
    }
    case 'off': case 'stop': {
      if (!E2E.keyReady) {
        e2eSysMsg(target, '🔐 Unlock encrypted chats before disabling encryption.');
        return;
      }
      const nick = _e2eIsChan(target) ? target : (args[1] || target);
      const k = await keyName(nick, 'Remove');
      if (k === null || !E2E.keyReady) return;
      const gen = E2E._lockGen;
      const stored = await _e2eReq({ type: 'e2e_load_keyring' }, 'e2e_keyring');
      if (_e2eBootStale(gen)) return;
      if (!stored) { e2eSysMsg(target, '🔐 Could not check stored keys. Encryption stays on.'); return; }
      const channels = Array.isArray(stored.channels) ? stored.channels : [];
      const peers = Array.isArray(stored.peers) ? stored.peers : [];
      const sh = E2E._serverHints;
      const h = _e2eHints();
      const isChannel = _e2eIsChan(target);
      const shared = isChannel || E2E.channelKeys[k] || E2E.chanRemoved[k] || E2E.state?.ch[k]?.on ||
        sh?.channels.includes(k) || h.ch.includes(k) || channels.some(name => _e2eK(name) === k);
      const storedSessions = peers.filter(name => _e2eK(name) === k);
      const session = !isChannel && (E2E.dmSessions[k] || E2E.state?.dm[k]?.on || sh?.peers.includes(k) || h.dm.includes(k) || storedSessions.length);
      if (shared && !(await removeChannelKey(k, channels))) {
        e2eSysMsg(target, '🔐 Could not confirm shared-key removal. Encryption stays on.');
        return;
      }
      if (session) {
        const removed = await _withRatchetLock(k, async () => {
          for (const partner of new Set([k, ...storedSessions])) {
            if (_e2eBootStale(gen) || !(await _e2eDeleteSlot({ type:'e2e_delete_session', partner }))) return false;
          }
          await _e2eDropSession(k, false);
          return true;
        });
        if (!removed) { e2eSysMsg(target, '🔐 Could not confirm session removal. Encryption stays on.'); return; }
        _e2eStateSetDm(k, false, true);
      }
      const pending = !!E2E._pendingOn?.[k];
      if (pending) delete E2E._pendingOn[k];
      if (sh) {
        if (shared) sh.channels = sh.channels.filter(x => x !== k);
        if (session) sh.peers = sh.peers.filter(x => x !== k);
      }
      _e2eLsSet(_e2eHintKey(), {
        dm: session ? h.dm.filter(x => x !== k) : h.dm,
        ch: shared ? h.ch.filter(x => x !== k) : h.ch
      });
      e2eSysMsg(target, shared || session || pending ? '🔓 Encryption disabled for ' + nick : '🔓 No encryption active for ' + nick);
      updateE2EIndicator(nick);
      break;
    }
    case 'verify': {
      const nick = args[1] || dmTarget;
      if (!nick) { e2eSysMsg(target,'Usage: /encrypt verify <nick>'); return; }
      const k = _e2eK(nick);
      const session = E2E.dmSessions[k];
      if (!session || session._unusable) { e2eSysMsg(target,`No E2E session with ${nick}`); return; }
      // #2: verify the PINNED long-term identity DH key (theirIdentityPub), NOT the ratchet key.
      if (!session.theirIdentityPub) { e2eSysMsg(target,`Session with ${nick} not yet established (no pinned identity)`); return; }
      const myPub  = await exportPub(E2E.identityKeys.dhKeyPair.publicKey, 'ECDH');
      const phrase = await safetyPhrase(myPub, session.theirIdentityPub);
      const fp     = E2E.trustStore[k]?.fingerprint || await computeFingerprint(session.theirIdentityPub);
      e2eSysMsg(target,`🔐 Safety phrase with ${nick}: ${phrase}`);
      e2eSysMsg(target,`Read this over voice. If they see the same words → /encrypt trust ${nick}`);
      e2eSysMsg(target,`Their fingerprint: ${fp}`);
      if (E2E.trustStore[k]?.pendingFingerprint) e2eSysMsg(target,`⚠️ A DIFFERENT key is pending for ${nick}: ${E2E.trustStore[k].pendingFingerprint}`);
      break;
    }
    case 'trust': {
      // MEDIUM: /encrypt trust used to mark ANY pin verified — including one the server
      // seeded, with no session and no fingerprint shown — and dropped the server_seeded
      // guard. Now it needs a live session whose identity IS the pinned key, no pending
      // key change, and an explicit confirm showing the fingerprint + safety phrase.
      const nick = args[1] || dmTarget;
      if (!nick) { e2eSysMsg(target,'Usage: /encrypt trust <nick>'); return; }
      const k = _e2eK(nick);
      const t = E2E.trustStore[k];
      const s = E2E.dmSessions[k];
      if (!t || t.server_seeded) { e2eSysMsg(target,`🔐 No identity for ${nick} has been confirmed on this device yet — start a session first (/encrypt on ${nick})`); return; }
      if (t.keyChanged) { e2eSysMsg(target,`⚠️ ${nick}'s identity key changed — /encrypt accept or /encrypt reject first`); return; }
      if (!s || s._unusable || !s.theirIdentityPub) { e2eSysMsg(target,`🔐 No E2E session with ${nick} — /encrypt on ${nick} first`); return; }
      if (s.theirSignPub && await computeIdentityFingerprint(s.theirIdentityPub, s.theirSignPub) !== t.fingerprint) {
        e2eSysMsg(target,`⚠️ The session with ${nick} does not use the pinned identity — not marking verified`); return;
      }
      const myPub  = await exportPub(E2E.identityKeys.dhKeyPair.publicKey, 'ECDH');
      const phrase = await safetyPhrase(myPub, s.theirIdentityPub);
      const ok = typeof confirm === 'function' && confirm(
        `Mark ${nick} as VERIFIED?\n\nFingerprint:\n${t.fingerprint}\n\nSafety phrase:\n${phrase}\n\n` +
        `Only do this after ${nick} read you the same safety phrase over a trusted channel (voice / in person).`);
      if (!ok) { e2eSysMsg(target,'Not marked as verified'); return; }
      if (e2eMarkVerified(k)) e2eSysMsg(target,`✓ ${nick} marked as verified`);
      updateE2EIndicator(nick);
      break;
    }
    case 'accept': {
      // C2: the only way a changed identity key becomes the pin.
      const nick = args[1] || dmTarget;
      if (!nick) { e2eSysMsg(target,'Usage: /encrypt accept <nick>'); return; }
      const k = _e2eK(nick);
      const t = E2E.trustStore[k];
      if (!t || !t.pendingFingerprint) { e2eSysMsg(target,`No pending key change for ${nick}`); return; }
      const ok = typeof confirm === 'function' && confirm(
        `⚠️ Accept a NEW identity key for ${nick}?\n\nPinned (old) fingerprint:\n${t.fingerprint}\n\nNEW fingerprint:\n${t.pendingFingerprint}\n\n` +
        `Only accept after confirming the NEW fingerprint with ${nick} over a trusted channel. If you did not expect ${nick} to change keys, this may be an attack.`);
      if (!ok) { e2eSysMsg(target,'Key change NOT accepted — messages under the new key stay blocked'); return; }
      t.fingerprint = t.pendingFingerprint; t.pendingFingerprint = null; t.keyChanged = false; t.verified = false;
      _e2eWs({ type:'e2e_update_trust', nick:k, fingerprint:t.fingerprint, verified:false });
      _e2eStateSetTrust(k);
      // The old session belongs to the old identity.
      if (E2E.dmSessions[k]) _e2eDropSession(k);
      e2eSysMsg(target,`🔐 New identity for ${nick} accepted (not verified — compare with /encrypt verify ${nick})`);
      // Decrypt what arrived under the new key while it was pending.
      const stash = (E2E._changedStash && E2E._changedStash[k]) || [];
      if (E2E._changedStash) delete E2E._changedStash[k];
      let established = false;
      for (const item of stash) {
        try {
          let pt;
          if (!established && item.x3dh) {
            const r = await _e2eEstablishAndDecrypt(nick, item.x3dh, item.envelope, { withEnvelope: true });
            if (!r.ok) continue;
            established = true; pt = r.pt;
          } else pt = await ratchetDecrypt(k, item.envelope);
          _e2eShowDecrypted(item.conn_id || conn_id, nick, nick, pt, `🔐 The next message from ${nick} was held until you accepted the new key:`);
        } catch (e) { console.warn('[E2E] stashed message failed:', e && e.message); }
      }
      if (!established && E2E._pendingIncomingX3DH && E2E._pendingIncomingX3DH[k]) {
        const r = await e2eEstablishResponderSession(nick, E2E._pendingIncomingX3DH[k]);
        if (r.ok) { delete E2E._pendingIncomingX3DH[k]; established = true; }
      }
      if (!established) e2eSysMsg(target,`🔐 Run /encrypt on ${nick} to start a session with the new key`);
      updateE2EIndicator(nick);
      break;
    }
    case 'reject': {
      const nick = args[1] || dmTarget;
      if (!nick) { e2eSysMsg(target,'Usage: /encrypt reject <nick>'); return; }
      const k = _e2eK(nick);
      const t = E2E.trustStore[k];
      if (!t || !t.pendingFingerprint) { e2eSysMsg(target,`No pending key change for ${nick}`); return; }
      t.pendingFingerprint = null; t.keyChanged = false;
      if (E2E._changedStash) delete E2E._changedStash[k];
      if (E2E._pendingIncomingX3DH) delete E2E._pendingIncomingX3DH[k];
      e2eSysMsg(target,`🔐 Rejected the new key for ${nick} — keeping the pinned key ${t.fingerprint}`);
      updateE2EIndicator(nick);
      break;
    }
    case 'reset-identity': {
      if (!E2E.keyReady) { e2eSysMsg(target,'🔐 E2E is locked on this device — /encrypt unlock first'); return; }
      const ok = typeof confirm === 'function' && confirm('Create a NEW E2E identity? Every contact will see a key-change warning and existing sessions stop working.');
      if (!ok) return;
      await e2eGenerateAndPublishIdentity({ replace: true });
      if (!E2E.identityReady) { e2eSysMsg(target, '🔐 Identity generation failed'); break; }
      // r8 (codex-p3 e2e.js:4399): the existing sessions are bound to the OLD identity —
      // they are closed (live, stored on the server and on this device), as the question
      // promised; E2E stays on for those peers (blocked) until /encrypt on sets up new ones.
      const closed = new Set(Object.keys(E2E.dmSessions));
      for (const [nk, d] of Object.entries((E2E.state && E2E.state.dm) || {})) if (d && d.on) closed.add(nk);
      for (const nk of ((E2E._serverHints && E2E._serverHints.peers) || [])) closed.add(nk);
      for (const nk of closed) if (nk && !nk.startsWith('__')) _e2eDropSession(nk);
      e2eSysMsg(target, '🔐 New identity created — your fingerprint: ' + await _e2eOwnFingerprint());
      if (closed.size) e2eSysMsg(target, `🔐 ${closed.size} encrypted session${closed.size === 1 ? '' : 's'} (bound to the old identity) closed — /encrypt on <nick> sets up a new one.`);
      break;
    }
    case 'status': {
      const t = args[1] || target;
      const st = e2eTargetState(t, { conn_id });
      if (st.mode === 'blocked') { e2eSysMsg(target, `⛔ ${t} — encryption ON but unavailable: ${st.reason}`); break; }
      if (_e2eIsChan(t)) {
        e2eSysMsg(target, st.mode === 'psk' ? `🔐 ${t} — encrypted` : `🔓 ${t} — not encrypted`);
      } else {
        const trust = E2E.trustStore[_e2eK(t)];
        const badge = trust?.keyChanged ? '⚠ KEY CHANGED (pending)' : trust?.verified ? '✓ verified' : 'TOFU';
        e2eSysMsg(target, st.mode === 'psk' ? `🔐 DM ${t} — encrypted (shared key)` :
                          st.mode === 'dm'  ? `🔐 DM ${t} — encrypted (${badge})` : `🔓 DM ${t} — not encrypted. /encrypt on ${t}`);
      }
      break;
    }
    case 'fingerprint': case 'fp': {
      if (!E2E.identityKeys) { e2eSysMsg(target, E2E.keyReady ? 'E2E not initialised' : '🔐 E2E is locked on this device — /encrypt unlock'); return; }
      // #11: show the combined (dh+sign) identity fingerprint — the same value
      // peers pin via TOFU — so an out-of-band match is meaningful.
      e2eSysMsg(target,`🔑 Your fingerprint: ${await _e2eOwnFingerprint()}`);
      break;
    }
    default:
      e2eSysMsg(target,[
        '🔐 /encrypt commands:',
        '  on <nick>       — start E2E DM session',
        '  off [nick]      — end session or remove channel key',
        '  keygen          — generate channel key (in channel)',
        '  add <32 words>  — add channel key from words',
        '  share           — show current channel key as words',
        '  rotate          — rotate channel key',
        '  verify <nick>   — show safety phrase',
        '  trust <nick>    — mark nick as verified (after verify)',
        '  accept <nick>   — accept a CHANGED identity key',
        '  reject <nick>   — keep the pinned key, drop a changed one',
        '  status [target] — check E2E status',
        '  fingerprint     — show your key fingerprint',
        '  unlock          — enable E2E on this device (vault passphrase)',
        '  reset-identity  — create a new identity (contacts see a key change)',
      ].join('\n'));
  }
}

// ─── UI helpers ───────────────────────────────────────────────────────────────

function e2eSysMsg(target, text) {
  // r3 (w-web INFO): a notice raised before any window is open (fresh browser, during
  // boot — e.g. "the server returned an INVALID E2E keyring") used to be dropped. It is
  // kept (≤20) and shown in that network's window once one is active.
  if (!active) {
    E2E._sysQueue = E2E._sysQueue || [];
    if (E2E._sysQueue.length < 20) E2E._sysQueue.push({ target, text });
    return;
  }
  _e2eFlushSysQueue();
  // multi-line messages displayed as separate rows
  for (const line of text.split('\n')) {
    sysMsg(active.conn_id, target, line, 'system');
  }
}
function _e2eFlushSysQueue() {
  const q = E2E._sysQueue; if (!q || !q.length || !active) return;
  E2E._sysQueue = [];
  for (const m of q) {
    const tg = (!m.target || m.target === 'status') ? (active.target || 'status') : m.target;
    for (const line of String(m.text).split('\n')) { try { sysMsg(active.conn_id, tg, line, 'system'); } catch (_) {} }
  }
}

function updateE2EIndicator(target) {
  try { _e2eFlushSysQueue(); } catch (_) {}
  // Always update lock icon based on current active view
  const lock = document.getElementById('e2e-lock');
  if (lock && active) {
    const t = active.target;
    const st = (t && t !== 'status') ? e2eTargetState(t, { conn_id: active.conn_id }) : { mode:'none' };
    const trust = E2E.trustStore[_e2eK(t)];
    const lockedSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4" fill="none" stroke-width="2"/></svg>';
    const unlockedSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9 0" fill="none"/></svg>';
    const encActive = st.mode === 'psk' || st.mode === 'dm';
    const blocked = st.mode === 'blocked';
    lock.innerHTML = (encActive || blocked) ? lockedSvg : unlockedSvg;
    // H5: the icon reflects reality — accent = usable; red = E2E on but sends blocked.
    lock.style.color = blocked ? 'var(--red, #e5484d)' : (encActive && !(trust && trust.keyChanged)) ? 'var(--accent)' : encActive ? 'var(--red, #e5484d)' : 'var(--text2)';
    lock.title = blocked
      ? ('Encryption ON but unavailable — messages are blocked: ' + st.reason)
      : encActive
        ? (trust?.keyChanged ? 'KEY CHANGED (not accepted) — verify, then /encrypt accept' : st.mode === 'psk' ? 'Encrypted (shared key)' : trust?.verified ? 'E2E verified' : 'E2E encrypted (TOFU)')
        : 'Not encrypted — click to set up';
  }
  try { if (typeof renderSidebar === 'function') renderSidebar(); } catch (_) {}
}

function e2eShowKeyChangeWarning(nick, fp, first = true) {
  const t = E2E.trustStore[_e2eK(nick)];
  const pinned = t ? t.fingerprint : '(none)';
  // r3 (agy-flash P3 HIGH, same class): the warning is the app's NON-blocking in-app
  // alert, and a peer cycling keys can't stack them: no new one while that peer's alert
  // is still on screen, at most 5 per peer per 10 minutes (the system line below is
  // always written).
  const k = _e2eK(nick), now = Date.now();
  E2E._kcOpen = E2E._kcOpen || Object.create(null);
  E2E._kcLog = E2E._kcLog || Object.create(null);
  const log = (E2E._kcLog[k] || []).filter((t) => now - t < 10 * 60 * 1000);
  if (first && !E2E._kcOpen[k] && log.length < 5) {
    log.push(now); E2E._kcLog[k] = log;
    const msg = `⚠️ KEY CHANGE WARNING\n\nSomeone using the nick ${nick} presented a DIFFERENT identity key.\nThis may indicate a MITM attack or key regeneration.\n\nPinned (trusted) fingerprint:\n${pinned}\n\nNew fingerprint:\n${fp}\n\nThe new key is NOT used. Verify with ${nick} out-of-band, then /encrypt accept ${nick} — or /encrypt reject ${nick}.`;
    try {
      if (typeof customAlert === 'function') {
        E2E._kcOpen[k] = true;
        Promise.resolve(customAlert(msg)).catch(() => {}).then(() => { delete E2E._kcOpen[k]; });
      } else if (typeof alert === 'function') alert(msg);   // no app.js (test harness)
    } catch (_) { delete E2E._kcOpen[k]; }
  }
  _e2eSys(nick, `⚠️ KEY CHANGED for ${nick} — new key ${fp} NOT accepted. Verify, then /encrypt accept ${nick} (or /encrypt reject ${nick})`);
  updateE2EIndicator(nick);
}

// ─── WebCrypto primitives ─────────────────────────────────────────────────────

async function ecdh(privateKey, publicKey) {
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name:'ECDH', public:publicKey }, privateKey, 256
  ));
}

// Standard HKDF (extract-then-expand) with a zero salt. The X3DH F constant (#81) is
// prepended to `ikm` by the callers, not here, so this stays a plain HKDF usable by
// both the X3DH root derivation and the Double Ratchet root step.
async function hkdf(ikm, info, length) {
  const infoBytes = typeof info === 'string' ? new TextEncoder().encode(info) : info;
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name:'HKDF', hash:'SHA-256', salt:new Uint8Array(32), info:infoBytes }, base, length*8
  ));
}
// (#26: the former hkdfExpand approximation was replaced by the spec KDF_CK in
// chainKeyStep — HMAC(CK,0x01)/HMAC(CK,0x02) — and removed.)

async function exportPub(key, usage) {
  return bytesToBase64(new Uint8Array(await crypto.subtle.exportKey('raw', key)));
}

async function importPub(b64, usage) {
  return crypto.subtle.importKey(
    'raw', base64ToBytes(b64),
    { name: usage==='ECDSA' ? 'ECDSA' : 'ECDH', namedCurve:'P-256' },
    true,  // Public keys must be extractable — exportPub() needs it for E2E bundle sharing
    usage==='ECDSA' ? ['verify'] : []
  );
}

async function exportPriv(key) {
  return JSON.stringify(await crypto.subtle.exportKey('jwk', key));
}

async function importPriv(jsonStr) {
  return crypto.subtle.importKey(
    'jwk', JSON.parse(jsonStr), { name:'ECDH', namedCurve:'P-256' }, false, ['deriveBits']
  );
}

async function exportIdentityKeys({ dhKeyPair, signKeyPair }) {
  return {
    dh_priv:   await exportPriv(dhKeyPair.privateKey),
    dh_pub:    await exportPub(dhKeyPair.publicKey,   'ECDH'),
    sign_priv: await exportPriv(signKeyPair.privateKey),
    sign_pub:  await exportPub(signKeyPair.publicKey, 'ECDSA'),
  };
}

async function importIdentityKeys(obj) {
  const dhPriv   = await importPriv(obj.dh_priv);
  const dhPub    = await importPub(obj.dh_pub,    'ECDH');
  const signPriv = await crypto.subtle.importKey(
    'jwk', JSON.parse(obj.sign_priv), { name:'ECDSA', namedCurve:'P-256' }, false, ['sign']
  );
  const signPub  = await importPub(obj.sign_pub, 'ECDSA');
  return {
    dhKeyPair:   { privateKey:dhPriv,   publicKey:dhPub   },
    signKeyPair: { privateKey:signPriv, publicKey:signPub },
  };
}

// ─── Mnemonic (256-word list — C3 fix) ───────────────────────────────────────
// C3: Exactly 256 unique words so every byte 0-255 maps to a unique word.
// Round-trip is now lossless: bytesToMnemonic(mnemonicToBytes(words)) === words.

window.WORDLIST = [
  // 0-31
  'ability','able','about','above','absent','absorb','abstract','absurd',
  'abuse','access','accident','account','accuse','achieve','acid','acoustic',
  'acquire','across','act','action','actor','actress','actual','adapt',
  'add','addict','address','adjust','admit','adult','advance','advice',
  // 32-63
  'aerobic','afford','afraid','again','agent','agree','ahead','aim',
  'air','airport','aisle','alarm','album','alcohol','alert','alien',
  'all','alley','allow','almost','alone','alpha','already','also',
  'alter','always','amateur','amazing','among','amount','amused','analyst',
  // 64-95
  'anchor','ancient','anger','angle','angry','animal','ankle','announce',
  'annual','another','answer','antenna','antique','anxiety','any','apart',
  'apology','appear','apple','approve','april','arch','arctic','area',
  'arena','argue','arm','armor','army','around','arrange','arrest',
  // 96-127
  'arrow','art','artefact','artist','artwork','ask','aspect','assault',
  'asset','assist','assume','asthma','athlete','atom','attack','attend',
  'attitude','attract','auction','audit','august','aunt','author','auto',
  'autumn','average','avocado','avoid','awake','aware','away','awesome',
  // 128-159
  'awful','awkward','axis','baby','balance','bamboo','banana','banner',
  'bar','barely','bargain','barrel','base','basic','basket','battle',
  'beach','bean','beauty','because','become','beef','before','begin',
  'behave','behind','believe','below','belt','bench','benefit','best',
  // 160-191
  'betray','better','between','beyond','bicycle','bid','bike','bind',
  'biology','bird','birth','bitter','black','blade','blame','blanket',
  'blast','bleak','bless','blind','blood','blossom','blouse','blue',
  'blur','blush','board','boat','body','boil','bomb','bone',
  // 192-223
  'book','boost','border','boring','borrow','boss','bottom','bounce',
  'box','boy','bracket','brain','brand','brave','bread','breeze',
  'brick','bridge','brief','bright','bring','brisk','broccoli','broken',
  'bronze','broom','brother','brown','brush','bubble','buddy','budget',
  // 224-255
  'buffalo','build','bulb','bulk','bullet','bundle','bunker','burden',
  'burger','burst','bus','business','busy','butter','buyer','buzz',
  'cabbage','cage','cake','call','calm','camera','camp','canal',
  'cancel','candy','cannon','canoe','canvas','canyon','capable','capital',
];

// Sanity check at load time
if (WORDLIST.length !== 256) console.error('[E2E] WORDLIST must have exactly 256 entries, has', WORDLIST.length);
if (new Set(WORDLIST).size !== 256) console.error('[E2E] WORDLIST contains duplicate words');

function bytesToMnemonic(bytes) {
  // C3: index directly — WORDLIST[i] for i in 0-255, always unique and invertible
  return Array.from(bytes).map(b => WORDLIST[b]);
}

function mnemonicToBytes(words) {
  const out = new Uint8Array(words.length);
  for (let i = 0; i < words.length; i++) {
    const idx = WORDLIST.indexOf(words[i].toLowerCase());
    if (idx < 0) throw new Error(`Unknown word: "${words[i]}"`);
    out[i] = idx;  // idx is 0-255, fits in one byte exactly
  }
  return out;
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function base64ToBytes(b64) {
  const std = b64.replace(/-/g,'+').replace(/_/g,'/');
  const bin = atob(std);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function bytesToBase64(bytes) {
  // Spread may overflow stack for large arrays; use reduce instead
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function concat(...arrays) {
  const total = arrays.reduce((s,a) => s+a.length, 0);
  const out   = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

// r4 (C3-1): keep this the LAST statement of e2e.js — see E2E._engineLoaded.
window.E2E._engineLoaded = true;
