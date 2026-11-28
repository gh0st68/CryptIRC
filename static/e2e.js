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
const E2E_SHARED_KEY_CONFLICT = '🔐 This Signal message could not be opened because this chat uses a shared key. Review encryption to retry the message.';
const E2E_RESTART_RECEIVE_MS = 5 * 60 * 1000;
const _e2eReactionAltExpiry = new WeakMap();
const E2E_SETUP_NOTICE_MS = 60 * 1000;
const _e2eSetupNotices = new Map();

function _e2eSetupRow(connId,nick,text,action,prefix = null) {
  if (!connId || !_e2eSetupNick(nick,true) || !networks.some(net => net.config.id === connId && net.connected)) return;
  const incoming = action !== 'send';
  if (incoming && ((!['methods','method-request'].includes(action) && E2E.keyReady) || isIgnored(nick,prefix) ||
      (getPmSettings(connId).enabled && !isPmAllowedFor(connId,nick)))) return;
  const now = Date.now();
  let incomingCount=0;
  for (const [key,at] of _e2eSetupNotices) {
    if (now - at >= E2E_SETUP_NOTICE_MS) _e2eSetupNotices.delete(key);
    else if (key.startsWith('["incoming",')) incomingCount++;
  }
  const key = JSON.stringify([incoming?'incoming':'send',connId,_e2eRecvFold(nick,_e2eCaseMap(connId)),action]);
  if (_e2eSetupNotices.has(key) || (incoming && incomingCount >= 8)) return;
  if (_e2eSetupNotices.size >= 128) _e2eSetupNotices.delete(_e2eSetupNotices.keys().next().value);
  _e2eSetupNotices.set(key,now);
  sysMsg(connId,_dmTarget(nick),text,'system',{e2eSetupAction:action,e2eSetupConn:connId,e2eSetupNick:nick});
}

function _e2eSetupNick(nick, namedStatusQuery=false) {
  return /^[A-Za-z\[\]\\\x60_^{}|][A-Za-z0-9\[\]\\\x60_^{}|-]{0,63}$/.test(nick) &&
    (namedStatusQuery || nick.toLowerCase() !== 'status') && !_e2eReservedNamespace(nick) && !_isServiceNick(nick);
}

function e2eSendSetupInstructions(connId,nick) {
  if (!E2E.keyReady) return 'Unlock encryption to send setup instructions.';
  if (E2E._bootPhase !== 'ready' || E2E._resyncPending) return 'Wait for encryption to finish loading, then try again.';
  if (!_e2eSetupNick(nick,true) || !_wsReady() ||
      !networks.some(net => net.config.id === connId && net.connected)) return 'Reconnect to send setup instructions.';
  const st = e2eTargetState(nick,{conn_id:connId});
  const canonical = _e2eCanon(nick,connId) || nick;
  if (st.mode !== 'none' || E2E.trustStore[_e2eDmKey(canonical,connId)]) return 'Check this chat’s encryption and try your message again.';
  const key = JSON.stringify(['sent',connId,_e2eRecvFold(nick,_e2eCaseMap(connId))]);
  const now = Date.now();
  if (now - (_e2eSetupNotices.get(key)||0) < E2E_SETUP_NOTICE_MS) return 'Setup instructions were sent recently.';
  const text = 'I’d like to send you an encrypted DM. Open CryptIRC (https://cryptirc.com/), join this IRC network, and run /encrypt unlock. For Signal chats, use my CryptIRC service or a network with the CryptIRC bridge.';
  if (wsend({type:'send',conn_id:connId,raw:`NOTICE ${nick} :${text}`}) === false) return 'Could not send setup instructions.';
  if (_e2eSetupNotices.size >= 128) _e2eSetupNotices.delete(_e2eSetupNotices.keys().next().value);
  _e2eSetupNotices.set(key,now);
  return null;
}
const E2E_REACTION_DM_PREFIX = 'e2r1:';
const E2E_REACTION_PSK_PREFIX = 'e2r1p:';
const E2E_REACTION_AD = new TextEncoder().encode('\nCryptIRC-Reaction-v1');
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
// payload or the null "no E2E → plaintext" result. Check `.e2eBlocked === true`:
// a readiness block also carries the state to display and its reason.
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
function _e2eDmScope(k) { return /^@([0-9a-f-]{36}):(.+)$/.exec(k); }
function _e2eDmNick(k) { return _e2eDmScope(k)?.[2] || k; }
function _e2eScopedPskSlot(name,cid) {
  const bare = _e2eK(name), scoped = `@${_e2eK(cid)}:${bare}`;
  return _e2eDmScope(bare) || !_e2eDmScope(scoped) ? bare : scoped;
}
function _e2ePskSlot(name,cid,hinted = _e2eHints().ch) {
  const scoped = _e2eScopedPskSlot(name,cid);
  if (E2E.channelKeys[scoped] || E2E.chanRemoved[scoped] || E2E.state?.ch?.[scoped]?.on ||
      hinted.includes(scoped) || E2E._serverHints?.channels?.includes(scoped) ||
      (E2E.keyReady && E2E.state?.ch?.[scoped]?.legacyOff === 1)) return scoped;
  return _e2eK(name);
}
function _e2eDmKey(nick, cid) {
  const k = _e2eK(nick);
  const scope = String(cid || '').toLowerCase();
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(scope) || _e2eIsChan(k) || _e2eDmScope(k)) return k;
  const scoped = `@${scope}:${k}`;
  const hints = _e2eHints();
  const sh = E2E._serverHints;
  const known = key => [E2E.dmSessions, E2E.state?.dm, E2E.trustStore, E2E._pendingOn]
    .some(map => map && Object.hasOwn(map, key)) || sh?.peers.includes(key) || hints.dm.includes(key);
  if (known(scoped)) return scoped;
  // Keep existing nick-only sessions usable. A leftover pin by itself must not
  // make a new session global across all of the user's networks.
  return (E2E.dmSessions[k] || E2E.state?.dm[k]?.on || E2E._pendingOn?.[k] ||
    sh?.peers.includes(k) || hints.dm.includes(k)) ? k : scoped;
}
function _e2eKnownNames(cid, scopedOnly = false) {
  const out = new Set();
  const add = a => {
    for (const n of a || []) {
      if (!n) continue;
      const k = _e2eK(n), scoped = _e2eDmScope(k);
      if (scopedOnly ? !!scoped : !scoped || scoped[1] === String(cid || '').toLowerCase()) out.add(scoped ? scoped[2] : k);
    }
  };
  try {
    add(Object.keys(E2E.channelKeys)); add(Object.keys(E2E.dmSessions)); add(Object.keys(E2E.chanRemoved)); add(Object.keys(E2E.trustStore));
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
  const known = _e2eKnownNames(cid);
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
  const snapshot = typeof networks === 'undefined' ? null : networks.find(n => n.config.id === cid);
  const c = String(i?.casemapping || snapshot?.casemapping || '').trim().toLowerCase();
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
  const known = _e2eKnownNames(cid);
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
  const known = _e2eKnownNames(cid);
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
async function _e2eKeyCmdConfirm(msg, okLabel, explicitApproval = false, approvalLabel, expiresAt) {
  try {
    if (explicitApproval && (typeof customConfirm !== 'function' || !customConfirm.supportsExplicitApproval)) return false;
    if (typeof customConfirm === 'function' && typeof document !== 'undefined' && document && document.body) return !!(await customConfirm(msg, okLabel || 'Continue', 'Cancel', explicitApproval, approvalLabel, expiresAt));
    if (typeof confirm === 'function') return !!confirm(msg);
  } catch (_) {}
  return false;
}

// ─── State ────────────────────────────────────────────────────────────────────

window.E2E = {
  storageVersion: E2E_STORAGE_VERSION,
  protocolVersion: 4,
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
  trustStore:   _e2eCiMap(),   // nick → { fingerprint, verified, keyChanged, pendingFingerprint }
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
  _serverLockGen: 0,
  _sessionTombstones: new Map(),
  _sessionSyncRepair: new Map(),
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
// A close may lose its reply after the server removed the active snapshot.
// Keep that observed floor separately until the close or a newer save succeeds.
function _e2ePendingCloseKey() { return 'cryptirc_e2e_pending_close_' + _e2eUser(); }
function _e2ePendingCloseFloor(key, floor) {
  const slot = _e2ePendingCloseKey();
  const pending = _e2eLsGet(slot) || {};
  const current = Number.isSafeInteger(pending[key]) && pending[key]>0 ? pending[key] : 0;
  if (floor===undefined) return current;
  if (floor===null) delete pending[key];
  else if (floor<=current) return current;
  else if (current || Object.keys(pending).length<4096) pending[key] = floor;
  else return 0;
  if (Object.keys(pending).length) _e2eLsSet(slot,pending);
  else _e2eLsDel(slot);
  return _e2eLsGet(slot)?.[key] || 0;
}
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

// Keep authenticated message text on this browser, encrypted under the device's
// E2E master key. Opening history never advances a ratchet or preserves extra
// message keys. The IRC log is still the source of message order and timestamps.
const E2E_DM_HISTORY_LIMIT = 1024;
const E2E_DM_HISTORY_TIMEOUT = 1500;
let _e2eHistoryRevision = 0;
const _e2eHistoryScopeRevisions = new Map();
const _e2eHistoryKeys = new WeakMap();
const _e2eDmHistoryWires = new WeakMap();

function _e2eHistoryScope(connId,target) {
  return connId && target && !_e2eIsChan(target) ? JSON.stringify([connId,_e2eK(target).replace(/^\u200bstatus$/,'status')]) : null;
}

function e2eIsDmHistoryWire(wire) {
  return typeof wire === 'string' && /^\[e2edm[12]\]/.test(wire);
}

function _e2eSentDigest(envelope) {
  const {d,p,n} = envelope.h;
  return _e2eSha256Hex(JSON.stringify([d,p,n,envelope.c]));
}
function _e2eOwnDigestMatches(peer,session,header,digest) {
  if (!session?.startEph) return false;
  const id = JSON.stringify([peer,session.startEph,header.dh,header.n]);
  const key = _e2eEchoKeys.get(id);
  return (key?.until>Date.now() && key.digest===digest) || (session.sentDigests || []).some(entry=>
    entry===digest || (Array.isArray(entry) && entry[0]===header.dh && entry[1]===header.n && entry[2]===digest));
}

// An account echo from another open device uses our sending chain. Opening it
// locally must never advance either ratchet or send a receipt to the peer.
async function e2eReadOwnEcho(cid,target,line,sync) {
  if (!cid || _e2eIsChan(target) || !E2E.keyReady || !line.text?.startsWith(E2E_DM_PREFIX) ||
      line.text.length > 8192 || !line.from) return;
  const mapping = _e2eRecvCaseMap(cid);
  if (_e2eRecvFold(line.from,mapping) !== _e2eRecvFold(getNick(cid),mapping)) return;
  const peer = _e2eDmKey(target,cid), gen = E2E._lockGen;
  const historyCurrent = _e2eHistoryCurrent(_e2eUser(),_e2eHistoryScope(cid,target));
  const current = () => E2E.keyReady && !_e2eBootStale(gen) && historyCurrent() &&
    E2E.trustStore[peer]?.fingerprint && !E2E.trustStore[peer].keyChanged;
  if (!current()) return;
  try {
    const env = JSON.parse(atob(line.text.slice(E2E_DM_PREFIX.length)));
    if (!_e2eEnvelopeOk(env) || !env.h) return;
    const header = {dh:env.h.d,pn:env.h.p,n:env.h.n};
    const digest = await _e2eSentDigest(env);
    return await _withRatchetLock(peer,async()=>{
      if (sync && current() && !_e2eOwnDigestMatches(peer,E2E.dmSessions[peer],header,digest)) _e2eMarkMaybeMoved(peer);
      if (sync && _e2eMovedPending(peer) && current()) await _e2eAdoptMovedInner(peer);
      const session = E2E.dmSessions[peer];
      if (!current() || !session?.startEph || session.connId !== cid || _e2eSessPinMismatch(peer,session) !== false ||
          !_e2eOwnDigestMatches(peer,session,header,digest)) return;
      const usable = () => current() && E2E.dmSessions[peer] === session;
      const id = JSON.stringify([peer,session.startEph,header.dh,header.n]);
      _e2eForgetEchoKeys(null,true);
      if (!_e2eEchoKeys.has(id) && header.dh === session.DHs?.pub) {
        await _e2eRememberEchoChain(peer,session,header.dh,session.CKs,session.Ns,header.n+1,usable);
      }
      if (!_e2eEchoKeys.has(id)) await _e2eReadInitialEchoKeys(peer,session,header,usable);
      const record = _e2eEchoKeys.get(id);
      if (!record || !usable()) return;
      const mk = record.mk.slice();
      let bytes;
      try {
        bytes = await messageDecrypt(mk,base64ToBytes(env.c),header,sessionIdentityAD(session));
        if (!usable()) return;
        const plaintext = new TextDecoder().decode(bytes);
        await e2eRememberDmHistory(cid,target,line.from,line.text,plaintext);
        if (!usable()) return;
        record.mk.fill(0); _e2eEchoKeys.delete(id);
        // A long paste can drain slowly at the user's configured IRC line rate.
        // Extend only its still-pending keys on an authenticated echo, up to
        // the time needed for one full skipped-message window at 10 s/line.
        const now = Date.now();
        for (const pending of _e2eEchoKeys.values()) {
          if (pending.peer===peer && pending.start===session.startEph && pending.dh===header.dh && pending.until>now) {
            pending.until=Math.min(pending.deadline,now+60000);
          }
        }
        return plaintext;
      } finally { mk.fill(0); bytes?.fill(0); }
    });
  } catch (_) { /* Missing or unauthenticated echoes stay unreadable. */ }
}

// The wrapped per-browser key keeps the disk index from naming peers or matching
// its entry IDs against copies of the encrypted IRC log.
function _e2eHistoryKey(user,master) {
  if (!_e2eHistoryKeys.has(master)) {
    const load = async () => {
      const keySlot = ['dm-history-id-key',user];
      const indexSlot = ['dm-history-index',user];
      const aad = _e2eBlobAAD('dmhistory-index-key\n'+user);
      const open = async blob => {
        const raw = await _e2eGcmDec(master,blob,aad);
        try { return await crypto.subtle.importKey('raw',raw,{name:'HMAC',hash:'SHA-256'},false,['sign']); }
        finally { raw.fill(0); }
      };
      let wrapped = await _e2eIdbOp('readonly',store=>store.get(keySlot),E2E_DM_HISTORY_TIMEOUT);
      if (wrapped) {
        try { return await open(wrapped); } catch (_) { /* A new master key needs a fresh index. */ }
      }
      const raw = crypto.getRandomValues(new Uint8Array(32));
      let replacement;
      try { replacement = await _e2eGcmEnc(master,raw,aad); }
      finally { raw.fill(0); }
      await _e2eIdbOp('readwrite',store=>{
        const req = store.get(keySlot);
        req.onsuccess = () => {
          if (_e2eUser()!==user) return;
          const stored = req.result;
          if (stored && (!wrapped || (stored instanceof Uint8Array &&
              (!(wrapped instanceof Uint8Array) || _e2eCmpBytes(stored,wrapped)!==0)))) {
            wrapped = stored; // Another tab initialized or replaced it first.
            return;
          }
          if (stored && (!E2E.keyReady || E2E.e2eEncKey!==master)) return;
          wrapped = replacement;
          store.put(wrapped,keySlot);
          if (!stored) return;
          const index = store.get(indexSlot);
          index.onsuccess = () => {
            for (const item of Array.isArray(index.result)?index.result:[]) store.delete(['dm-history',user,item.id]);
            store.delete(indexSlot);
          };
        };
      },E2E_DM_HISTORY_TIMEOUT);
      return open(wrapped);
    };
    _e2eHistoryKeys.set(master,load().catch(error=>{ _e2eHistoryKeys.delete(master); throw error; }));
  }
  return _e2eHistoryKeys.get(master);
}

async function _e2eHistoryId(key,fields) {
  const digest = await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(JSON.stringify(fields)));
  return bytesToBase64(new Uint8Array(digest));
}

function _e2eHistoryCurrent(user,scope) {
  const revision = _e2eHistoryRevision, scoped = _e2eHistoryScopeRevisions.get(scope);
  return () => _e2eUser() === user && _e2eHistoryRevision === revision && _e2eHistoryScopeRevisions.get(scope) === scoped;
}

async function e2eRememberDmHistory(connId,target,from,wire,plaintext,deviceCopy = false) {
  const scope = _e2eHistoryScope(connId,target);
  const user = _e2eUser(), key = E2E.e2eEncKey, generation = E2E._lockGen;
  if (!scope || !user || !key || !E2E.keyReady || !from || !e2eIsDmHistoryWire(wire) ||
      wire.length > 8192 || typeof plaintext !== 'string' || plaintext.length > 8192) return;
  const sameHistory = _e2eHistoryCurrent(user,scope);
  const current = () => E2E.keyReady && E2E.e2eEncKey === key && !_e2eBootStale(generation) && sameHistory();
  try {
    await _e2eXLock('dm-history',async()=>{
      if (!current()) return;
      const idKey = await _e2eHistoryKey(user,key);
      const [id,bucket] = await Promise.all([_e2eHistoryId(idKey,['message',scope,_e2eK(from),wire]),_e2eHistoryId(idKey,['scope',scope])]);
      const data = new TextEncoder().encode(plaintext);
      let blob;
      const context = deviceCopy?'dmhistory-device\n':'dmhistory\n';
      try { blob = await _e2eGcmEnc(key,data,_e2eBlobAAD(context+id)); }
      finally { data.fill(0); }
      await _e2eIdbOp('readwrite',store=>{
        const slot = ['dm-history',user,id];
        const put = () => {
          const req = store.get(['dm-history-index',user]);
          req.onsuccess = () => {
            if (!current()) return;
            const existing = (Array.isArray(req.result) ? req.result : []).filter(item=>item.id!==id);
            const discarded = existing.splice(0,Math.max(0,existing.length+1-E2E_DM_HISTORY_LIMIT));
            for (const item of discarded) store.delete(['dm-history',user,item.id]);
            store.put(deviceCopy?{deviceCopy:true,blob}:blob,slot);
            existing.push({id,bucket});
            store.put(existing,['dm-history-index',user]);
          };
        };
        if (!deviceCopy) put();
        else {
          // A device copy cannot overwrite an already saved local decryption.
          const cached = store.get(slot);
          cached.onsuccess = () => { if (!cached.result) put(); };
        }
      },E2E_DM_HISTORY_TIMEOUT);
    });
  } catch (_) { /* History caching is best-effort if browser storage is unavailable. */ }
}

async function e2eReadDmHistory(connId,target,lines,{cachedOnly = false, deviceCopies = null} = {}) {
  const scope = _e2eHistoryScope(connId,target);
  const user = _e2eUser(), key = E2E.e2eEncKey, generation = E2E._lockGen;
  const sameHistory = _e2eHistoryCurrent(user,scope);
  const current = () => E2E.keyReady && E2E.e2eEncKey === key && E2E._lockGen === generation && sameHistory();
  const results = new Map();
  if (!scope || !user || !key || !E2E.keyReady || !lines.length) return results;
  try {
    const candidates = lines.filter(l=>l?.from && e2eIsDmHistoryWire(l.text) && l.text.length<=8192);
    if (!candidates.length) return results;
    const idKey = await _e2eHistoryKey(user,key);
    const entries = await Promise.all(candidates.map(async line=>
      ({line,id:await _e2eHistoryId(idKey,['message',scope,_e2eK(line.from),line.text])})));
    if (!current()) return results;
    await _e2eIdbOp('readonly',store=>{
      for (const entry of entries) {
        const req = store.get(['dm-history',user,entry.id]);
        req.onsuccess = () => { entry.blob = req.result; };
      }
    },E2E_DM_HISTORY_TIMEOUT);
    if (!current()) return results;
    await Promise.all(entries.map(async ({line,id,blob})=>{
      if (!blob) return;
      try {
        const deviceCopy = blob.deviceCopy === true;
        const context = deviceCopy?'dmhistory-device\n':'dmhistory\n';
        const plaintext = await _e2eGcmDec(key,deviceCopy?blob.blob:blob,_e2eBlobAAD(context+id));
        results.set(line,new TextDecoder().decode(plaintext));
        if (deviceCopy) deviceCopies?.add(line);
        plaintext.fill(0);
      } catch (_) {}
    }));
  } catch (_) {}
  // A reconnect may return the sibling's outgoing echoes long after they were
  // sent. Recover what this device's surviving chain can authenticate. Bound
  // the work per history page and perform at most one server refresh.
  if (!cachedOnly && current() && typeof getNick === 'function') {
    const cm = _e2eRecvCaseMap(connId), me = _e2eRecvFold(getNick(connId),cm);
    const missing = lines.filter(l=>l?.from && !results.has(l) && l.text?.startsWith(E2E_DM_PREFIX) &&
      _e2eRecvFold(l.from,cm) === me).sort((a,b)=>(a.ts||0)-(b.ts||0) || (a.id||0)-(b.id||0)).slice(-E2E_MAX_SKIP);
    for (const [index,line] of missing.entries()) {
      if (!current()) break;
      const text = await e2eReadOwnEcho(connId,target,line,index===0);
      if (typeof text === 'string') results.set(line,text);
    }
  }
  return current() ? results : new Map();
}

// History handoff uses the account's client-held key and a live WebSocket. The
// request identifies exact cached IRC rows, and replies carry their text only.
// Neither device exports a session, message key, or identity key.
const E2E_HISTORY_SYNC_ROWS = 12;
const E2E_HISTORY_SYNC_BYTES = 16384;
const E2E_HISTORY_SYNC_PAYLOAD = 12000;
const E2E_HISTORY_SYNC_WAIT = 6000;
const E2E_HISTORY_SYNC_MAX_AGE = 60000;
let _e2eHistorySyncSocket = null, _e2eHistoryAnnounced = false, _e2eHistoryPending = null;
let _e2eHistoryAsked = new WeakMap();
const _e2eHistorySeen = new Set();

function _e2eResetHistorySync() {
  _e2eHistoryAnnounced = false;
  clearTimeout(_e2eHistoryPending?.timer);
  _e2eHistoryPending = null;
  _e2eHistoryAsked = new WeakMap();
}

function _e2eHistorySyncContext() {
  const socket = _e2eHistorySyncSocket, key = E2E.e2eEncKey, user = _e2eUser(), generation = E2E._lockGen;
  const current = () => !!socket && socket === _e2eHistorySyncSocket && socket === ws && _wsReady() &&
    !!key && E2E.e2eEncKey === key && E2E.keyReady && E2E._vaultUp && E2E._bootPhase === 'ready' &&
    !E2E._resyncPending && !encryptionDeviceLocked() && !_e2eBootStale(generation) && !!user && _e2eUser() === user;
  return current() ? { key, user, current } : null;
}

function _e2eHistorySyncChat(connId,target) {
  if (typeof target !== 'string' || !target || target.length > 128 || /[\s,\x00-\x1f\x7f]/u.test(target) ||
      !_e2eHistoryScope(connId,target) || !networks.some(n=>n.config.id === connId)) return false;
  const nick = _e2eK(target).replace(/^\u200bstatus$/,'status');
  const peer = _e2eDmKey(nick,connId);
  return E2E.state?.dm?.[peer]?.on !== 0 && !E2E._pendingOn?.[peer]?.closing &&
    _e2eAllowHeldDm(connId,nick,null,true);
}

function _e2eHistorySyncAAD(user,id,kind) {
  return _e2eBlobAAD(JSON.stringify(['device-dm-history-v1',user,id,kind]));
}

function _e2eHistorySeenBefore(kind,id) {
  const token = kind+':'+id;
  if (_e2eHistorySeen.has(token)) return true;
  if (_e2eHistorySeen.size >= 128) _e2eHistorySeen.delete(_e2eHistorySeen.values().next().value);
  _e2eHistorySeen.add(token);
  return false;
}

async function _e2eSendHistorySync(ctx,id,kind,body,current = ctx.current) {
  const bytes = new TextEncoder().encode(JSON.stringify({issuedAt:Date.now(),body}));
  try {
    const seal = await _e2eGcmEnc(ctx.key,bytes,_e2eHistorySyncAAD(ctx.user,id,kind));
    const blob = E2E_BLOB_PREFIX+bytesToBase64(seal);
    if (blob.length > E2E_HISTORY_SYNC_BYTES || !current()) return;
    await _e2eWs({type:'e2e_history_sync',id,kind,blob},current);
  } catch (_) { /* History stays unavailable until another online attempt. */ }
  finally { bytes.fill(0); }
}

function _e2eAnnounceHistorySync() {
  const ctx = _e2eHistorySyncContext();
  if (!ctx || _e2eHistoryAnnounced) return;
  _e2eHistoryAnnounced = true;
  const id = crypto.randomUUID();
  _e2eHistorySeenBefore('ready',id);
  void _e2eSendHistorySync(ctx,id,'ready',null);
  requestVisibleDmHistorySync();
}

function e2eSyncDmHistory(connId,target,rows,sourceReady = false) {
  const ctx = _e2eHistorySyncContext();
  if (!ctx || !_e2eHistorySyncChat(connId,target)) return;
  if (_e2eHistoryPending && !_e2eHistoryPending.fresh()) {
    clearTimeout(_e2eHistoryPending.timer);
    _e2eHistoryPending = null;
  }
  if (_e2eHistoryPending) {
    if (sourceReady) _e2eHistoryPending.retry = true;
    return;
  }
  const now = performance.now();
  const findRows = row => row._dmHistoryState === 'unavailable' && typeof row.from === 'string' && row.from.length <= 128 &&
    e2eIsDmHistoryWire(row._dmHistoryWire) && row._dmHistoryWire.length <= 8192 &&
    (sourceReady || (_e2eHistoryAsked.get(row)||0) <= now);
  const missing = [], lines = [];
  let used = _e2eUtf8len(JSON.stringify({connId,target,lines}));
  for (let i=rows.length-1; i>=0 && lines.length<E2E_HISTORY_SYNC_ROWS; i--) {
    const row = rows[i];
    if (!findRows(row)) continue;
    const line = {from:row.from,text:row._dmHistoryWire};
    const size = _e2eUtf8len(JSON.stringify(line))+1;
    if (used + size > E2E_HISTORY_SYNC_PAYLOAD) continue;
    used += size;
    missing.push(row);
    lines.push(line);
  }
  if (!lines.length) return;
  const id = crypto.randomUUID(), until = now+E2E_HISTORY_SYNC_WAIT;
  const sameHistory = _e2eHistoryCurrent(ctx.user,_e2eHistoryScope(connId,target));
  const fresh = () => _e2eHistoryPending === request && performance.now() < until && ctx.current() &&
    sameHistory() && isActive(connId,target) && _e2eHistorySyncChat(connId,target);
  const request = { id, connId, target, lines, fresh, progress:false, retry:false };
  _e2eHistoryPending = request;
  request.timer = setTimeout(()=>{
    if (_e2eHistoryPending !== request) return;
    _e2eHistoryPending = null;
    for (const row of missing) _e2eHistoryAsked.set(row,performance.now()+60000);
    if (ctx.current() && (request.progress || request.retry)) requestVisibleDmHistorySync(request.retry);
  },E2E_HISTORY_SYNC_WAIT);
  _e2eHistorySeenBefore('request',id);
  void _e2eSendHistorySync(ctx,id,'request',{connId,target,lines},fresh);
}

async function _e2eHandleHistorySync({id,kind,blob}) {
  const ctx = _e2eHistorySyncContext();
  if (!ctx || typeof id !== 'string' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(id) ||
      !['ready','request','reply'].includes(kind) || typeof blob !== 'string' ||
      !blob.startsWith(E2E_BLOB_PREFIX) || blob.length > E2E_HISTORY_SYNC_BYTES) return;
  const pending = _e2eHistoryPending;
  if (kind === 'reply' && (pending?.id !== id || !pending.fresh())) return;
  let data, opened;
  try {
    opened = await _e2eGcmDec(ctx.key,base64ToBytes(blob.slice(E2E_BLOB_PREFIX.length)),_e2eHistorySyncAAD(ctx.user,id,kind));
    const packet = JSON.parse(new TextDecoder().decode(opened));
    if (!Number.isFinite(packet?.issuedAt) || Math.abs(Date.now()-packet.issuedAt)>E2E_HISTORY_SYNC_MAX_AGE) return;
    data = packet.body;
  } catch (_) { return; }
  finally { opened?.fill(0); }
  if (!ctx.current()) return;
  if (kind === 'ready') {
    if (data === null && !_e2eHistorySeenBefore(kind,id)) requestVisibleDmHistorySync(true);
    return;
  }
  if (kind === 'request') {
    const {connId,target,lines} = data || {};
    if (!_e2eHistorySyncChat(connId,target) || !Array.isArray(lines) || !lines.length || lines.length > E2E_HISTORY_SYNC_ROWS ||
        !lines.every(line=>typeof line?.from === 'string' && line.from && line.from.length <= 128 &&
          e2eIsDmHistoryWire(line.text) && line.text.length <= 8192) || _e2eHistorySeenBefore(kind,id)) return;
    const sameHistory = _e2eHistoryCurrent(ctx.user,_e2eHistoryScope(connId,target));
    const until = performance.now()+E2E_HISTORY_SYNC_WAIT;
    const current = () => performance.now()<until && ctx.current() && sameHistory() && _e2eHistorySyncChat(connId,target);
    const cache = await e2eReadDmHistory(connId,target,lines,{cachedOnly:true});
    if (!current()) return;
    const matches = [];
    let used = 2; // JSON array delimiters
    for (const [index,line] of lines.entries()) if (cache.has(line)) {
      const bytes = new TextEncoder().encode(cache.get(line));
      const item = [index,bytesToBase64(bytes)];
      bytes.fill(0);
      const size = _e2eUtf8len(JSON.stringify(item))+1;
      if (used + size > E2E_HISTORY_SYNC_PAYLOAD) continue;
      used += size;
      matches.push(item);
    }
    if (matches.length) await _e2eSendHistorySync(ctx,id,'reply',matches,current);
    return;
  }
  if (!Array.isArray(data) || data.length > E2E_HISTORY_SYNC_ROWS) return;
  const {connId,target,lines,fresh} = pending;
  for (const item of data) {
    if (!fresh()) return;
    if (!Array.isArray(item) || !Number.isInteger(item[0]) || !lines[item[0]] ||
        typeof item[1] !== 'string' || item[1].length > 8192) continue;
    const line = lines[item[0]];
    let text, bytes;
    try {
      bytes = base64ToBytes(item[1]);
      text = new TextDecoder('utf-8',{fatal:true}).decode(bytes);
    } catch (_) { continue; }
    finally { bytes?.fill(0); }
    if (applyHeldDmHistory(connId,target,line.from,line.text,text,true)) {
      pending.progress = true;
      await e2eRememberDmHistory(connId,target,line.from,line.text,text,true);
    }
  }
}

async function e2eClearDmHistory(connId,target) {
  const user = _e2eUser();
  if (!user) return;
  const scope = connId ? _e2eHistoryScope(connId,target) : null;
  if (connId && !scope) return;
  const key = E2E.keyReady && E2E.e2eEncKey;
  if (scope && key) _e2eHistoryScopeRevisions.set(scope,(_e2eHistoryScopeRevisions.get(scope)||0)+1);
  else { _e2eHistoryRevision++; _e2eHistoryScopeRevisions.clear(); }
  try {
    // While locked we cannot identify the peer's opaque bucket. Clear the cache
    // for this browser so the requested deletion still takes effect.
    await _e2eXLock('dm-history',async()=>{
      const bucket = scope && key ? await _e2eHistoryKey(user,key).then(k=>_e2eHistoryId(k,['scope',scope])).catch(()=>null) : null;
      await _e2eIdbOp('readwrite',store=>{
        const req = store.get(['dm-history-index',user]);
        req.onsuccess = () => {
          const retained = [];
          for (const item of Array.isArray(req.result) ? req.result : []) {
            if (!bucket || item.bucket===bucket) store.delete(['dm-history',user,item.id]);
            else retained.push(item);
          }
          if (retained.length) store.put(retained,['dm-history-index',user]);
          else store.delete(['dm-history-index',user]);
        };
      },E2E_DM_HISTORY_TIMEOUT);
    });
  } catch (_) {}
}
// Device copy of one session: { ep, blob } (blob = e2e2. under the master key, slot
// "devsession\n<peer>", INCLUDING skipped/recent message keys), or { ep, del: 1 } after
// /encrypt off / a key change so other tabs drop theirs too.
async function _e2eDevSessPut(nk, rec) {
  const user = _e2eUser();
  if (!user || !E2E.keyReady) return;
  const generation = E2E._lockGen;
  const current = () => E2E.keyReady && !_e2eBootStale(generation) && _e2eUser() === user;
  const slot = 's:' + user + ':' + nk;
  const indexSlot = 'si:' + user;
  let committed;
  try {
    await _e2eIdbOp('readwrite', store => {
      const request = store.get(slot);
      request.onsuccess = () => {
        const stored = request.result;
        if (!current() || stored?.ep > rec.ep || (!rec.del && stored?.ep === rec.ep && stored.del)) return;
        const index = store.get(indexSlot);
        index.onsuccess = () => {
          if (!current()) return;
          const names = [...new Set(Array.isArray(index.result?.n) ? index.result.n : [])].filter(name=>name!==nk);
          names.push(nk);
          for (const retired of names.splice(0,Math.max(0,names.length-4096))) store.delete('s:' + user + ':' + retired);
          store.put(rec,slot);
          store.put({n:names},indexSlot);
          committed = rec.ep;
        };
      };
    });
  } catch (_) { return; }
  if (!current()) return;
  if (committed !== undefined) (E2E._devIdx ||= new Set()).add(nk);
  return committed;
}
async function _e2eDevSessWipe(user) {
  if (!user) return;
  const indexSlot = 'si:' + user;
  try {
    await _e2eIdbOp('readwrite', store => {
      const index = store.get(indexSlot);
      index.onsuccess = () => {
        for (const nk of (Array.isArray(index.result?.n) ? index.result.n : [])) store.delete('s:' + user + ':' + nk);
        store.delete(indexSlot);
      };
    });
  } catch (_) {}
  E2E._devIdx = new Set();
}
// Adopt the newest copy of `nk`'s session written by another tab of this browser.
// Runs at the start of every ratchet-locked operation.
async function _e2eSyncFromDevice(nk) {
  if (!E2E.keyReady || !E2E.e2eEncKey) return;
  const generation = E2E._lockGen, user = _e2eUser(), master = E2E.e2eEncKey, identity = E2E.identityKeys;
  const current = () => !_e2eBootStale(generation) && E2E.keyReady && E2E.e2eEncKey === master &&
    E2E.identityKeys === identity && _e2eUser() === user;
  const rec = await _e2eIdbGet('s:' + user + ':' + nk);
  if (!current()) return;
  if (!rec || !Number.isInteger(rec.ep)) return;
  const cur = E2E.dmSessions[nk];
  const curEp = cur ? (cur.epoch | 0) : -1;
  const floor = () => Math.max(E2E._sessionEpoch[nk] || 0, _e2eDev().ep[nk] || 0);
  // Updating a device-only receive fallback does not move the primary ratchet epoch.
  if (rec.ep < floor() || rec.ep < curEp ||
      (rec.ep === curEp && !rec.del && !(cur?.x3dhPending && (cur.restartPrev || rec.restart)))) return;
  if (rec.del) {
    delete E2E.dmSessions[nk];
    E2E._sessionEpoch[nk] = Math.max(E2E._sessionEpoch[nk] || 0, rec.ep);
    if ((E2E._sessionTombstones.get(nk) ?? -1)<rec.ep) {
      _e2eForgetEchoKeys(nk);
      _e2ePriorHistorySessions.delete(nk);
    }
    if ((_e2eInitialEchoes.get(nk)?.epoch ?? Infinity)<=rec.ep) _e2eInitialEchoes.delete(nk);
    E2E._sessionTombstones.set(nk,Math.max(E2E._sessionTombstones.get(nk) || 0,rec.ep));
    return;
  }
  if (E2E.state?.dm?.[nk]?.on===0 || rec.ep <= Math.max(E2E._sessionTombstones.get(nk) ?? -1,E2E.state?.dm?.[nk]?.closedEpoch ?? -1)) return;
  try {
    let o = JSON.parse(new TextDecoder().decode(await aesDecryptBlob(rec.blob, _e2eDevSlot(nk))));
    if (!current() || !o || typeof o !== 'object' || !o.RK || (o.epoch | 0) !== rec.ep) return;
    if (!_e2eSessionScopeMatches(nk,o) || !await _e2eUsesCurrentIdentity(o)) return;
    if (E2E.trustStore[nk]?.fingerprint) await _e2eSessFp(o);
    if (!current() || E2E.dmSessions[nk] !== cur || (cur && cur.epoch !== curEp) ||
        rec.ep < floor() || _e2eSessPinMismatch(nk,o) !== false) return;
    if (rec.ep === curEp) {
      if (!cur.startEph || o.startEph !== cur.startEph) return;
      const { restartPrev, ...primary } = cur;
      o = o.restartPrev ? { ...primary, restartPrev:o.restartPrev } : primary;
    }
    o.nick = nk; o.skipped = o.skipped || {}; o.recent = o.recent || {};
    if (rec.ep > curEp) await _e2eNoteSessionAdoption(nk,cur,o);
    if (!current() || E2E.dmSessions[nk] !== cur) return;
    _e2eRememberFirstAdoption(cur,o,false);
    E2E.dmSessions[nk] = o;
    if (rec.ep > curEp) _e2eAdoptedEpochs[nk] = o.epoch;
    E2E._sessionEpoch[nk] = Math.max(E2E._sessionEpoch[nk] || 0, rec.ep);
    if (o.restartPrev?.until > Date.now() && cur?.restartPrev?.until !== o.restartPrev.until) {
      _e2eScheduleRestartExpiry(nk, o.restartPrev.until);
    }
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
function _e2eSys(target, text, cid) { try { e2eSysMsg(target, text, cid); } catch (_) {} }
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
function _e2eWs(msg, stillPending = null) {
  return new Promise(resolve => { E2E._txq.push({ msg, resolve, stillPending }); _e2eTxPump(); });
}
function _e2eTxPump() {
  const now = Date.now();
  E2E._txTokens = Math.min(E2E_TX_RATE, E2E._txTokens + (now - E2E._txLast) * E2E_TX_RATE / 1000);
  E2E._txLast = now;
  while (E2E._txq.length && E2E._txTokens >= 1) {
    const { msg, resolve, stillPending } = E2E._txq.shift();
    if (stillPending && !stillPending()) { resolve(false); continue; }
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
function _e2eReq(msg, replyType, timeoutMs = 6000, match = null, retries = 2, stillPending = null) {
  return new Promise(resolve => {
    const list = E2E._waiters[replyType] || (E2E._waiters[replyType] = []);
    const entry = { match, done: null };
    let t = null, left = retries;
    entry.done = (ev) => { if (t) clearTimeout(t); resolve(ev); };
    list.push(entry);
    const drop = () => { const i = list.indexOf(entry); if (i >= 0) list.splice(i, 1); resolve(null); };
    const attempt = () => _e2eWs(msg,stillPending).then(ok => {
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
const E2E_DEVICE_KEY_TIMEOUT_MS = 4000;
function _e2eIdbOpen(version, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new Error('idb open timed out')); return; }
    if (typeof indexedDB === 'undefined' || !indexedDB) { reject(new Error('no indexedDB')); return; }
    const r = version ? indexedDB.open(E2E_IDB_NAME, version) : indexedDB.open(E2E_IDB_NAME);
    let failed = false;
    const cleanup = () => signal?.removeEventListener('abort', cancel);
    const fail = error => { failed = true; cleanup(); reject(error); };
    const cancel = () => fail(new Error('idb open timed out'));
    signal?.addEventListener('abort', cancel, { once: true });
    r.onupgradeneeded = () => {
      if (failed) { try { r.transaction.abort(); } catch (_) {} return; }
      try { const db = r.result; if (!db.objectStoreNames || !db.objectStoreNames.contains(E2E_IDB_STORE)) db.createObjectStore(E2E_IDB_STORE); } catch (_) {}
    };
    r.onsuccess = () => {
      cleanup();
      const db = r.result;
      if (failed) { db.close(); return; }
      if (db.objectStoreNames && !db.objectStoreNames.contains(E2E_IDB_STORE)) {
        const v = (db.version || 1) + 1;
        db.close();
        if (version) { reject(new Error('idb store missing after upgrade')); return; }
        _e2eIdbOpen(v, signal).then(resolve, reject);
        return;
      }
      db.onversionchange = () => { try { db.close(); } catch (_) {} };
      resolve(db);
    };
    r.onerror = () => fail(r.error || new Error('idb open failed'));
    r.onblocked = () => fail(new Error('idb open blocked'));
  });
}
async function _e2eIdbOp(mode, fn, timeoutMs) {
  const controller = timeoutMs ? new AbortController() : null;
  const signal = controller?.signal;
  const timer = controller && setTimeout(() => controller.abort(), timeoutMs);
  let db;
  try {
    db = await _e2eIdbOpen(undefined, signal);
    if (signal?.aborted) throw new Error('idb transaction timed out');
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(E2E_IDB_STORE, mode);
      const req = fn(tx.objectStore(E2E_IDB_STORE));
      const cleanup = () => signal?.removeEventListener('abort', cancel);
      const fail = error => { cleanup(); reject(error); };
      const cancel = () => {
        try { tx.abort(); } catch (_) {}
        fail(new Error('idb transaction timed out'));
      };
      signal?.addEventListener('abort', cancel, { once: true });
      tx.oncomplete = () => { cleanup(); resolve(req ? req.result : undefined); };
      tx.onerror = () => fail(tx.error || new Error('idb tx failed'));
      tx.onabort = () => fail(tx.error || new Error('idb tx aborted'));
    });
  } finally {
    clearTimeout(timer);
    db?.close();
  }
}
async function _e2eIdbGetKey(user) {
  try {
    const rec = await _e2eIdbOp('readonly', s => s.get('m:' + user), E2E_DEVICE_KEY_TIMEOUT_MS);
    return rec && rec.v === 3 && rec.k ? rec : null;
  } catch (_) { return null; }
}
async function _e2eIdbPutKey(user, keys) {
  try { await _e2eIdbOp('readwrite', s => s.put({ ...keys, v: 3 }, 'm:' + user), E2E_DEVICE_KEY_TIMEOUT_MS); return true; } catch (_) { return false; }
}
async function _e2eIdbDelKey(user, timeoutMs) {
  try { await _e2eIdbOp('readwrite', s => s.delete('m:' + user), timeoutMs); } catch (_) {}
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
  const generation = E2E._lockGen;
  const open = async (key, data, aad) => {
    const pt = await _e2eGcmDec(key,data,aad);
    if (!_e2eBootStale(generation)) return pt;
    pt.fill(0);
    throw new Error('Encrypted chats were locked while opening keys');
  };
  if (blob.startsWith(E2E_BLOB_PREFIX)) {
    if (!E2E.e2eEncKey) throw new Error('E2E key not available on this device');
    const pt = await open(E2E.e2eEncKey, base64ToBytes(blob.slice(E2E_BLOB_PREFIX.length)), _e2eBlobAAD(ctx));
    if (_e2eBootStale(generation)) { pt.fill(0); throw new Error('Encrypted chats were locked while opening keys'); }
    E2E._v2Slots.add(ctx);
    return { pt, legacy: false };
  }
  if (blob.startsWith(E2E_V2_BLOB)) {
    if (!E2E._previousKey) throw new Error('E2E v2 migration key unavailable');
    const pt = await open(E2E._previousKey, base64ToBytes(blob.slice(E2E_V2_BLOB.length)), _e2eBlobAAD(ctx, 2));
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
  return { pt: await open(E2E._legacyKey,data,undefined), legacy: true };
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
  if (ev.e2e_storage_unavailable) { E2E._legacyKey = null; E2E._pepper = null; }
  else if (ev.e2e_migrated) { E2E._migrated = true; E2E._legacyKey = null; }
  const legacy = ev.e2e_storage_unavailable ? '' : ev.e2e_legacy_key || ev.e2e_enc_key || '';
  if (legacy && !E2E._legacyKey && !E2E._migrated) { try { E2E._legacyKey = await _e2eImportAesKey(base64ToBytes(legacy)); } catch (_) {} }
  if (!ev.e2e_storage_unavailable && ev.e2e_pepper) E2E._pepper = ev.e2e_pepper;
  const pass = ev.e2e_pepper ? E2E._pendingPass : null;
  const verified = ev.vault_verified || ev.e2e_pepper || ev.e2e_legacy_key;
  const resumeSetup = !!(verified && E2E._devicePromptPending);
  if (verified) {
    e2eNotePassphrase(null);
    E2E._devicePromptPending = false;
  }
  return resumeSetup ? _e2eRunInteractive(pass, true) : _e2eRun(() => _e2eBoot(null));
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
  // BroadcastChannel; the short delay covers the race) and otherwise stays locked
  // until the user asks to unlock encrypted chats.
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
function e2eOnSocketAuthed(historySync = false) {
  _e2eResetHistorySync();
  _e2eHistorySyncSocket = historySync ? ws : null;
  _e2ePlainConnections.clear();
  for(const probe of _e2eChatProbes.values()) _e2eDropChatProbe(probe);
  E2E._krReceived = false;                 // locked device: its hints may be stale too
  if (E2E.keyReady) { E2E._resyncTicket = Symbol(); E2E._resyncPending = true; }
}
function _e2eResyncDone(ticket) {
  if (ticket !== E2E._resyncTicket) return;
  clearTimeout(E2E._resyncTimer);
  E2E._resyncTimer = null;
  E2E._resyncPending = false;
  const w = E2E._resyncWaiters || []; E2E._resyncWaiters = [];
  for (const f of w) { try { f(); } catch (_) {} }
  _e2eAnnounceHistorySync();
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
  const remaining = 5000 - (now - (E2E._resyncKickAt || 0));
  if (remaining > 0) {
    E2E._resyncTimer ??= setTimeout(() => {
      E2E._resyncTimer = null;
      _e2eKickResync();
    },remaining);
    return;
  }
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
  const ticket = E2E._resyncTicket;
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
      // The old key cannot authenticate this replacement keyring, even if the
      // device cache is unavailable. Continue to discovery if deleting it stalls.
      await _e2eIdbDelKey(user, E2E_DEVICE_KEY_TIMEOUT_MS);
      E2E._bootPhase = undefined;
      E2E._resyncRunning = false;
      return _e2eBoot(null);
    }
    E2E._krReceived = true;
    if (kr.migrated) { E2E._migrated = true; E2E._legacyKey = null; }
    E2E._serverHints = { peers: (kr.peers || []).map(_e2eK), channels: (kr.channels || []).map(_e2eK),
      disabledPsk:(kr.disabled_channels || []).map(_e2eK), hasIdentity: !!kr.has_identity, migrated: !!kr.migrated };
    // A sibling can rotate this identity while our socket is down. An already
    // committed message in the rate queue must wait for this check as well.
    const keys = E2E.identityKeys;
    const identity = await _e2eReq({type:'e2e_load_identity'},'e2e_identity_blob');
    if (!identity?.blob || _e2eBootStale(gen) || keys !== E2E.identityKeys) return;
    const revision = await _e2eSha256Hex(identity.blob);
    if (_e2eBootStale(gen) || keys !== E2E.identityKeys) return;
    if (_e2eIdentityRevisions.get(keys)!==revision) { _e2eRefreshChangedIdentity(keys); return; }
    await _e2eRepairPublishedIdentity(identity,keys);
    if (_e2eBootStale(gen) || keys !== E2E.identityKeys) return;
    // What other devices saved meanwhile (merged the way e2eSaveState merges).
    const sb = await _e2eFetchSession('__state__');
    if (_e2eBootStale(gen)) return;
    const srv = sb ? await _e2eDecodeState(sb) : null;
    if (_e2eBootStale(gen)) return;
    if (srv && E2E.state && _e2eMergeStateInto(E2E.state, srv)) _e2eApplyMergedState();
    for (const s of Object.values(E2E.dmSessions)) { try { await _e2eSessFp(s); } catch (_) {} }   // r7: pin comparison
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
    _e2eResyncDone(ticket);
    E2E._resyncBadNotice = false;
    console.log('[E2E] re-synced after the reconnect');
  } finally {
    E2E._resyncRunning = false;
    if (ticket !== E2E._resyncTicket) _e2eKickResync();
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
  if (!(opts && opts.deviceOnly)) {
    E2E._serverLocked = true;
    E2E._serverLockGen++;
  }
  _e2eCancelPrompt();
  _e2eCloseIdentityQuestions();   // r4 (N3)
  clearTimeout(E2E._stateBootTimer);
  _e2eWipeMemory();
  E2E._bootPhase = 'locked';
  E2E._lockReason = 'vault';
  E2E._lockedNoticeShown = false;
  if (had) { await e2eForgetDevice(); await _e2eDevSessWipe(user); }
  try { updateE2EIndicator(_e2eStatusTarget()); } catch (_) {}
}
// Every key / session / pending request out of memory (vault lock, session end).
function _e2eWipeMemory() {
  if (typeof lockCachedDmHistory === 'function') lockCachedDmHistory();
  _e2eResetHistorySync();
  E2E.keyReady = false; E2E.identityReady = false;
  if (typeof clearEncryptedChatReactions === 'function') clearEncryptedChatReactions();
  E2E._v2Slots = new Set();
  E2E.e2eEncKey = null; E2E._previousKey = null; E2E._finalKeyring = null; E2E._legacyKey = null; E2E._pepper = null; E2E.identityKeys = null;
  e2eNotePassphrase(null);
  E2E._devicePromptPending = false;
  for (const k of Object.keys(E2E.dmSessions)) delete E2E.dmSessions[k];
  for (const k of Object.keys(E2E.channelKeys)) delete E2E.channelKeys[k];
  E2E._chanKeyGen = Object.create(null);
  _e2eRecentPskWrites.clear();
  _e2ePskInventoryChecks.clear();
  E2E._stateOps = [];
  E2E._stateDirty = false;
  E2E._resyncTicket = undefined;
  _e2eResyncDone();               // waiters re-check the lock
  E2E._spkBlob = null; E2E._sessionCache = Object.create(null); E2E._glareAlt = Object.create(null);
  for (const pending of Object.values(E2E._pendingOn || {})) {
    pending.done?.('blocked');
    pending.finishResume?.('blocked');
  }
  E2E._pendingOn = Object.create(null); E2E._moved = Object.create(null); E2E._maybeMoved = Object.create(null); E2E._devIdx = new Set();
  _e2eAutoBusy.clear();
  _e2ePlainConnections.clear();
  for(const probe of _e2eChatProbes.values()) _e2eDropChatProbe(probe);
  E2E._orphans = Object.create(null); E2E._hdrWait = Object.create(null); E2E._lazyTried = Object.create(null);   // r8
  E2E._pendingIncomingX3DH = Object.create(null); E2E._hdrFrags = Object.create(null);
  _e2eRecentOffers.clear();
  _e2eCrossedStarts.clear();
  _e2eLiveReceipts.clear();
  _e2eHistoryAttempts.clear();
  _e2ePriorHistorySessions.clear();
  _e2eForgetEchoKeys();
  _e2eInitialEchoes.clear();
  E2E._sessionSyncRepair.clear();
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
  E2E._serverLockGen++;
  E2E._sessionTombstones.clear();
  clearTimeout(E2E._stateBootTimer);
  _e2eWipeMemory();
  E2E._bootPhase = undefined; E2E._krReceived = false; E2E._serverHints = null; E2E._migrated = false;
  E2E._recoverySetup = false; E2E._offerRecoverySetup = false;
  E2E._interactiveUnlock = null;
  E2E._lockedNoticeShown = false; E2E._lockedHold = [];
}
function _e2eCancelPrompt(keyArrived = false) {
  if (!E2E._promptText || (keyArrived && E2E._promptPurpose==='share')) return;
  try {
    const msg = document.getElementById('custom-prompt-msg');
    const cancel = document.getElementById('custom-prompt-cancel');
    if (msg && cancel && msg.textContent === E2E._promptText && typeof cancel.onclick === 'function') cancel.onclick();
  } catch (_) {}
}
async function _e2ePrompt(message, value = '', masked = true, cancelLabel = 'Cancel', onCancelClick = null, purpose = 'unlock') {
  const token = Symbol();
  E2E._promptToken = token;
  E2E._promptText = message;
  E2E._promptPurpose = purpose;
  try {
    return await customPrompt(message, value, masked, true, cancelLabel, onCancelClick);
  } finally {
    if (E2E._promptToken===token) { E2E._promptText=null; E2E._promptPurpose=null; E2E._promptToken=null; }
  }
}
async function _e2eShowSharedKey(words) {
  if (E2E.keyReady && !E2E._promptText) {
    await _e2ePrompt('Copy this key and share it over a trusted, encrypted connection.', words, false, 'Cancel', null, 'share');
  }
}
function _e2eDiscardSetupCode() {
  _e2eSys(_e2eStatusTarget(), '🔐 The recovery code just shown was not saved. Discard it and run /encrypt unlock.');
}
function _e2eSetupPreference() { return 'cryptirc_e2e_setup_ignored_' + _e2eUser(); }
function e2eIgnoreRecoverySetup() {
  const user = _e2eUser();
  if (!user) return;
  E2E._setupIgnoredUser = user;
  _e2eLsSet(_e2eSetupPreference(), true);
  updateE2EIndicator();
}
async function _e2eSetupCode(gen) {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const code = bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  bytes.fill(0);
  const ignore = () => { if (!_e2eBootStale(gen)) e2eIgnoreRecoverySetup(); };
  const saved = await _e2ePrompt('Copy this E2E recovery code and save it somewhere safe. The app will confirm when it is active. You’ll need it on other devices and after clearing browser data.', code, false, 'Ignore', ignore);
  if (saved === code && !_e2eBootStale(gen)) {
    const confirm = await _e2ePrompt('Paste your saved E2E recovery code to confirm.', '', true, 'Ignore', ignore);
    if (!_e2eBootStale(gen) && confirm?.trim() === code) return code;
  }
  _e2eDiscardSetupCode();
  return null;
}
async function e2ePromptDeviceUnlock() {
  if (typeof encryptionDeviceLocked === 'function' && encryptionDeviceLocked()) return;
  if (E2E._interactiveUnlock) return E2E._interactiveUnlock;
  if ((E2E.keyReady && (E2E.identityReady || E2E._booting || E2E._idDialogClose)) || E2E._promptText || E2E._devicePromptPending) return;
  if (typeof _wsReady === 'function' && !_wsReady()) {
    _e2eToast('Connect to CryptIRC before unlocking encrypted chats.');
    return;
  }
  if (E2E._vaultUp !== true) {
    if (typeof showVaultForEncryptedChat === 'function') showVaultForEncryptedChat();
    return;
  }
  return _e2eRunInteractive(null);
}
async function _e2eRunInteractive(pass, continuation = false) {
  if (!continuation && E2E._interactiveUnlock) return E2E._interactiveUnlock;
  const gen = E2E._lockGen;
  const run = _e2eRun(() => {
    if (!_e2eBootStale(gen) && E2E._vaultUp &&
        !(typeof encryptionDeviceLocked === 'function' && encryptionDeviceLocked())) return _e2eBoot(pass, true);
  });
  E2E._interactiveUnlock = run;
  try { return await run; }
  finally { if (E2E._interactiveUnlock === run) E2E._interactiveUnlock = null; }
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
    if (p && !p.req && !p.answered) {
      delete E2E._pendingOn[k];
      p.done?.('blocked');
      _e2eSys(p.target, `🔓 ${m}. Encryption with ${mm[1]} was NOT started — messages to ${mm[1]} are not encrypted.`);
      try { updateE2EIndicator(p.target); } catch (_) {}
    } else _e2eSys(mm[1], '🔐 ' + m);
    return true;
  }
  if (/^Too many key-bundle requests/.test(m)) {
    for (const [k, p] of Object.entries(E2E._pendingOn || {})) {
      if (p.req || p.answered) continue;
      delete E2E._pendingOn[k];
      p.done?.('blocked');
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
    catch (_) {
      const message = 'That recovery code did not unlock your encrypted chats. Try again.';
      _e2eSys(_e2eStatusTarget(), '🔐 ' + message);
      _e2eToast(message);
      return null;
    }
  }

  // A normal vault unlock can return legacy material. Only an explicit encryption
  // action may open the migration or recovery-code setup prompts.
  if (!interactive) return null;
  const upgrade = !!kr.blob;
  if (upgrade && !vaultPass) {
    await _e2eProveVault(gen, 'Enter your vault passphrase to upgrade your existing E2E keyring.');
    return null;
  }

  // The server compares the expected keyring atomically. A tab waiting for its
  // user to save a recovery code must not block another tab's setup prompt.
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
    if (_e2eBootStale(gen)) return null;
    if (!result) {
      _e2eSys(_e2eStatusTarget(), '🔐 Could not confirm setup. Keep the recovery code and run /encrypt unlock to check.');
      return null;
    }
    if (!result.ok) {
      _e2eDiscardSetupCode();
      _e2eToast('Another tab or device finished encryption setup. Discard the code shown here and use the recovery code from the completed setup.');
      return null;
    }
    E2E._setupIgnoredUser = null;
    _e2eLsDel(_e2eSetupPreference());
    _e2eSys(_e2eStatusTarget(), '🔐 Your saved E2E recovery code is now active.');
    kr.blob = blob;
    kr.migrated = !!result.migrated;
    return { keys: await _e2eUnwrapKeyring(blob, code, user), remember: true };
  } finally {
    if (previous) previous.fill(0);
    if (raw) raw.fill(0);
  }
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
  const ticket = E2E._resyncTicket;
  E2E._booting = true;
  E2E._bootPhase = 'loading';
  E2E._bootStarted = Date.now();
  if (E2E.keyReady) { try { updateE2EIndicator(_e2eStatusTarget()); } catch (_) {} }
  try {
    const user = _e2eUser();
    const kr = await _e2eReq({ type: 'e2e_load_keyring' }, 'e2e_keyring');
    if (_e2eBootStale(gen)) return;
    if (!kr) {
      E2E._bootPhase = 'failed';
      if (interactive) _e2eToast('Could not load your encryption keyring. Try unlocking again.');
      return;
    }
    kr.peers = Array.isArray(kr.peers) ? kr.peers : [];
    kr.channels = Array.isArray(kr.channels) ? kr.channels : [];
    E2E._krReceived = true;
    E2E._lockReason = null;
    if (kr.migrated) { E2E._migrated = true; E2E._legacyKey = null; }
    E2E._serverHints = { peers: (kr.peers || []).map(_e2eK), channels: (kr.channels || []).map(_e2eK),
      disabledPsk:(kr.disabled_channels || []).map(_e2eK), hasIdentity: !!kr.has_identity, migrated: !!kr.migrated };
    E2E._recoverySetup = false; E2E._offerRecoverySetup = false;
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
    E2E._recoverySetup = !kr.blob?.startsWith(E2E_KEYRING_PREFIX);
    E2E._offerRecoverySetup = E2E._recoverySetup && !!(kr.blob || kr.has_identity || kr.peers.length || kr.channels.length);
    const opened = E2E.e2eEncKey
      ? { keys: { k: E2E.e2eEncKey, previous: E2E._previousKey, finalized: E2E._finalKeyring }, remember: false }
      : await _e2eOpenKeys(kr, user, gen, vaultPass, interactive);
    if (_e2eBootStale(gen)) return;
    if (!opened) {
      E2E._bootPhase = 'locked';
      if (!E2E._lockReason) E2E._lockReason = 'nokey';
      if (interactive && (kr.has_identity || kr.blob) && !E2E._lockedNoticeShown) {
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
    try { updateE2EIndicator(_e2eStatusTarget()); } catch (_) {}
    E2E._recoverySetup = false; E2E._offerRecoverySetup = false;
    if (opened.remember) {
      await _e2eIdbPutKey(user, opened.keys);
      // A lock during the write: the lock's forget may have run before it — remove it.
      if (_e2eBootStale(gen)) { try { await _e2eIdbDelKey(user); } catch (_) {} _e2eWipeMemory(); return; }
      _e2eBcPost({ t: 'key' });
    }
    _e2eCancelPrompt(true);   // the key arrived while this browser was asking to unlock
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
    _e2eWs({ type: 'e2e_list_channel_keys' });
    _e2eWs({ type: 'e2e_load_session', partner: '__spk__' });
    await _e2eRestoreSessions(gen);
    if (_e2eBootStale(gen)) { _e2eWipeMemory(); return; }
    if (E2E.identityReady) await e2eEnsureOTPKs();
    if (_e2eBootStale(gen)) { _e2eWipeMemory(); return; }
    E2E._bootPhase = 'ready';
    _e2eResyncDone(ticket);
    if (typeof recoverReactionReceipts === 'function') recoverReactionReceipts(true);
    if (typeof restoreCachedDmHistory === 'function') void restoreCachedDmHistory();
    if (typeof restoreCachedPskHistory === 'function') restoreCachedPskHistory();
    _e2eReleaseLockedHold();
    // The active chat may have loaded its first page while the vault was locked.
    if (typeof active !== 'undefined' && active?.conn_id && _e2eSetupNick(active.target) && typeof _isE2eConversation === 'function' &&
        _isE2eConversation(active.target,active.conn_id)) {
      _e2eWs({type:'get_logs',conn_id:active.conn_id,target:active.target,limit:60});
    }
    if (typeof showEncryptPanel === 'function' && document.getElementById('encrypt-overlay')?.classList.contains('show')) {
      showEncryptPanel();
    }
  } finally {
    E2E._booting = false;
    if (ticket !== E2E._resyncTicket) _e2eKickResync();
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
    const sev = await _e2eRequestSession(p);
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
    const sev = await _e2eRequestSession(p);
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
    const event = await _e2eRequestSession(name);
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

function _e2eRequestSession(partner, withFloor = false, stillPending = null, resumePeer = null, singleReadMs = 0) {
  const req = crypto.randomUUID();
  const msg={type:'e2e_load_session',partner,req,...(withFloor ? {with_floor:true} : {}),...(resumePeer ? {resume_peer:resumePeer} : {})};
  const match=e=>e.partner===partner && e.req===req;
  if (!singleReadMs) return _e2eReq(msg,'e2e_session',6000,match,2,stillPending);
  // Bound the time under the ratchet lock even while the socket is queued.
  let timer,expired=false;
  const allowed=()=>!expired && (!stillPending || stillPending());
  const request=_e2eReq(msg,'e2e_session',singleReadMs,match,0,allowed);
  const timeout=new Promise(resolve=>{timer=setTimeout(()=>{expired=true;resolve(null);},singleReadMs);});
  return Promise.race([request,timeout]).finally(()=>clearTimeout(timer));
}
async function _e2eFetchSession(partner) {
  return (await _e2eRequestSession(partner))?.blob || null;
}

function _e2eSessionFloorContext(user) { return 'signal-session-floor\n' + user; }

async function _e2eReadSessionFloor(blob, user) {
  if (blob === '') return {epoch:0,digest:''};
  if (typeof blob !== 'string' || !blob.startsWith(E2E_BLOB_PREFIX) || blob.length > 128) return null;
  try {
    const bytes = await aesDecryptBlob(blob,_e2eSessionFloorContext(user));
    let epoch;
    try { epoch = JSON.parse(new TextDecoder().decode(bytes)); }
    finally { bytes.fill(0); }
    return Number.isSafeInteger(epoch) && epoch > 0 && epoch < Number.MAX_SAFE_INTEGER ?
      {epoch,digest:await _e2eSha256Hex(blob)} : null;
  } catch (_) { return null; }
}

async function _e2eSealSessionFloor(epoch, user) {
  const bytes = new TextEncoder().encode(JSON.stringify(epoch));
  try { return await aesEncryptBlob(bytes,_e2eSessionFloorContext(user)); }
  finally { bytes.fill(0); }
}

async function _e2eRefreshAccountState(gen, resume = null) {
  const settings = await _e2eRequestSession('__state__',false,null,resume?.peer);
  if (!settings || _e2eBootStale(gen) || !E2E.keyReady) return false;
  if (resume && E2E._pendingOn?.[resume.peer]===resume && typeof settings.resume_blob==='string' && settings.resume_blob.startsWith(E2E_BLOB_PREFIX) &&
      settings.resume_blob.length<=65536) resume.before = settings.resume_blob;
  const remote = settings.blob ? await _e2eDecodeState(settings.blob) : null;
  if ((settings.blob && !remote) || _e2eBootStale(gen) || !E2E.keyReady) return false;
  if (remote && E2E.state && _e2eMergeStateInto(E2E.state,remote)) _e2eApplyMergedState();
  return true;
}

// Authenticated state blob ("__state__" session slot): trust pins, which DM peers /
// channels have E2E on, PSK generations, own identity fingerprint, and a sequence
// number. The latest copy is ALSO kept on this device so the server can't roll it back.
function _e2eEmptyState() { return { v: 1, seq: 0, idfp: '', trust: {}, dm: {}, ch: {} }; }
async function _e2eDecodeState(blob, deviceKey = null) {
  let bytes;
  try {
    const context=_e2eCtxSession('__state__');
    if(deviceKey&&!blob.startsWith(E2E_BLOB_PREFIX)) return null;
    bytes=deviceKey ? await _e2eGcmDec(deviceKey,base64ToBytes(blob.slice(E2E_BLOB_PREFIX.length)),_e2eBlobAAD(context)) :
      await aesDecryptBlob(blob,context);
    const o = JSON.parse(new TextDecoder().decode(bytes));
    if (!o || o.v !== 1) return null;
    o.trust = o.trust || {}; o.dm = o.dm || {}; o.ch = o.ch || {};
    return o;
  } catch (_) { return null; }
  finally { bytes?.fill(0); }
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
      } else {
        const closed = Math.max(cur?.closedEpoch || 0,e.closedEpoch || 0);
        if (closed && w.closedEpoch !== closed) w = { ...w, closedEpoch:closed };
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
  // Trust the newer explicit identity decision even when an unrelated setting
  // on this browser has a larger overall state sequence.
  if (src.idfp && (!dst.idfp || (src.idfpGeneration || 0)>(dst.idfpGeneration || 0))) {
    dst.idfp = src.idfp;
    dst.idfpGeneration = src.idfpGeneration || 0;
    changed = true;
  }
  if (src.identityRotated === true && !dst.identityRotated) { dst.identityRotated = true; changed = true; }
  if ((src.seq | 0) > (dst.seq | 0)) dst.seq = src.seq | 0;
  return changed;
}
// Make in-memory views follow a merged state (pins accepted / made in another tab).
function _e2eApplyMergedState() {
  const st = E2E.state; if (!st) return;
  for (const [nick, t] of Object.entries(st.trust || {})) {
    if (!t || typeof t.fp !== 'string') continue;
    const ts = E2E.trustStore[nick];
    if (!ts || ts.fingerprint !== t.fp) {
      const pending = ts && ts.pendingFingerprint && ts.pendingFingerprint !== t.fp ? ts.pendingFingerprint : null;
      E2E.trustStore[nick] = { fingerprint: t.fp, verified: !!t.ver, keyChanged: !!pending, pendingFingerprint: pending };
      _e2eScheduleOwnEchoes(nick);
    } else if (!!ts.verified !== !!t.ver) ts.verified = !!t.ver;
  }
  for (const [ch, c] of Object.entries(st.ch || {})) { if (c && Number.isInteger(c.g)) E2E._chanGen[ch] = Math.max(E2E._chanGen[ch] || 0, c.g); }
  _e2eHintsRefresh();
}
// Record a local change: applied now, and again on top of whatever the next save merges in.
function _e2eStateOp(sec, k, fn, supersededBy = null) {
  if (!E2E.state) return;
  E2E.state[sec] = E2E.state[sec] || {};
  E2E.state[sec][k] = fn(E2E.state[sec][k]);
  (E2E._stateOps = E2E._stateOps || []).push({ sec, k, fn, supersededBy });
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
  if (!E2E.identityKeys) return;
  if (E2E._stateSaving) return E2E._stateSaving;
  E2E._stateSaving = (async () => {
    let confirmed = false, conflicts = 0, retryScheduled = false;
    try {
      while (E2E._stateDirty && E2E.identityKeys && E2E.keyReady) {
        E2E._stateDirty = false;
        confirmed = false;
        await _e2eXLock('state', async () => {
          const keys = E2E.identityKeys, st = E2E.state, gen = E2E._lockGen;
          const current = () => keys && E2E.identityKeys===keys && E2E.state===st && E2E.keyReady && !_e2eBootStale(gen);
          if (!current()) return;
          // Merge what other tabs (device copy) and devices (server copy) saved since.
          let grew = false;
          const dev = _e2eDev();
          if (dev.st) {
            const loc = await _e2eDecodeState(dev.st);
            if (!current()) return;
            if (loc) grew = _e2eMergeStateInto(st,loc) || grew;
          }
          const sb = await _e2eFetchSession('__state__');
          const srv = sb ? await _e2eDecodeState(sb) : null;
          if (!current() || (sb && !srv)) return;
          if (srv) grew = _e2eMergeStateInto(E2E.state, srv) || grew;
          // Local intents win over what was merged in (version above it).
          // A replacement identity may arrive during encryption. Keep these
          // local choices queued until their sealed copy is saved on the device.
          const queue = E2E._stateOps || [];
          const ops = queue.slice();
          for (const op of ops) {
            const published = srv?.[op.sec]?.[op.k];
            if (op.supersededBy?.(published)) {
              E2E.state[op.sec][op.k] = published;
              grew = true;
            } else {
              E2E.state[op.sec] ||= {};
              E2E.state[op.sec][op.k] = op.fn(E2E.state[op.sec][op.k]);
            }
          }
          if (grew || ops.length) _e2eApplyMergedState();
          E2E.state.seq = Math.max(E2E.state.seq | 0, dev.seq | 0, (srv && srv.seq) | 0) + 1;
          const expect = sb ? await _e2eSha256Hex(sb) : '';
          const blob = await aesEncryptBlob(new TextEncoder().encode(JSON.stringify(E2E.state)), _e2eCtxSession('__state__'));
          if (!current()) return;
          const d2 = _e2eDev(); d2.seq = E2E.state.seq; d2.st = blob; _e2eDevSave();
          const req = crypto.randomUUID();
          const reply = await _e2eReq({type:'e2e_store_session',partner:'__state__',blob,expect,req,id_hash:_e2eIdentityRevisions.get(keys)},
            'e2e_session_committed',4000,event=>event.req===req && event.partner==='__state__',1,current);
          if (!current()) return;
          if (typeof reply?.conflict === 'string') {
            // Another device saved after our read. Merge its current document
            // before retrying these intents. Each request still names its base.
            if (++conflicts <= 4) E2E._stateDirty = true;
            else if (!retryScheduled) {
              retryScheduled = true;
              setTimeout(() => {
                if (current() && (E2E._stateOps?.length || _e2eDev().st === blob)) _e2eRun(e2eSaveState);
              }, 500 + Math.random() * 500);
            }
            return;
          }
          queue.splice(0,ops.length);
          confirmed = reply?.ok === true;
          if (confirmed) conflicts = 0;
          if (reply?.identity_changed) _e2eRefreshChangedIdentity(keys);
        });
      }
      return confirmed;
    } finally { E2E._stateSaving = null; }
  })();
  _e2eHintsRefresh();
  return E2E._stateSaving;
}
function _e2eStateSetDm(k, on, force = false, reopeningVersion = null) {
  if (!E2E.state) return;
  const cur = E2E.state.dm[k];
  if (!force && (on ? (cur && cur.on) : !(cur && cur.on))) return;
  // A second device can explicitly start a new session while this device still
  // holds its deletion marker. Carry that marker in the authenticated account
  // settings so the new handshake is strictly newer on both devices.
  const closed = on ? 0 : E2E._sessionTombstones.get(k) || 0;
  const plainFingerprint = on ? null : E2E.trustStore[k]?.fingerprint || '';
  _e2eStateOp('dm', k, c => {
    const closedEpoch = Math.max(closed,c?.closedEpoch || 0);
    return { on:on ? 1 : 0,n:((c && c.n) | 0)+1,...(closedEpoch ? {closedEpoch} : {}),
      ...(on && c?.signal===1 ? {signal:1} : {}),...(!on ? {plainFingerprint:E2E.state.trust[k]?.fp||plainFingerprint} : {}) };
  }, reopeningVersion===null ? null : published=>published?.on===0 && published.n>reopeningVersion);
}
function _e2eStateSetChan(k, on, g, legacyOff = false) {
  if (!E2E.state) return;
  _e2eStateOp('ch', k, (c) => ({ on: on ? 1 : 0, g: Math.max((c && c.g) | 0, g | 0), n: ((c && c.n) | 0) + 1, ...(legacyOff ? {legacyOff:1} : {}) }));
}
function _e2eStateSetTrust(k) {
  if (!E2E.state) return;
  const t = E2E.trustStore[k];
  if (!t) return;
  const cur = E2E.state.trust[k];
  if (cur && cur.fp === t.fingerprint && !!cur.ver === !!t.verified) return;
  const fp = t.fingerprint, ver = !!t.verified;
  // Verification belongs to the keys the user actually confirmed. A newer
  // independent contact replacement supersedes an interrupted verification.
  const superseded = entry => entry?.fp && entry.fp!==fp && entry.fp!==cur?.fp && (entry.n||0)>=(cur?.n||0);
  _e2eStateOp('trust', k, c => superseded(c) ? c : {
    fp, ver, t: (c && c.fp === fp && c.t) || Math.floor(Date.now() / 1000), n: ((c && c.n) | 0) + 1
  },superseded);
}

// ─── Identity keys ────────────────────────────────────────────────────────────

const _e2eIdentityPublicCache = new WeakMap();
const _e2eIdentityRevisions = new WeakMap();
async function _e2ePublicIdentity(keys) {
  if (!keys) return null;
  let pair = _e2eIdentityPublicCache.get(keys);
  if (!pair) {
    pair = await Promise.all([exportPub(keys.dhKeyPair.publicKey,'ECDH'),exportPub(keys.signKeyPair.publicKey,'ECDSA')]);
    _e2eIdentityPublicCache.set(keys,pair);
  }
  return pair;
}
// The fingerprint peers pin for this identity (v2), shown by /encrypt fingerprint.
async function _e2eOwnFingerprint() {
  return computeIdentityFingerprint(...await _e2ePublicIdentity(E2E.identityKeys));
}
// The account setting `idfp` that names the identity in use keeps the form every
// release (and every open tab) already compares; it is never a peer pin.
async function _e2eOwnIdfp() {
  return e2eLegacyIdentityFingerprint(...await _e2ePublicIdentity(E2E.identityKeys));
}
function _e2eSessionBoundTo(session, publicKeys) {
  return !!publicKeys && !!session?.identityAD && !!session.theirIdentityPub &&
    session.identityAD === bytesToBase64(e2eIdentityAD(...publicKeys,session.theirIdentityPub,session.theirSignPub));
}
async function _e2eUsesCurrentIdentity(session) {
  // Older records can predate binding both identities. After an explicit
  // identity replacement an unbound record cannot resume a live conversation.
  if (!session.identityAD || !session.theirIdentityPub || !session.theirSignPub) return !E2E.state?.identityRotated;
  const keys = E2E.identityKeys;
  const pair = await _e2ePublicIdentity(keys);
  return keys === E2E.identityKeys && _e2eSessionBoundTo(session,pair);
}

function _e2eRefreshChangedIdentity(keys) {
  if (!keys || keys !== E2E.identityKeys) return;
  // Invalidate work started under the old identity. The unlocked account
  // encryption key, held drafts and sealed message history remain available.
  E2E._lockGen++;
  E2E.identityKeys = null;
  E2E.identityReady = false;
  _e2eCloseIdentityQuestions();
  for (const name of Object.keys(E2E.dmSessions)) _e2eForgetSessionRuntime(name);
  for (const pending of Object.values(E2E._pendingOn || {})) {
    pending.done?.('blocked');
    pending.finishResume?.('blocked');
  }
  E2E._pendingOn = Object.create(null);
  _e2eRun(() => _e2eBoot(null));
}

// Only ever runs for the reply to OUR e2e_load_identity (an unsolicited
// e2e_identity_blob pushed by the server is ignored), and NEVER regenerates the
// identity because a blob failed to decrypt or the server claimed there is none while
// we know one exists — that would let the server force a global re-TOFU at will.
async function _e2eLoadIdentity(kr, gen) {
  const ev = await _e2eReq({ type: 'e2e_load_identity' }, 'e2e_identity_blob');
  if (gen !== undefined && _e2eBootStale(gen)) return;
  if (!ev) { _e2eSys(_e2eStatusTarget(), '🔐 Your Signal identity did not load. Open Encryption and retry setup, or run /encrypt unlock.'); return; }
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
    // The `idfp` account setting's form (see _e2eOwnIdfp).
    const fp = await e2eLegacyIdentityFingerprint(await exportPub(keys.dhKeyPair.publicKey, 'ECDH'), await exportPub(keys.signKeyPair.publicKey, 'ECDSA'));
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
        _e2eRun(() => _e2eBoot(null));       // load it now (and the steps that need it)
      }, () => {});
      return;
    }
    const stored = legacy ? await aesEncryptBlob(pt,'identity') : blob;
    _e2eIdentityRevisions.set(keys,await _e2eSha256Hex(stored));
    if (gen !== undefined && _e2eBootStale(gen)) return;
    E2E.identityKeys = keys;
    if (legacy) _e2eWs({type:'e2e_store_identity',blob:stored});
    if (E2E.state && (E2E.state.idfp !== fp || E2E._stateDirty || E2E._stateOps?.length)) {
      if (known && known!==fp && E2E._idAcceptFp===fp) {
        E2E.state.idfpGeneration=(E2E.state.idfpGeneration || 0)+1;
        E2E.state.identityRotated=true;
      }
      E2E.state.idfp = fp;
      await e2eSaveState();
      if (E2E.identityKeys!==keys || (gen!==undefined && _e2eBootStale(gen))) return;
    }
    E2E._idAcceptFp = null;
    await _e2eRepairPublishedIdentity(ev,keys);
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
async function _e2eStoreIdentityCompared(blob, expected, current) {
  for (let i = 0; i < 2; i++) {
    if (!current()) return {state:'noreply'};
    _e2eWs({type:'e2e_store_identity',blob,expect:expected},current);
    const ev = await _e2eReq({type:'e2e_load_identity'},'e2e_identity_blob',6000,null,1,current);
    if (!ev || !current()) return { state: 'noreply' };
    if (ev.blob === blob) return { state: 'won' };
    if (ev.blob !== expected) return {state:'lost',blob:ev.blob};
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
  const gen = E2E._lockGen, user = _e2eUser(), former = E2E.identityKeys;
  const current = () => E2E.keyReady && !_e2eBootStale(gen) && _e2eUser() === user && E2E.identityKeys === former;
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
      if (!await _e2eRefreshAccountState(gen) || !current()) return;
      const previous = await _e2eReq({type:'e2e_load_identity'},'e2e_identity_blob',6000,null,1,current);
      if (typeof previous?.blob !== 'string' || !current()) return;
      if (former && _e2eIdentityRevisions.get(former)!==await _e2eSha256Hex(previous.blob)) {
        if (current()) _e2eRefreshChangedIdentity(former);
        return;
      }
      const saved = await _e2eStoreIdentityCompared(blob,previous.blob,current);
      if (!current() || saved.state !== 'won') {
        if (current()) _e2eSys(_e2eStatusTarget(),'🔐 The new encryption identity could not be confirmed. Reconnect and retry the reset.');
        return;
      }
    } else {
      // Two devices doing their first unlock at once used to BOTH install (and keep
      // using) their own identity and publish their own bundle; whichever wrote last
      // won on the server and the other one's sessions broke after a reload.
      const r = await _e2eStoreIdentityCompared(blob,'',current);
      if (!current()) return;
      if (r.state === 'lost') {
        // The loser adopts the stored identity (same master key — the keyring is
        // compare-and-swapped too) and publishes NOTHING (no SPK/prekeys/bundle):
        // the winner's bundle is the one that matches the stored identity.
        try {
          const { pt } = await aesDecryptBlobEx(r.blob, 'identity');
          const keys = await importIdentityKeys(JSON.parse(new TextDecoder().decode(pt)));
          _e2eIdentityRevisions.set(keys,await _e2eSha256Hex(r.blob));
          if (!current()) return;
          E2E.identityReady = false;
          E2E.identityKeys = keys;
        } catch (e) {
          E2E.identityKeys = null;
          _e2eSys(_e2eStatusTarget(), '⚠️ E2E: another device created your E2E identity at the same time and it does not open here — reload this page to retry.');
          return;
        }
        const adopted = E2E.identityKeys;
        const stillAdopted = () => E2E.keyReady && !_e2eBootStale(gen) && _e2eUser()===user && E2E.identityKeys===adopted;
        const fp = await _e2eOwnIdfp();
        if (!stillAdopted()) return;
        if (E2E.state && E2E.state.idfp !== fp) {
          E2E.state.idfp = fp;
          await e2eSaveState();
          if (!stillAdopted()) return;
        }
        const reply=await _e2eReq({type:'e2e_load_identity'},'e2e_identity_blob',6000,null,1,stillAdopted);
        if (!stillAdopted() || !await _e2eRepairPublishedIdentity(reply?.blob===r.blob ? reply : null,adopted,true)) return;
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
    const hash = await _e2eSha256Hex(blob);
    if (!current()) return;
    const keys = { dhKeyPair, signKeyPair };
    E2E.identityReady = false;
    E2E.identityKeys = keys;
    _e2eIdentityRevisions.set(E2E.identityKeys,hash);
    if (E2E.state) {
      E2E.state.idfp = await _e2eOwnIdfp();
      if (replace) {
        E2E.state.identityRotated = true;
        E2E.state.idfpGeneration = (E2E.state.idfpGeneration || 0)+1;
      }
      await e2eSaveState();
    }
    if (_e2eBootStale(gen) || _e2eIdentityRevisions.get(E2E.identityKeys)!==hash) return;
    const publishing=()=>E2E.keyReady&&!_e2eBootStale(gen)&&E2E.identityKeys===keys;
    const sent=await e2ePublishBundle(hash);
    if (!publishing()) return;
    const reply=sent && await _e2eReq({type:'e2e_load_identity'},'e2e_identity_blob',6000,null,1,publishing);
    if (!publishing() || !await _e2eRepairPublishedIdentity(reply?.blob===blob ? reply : null,keys)) return;
    console.log('[E2E] Generated and published fresh identity keys');
  } catch(e) {
    if (_e2eLockedMeanwhile(gen)) console.log('[E2E] identity setup stopped: the vault was locked meanwhile (' + (e && (e.message || e.name) || e) + ')');
    else console.error('[E2E] Key generation failed:', e);
    E2E.identityKeys = null;
  }
}

async function _e2eRepairPublishedIdentity(reply,keys,waitForPublisher=false) {
  const current = () => !!keys && E2E.keyReady && E2E.identityKeys===keys;
  if (!current()) return false;
  try {
    const revision = _e2eIdentityRevisions.get(keys);
    if (!reply?.blob || !revision) throw new Error('unconfirmed identity');
    // New servers report the published pair. Older servers still process the
    // authenticated identity read after the paced publication on this socket.
    if (Object.hasOwn(reply,'published_identity')) {
      const [dh,sign] = await _e2ePublicIdentity(keys);
      const matches = value => Array.isArray(value?.published_identity) && value.published_identity[0]===dh && value.published_identity[1]===sign;
      const read = () => _e2eReq({type:'e2e_load_identity'},'e2e_identity_blob',6000,null,1,current);
      // A sibling that wins first setup is already publishing its prekeys.
      // Give that write time before recovering an interrupted setup ourselves.
      if (waitForPublisher) for (const delay of [300,800,1600]) {
        if (matches(reply) || !current()) break;
        await new Promise(resolve=>setTimeout(resolve,delay));
        if (!current()) return false;
        reply=await read();
      }
      if (!current()) return false;
      if (!matches(reply)) {
        if (!await e2ePublishBundle(revision,true) || !current() || !matches(await read()))
          throw new Error('unconfirmed key bundle');
      }
    }
    if (!current()) return false;
    E2E.identityReady = true;
    return true;
  } catch (_) {
    if (current()) _e2eSys(_e2eStatusTarget(),'🔐 Could not confirm your public encryption keys. Open Encryption and retry setup, or run /encrypt unlock.');
    return false;
  }
}

// idHash (r3): SHA-256 hex of the identity blob this bundle belongs to — the server
// refuses the bundle if a different identity is stored.
async function e2ePublishBundle(idHash = null, repair = false) {
  if (!E2E.identityKeys) return;
  const keys = E2E.identityKeys;
  const current=()=>E2E.keyReady && E2E.identityKeys===keys && (!idHash || _e2eIdentityRevisions.get(keys)===idHash);
  const { dhKeyPair, signKeyPair } = keys;

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
  if (repair) {
    // The server reserves the numbered slot and publishes its matching public
    // key under one lock. Ordinary publishes use consecutive small IDs.
    spkId = 0x40000000 + (crypto.getRandomValues(new Uint32Array(1))[0] & 0x3fffffff);
  } else if (E2E._spkBlob) {
    try { const o = JSON.parse(new TextDecoder().decode(await aesDecryptBlob(E2E._spkBlob, _e2eCtxSession('__spk__')))); if (Number.isInteger(o.spk_id)) spkId = o.spk_id + 1; } catch(_) {}
  }
  const spkPrivJwk = await crypto.subtle.exportKey('jwk', spkPair.privateKey);
  const spkPlain   = new TextEncoder().encode(JSON.stringify({ spk_priv: spkPrivJwk, spk_pub: spkPub, spk_id: spkId }));
  const spkBlob    = await aesEncryptBlob(spkPlain, _e2eCtxSession('__spk__'));
  const spkBlobId  = await aesEncryptBlob(spkPlain, _e2eCtxSession(`__spk__${spkId}`));
  spkPlain.fill(0);
  if (repair) {
    return current() && _e2eWs({type:'e2e_publish_bundle',v:3,id_hash:idHash,repair_spk:[spkBlobId,spkBlob],
      bundle:{identity_dh_key:dhPub,identity_sign_key:signPub,one_time_prekeys:[],
        signed_prekey:{key_id:spkId,public_key:spkPub,signature:bytesToBase64(new Uint8Array(spkSig))}}},current);
  }
  _e2eWs({ type: 'e2e_store_session', partner: '__spk__', blob: spkBlob },current);
  _e2eWs({ type: 'e2e_store_session', partner: `__spk__${spkId}`, blob: spkBlobId },current);
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
    _e2eWs({ type: 'e2e_store_session', partner: `__otpk__${keyId}`, blob: opkBlob },current);
  }

  if (_e2eKeyGone()) { console.log('[E2E] key bundle not published: the vault was locked meanwhile'); return; }
  const sent=await _e2eWs({
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
  },current);
  if (!sent || !current()) return false;
  E2E._spkId = spkId;
  return true;
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
// The ordinary X3DH offer signature remains usable by older clients. This
// optional second signature binds a deliberate restart to its predecessor.
function _e2eRestartSignatureData(previous,header) {
  return new TextEncoder().encode(JSON.stringify([
    'CryptIRC-X3DH-RESTART-v1',previous.identityAD,previous.startEph,
    header.sender_ik,header.ephemeral_pub,header.spk_id,header.used_otpk_id ?? null
  ]));
}
// Older releases retained public offer identifiers in their sealed sessions.
// Refresh a previously used, still-unconfirmed old start on the next ordinary
// send. A confirmed conversation or a new-format offer needs no migration.
function _e2eLegacyPendingStart(session) {
  const header=session?.x3dhPending;
  if (!session?.isInitiator || session.offerVersion===2 || session._unusable || session.CKr || !session.identityAD ||
      !session.connId || !session._storeRevision || !header?.ephemeral_pub || header.restart_sig ||
      header.ephemeral_pub!==session.startEph || !(session.Ns>0 || session.priorEstablishEphs?.length)) return null;
  const anchor=Array.isArray(session.priorEstablishEphs) && session.priorEstablishEphs.at(-1);
  const previous=session.restartPrev;
  if (typeof anchor==='string' && anchor && (!previous ||
      (!previous.isInitiator && previous.startEph===anchor && _e2eSameSessionIdentity(previous,session)))) return anchor;
  // The original sender may have no alternate receive keys left after closing
  // every browser. Its own previously used offer identifies that old session.
  return session.startEph;
}
async function _e2eIsSignedSuccessor(peer,session,header,cid,fromHistory=false) {
  if (!session || session._unusable || !session.startEph || !session.identityAD ||
      (fromHistory ? !session._storeRevision : (!session.isInitiator || !session.x3dhPending)) ||
      session.connId!==cid || session.theirIdentityPub!==header.sender_ik || session.theirSignPub!==header.sender_sign_ik ||
      !E2E.trustStore[peer]?.fingerprint || E2E.trustStore[peer].keyChanged || _e2eSessPinMismatch(peer,session)!==false ||
      typeof header.restart_sig!=='string' || header.restart_sig.length!==88) return false;
  try {
    if (!await _e2eUsesCurrentIdentity(session)) return false;
    const signer=await importPub(session.theirSignPub,'ECDSA');
    return await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},signer,
      base64ToBytes(header.restart_sig),_e2eRestartSignatureData(session,header));
  } catch (_) { return false; }
}
const _e2eVerifiedOffers = new WeakSet();
async function _e2eVerifyOffer(header) {
  if (!header || !header.sender_sign_ik || !header.sender_ik || !header.sender_sign_sig) return false;
  if (_e2eVerifiedOffers.has(header)) return true;
  try {
    const key = await importPub(header.sender_sign_ik, 'ECDSA');
    const valid = await crypto.subtle.verify({ name:'ECDSA', hash:'SHA-256' }, key,
      base64ToBytes(header.sender_sign_sig),
      _x3dhHeaderSigMsg(header.sender_ik,header.ephemeral_pub,header.spk_id,header.used_otpk_id));
    if (valid) _e2eVerifiedOffers.add(header);
    return valid;
  } catch (_) { return false; }
}
// Serialised per peer (same lock as the ratchet), so the relayed copy and the IRC copy
// of one header can't both run the X3DH respond (double OTPK use / double prompt).
async function e2eEstablishResponderSession(from, header, opts = {}) {
  const peerKey = _e2eDmKey(from, opts.connId);
  return _withRatchetLock(peerKey, () => _e2eEstablishInner(from, header, { ...opts, peerKey }));
}
async function _e2eEstablishInner(from, header, opts = {}) {
  const nk = opts.peerKey || _e2eDmKey(from, opts.connId);
  const gen = E2E._lockGen;
  const user = _e2eUser();
  const sharedKeyConfigured = () => !_e2ePrefersSignal(nk) && _e2eSharedKeyConfigured(_e2eCanon(from,opts.connId) || _e2eK(from),opts.connId);
  if (E2E.state?.dm?.[nk]?.on===0) return {ok:false,why:'disabled'};
  // SECURITY: peer ratchet sessions share the server-side e2e/sessions namespace with
  // the user's OWN internal key blobs ('__spk__', '__otpk__<id>', '__state__'). Test
  // the SERVER-SANITIZED form (see _e2eReservedNamespace). (saveSession enforces too.)
  if (_e2eReservedNamespace(_e2eDmNick(nk))) {
    console.warn('[E2E] refusing reserved-namespace peer:', from);
    return { ok: false, why: 'invalid' };
  }
  if (!header || typeof header !== 'object' || !header.sender_ik) {
    console.warn('[E2E] responder establish: missing sender_ik');
    return { ok: false, why: 'invalid' };
  }
  if (sharedKeyConfigured()) return { ok:false, why:'shared-key' };
  // REPLAY GUARD: a header that already established the live session (same ephemeral —
  // x3dhInitiate generates a new ephemeral every time, a replay/duplicate reuses it) is
  // an idempotent no-op instead of resetting the receive chain. The initiator re-sends
  // its header (relay + inline) until it hears back, so duplicates are normal.
  const current = E2E.dmSessions[nk];
  // The public-identity tie breaker resolves independent, simultaneous starts.
  // A peer that explicitly replaced our still-unconfirmed session can prove
  // which start it already used. Its first authentic text commits the successor.
  const successor = opts.alt && (opts.live || opts.historySuccessor?.()) && opts.envelope &&
    await _e2eIsSignedSuccessor(nk,current,header,opts.connId,!!opts.historySuccessor);
  if (opts.requireSuccessor && !successor) return {ok:false,why:'invalid'};
  if (successor && (_e2eBootStale(gen) || !E2E.keyReady || E2E.dmSessions[nk]!==current ||
      E2E.state?.dm?.[nk]?.on!==1 || E2E.trustStore[nk]?.keyChanged)) return {ok:false,why:'invalid'};
  const useAlt = !!opts.alt && !successor;
  const _existing = useAlt ? null : current;
  if (_existing?.connId && _existing.connId !== opts.connId) return { ok:false, why:'invalid' };
  if (_e2eSessionHasOffer(_existing,header)) {
    const pt = opts.envelope ? await _ratchetDecryptInner(nk, opts.envelope) : undefined;
    return { ok: true, why: 'replay', pt };
  }
  // #25: REQUIRE a non-empty signing identity key so the pin always covers BOTH keys.
  // #47: verify the header before using it or asking the user to trust a new identity.
  if (!await _e2eVerifyOffer(header)) return { ok:false, why:'invalid' };
  // #11/#25: pin BOTH identity keys (dh + sign), validated P-256 points.
  const fp    = await computeIdentityFingerprint(header.sender_ik, header.sender_sign_ik).catch(() => null);
  if (!fp) return { ok:false, why:'invalid' };
  if (opts.expectedFingerprint && (!await e2ePinMatchesIdentity(opts.expectedFingerprint, header.sender_ik, header.sender_sign_ik) ||
      E2E.trustStore[nk]?.fingerprint !== opts.expectedFingerprint ||
      E2E.trustStore[nk].keyChanged || E2E.state?.dm?.[nk]?.on === 0 || _e2eBootStale(gen))) return {ok:false,why:'invalid'};
  // A delayed setup frame may belong to an identity the contact has already
  // replaced. Wait for the accompanying message before revisiting a live pin.
  if (_existing && !_existing._unusable && !opts.envelope) return {ok:false,why:'deferred'};
  const trust = await e2eCheckTrust(from, fp, { connId: opts.connId, peerKey: nk, keys: [header.sender_ik, header.sender_sign_ik] });

  // #1/C2: a changed identity must NOT silently re-establish. Warn and refuse; the pin
  // and the live session (if any) stay exactly as they were.
  if (trust.keyChanged) {
    e2eShowKeyChangeWarning(from, fp, trust.firstWarning, opts.connId);
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
                                     { previous: _existing, theirSignPub: header.sender_sign_ik, connId:_e2eDmScope(nk)?.[1] });
  if (!E2E.keyReady || _e2eBootStale(gen)) return { ok:false, why:'invalid' };
  if (sharedKeyConfigured()) return { ok:false, why:'shared-key' };
  if (E2E.state?.dm?.[nk]?.on===0) return {ok:false,why:'disabled'};
  // A replacement only becomes live after its first message authenticates.
  let pt;
  if (opts.envelope) pt = await _ratchetDecryptInner(nk, opts.envelope, {
    useAlt, candidate:sess, create:true, historyCurrent:successor ? opts.historySuccessor : null
  });
  else {
    try { await saveSession(nk,sess,{create:true}); }
    catch (error) {
      if (!(error instanceof E2ESessionConflict) || !_e2eSessionHasOffer(E2E.dmSessions[nk],header)) throw error;
    }
  }
  if (opts.live && opts.envelope && !successor) {
    try {await _e2eShareLiveReceipt(nk,useAlt ? E2E._glareAlt?.[nk] : E2E.dmSessions[nk],opts.envelope);}
    catch (_) { /* A sibling receipt is optional to the authenticated local delivery. */ }
  }
  if (consumedOtpkId != null && user === _e2eUser()) {
    _e2eWs({ type: 'e2e_delete_session', v: E2E_STORAGE_VERSION, partner: `__otpk__${consumedOtpkId}` }, () => user === _e2eUser());
    delete E2E._sessionCache[`__otpk__${consumedOtpkId}`];
  }
  if (!E2E.keyReady || _e2eBootStale(gen)) return { ok:false, why:'invalid' };
  if (!useAlt) _e2eStateSetDm(nk, true);
  if (successor && E2E._glareAlt) delete E2E._glareAlt[nk];
  return { ok: true, why: '', pt };
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
const _e2eAdoptedEpochs = Object.create(null);
const _e2ePriorHistorySessions = new Map();
function _e2eRememberSessionEpoch(peer,epoch) {
  E2E._sessionEpoch[peer] = Math.max(E2E._sessionEpoch[peer] || 0,epoch);
  const dev = _e2eDev();
  if ((dev.ep[peer] || 0) < epoch) { dev.ep[peer] = epoch; _e2eDevSave(); }
  _e2eScheduleOwnEchoes(peer);
}
const _e2eInitialEchoes = new Map();
const _e2eFirstAdoptions = new WeakMap();
function _e2eRememberFirstAdoption(previous,next,canonical) {
  if (!next?.startEph) return;
  if (!previous || previous.startEph!==next.startEph || !_e2eSameSessionIdentity(previous,next)) {
    if (canonical) _e2eFirstAdoptions.set(next,Date.now());
    return;
  }
  const seen=_e2eFirstAdoptions.get(previous);
  if (seen>Date.now()-60000) _e2eFirstAdoptions.set(next,seen);
}
async function _e2eNoteInitialEcho(peer,blob) {
  if (!E2E.keyReady || !_e2eDmScope(peer) || !blob?.startsWith('e2e3.') || blob.length>65536 ||
      _e2eInitialEchoes.get(peer)?.blob===blob) return;
  const gen = E2E._lockGen, tombstone = E2E._sessionTombstones.get(peer);
  const floor = Math.max(E2E.dmSessions[peer]?.epoch || 0,E2E._sessionEpoch[peer] || 0,_e2eDev().ep[peer] || 0);
  let epoch, lateFirst=false;
  try {
    const bytes = await aesDecryptBlob(blob,_e2eCtxSession(peer));
    try {
      const seed = JSON.parse(new TextDecoder().decode(bytes));
      if (!seed?.isInitiator || seed.Ns!==0 || !seed.CKs || !seed.startEph || !_e2eSessionScopeMatches(peer,seed)) return;
      epoch = seed.epoch;
      // A reconnect can adopt the committed first sends before an already-in-flight
      // creation notice is processed. Recognize only that exact initial chain,
      // on a newly restored, independently authenticated canonical session.
      const live=E2E.dmSessions[peer];
      lateFirst=!!(live?.isInitiator && _e2eFirstAdoptions.get(live)>Date.now()-60000 && live.epoch>=floor &&
        epoch>(tombstone ?? -1) && live.epoch>=epoch && live.epoch-epoch<=E2E_MAX_SKIP && live.startEph===seed.startEph &&
        _e2eSameSessionIdentity(seed,live) && live.sentDigests?.some(d=>Array.isArray(d) && d[0]===seed.DHs?.pub));
    } finally { bytes.fill(0); }
  } catch (_) { return; }
  if (!E2E.keyReady || _e2eBootStale(gen) || E2E._sessionTombstones.get(peer)!==tombstone ||
      !Number.isSafeInteger(epoch) || (epoch<=floor && !lateFirst) || epoch<=(_e2eInitialEchoes.get(peer)?.epoch ?? -1)) return;
  const ticket = Symbol();
  const entry = {blob,floor,epoch,lateFirst,ticket,until:Date.now()+60000,scheduled:false,attempts:0};
  if (!_e2eInitialEchoes.has(peer) && _e2eInitialEchoes.size>=24) _e2eInitialEchoes.delete(_e2eInitialEchoes.keys().next().value);
  _e2eInitialEchoes.set(peer,entry);
  setTimeout(()=>{ if (_e2eInitialEchoes.get(peer)?.ticket===ticket) _e2eInitialEchoes.delete(peer); },60000);
  _e2eScheduleOwnEchoes(peer);
}
function _e2eScheduleOwnEchoes(peer) {
  const entry = _e2eInitialEchoes.get(peer), scope = _e2eDmScope(peer);
  if (!entry || !scope || typeof restoreCachedDmHistory!=='function') return;
  if (entry.scheduled) { entry.again = true; return; }
  entry.scheduled = true;
  entry.again = false;
  const gen = E2E._lockGen;
  const current = () => E2E.keyReady && !_e2eBootStale(gen) && _e2eInitialEchoes.get(peer)===entry && entry.until>Date.now();
  const disabled = () => E2E.state?.dm?.[peer]?.on===0;
  setTimeout(async()=>{
    try {
      if (!current()) return;
      // The initiating device records its accepted pin independently of committing
      // the ratchet. On first contact the sealed account state can arrive later.
      if ((!E2E.trustStore[peer]?.fingerprint || disabled()) && E2E.state) {
        const blob = await _e2eFetchSession('__state__');
        const state = current() && blob ? await _e2eDecodeState(blob) : null;
        if (state && current() && _e2eMergeStateInto(E2E.state,state)) _e2eApplyMergedState();
      }
      const pin = E2E.trustStore[peer];
      if (!current() || disabled() || !pin?.fingerprint || pin.keyChanged) return;
      if (!E2E.dmSessions[peer] || (E2E.dmSessions[peer].epoch || 0)<entry.epoch) {
        _e2eMarkMaybeMoved(peer);
        const fingerprint=pin.fingerprint;
        await _e2eAdoptMoved(peer,()=>current() && !disabled() && E2E.trustStore[peer]?.fingerprint===fingerprint &&
          !E2E.trustStore[peer].keyChanged);
      }
      if (current() && !disabled() && E2E.dmSessions[peer]) await restoreCachedDmHistory(scope[1],scope[2],true);
    } catch (_) { /* A subsequent authenticated move or echo can retry. */ }
    finally {
      entry.scheduled = false;
      if (entry.again && current()) _e2eScheduleOwnEchoes(peer);
      else if (current() && ((E2E.dmSessions[peer]?.epoch || 0)<entry.epoch || !E2E.trustStore[peer]?.fingerprint || disabled())) {
        const delay = Math.min(10000,300 * 2**entry.attempts++);
        setTimeout(()=>{ if (current()) _e2eScheduleOwnEchoes(peer); },delay);
      }
    }
  },0);
}
async function _e2eReadInitialEchoKeys(peer,live,header,usable) {
  const entry = _e2eInitialEchoes.get(peer);
  if (!entry || entry.until<=Date.now() || header.n>=E2E_MAX_SKIP || !usable()) return;
  const bytes = await aesDecryptBlob(entry.blob,_e2eCtxSession(peer));
  let seed;
  try { seed = JSON.parse(new TextDecoder().decode(bytes)); } finally { bytes.fill(0); }
  // A creation notice cannot install, enable or rewind a session. Use it only
  // for our own echo under an independently pinned, currently active session.
  if (!usable() || _e2eInitialEchoes.get(peer)!==entry || !Number.isSafeInteger(seed?.epoch) || (seed.epoch<=entry.floor && !entry.lateFirst) ||
      seed.epoch>live.epoch || !seed.isInitiator || seed.Ns!==0 || !seed.CKs || seed.DHs?.pub!==header.dh ||
      seed.startEph!==live.startEph || !_e2eSameSessionIdentity(seed,live)) return;
  const committed = live.DHs?.pub===header.dh ? live.Ns : live.PN;
  const known = (live.sentDigests || []).reduce((n,d)=>Array.isArray(d) && d[0]===header.dh ? Math.max(n,d[1]+1) : n,0);
  const limit = Math.min(E2E_MAX_SKIP,Math.max(header.n+1,committed||0,known));
  await _e2eRememberEchoChain(peer,live,header.dh,seed.CKs,0,limit,usable);
  if (usable() && _e2eInitialEchoes.get(peer)===entry) _e2eInitialEchoes.delete(peer);
}
// An unlocked sibling can already derive these message keys from its own sending
// chain. Hold only the keys crossed by an authenticated device update until the
// corresponding IRC echoes arrive. They never enter a stored or relayed session.
const _e2eEchoKeys = new Map();
let _e2eEchoExpiry = null;
function _e2eForgetEchoKeys(peer,expiredOnly = false) {
  for (const [id,entry] of _e2eEchoKeys) {
    if ((peer && entry.peer !== peer) || (expiredOnly && entry.until > Date.now())) continue;
    entry.mk.fill(0);
    _e2eEchoKeys.delete(id);
  }
  if (!_e2eEchoKeys.size && _e2eEchoExpiry !== null) { clearTimeout(_e2eEchoExpiry); _e2eEchoExpiry = null; }
}
function _e2eScheduleEchoExpiry() {
  if (_e2eEchoExpiry !== null || !_e2eEchoKeys.size) return;
  const until = Math.min(...Array.from(_e2eEchoKeys.values(),entry=>entry.until));
  _e2eEchoExpiry = setTimeout(() => {
    _e2eEchoExpiry = null;
    _e2eForgetEchoKeys(null,true);
    _e2eScheduleEchoExpiry();
  },Math.max(0,until-Date.now()));
}
async function _e2eRememberEchoChain(peer,session,dh,chain,from,to,current) {
  if (!chain || !dh || !Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from < 0 || to <= from || to-from > E2E_MAX_SKIP) return;
  const digests = new Map((session.sentDigests || []).filter(entry=>Array.isArray(entry)&&entry[0]===dh).map(entry=>[entry[1],entry[2]]));
  let ck = base64ToBytes(chain);
  try {
    for (let n=from; n<to && current(); n++) {
      const [mk,next] = await chainKeyStep(ck);
      ck.fill(0); ck = next;
      if (!current()) { mk.fill(0); return; }
      const id = JSON.stringify([peer,session.startEph,dh,n]);
      if (_e2eEchoKeys.has(id)) {
        if (digests.has(n)) _e2eEchoKeys.get(id).digest=digests.get(n);
        mk.fill(0); continue;
      }
      if (_e2eEchoKeys.size >= 4*E2E_MAX_SKIP) {
        const [old,entry] = _e2eEchoKeys.entries().next().value;
        entry.mk.fill(0); _e2eEchoKeys.delete(old);
      }
      const now = Date.now();
      _e2eEchoKeys.set(id,{peer,start:session.startEph,dh,mk,digest:digests.get(n),
        until:now+60000,deadline:now+60000+10000*E2E_MAX_SKIP});
    }
  } finally { ck.fill(0); _e2eScheduleEchoExpiry(); }
}
async function _e2eEchoKeysAfterAdoption(peer,previous,next) {
  if (!_e2eSameSessionIdentity(previous,next) || !previous.startEph || previous.startEph !== next.startEph) {
    _e2eForgetEchoKeys(peer); return;
  }
  const gen = E2E._lockGen;
  const current = () => E2E.keyReady && !_e2eBootStale(gen) && E2E.dmSessions[peer] === previous &&
    !E2E.trustStore[peer]?.keyChanged && _e2eSessPinMismatch(peer,next) === false;
  const sameDH = previous.DHs?.pub === next.DHs?.pub;
  await _e2eRememberEchoChain(peer,next,previous.DHs?.pub,previous.CKs,previous.Ns,sameDH ? next.Ns : next.PN,current);
  if (sameDH || !next.Ns || next.Ns > E2E_MAX_SKIP || !current() || !next.DHr || !next.DHs?.priv) return;
  // Both device snapshots can span one DH turn. Recreate its sending half using
  // the adopted private DH key and verify the resulting root before retaining keys.
  const oldPrivate = await importPriv(previous.DHs.priv);
  const root = base64ToBytes(previous.RK);
  let first,middle,outgoing;
  try {
    if (previous.isInitiator && !previous.CKr && previous.DHr !== next.DHr) {
      first = await _e2eRatchetKdf(root,oldPrivate,await importPub(previous.DHr,'ECDH'));
    }
    const remote = await importPub(next.DHr,'ECDH');
    middle = await _e2eRatchetKdf(first ? first.subarray(0,32) : root,oldPrivate,remote);
    outgoing = await _e2eRatchetKdf(middle.subarray(0,32),await importPriv(next.DHs.priv),remote);
    if (bytesToBase64(outgoing.subarray(0,32)) === next.RK) {
      await _e2eRememberEchoChain(peer,next,next.DHs.pub,bytesToBase64(outgoing.subarray(32)),0,next.Ns,current);
    }
  } finally { root.fill(0); first?.fill(0); middle?.fill(0); outgoing?.fill(0); }
}
function _e2eSessionScopeMatches(key,session) {
  return !session.connId || _e2eDmScope(key)?.[1] === session.connId;
}
function _e2eSameSessionIdentity(a,b) {
  return !!(a && b && !a._unusable && !b._unusable && a.connId === b.connId &&
    a.identityAD === b.identityAD && a.theirIdentityPub === b.theirIdentityPub && a.theirSignPub === b.theirSignPub);
}
async function _e2eNoteSessionAdoption(key,previous,session) {
  const generation = E2E._lockGen;
  try { await _e2eEchoKeysAfterAdoption(key,previous,session); } catch (_) { /* An echo may have aged out. */ }
  if (!E2E.keyReady || _e2eBootStale(generation) || E2E.dmSessions[key] !== previous) return;
  if (!_e2eSameSessionIdentity(previous,session)) { _e2ePriorHistorySessions.delete(key); return; }
  if (_e2ePriorHistorySessions.get(key)?.session.startEph === previous.startEph) return;
  const {CKs,restartPrev,x3dhPending,...receive} = previous;
  const ticket = Symbol();
  _e2ePriorHistorySessions.set(key,{session:receive,ticket});
  if (_e2ePriorHistorySessions.size > 32) _e2ePriorHistorySessions.delete(_e2ePriorHistorySessions.keys().next().value);
  setTimeout(()=>{ if (_e2ePriorHistorySessions.get(key)?.ticket === ticket) _e2ePriorHistorySessions.delete(key); },60000);
}
// opts.hint (r2 security review — e2e_session_moved): the server merely SAYS another
// device moved this session on. Its blob is installed only if its epoch is STRICTLY
// newer than everything this device has seen for the peer (live session, page and
// device high-water marks) and it continues the same identity binding. Hint results
// are true for adoption, false for a known session, and null if still unconfirmed.
// The buffered skipped / recent message keys of the live session are kept.
async function _e2eInstallStoredInner(nk, blob, slot = null, opts = null) {
    const generation = E2E._lockGen, master = E2E.e2eEncKey, identity = E2E.identityKeys;
    const tombstone = E2E._sessionTombstones.get(nk);
    const current = () => !_e2eBootStale(generation) && E2E.keyReady && E2E.e2eEncKey === master &&
      E2E.identityKeys === identity && E2E._sessionTombstones.get(nk) === tombstone && (!opts?.allowed || opts.allowed());
    const hint = !!(opts && opts.hint);
    try {
      const { pt, legacy } = await aesDecryptBlobEx(blob, _e2eCtxSession(slot || nk));
      let session;
      try { if (!current()) return null; session = JSON.parse(new TextDecoder().decode(pt)); }
      finally { pt.fill(0); }
      if (!session || typeof session !== 'object' || !session.RK || !_e2eSessionScopeMatches(nk,session)) return null;
      if (opts?.receiptStart && (session.isInitiator || session.startEph!==opts.receiptStart ||
          !_e2eSameSessionIdentity(E2E.dmSessions[nk],session))) return null;
      // Only the user's explicit enable command may inspect a newer replacement
      // while this chat is off. It must be a modern, scoped, identity-bound row.
      const enableCandidate = opts?.enableFromOff && opts.candidateOnly;
      if (enableCandidate && (legacy || !session.connId || !session.identityAD || !_e2eSessFpKey(session) ||
          !E2E.trustStore[nk]?.fingerprint || E2E.trustStore[nk]?.keyChanged || !Number.isSafeInteger(session.epoch))) return null;
      if ((E2E.state?.dm?.[nk]?.on===0 && !enableCandidate) ||
          (session.epoch || 0) <= Math.max(tombstone ?? -1,E2E.state?.dm?.[nk]?.closedEpoch ?? -1)) return null;
      session._storeRevision = !slot || slot === nk ? await _e2eSha256Hex(blob) : '';
      if (!current()) return null;
      if (!await _e2eUsesCurrentIdentity(session)) {
        // Retain the exact stored revision so an explicit restart can replace
        // it. A session under the previous identity supplies no live chains.
        if (current() && identity && !slot && !opts?.candidateOnly && !E2E.dmSessions[nk]?.RK) {
          E2E.dmSessions[nk] = {nick:nk,epoch:session.epoch || 0,_storeRevision:session._storeRevision,
            _unusable:'your encryption identity changed. Use /encrypt restart to establish a new session'};
        }
        return null;
      }
      if (!current()) return null;
      if (E2E.trustStore[nk]?.fingerprint) {
        await _e2eSessFp(session);
        if (!current() || _e2eSessPinMismatch(nk,session) !== false) return null;
      }
      if (opts?.resumeAgainst) {
        const live = opts.resumeAgainst;
        // Only the live, already-approved session may authorize its earlier
        // receive chain. This candidate is never installed or saved.
        if (!enableCandidate || E2E.dmSessions[nk]!==live || !live.startEph || session.startEph!==live.startEph ||
            !Number.isSafeInteger(live.epoch) || session.epoch>live.epoch || !_e2eSameSessionIdentity(session,live) ||
            _e2eSessPinIs(session,E2E.trustStore[nk]?.fingerprint)!==true) return null;
        delete session.CKs;
        delete session.restartPrev;
        return session;
      }
      const floor = () => Math.max(E2E._sessionEpoch[nk] || 0, _e2eDev().ep[nk] || 0);
      const hwm = floor();
      if (hint) {
        const cur = E2E.dmSessions[nk];
        const curEp = cur ? (cur.epoch || 0) : 0;
        if (legacy) return null;
        if (!((session.epoch || 0) > Math.max(hwm, curEp))) {
          if (!_e2eSameSessionIdentity(cur,session) || session.startEph !== cur.startEph) return null;
          // An older browser's IndexedDB record has no revision. Bind it only
          // when the authenticated server copy has the exact same ratchet state.
          if (!cur._storeRevision && curEp === session.epoch && curEp >= hwm &&
              ['RK','CKs','CKr','DHr','Ns','Nr','PN'].every(field => cur[field] === session[field]) &&
              cur.DHs?.pub === session.DHs?.pub) cur._storeRevision = session._storeRevision;
          return opts?.conflict && cur._storeRevision !== session._storeRevision ? null : false;
        }
        let replaced = false;
        if (cur && !cur._unusable && !_e2eSameSessionIdentity(cur,session)) {
          // r7 (codex-p3 e2e.js:1375): a different identity binding is taken only when the
          // stored copy is bound to the identity this account pins NOW and the live session
          // is not — the peer's replacement identity was accepted on another device, which
          // then set up this session with it.
          const tr = E2E.trustStore[nk];
          const pinNow = tr?.fingerprint || null;
          await _e2eSessFp(session); await _e2eSessFp(cur);
          // Either pin format over both keys; a pre-#11 DH-only pin confirms neither
          // binding (see _e2eSessPinIs), so the hint is ignored.
          const newOk = !!pinNow && _e2eSessPinIs(session,pinNow) === true;
          const curOk = !!pinNow && _e2eSessPinIs(cur,pinNow) === true;
          if (!current() || E2E.dmSessions[nk] !== cur || (session.epoch || 0) <= floor() ||
              E2E.trustStore[nk]?.fingerprint !== pinNow || !(newOk && !curOk)) {
            console.warn('[E2E] ignoring a "session moved" hint: different identity binding for', nk);
            return null;
          }
          replaced = true;
          console.log('[E2E] taking over the session with', nk, 'bound to its accepted replacement identity');
        }
        session.nick = nk;
        const sameStart = !replaced && cur?.startEph && cur.startEph === session.startEph;
        session.skipped = Object.assign({},session.skipped || {},sameStart ? cur.skipped : {});
        session.skippedMeta = Object.assign({},sameStart ? cur.skippedMeta : {});
        session.recent = Object.assign({},sameStart ? cur.recent : {});
        _e2ePreserveRestartReceive(nk,cur,session);
        await _e2eNoteSessionAdoption(nk,cur,session);
        if (!current() || E2E.dmSessions[nk] !== cur || (session.epoch || 0) <= floor()) return null;
        E2E.dmSessions[nk] = session;
        _e2eRememberFirstAdoption(cur,session,true);
        _e2eAdoptedEpochs[nk] = session.epoch;
        _e2eRememberSessionEpoch(nk,session.epoch || 0);
        await _e2eWriteDeviceSession(nk,session);
        return current() ? true : null;
      }
      if ((session.epoch || 0) < hwm) {
        if (opts?.candidateOnly) return null;
        console.warn('[E2E] refusing stale session blob for', nk, '(epoch', session.epoch, '<', hwm, ')');
        _e2eSys(nk, `⚠️ E2E: the server returned an OLD copy of your session with ${nk} (possible replay) — refused. /encrypt on ${nk} to start a fresh session.`);
        const live = E2E.dmSessions[nk];
        if (!live) E2E.dmSessions[nk] = { nick: nk, _unusable: 'session state was rolled back — re-establish with /encrypt on',
          _storeRevision:session._storeRevision, epoch: hwm };
        return null;
      }
      const live = E2E.dmSessions[nk];
      if (live && !live._unusable && (live.epoch || 0) >= (session.epoch || 0) && !enableCandidate) return live;
      session.nick = nk;
      session.skipped = session.skipped || {};
      if (opts?.candidateOnly) return session;
      E2E.dmSessions[nk] = session;
      _e2eRememberFirstAdoption(live,session,true);
      _e2eRememberSessionEpoch(nk,session.epoch || 0);
      if (legacy) await saveSession(nk, session, {create:!!slot && slot!==nk});
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
      await _withRatchetLock(nk, () => _e2eInstallStoredInner(nk, blob, null, { hint: true }));
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
  E2E._maybeMoved[k] ||= {at:Date.now()};
}
function _e2eMovedPending(k) { return !!((E2E._moved && E2E._moved[k]) || (E2E._maybeMoved && E2E._maybeMoved[k])); }
// r7 (codex-p3 e2e.js:1375): the identity a DM session is bound to vs the identity this
// account pins for the peer NOW. Accepting a peer's replacement identity on another
// device reaches this one as a new pin (re-sync / state merge) — but the old session
// stayed and kept encrypting to (and authenticating) the previous identity.
E2E._fpCache = new Map();         // session identity keys → v2 fingerprint (null: invalid keys)
E2E._fpLegacyCache = new Map();   // the same keys → an earlier release's full-pin form
function _e2eSessFpKey(s) { return s && s.theirIdentityPub && s.theirSignPub ? s.theirIdentityPub + '|' + s.theirSignPub : null; }
function _e2eSessFpCached(s) { const key = _e2eSessFpKey(s); return key ? E2E._fpCache.get(key) : undefined; }
async function _e2eSessFp(s) {
  const key = _e2eSessFpKey(s);
  if (!key) return null;
  let fp = E2E._fpCache.get(key);
  if (fp === undefined) {
    const valid = await e2eValidIdentityKeys(s.theirIdentityPub, s.theirSignPub);
    fp = valid ? await computeIdentityFingerprint(s.theirIdentityPub, s.theirSignPub) : null;
    const legacy = valid ? await e2eLegacyIdentityFingerprint(s.theirIdentityPub, s.theirSignPub) : null;
    // Paired entries, inserted and evicted together.
    E2E._fpLegacyCache.set(key, legacy);
    E2E._fpCache.set(key, fp);
    while (E2E._fpCache.size > 1000) {
      const oldest = E2E._fpCache.keys().next().value;
      E2E._fpCache.delete(oldest); E2E._fpLegacyCache.delete(oldest);
    }
  }
  return fp;
}
// Does the session use the identity `pin` confirms? A v2 pin, or a full pin made by an
// earlier release over the same two validated keys. Never the DH key alone: a pre-#11
// pin does not vouch for the session's signing key (the user confirms it once through
// the key-change flow). undefined = not computed yet (call _e2eSessFp first).
function _e2eSessPinIs(s, pin) {
  const key = _e2eSessFpKey(s);
  if (!key || typeof pin !== 'string' || !pin) return false;
  const fp = E2E._fpCache.get(key);
  if (fp === undefined) return undefined;
  if (fp === null) return false;
  return pin === fp || (e2eIsLegacyFingerprint(pin) && pin === E2E._fpLegacyCache.get(key));
}
// true = the session is bound to ANOTHER identity than the current (locally owned) pin;
// null = not known yet (being computed); false = same, or nothing to compare (no pin, a
// server-seeded pin, a legacy session without the signing key).
function _e2eSessPinMismatch(k, s) {
  const tr = E2E.trustStore[k];
  if (!s || s._unusable || !tr || !tr.fingerprint || !_e2eSessFpKey(s)) return false;
  const same = _e2eSessPinIs(s, tr.fingerprint);
  if (same === undefined) { _e2eSessFp(s).catch(() => {}); return null; }
  return !same;
}
// r2 (NEW-7, cross-device): another device of this account SENT on the session with
// `k`, so its send chain moved past ours. The server's "session moved" event is only a
// HINT: the stored copy is installed under the strict rules of _e2eInstallStoredInner
// (strictly newer epoch, same identity binding, epoch never raised, no re-save).
async function _e2eAdoptMoved(k,allowed = null) {
  if (!E2E.keyReady || !_e2eMovedPending(k)) return true;
  return _withRatchetLock(k, () => _e2eAdoptMovedInner(k,allowed));
}
async function _e2eAdoptMovedInner(k,allowed = null) {
  if (!E2E.keyReady || !_e2eMovedPending(k)) return true;
  const generation = E2E._lockGen;
  const tombstone = E2E._sessionTombstones.get(k);
  const current = () => E2E.keyReady && !_e2eBootStale(generation) && E2E._sessionTombstones.get(k) === tombstone && (!allowed || allowed());
  const moved = E2E._moved?.[k], maybeMoved = E2E._maybeMoved?.[k];
  const reply = await _e2eRequestSession(k);
  if (!reply || !current()) return null;
  if (!reply.blob && moved && Date.now() - moved.at < 120000) return null;
  const adopted = reply.blob ? await _e2eInstallStoredInner(k,reply.blob,null,{hint:true,allowed}) : false;
  if (!current()) return null;
  if (moved && E2E._moved?.[k] === moved) delete E2E._moved[k];
  if (maybeMoved && E2E._maybeMoved?.[k] === maybeMoved) delete E2E._maybeMoved[k];
  if (adopted === null || (!reply.blob && moved)) {
    const revision = reply.blob ? await _e2eSha256Hex(reply.blob) : '';
    if (current()) E2E._sessionSyncRepair.set(k,revision);
    return null;
  }
  if (adopted) E2E._sessionSyncRepair.delete(k);
  return adopted;
}

// A real move can arrive during the preceding read, particularly when two
// devices approve a new contact together. Synchronize again under the same
// ratchet lock before preparing any ciphertext. A failed read still holds the draft.
async function _e2eReadyToSendInner(key) {
  const generation=E2E._lockGen;
  const tombstone=E2E._sessionTombstones.get(key);
  const current=()=>E2E.keyReady && !_e2eBootStale(generation) && E2E._sessionTombstones.get(key)===tombstone;
  for (let i=0; i<4 && _e2eMovedPending(key); i++) {
    if (!current()) return false;
    const moved=E2E._moved?.[key], maybe=E2E._maybeMoved?.[key];
    const result=await _e2eAdoptMovedInner(key);
    if (result===null && (!_e2eMovedPending(key) || E2E._sessionSyncRepair.has(key) ||
        (moved===E2E._moved?.[key] && maybe===E2E._maybeMoved?.[key]))) return false;
  }
  const session = E2E.dmSessions[key];
  if (session?.RK && !await _e2eUsesCurrentIdentity(session)) throw new Error('Your encryption identity changed. Use /encrypt restart to establish a new session.');
  return current() && !_e2eMovedPending(key) && !E2E._sessionSyncRepair.has(key);
}

// ─── Double Ratchet ───────────────────────────────────────────────────────────

function _e2ePriorEstablishEphs(previous, except = null) {
  if (!previous) return [];
  const prior = Array.isArray(previous.priorEstablishEphs) ? previous.priorEstablishEphs : [];
  return [...new Set([...prior, previous.establishEph].filter(e => e && e !== except))].slice(-32);
}

function _e2eRestartFrom(session) {
  return session ? session.startEph || session.establishEph || session.x3dhPending?.ephemeral_pub || null : undefined;
}

function _e2eScheduleRestartExpiry(nick, until) {
  const user = _e2eUser();
  setTimeout(() => {
    if (user === _e2eUser() && E2E.keyReady) {
      void _withRatchetLock(nick, () => {}).catch(() => {});
    }
  }, Math.max(0, until - Date.now()));
}

function _e2ePreserveRestartReceive(nick,previous,next) {
  if (!next.x3dhPending || !previous?.startEph || !_e2eSameSessionIdentity(previous,next)) return;
  if (previous.startEph === next.startEph) {
    if (previous.restartPrev?.until > Date.now()) next.restartPrev = previous.restartPrev;
    return;
  }
  const { CKs,recent,restartPrev,x3dhPending,_storeRevision,...receive } = previous;
  next.restartPrev = { ...receive,until:Date.now()+E2E_RESTART_RECEIVE_MS };
  _e2eScheduleRestartExpiry(nick,next.restartPrev.until);
}

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
    connId: extra.connId || null,
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
    offerVersion: 2,  // Sealed local format for an initiator that supports bound restarts.
    startEph:    extra.x3dhHeader?.ephemeral_pub || null,
    priorEstablishEphs: _e2ePriorEstablishEphs(extra.previous),
  };

  if (extra.stillPending && !extra.stillPending()) return null;
  const previous = extra.previous;
  _e2ePreserveRestartReceive(nick,previous,session);
  try { await saveSession(nick,session,{create:true,replaceRevision:extra.replaceRevision}); }
  catch (error) {
    const winner = E2E.dmSessions[nick];
    // Two devices can discover the same peer, and the winner may have already
    // received an authenticated reply by the time this commit loses.
    if (!(error instanceof E2ESessionConflict) || previous || !winner?.startEph ||
        !_e2eSameSessionIdentity(session,winner) || E2E.trustStore[nick]?.keyChanged ||
        extra.reuseConfirmed===false || E2E.state?.dm?.[nick]?.on===0 ||
        (winner.epoch || 0) <= Math.max(E2E._sessionTombstones.get(nick) ?? -1,E2E.state?.dm?.[nick]?.closedEpoch ?? -1) ||
        _e2eSessPinMismatch(nick,winner) !== false || (extra.stillPending && !extra.stillPending())) throw error;
    if (!winner.x3dhPending && (!extra.reuseConfirmed || !winner.connId || !winner.isInitiator || !winner.CKr || (!winner.CKs && !winner.DHr) ||
        !E2E.trustStore[nick]?.fingerprint)) throw error;
    _e2eStateSetDm(nick,true);
    return winner;
  }
  _e2eStateSetDm(nick, true);
  return session;
}

async function ratchetInitRecv(nick, sharedSecret, theirIdentityPub, identityAD, establishEph, selectedSpk, opts = {}) {
  nick = _e2eK(nick);
  const RK  = sharedSecret.slice(0, 32);
  const CKr = sharedSecret.slice(32, 64);

  // Carry forward EVERY ephemeral that has previously established this session so the
  // replay guard recognises a re-delivered OLDER genuine header. Bounded to 32 + deduped.
  const prior = _e2ePriorEstablishEphs(opts.previous, establishEph);

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
    connId: opts.connId || null,
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
    startEph:    establishEph || null,
    priorEstablishEphs: prior,
    skipped:     {},
    isInitiator: false,
  };

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
      return await _e2eXLock('r:' + nick, async () => {
        await _e2eSyncFromDevice(nick);
        const session = E2E.dmSessions[nick];
        if (E2E.keyReady && session?.restartPrev && !(session.restartPrev.until > Date.now())) {
          const { restartPrev, ...activeSession } = session;
          E2E.dmSessions[nick] = activeSession;
          await _e2eWriteDeviceSession(nick, activeSession);
        }
        return await fn();
      });
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
const E2E_HEADER_TTL_MS = 10 * 60 * 1000;
const _e2eRecentOffers = new Map();
const _e2eHistoryAttempts = new Map();
const _e2eHeldInFlight = new WeakSet();
// r9 (astra-p3 e2e.js:3453): when each pending X3DH header arrived (keyed by the header
// object, so the stored value keeps its shape).
const _e2ePendHdrAt = new WeakMap();
const _e2eHeaderNetworks = new WeakMap();
function _e2eForgetPendingHeader(k,hdr) {
  if (hdr && E2E._pendingIncomingX3DH?.[k] === hdr) delete E2E._pendingIncomingX3DH[k];
}
function _e2eSessionHasOffer(session,header) {
  const ephemeral = header?.ephemeral_pub;
  return !!(session && ephemeral && (session.establishEph === ephemeral ||
    (Array.isArray(session.priorEstablishEphs) && session.priorEstablishEphs.includes(ephemeral))));
}
function _e2ePendingHeader(k) {
  const hdr = E2E._pendingIncomingX3DH?.[k];
  if (_e2eSessionHasOffer(E2E.dmSessions[k],hdr) ||
      (hdr && !E2E.trustStore[k]?.pendingFingerprint && Date.now() - _e2ePendHdrAt.get(hdr) >= E2E_HEADER_TTL_MS)) {
    _e2eForgetPendingHeader(k,hdr);
    return null;
  }
  return hdr;
}
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
      else if (now - t < E2E_HEADER_TTL_MS) live.push([k, t]); else delete P[k];
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

async function ratchetEncrypt(nick, plaintext, reaction = false) {
  return _withRatchetLock(_e2eK(nick), async () => {
    if (!await _e2eReadyToSendInner(nick)) throw new Error('Signal is syncing with another device. Try again shortly.');
    if (E2E._sessionSyncRepair.has(nick)) throw new Error('Restart this Signal session before sending.');
    return _ratchetEncryptInner(_e2eK(nick), plaintext, reaction);
  });
}

async function _ratchetEncryptInner(nick, plaintext, reaction = false, canCommit = null) {
  const initial = E2E.dmSessions[nick], generation = E2E._lockGen;
  for (let attempt = 0; attempt < 8; attempt++) {
    const live = E2E.dmSessions[nick];
    if (attempt && (_e2eBootStale(generation) || !E2E.keyReady || !_e2eSameSessionIdentity(initial,live) ||
        live.startEph !== initial.startEph || _e2eSessPinMismatch(nick,live) !== false || E2E.trustStore[nick]?.keyChanged)) {
      throw new Error('Encryption changed while preparing this message. Try again.');
    }
    try { return await _e2eEncryptAndCommit(nick,plaintext,reaction,canCommit); }
    catch (error) { if (!(error instanceof E2ESessionConflict)) throw error; }
  }
  throw new Error('Another device is busy sending. Your message is still in the composer.');
}

async function _e2eEncryptAndCommit(nick,plaintext,reaction,canCommit) {
  const live = E2E.dmSessions[nick], generation = E2E._lockGen;
  if (!live) throw new Error(`No ratchet session with ${nick}`);
  if (live._unusable) throw new Error(live._unusable);
  const session = {...live};
  // Older clients may miss every reaction. Leave most of the skipped-key budget
  // available for ordinary messages, including across page reloads.
  if (reaction && (session.reactionRun || 0) >= 16) {
    throw new E2EReactionWait('Send a Signal message before adding more encrypted reactions.');
  }
  if (reaction) {
    await _e2eSessFp(session);
    if (!E2E.keyReady || !E2E.trustStore[nick]?.fingerprint || E2E.trustStore[nick].keyChanged ||
        _e2eSessPinMismatch(nick,session) !== false) throw new Error('Encrypted reaction session unavailable');
    if (session.x3dhPending && (typeof hasEchoedSignalMessage !== 'function' || !await hasEchoedSignalMessage(nick,session))) {
      throw new E2EReactionWait(session.Ns ? 'Wait for IRC to confirm your first Signal message or for your contact to reply, then try the reaction again.' :
        'Send a Signal message in this chat first, then try the reaction again.');
    }
  }

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
  const boundIdentities = sessionIdentityAD(session);
  if (reaction && !boundIdentities) throw new Error('Encrypted reaction identity unavailable');
  const identAD = reaction && boundIdentities ? concat(boundIdentities, E2E_REACTION_AD) : boundIdentities;
  const ct = await messageEncrypt(mk, new TextEncoder().encode(plaintext), header, identAD);
  const envelope = {h:{d:header.dh,p:header.pn,n:header.n},c:bytesToBase64(ct)};
  // Bind each sibling echo to the exact ciphertext our account authorized.
  // These hashes live inside the sealed session and do not change the IRC wire.
  if (!reaction) session.sentDigests = [...(session.sentDigests || []).slice(1-E2E_MAX_SKIP),
    [header.dh,header.n,await _e2eSentDigest(envelope)]];
  session.reactionRun = reaction ? (session.reactionRun || 0) + 1 : 0;
  if (!E2E.keyReady || _e2eBootStale(generation)) throw new Error('Encrypted chats were locked while preparing the message');
  if (canCommit && !canCommit()) throw new Error('Queued Signal message is no longer ready to send');
  await saveSession(nick, session, { snd: true });

  return envelope;
}

async function ratchetDecrypt(nick, envelope, useAlt = false, reaction = false, liveReceive = false) {
  // Serialise with the send path (and other decrypts) per nick — see _withRatchetLock.
  return _withRatchetLock(_e2eK(nick), () => _ratchetDecryptInner(_e2eK(nick), envelope, {useAlt,reaction,liveReceive}));
}

async function _ratchetDecryptInner(nick, envelope, {useAlt = false, reaction = false, liveReceive = false, candidate = null, restartBase = null, create = false,
    historyCurrent = null, historyPast = false, historySave = null, conflictsLeft = 3} = {}) {
  // L2: null-check session BEFORE any property access
  // useAlt: decrypt with the glare-loser's responder session held aside (not installed).
  const live = restartBase?.restartPrev || candidate || (useAlt ? E2E._glareAlt?.[nick] : E2E.dmSessions[nick]);
  if (!live) throw new Error(`No ratchet session with ${nick} — key exchange needed`);
  if (live._unusable) throw new Error(live._unusable);
  const gen = E2E._lockGen;
  if (reaction) {
    await _e2eSessFp(live);
    if (!E2E.keyReady || _e2eSessPinMismatch(nick, live) !== false) throw new Error('Encrypted reaction session unavailable');
  }
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
  const boundIdentities = sessionIdentityAD(session);
  if (reaction && !boundIdentities) throw new Error('Encrypted reaction identity unavailable');
  const identAD = reaction && boundIdentities ? concat(boundIdentities, E2E_REACTION_AD) : boundIdentities;

  const skipKey = `${nick}/${header.dh}/${header.n}`;
  const tombstone = E2E._sessionTombstones.get(nick);
  const commit = async (mk) => {
    if (!E2E.keyReady || _e2eBootStale(gen)) throw new Error('Encrypted chats were locked while opening the message');
    if (historyCurrent && !historyCurrent()) throw new Error('Signal history changed while opening the message');
    if (E2E._sessionTombstones.get(nick) !== tombstone) throw new Error('Signal session was closed');
    if (restartBase && (!(live.until > Date.now()) || E2E.dmSessions[nick] !== restartBase)) throw new Error('Previous Signal session expired');
    // First authenticated message from the peer: they have our X3DH header, stop resending it.
    const confirmed = !!session.x3dhPending;
    if (confirmed) {
      delete session.x3dhPending;
      delete session.restartPrev;
    }
    if (restartBase) {
      delete session.CKs;
      delete session.recent;
    } else if (mk) _e2eNoteRecent(session, skipKey, mk);
    if (historySave) { historySave(session); return; }
    if (useAlt) {
      // Only an authenticated ordinary message can open this short window.
      // Later gestures can advance the alternate receive chain within it.
      const until=candidate && !reaction ? Date.now()+E2E_RESTART_RECEIVE_MS : _e2eReactionAltExpiry.get(live);
      if (until) _e2eReactionAltExpiry.set(session,until);
      (E2E._glareAlt ||= Object.create(null))[nick] = session;
    }
    else if (restartBase) {
      const activeSession = { ...restartBase, restartPrev:session };
      E2E.dmSessions[nick] = activeSession;
      await _e2eWriteDeviceSession(nick, activeSession);
      if (_e2eBootStale(gen) || !E2E.keyReady || E2E.dmSessions[nick] !== activeSession) throw new Error('Signal session changed');
    } else {
      try { await saveSession(nick,session,{create,liveReceive:liveReceive && !create && !candidate && !historyCurrent}); }
      catch (error) {
        const winner = E2E.dmSessions[nick];
        const unconfirmed = error instanceof E2ESessionUnconfirmed;
        const trusted = (installed=winner) => E2E.keyReady && !_e2eBootStale(gen) && E2E.dmSessions[nick] === installed &&
          _e2eSameSessionIdentity(winner,session) &&
          !E2E.trustStore[nick]?.keyChanged && _e2eSessPinMismatch(nick,winner) === false &&
          E2E.state?.dm?.[nick]?.on !== 0 && (!historyCurrent || historyCurrent());
        if (!(unconfirmed || error instanceof E2ESessionConflict) || !mk || !trusted()) throw error;
        if (winner.startEph !== session.startEph) {
          if (!winner.x3dhPending || winner.restartPrev?.startEph !== session.startEph || !(winner.restartPrev.until > Date.now())) throw error;
          await _ratchetDecryptInner(nick,envelope,{reaction,restartBase:winner,historyCurrent,historyPast});
          return;
        }
        // Two logged-in devices may both open this incoming line. Retain the
        // authenticated message key locally; only one receive transition wins.
        const pastChain = (winner.rgen || 0) > (session.rgen || 0);
        if (unconfirmed) {
          // Preserve the authenticated receive advance locally, including consumed
          // skipped keys. Keep the last confirmed revision and reconcile before
          // sending. Every outbound packet still requires its own successful CAS.
          if (winner !== live) throw error;
          session.epoch = winner.epoch;
          session._storeRevision = winner._storeRevision;
          E2E.dmSessions[nick] = session;
          _e2eMarkMaybeMoved(nick);
          await _e2eWriteDeviceSession(nick,session);
          if (!trusted(session)) throw error;
        } else if (!pastChain && (winner.DHr !== header.dh || winner.Nr <= header.n)) {
          if (!conflictsLeft) throw error;
          await _ratchetDecryptInner(nick,envelope,{reaction,liveReceive,historyCurrent,historyPast,conflictsLeft:conflictsLeft-1});
        } else {
          // The committed ratchet has already passed this authenticated message.
          winner.skipped ||= {};
          winner.skippedMeta ||= {};
          for (const [id,key] of Object.entries(session.skipped || {})) {
            if (id === skipKey || winner.recent?.[id] || E2E._consumed?.has(id) || Object.hasOwn(winner.skipped,id)) continue;
            winner.skipped[id] = key;
            if (session.skippedMeta?.[id]) winner.skippedMeta[id] = session.skippedMeta[id];
          }
          delete winner.skipped?.[skipKey];
          delete winner.skippedMeta?.[skipKey];
          _e2eTrimSkipped(winner);
          _e2eNoteRecent(winner,skipKey,mk);
          await _e2eWriteDeviceSession(nick,winner);
          if (!trusted()) throw error;
        }
      }
    }
    _e2eMarkConsumed(skipKey);
    if (confirmed && !restartBase && !useAlt && !_e2eBootStale(gen)) {
      const pending=E2E._pendingOn?.[nick];
      // A real reply can confirm the original session while its automatic
      // migration is waiting for a bundle. Explicit restarts still run.
      if (pending?.migration?.confirmed(E2E.dmSessions[nick])) {
        delete E2E._pendingOn[nick];
        pending.done('ready');
      }
      updateE2EIndicator(_e2eDmNick(nick));
    }
  };
  // r2: another tab of this browser already decrypted this very message (and advanced
  // the shared ratchet): read it with the key it left behind — once per tab, no state
  // change. A replay to the same tab is still refused (consumed).
  // Only for a message another tab decrypted while THIS page was already open (it
  // received the same live line): a page loaded later is shown a re-sent old line as
  // what it is — a replay — exactly as before.
  const rk = session.recent && session.recent[skipKey];
  if (rk && !useAlt && (historyCurrent ? Date.now()-(rk.t || 0) < E2E_RECENT_MS :
      (rk.t || 0) >= E2E._pageStart && !E2E._consumed?.has(skipKey))) {
    try {
      const pt = await messageDecrypt(base64ToBytes(rk.k), ct, header, identAD);
      if (historyCurrent && !historyCurrent()) throw new Error('Signal history changed while opening the message');
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

  if (historyCurrent && (historyPast || (header.dh === session.DHr && header.n < session.Nr))) {
    throw new Error('Signal history message key is no longer available');
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

async function _e2eRatchetKdf(root,ourPrivate,theirPublic) {
  return hkdf(concat(root,await ecdh(ourPrivate,theirPublic)), 'DR-Ratchet-v1', 64);
}

async function dhRatchetStep(session, theirNewDHPub) {
  // Signal spec: when receiving a new DH ratchet pub from peer
  // Step 1: ECDH(our current DHs, their NEW DH pub) → KDF → new RK, CKr
  const ourPriv   = await importPriv(session.DHs.priv);
  const theirPub  = await importPub(theirNewDHPub, 'ECDH');
  const derived   = await _e2eRatchetKdf(base64ToBytes(session.RK),ourPriv,theirPub);
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
  const derived2  = await _e2eRatchetKdf(base64ToBytes(session.RK),newDHs.privateKey,theirPub);
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

  _e2eTrimSkipped(session);
}

function _e2eTrimSkipped(session) {
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

// Version 2 authenticates the network, sender, conversation and timestamp with
// AES-GCM. Version 1 used a separate MAC and is readable only in saved history.
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
function _e2ePskKeyCurrent(name, key, generation) {
  const current = E2E.channelKeys[name];
  const currentGeneration = E2E._chanKeyGen[name];
  if (!current || E2E.chanRemoved[name]) return false;
  // Reconnect may import the same authenticated generation as a new CryptoKey.
  if (generation !== undefined && currentGeneration !== undefined && generation !== currentGeneration) return false;
  return key === current || (_e2ePskIds.has(key) && _e2ePskIds.get(key) === _e2ePskIds.get(current) &&
    _e2ePskScopes.get(key) === _e2ePskScopes.get(current));
}

const _e2ePskScopes = new WeakMap();
const _e2ePskIds = new WeakMap();
const _e2eRecentPskWrites = new Map();
const _e2ePskInventoryChecks = new Map();
async function _e2eRecordPskKey(key,raw) {
  _e2ePskIds.set(key,bytesToBase64(new Uint8Array(await crypto.subtle.digest('SHA-256',raw))));
}
function _e2ePskNetworkName(cid) {
  const snapshot = typeof networks === 'undefined' ? null : networks.find(n => n.config.id === cid);
  const advertised = _e2eIsupport(cid)?.network || snapshot?.network_name;
  return _e2eK([...String(advertised || '').replace(/[\x00-\x1f\x7f-\x9f]/g,'')].slice(0,64).join(''));
}
function _e2ePskScopeAvailable(slot,scope) {
  const cid = _e2eDmScope(slot)?.[1];
  return !!cid && !Object.entries(E2E.channelKeys).some(([other,key])=>
    _e2ePskScopes.get(key) === scope && _e2eDmScope(other)?.[1] !== cid);
}
function _e2ePskSendBinding(slot,cid,key) {
  const connection = _e2eDmScope(slot)?.[1];
  if (connection && connection !== _e2eK(cid)) return null;
  const scope = _e2ePskScopes.get(key);
  if (scope) return _e2ePskScopeAvailable(slot,scope) ? ['shared',scope] : null;
  const name = _e2ePskNetworkName(cid);
  return name ? ['network',name] : null;
}
function _e2ePskConversation(name, sender, recipient, cid, network) {
  if (!cid || !sender || !network) return null;
  const cm = _e2eRecvCaseMap(cid), from = _e2eRecvFold(sender,cm);
  if (_e2eIsChan(name)) return JSON.stringify([network,'channel',_e2eRecvFold(name,cm),from]);
  if (!recipient) return null;
  return JSON.stringify([network,'dm',from,_e2eRecvFold(recipient,cm)]);
}
function _e2ePskParams(nonce, scope, ts, reaction) {
  return {name:'AES-GCM',iv:nonce,additionalData:new TextEncoder().encode(
    JSON.stringify(['CryptIRC-PSK-v2',reaction,scope,ts]))};
}

async function channelEncrypt(slot, plaintext, sender, reaction = false, cid = null) {
  const key = E2E.channelKeys[slot];
  const name = _e2eDmNick(slot);
  const network = _e2ePskSendBinding(slot,cid,key);
  const scope = _e2ePskConversation(name,sender,name,cid,network);
  if (!key || !scope) throw new Error('Shared-key network scope is unavailable. Share a new key code for this network.');
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const t = Math.floor(Date.now()/1000);
  const ct = await crypto.subtle.encrypt(_e2ePskParams(nonce,scope,t,reaction),key,new TextEncoder().encode(plaintext));
  return (reaction ? E2E_REACTION_PSK_PREFIX : E2E_CHAN_PREFIX) +
    btoa(JSON.stringify({v:2,n:bytesToBase64(nonce),c:bytesToBase64(new Uint8Array(ct)),t,...(network[0]==='shared'?{a:1}:{})}));
}
async function channelDecryptEx(slot, wire, sender = null, opts = {}) {
  const reaction = !!opts.reaction;
  const prefix = reaction ? E2E_REACTION_PSK_PREFIX : E2E_CHAN_PREFIX;
  if (typeof wire !== 'string' || wire.length > 8192 || !wire.startsWith(prefix) || !sender) return null;
  const generation = E2E._lockGen, keyGeneration = E2E._chanKeyGen[slot];
  const key = E2E.channelKeys[slot], name = _e2eDmNick(slot);
  const scoped = _e2eDmScope(slot);
  if (!key || (scoped && scoped[1] !== _e2eK(opts.conn_id))) return null;
  let env, plaintext, scope;
  const refused = {bad:true,verified:false};
  try {
    env = JSON.parse(atob(wire.slice(prefix.length)));
    if (!env || typeof env.n !== 'string' || typeof env.c !== 'string') return null;
    const nonce = base64ToBytes(env.n), ct = base64ToBytes(env.c);
    if (nonce.length !== 12 || ct.length < 16) return null;
    if (env.v === 2) {
      if (!Number.isSafeInteger(env.t) || env.t < 0 || (env.a !== undefined && env.a !== 1)) return refused;
      const cid = opts.conn_id;
      const bindings = [];
      if (env.a === 1) {
        const shared = _e2ePskScopes.get(key);
        if (!shared || (!opts.history && !_e2ePskScopeAvailable(slot,shared))) return {authFailed:true};
        bindings.push(['shared',shared]);
      } else {
        if (opts.history && opts.network) bindings.push(['network',_e2eK(opts.network)]);
        const advertised = _e2ePskNetworkName(cid);
        if (advertised) bindings.push(['network',advertised]);
        if (opts.history) {
          const config = typeof networks === 'undefined' ? null : networks.find(n=>n.config.id===cid)?.config;
          if (config?.server) bindings.push(['server',_e2eK(config.server).replace(/\.$/,''),Number(config.port)]);
        }
      }
      const scopes = new Set(bindings.map(binding=>_e2ePskConversation(name,sender,opts.recipient,cid,binding)).filter(Boolean));
      if (!scopes.size) return {pending:true};
      for (const candidate of scopes) {
        try {
          plaintext = await crypto.subtle.decrypt(_e2ePskParams(nonce,candidate,env.t,reaction),key,ct);
          scope = candidate;
          break;
        } catch (_) {}
      }
      if (!scope) return {authFailed:true};
    } else {
      // Only authenticated older messages can be opened from scrollback. Live messages
      // require the current format with an authenticated network and conversation.
      if (!opts.history && env.v === 1) return {...refused,oldFormat:true};
      if (!opts.history || reaction || env.v !== 1 || typeof env.m !== 'string' ||
          typeof env.i !== 'string' || !Number.isSafeInteger(env.t)) return refused;
      const got = base64ToBytes(env.m);
      const binding = _e2ePskBinding(name,sender), legacy = _e2ePskBinding(name,sender,true);
      const matches = async b=>_e2eCmpBytes(got,await _e2ePskMac(key,b,env)) === 0;
      if (!await matches(binding) && (legacy === binding || !await matches(legacy))) return refused;
      plaintext = await crypto.subtle.decrypt({name:'AES-GCM',iv:nonce},key,ct);
    }
  } catch (_) { return null; }
  if (_e2eBootStale(generation) || !_e2ePskKeyCurrent(slot,key,keyGeneration)) return null;
  const r = {pt:new TextDecoder().decode(plaintext),verified:env.v===2,legacy:env.v===1,bad:false,replay:false,old:false,ts:env.t};
  if (opts.live && scope) {
    r.old = Math.abs(Date.now()/1000-env.t) > E2E_PSK_OLD_SECS;
    if (!opts.self) {
      let seen = E2E._pskSeen.get(scope);
      if (!seen) { seen = new Map(); E2E._pskSeen.set(scope,seen); }
      if (E2E._pskSeen.size > 512) E2E._pskSeen.delete(E2E._pskSeen.keys().next().value);
      const id = bytesToBase64(base64ToBytes(env.n));
      if (seen.has(id)) r.replay = true;
      else { seen.set(id,env.t); if (seen.size > 2000) seen.delete(seen.keys().next().value); }
    }
  }
  return r;
}
function _e2ePskShown(r, sender) {
  if (r.pending) return '🔐 Waiting for the IRC network or recipient before opening this shared-key message.';
  if (r.authFailed) return '🔐 Shared-key message could not be opened. Check the shared key and IRC conversation used when it was sent.';
  if (r.oldFormat) return '🔐 This shared-key message uses an older format. Ask the sender to update CryptIRC and resend it.';
  if (r.bad) return `🔐 [encrypted message REFUSED — it was not sent by ${sender || 'this sender'} here (re-sent under another name or in another channel)]`;
  if (r.legacy) return '⚠️ (legacy encrypted history) ' + r.pt;
  if (r.old) { let when = ''; try { when = new Date(r.ts * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC'; } catch (_) {} return `⚠️ (sent ${when} — delayed or replayed) ` + r.pt; }
  return r.pt;
}
// String API kept for app.js (history / echo paths): plaintext with a marker, or null.
async function channelDecrypt(channel, wireText, sender = null, opts = {}) {
  const r = await channelDecryptEx(channel, wireText, sender,opts);
  return r ? _e2ePskShown(r, sender) : null;
}

async function generateChannelKey() {
  const raw   = crypto.getRandomValues(new Uint8Array(32));
  const key   = await crypto.subtle.importKey('raw', raw, { name:'AES-GCM' }, true, ['encrypt','decrypt']);
  const words = bytesToMnemonic(raw);
  return { keyWords: words.join(' '), keyB64: bytesToBase64(raw), key };
}

function _e2ePskShareText(key,words) {
  const scope = _e2ePskScopes.get(key);
  return scope ? words + ' scope:' + scope : words;
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
  const scope = _e2ePskScopes.get(key);
  const k = _e2eK(channel);
  const generation = E2E._lockGen;
  const persist = async()=>{
    if (scope && !_e2ePskScopeAvailable(k,scope)) throw new Error('This shared-key code belongs to another IRC connection.');
    const raw = base64ToBytes(keyB64);
    try { await _e2eRecordPskKey(key,raw); }
    finally { raw.fill(0); }
    if (!E2E.keyReady || _e2eBootStale(generation)) throw new Error('Unlock encryption and try again.');
    const g = _e2eKnownChanGen(k) + 1;
    const bytes = new TextEncoder().encode(JSON.stringify({k:keyB64,g,...(scope?{scope}:{})}));
    let blob;
    try { blob = await aesEncryptBlob(bytes,_e2eCtxChan(k)); }
    finally { bytes.fill(0); }
    if (!E2E.keyReady || _e2eBootStale(generation)) throw new Error('Unlock encryption and try again.');
    E2E.channelKeys[k] = key;
    E2E._chanGen[k] = g;
    E2E._chanKeyGen[k] = g;
    delete E2E.chanRemoved[k];
    _e2eRecentPskWrites.delete(k);
    _e2eRecentPskWrites.set(k,{generation:g,id:_e2ePskIds.get(key),scope,until:Date.now()+60_000});
    if (_e2eRecentPskWrites.size > 64) _e2eRecentPskWrites.delete(_e2eRecentPskWrites.keys().next().value);
    _e2eWs({ type:'e2e_store_channel_key', channel:k, blob });
    const dev = _e2eDev(); dev.gen[k] = g; _e2eDevSave();
    _e2eStateSetChan(k, true, g);
  };
  return _e2eXLock('psk:'+k,()=>scope?_e2eXLock('psk-scope:'+scope,persist):persist());
}

function _e2eAnnounceMissingPsk(slot) {
  _e2eSys(slot, `⚠️ The encryption key for ${slot} was removed on another device (or by the server). Messages to ${slot} are BLOCKED here — run /encrypt off to send unencrypted, or re-add the key.`);
  updateE2EIndicator(slot);
}

function _e2eRecheckWrittenPsk(slot) {
  const write = _e2eRecentPskWrites.get(slot);
  const generation = E2E._lockGen;
  const sameKey = () => {
    const key = E2E.channelKeys[slot];
    return E2E.keyReady && !_e2eBootStale(generation) && !!key && E2E._chanKeyGen[slot] === write?.generation &&
      _e2ePskIds.get(key) === write.id && _e2ePskScopes.get(key) === write.scope;
  };
  if (!write || write.until <= Date.now() || !sameKey()) return false;
  const check = {write,revision:0,promise:null};
  _e2ePskInventoryChecks.set(slot,check);
  const current = () => _e2ePskInventoryChecks.get(slot) === check && sameKey();
  check.promise = (async()=>{
    // A previously requested inventory can omit an immediately subsequent
    // local write. The scoped read follows the queued write on this socket.
    for (let attempt=0; attempt<3 && current(); attempt++) {
      const revision = check.revision;
      const req = crypto.randomUUID();
      const reply = await _e2eReq({type:'e2e_load_channel_key',channel:slot,req},'e2e_channel_key',4000,
        event=>event.req===req && _e2eK(event.channel)===slot,1,current);
      if (!current()) return;
      if (revision !== check.revision) continue;
      if (!reply) return;
      if (!reply.blob) {
        // A delayed key update from before this confirmed deletion cannot
        // restore the deleted generation.
        E2E.chanRemoved[slot] = {confirmedGeneration:write.generation};
        return;
      }
      const record = await _e2eDecodeChanBlob(reply.blob,slot);
      let id;
      try { id = bytesToBase64(new Uint8Array(await crypto.subtle.digest('SHA-256',record.raw))); }
      finally { record.raw.fill(0); }
      if (!current()) return;
      if (revision !== check.revision) continue;
      if (record.g===write.generation && id===write.id && (record.scope||null)===(write.scope||null)) {
        delete E2E.chanRemoved[slot];
      }
      return;
    }
  })().catch(()=>{}).finally(()=>{
    if (_e2ePskInventoryChecks.get(slot) !== check) return;
    _e2ePskInventoryChecks.delete(slot);
    if (sameKey() && E2E.chanRemoved[slot]) _e2eAnnounceMissingPsk(slot);
    else if (sameKey()) updateE2EIndicator(slot);
  });
  return true;
}

async function _e2eDeleteSlot(msg, stillPending = null) {
  const req = crypto.randomUUID();
  const gen = E2E._lockGen;
  // Retrying a delete could remove a replacement key saved after a lost reply.
  const event = await _e2eReq({ ...msg, req, v: E2E_STORAGE_VERSION }, 'e2e_key_deleted', 6000, e => e.req === req, 0, stillPending);
  return !!event?.ok && !_e2eBootStale(gen);
}

// A retirement can keep an already-correct replacement. Returns its sealed
// blob, true after confirmed deletion, or false if neither could be verified.
async function _e2eCloseSessionSlot(key, partner, gen, disposition = null, allowed = null) {
  const user = _e2eUser();
  const canonical = partner === key;
  const current = () => E2E.keyReady && !_e2eBootStale(gen) && _e2eUser() === user && (!allowed || allowed());
  try {
    const state = await _e2eRequestSession(partner,canonical,current);
    if (!state || !current() || (canonical && state.blob!==null && typeof state.blob!=='string')) return false;
    let blob = state.blob;
    let accountFloor = canonical ? await _e2eReadSessionFloor(state.floor_blob,user) : null;
    if (canonical && !accountFloor) return false;
    let changedRevisions=0, advancedFloors=0;
    while (changedRevisions<4 && advancedFloors<64 && current()) {
      let observed = 0;
      if (blob) {
        const bytes = await aesDecryptBlob(blob,_e2eCtxSession(partner));
        try {
          const session = JSON.parse(new TextDecoder().decode(bytes));
          if (!session?.RK || !_e2eSessionScopeMatches(key,session)) return false;
          observed = session.epoch ?? 0;
          if (!Number.isSafeInteger(observed) || observed<0) return false;
          if (disposition) {
            const decision = await disposition(session);
            if (!current()) return false;
            if (decision==='keep') return blob;
            if (decision!=='close') return false;
          }
        } finally { bytes.fill(0); }
      }
      const expect = blob ? await _e2eSha256Hex(blob) : '';
      if (!current()) return false;
      // Keep the authenticated upper bound even if the close succeeds and its
      // acknowledgment or this page is lost. The final tombstone exceeds it.
      const dev = _e2eDev();
      const floor = Math.max(observed,E2E.dmSessions[key]?.epoch || 0,E2E._sessionEpoch[key] || 0,
        dev.ep[key] || 0,E2E._sessionTombstones.get(key) || 0,E2E.state?.dm?.[key]?.closedEpoch || 0,_e2ePendingCloseFloor(key),
        !blob && canonical ? accountFloor.epoch : 0);
      if (floor && _e2ePendingCloseFloor(key,floor)<floor) return false;
      // Include this device's known high-water mark in case a backup
      // restored an older authenticated row. Absent or archived slots
      // cannot advance the account floor.
      const retire = canonical && blob ? floor + 1 : 0;
      if (!Number.isSafeInteger(retire) || retire >= Number.MAX_SAFE_INTEGER) return false;
      const floorWrite = retire > (accountFloor?.epoch || 0) ? await _e2eSealSessionFloor(retire,user) : null;
      if (!current()) return false;
      const req = crypto.randomUUID();
      const keys = E2E.identityKeys;
      const reply = await _e2eReq({type:'e2e_close_session',partner,expect,req,v:E2E_STORAGE_VERSION,id_hash:_e2eIdentityRevisions.get(keys),
        ...(canonical ? {floor_expect:accountFloor.digest} : {}),...(floorWrite ? {floor_blob:floorWrite} : {})},
        'e2e_session_closed',6000,event=>event.req===req && event.partner===partner,1,current);
      if (!current()) return false;
      if (reply?.identity_changed) { _e2eRefreshChangedIdentity(keys); return false; }
      if (reply?.ok) {
        // Legacy aliases are closed before the canonical slot. They can still
        // contribute to the final tombstone without changing live adoption.
        if (canonical) {
          // Closing an already absent slot is idempotent. The next creator is
          // entitled to use accountFloor + 1 even if the off setting arrives later.
          const marker = blob ? retire : floor;
          E2E._sessionTombstones.set(key,marker);
          _e2eRememberSessionEpoch(key,marker);
          if ((_e2eLsGet(_e2eDevKey())?.ep?.[key] || 0)>=floor) _e2ePendingCloseFloor(key,null);
        }
        return true;
      }
      if (typeof reply?.conflict !== 'string') return false;
      const sameRevision = blob===reply.conflict;
      let advancedFloor = false;
      if (canonical) {
        const newer = await _e2eReadSessionFloor(reply.floor_blob,user);
        if (!newer || newer.epoch < accountFloor.epoch) return false;
        advancedFloor = newer.epoch>accountFloor.epoch;
        accountFloor = newer;
      }
      // Another contact's acknowledged close advances the shared floor while
      // leaving this contact's revision intact. It can be retried separately.
      if (sameRevision && advancedFloor) advancedFloors++;
      else changedRevisions++;
      blob = reply.conflict;
    }
  } catch (_) { /* Keep the current protection if the stored session cannot be authenticated. */ }
  return false;
}

async function _e2eReadChannelInventory(current) {
  const deadline = Date.now()+6000;
  while (current() && Date.now()<deadline) {
    if (_wsReady()) {
      const socket=ws, req=crypto.randomUUID();
      const pending=()=>current() && _wsReady() && ws===socket;
      const list=await _e2eReq({type:'e2e_list_channel_keys',req},'e2e_channel_list',1500,e=>e.req===req,0,pending);
      if (pending() && Array.isArray(list?.channels)) return {list,socket};
    }
    await new Promise(resolve=>setTimeout(resolve,150));
  }
  return null;
}

async function removeChannelKey(k, storedNames, scopedOff = false, stillPending = null) {
  const generation = E2E._lockGen;
  const current = () => !_e2eBootStale(generation) && (!stillPending || stillPending());
  const remove = async () => {
    if (!current()) return false;
    const channels = scopedOff ? [k] : new Set([k,...storedNames.filter(name=>_e2eK(name)===k)]);
    for (const channel of channels) {
      if (await _e2eDeleteSlot({type:'e2e_delete_channel_key',channel,...(scopedOff?{scoped_off:true}:{})},stillPending)) continue;
      if (!scopedOff || !current()) return false;
      // An acknowledged state snapshot can confirm a scoped disable whose reply was lost.
      const updated = stillPending ? (await _e2eReadChannelInventory(current))?.list :
        await _e2eReq({type:'e2e_load_keyring'},'e2e_keyring');
      if (!current() || !updated?.disabled_channels?.includes(k) ||
          updated.channels?.some(name=>_e2eK(name)===k)) return false;
    }
    if (_e2eBootStale(generation)) return false;
    delete E2E.channelKeys[k];
    delete E2E._chanKeyGen[k];
    delete E2E.chanRemoved[k];
    if (scopedOff || E2E.state?.ch[k]) _e2eStateSetChan(k, false, E2E.state?.ch[k]?.g,scopedOff);
    if (E2E._serverHints) {
      E2E._serverHints.channels = E2E._serverHints.channels.filter(name => _e2eK(name) !== k);
      if (scopedOff) E2E._serverHints.disabledPsk = [...new Set([...(E2E._serverHints.disabledPsk || []),k])];
    }
    const hints = _e2eHints();
    _e2eLsSet(_e2eHintKey(), {dm:hints.dm,ch:hints.ch.filter(name => _e2eK(name) !== k)});
    return true;
  };
  return _e2eXLock('psk:'+k,remove);
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
  if (o.scope !== undefined && !/^[a-f0-9]{32}$/.test(o.scope)) throw new Error('bad shared-key scope');
  return { raw, g: o.g, scope:o.scope, legacy: false };
}

// ─── Session persistence ──────────────────────────────────────────────────────

async function _e2eWriteDeviceSession(nick,session) {
  const gen = E2E._lockGen;
  try {
    const blob = await aesEncryptBlob(new TextEncoder().encode(JSON.stringify(session)), _e2eDevSlot(nick));
    if (!_e2eBootStale(gen)) await _e2eDevSessPut(nick, { ep:session.epoch, blob, ...(session.restartPrev ? {restart:1} : {}) });
  } catch (e) { console.warn('[E2E] device session copy not written:', e && e.message); }
}

class E2ESessionConflict extends Error {}
class E2ESessionUnconfirmed extends Error {}
class E2EReactionWait extends Error {}

const E2E_DISABLED_DRAFT_REPAIR = Symbol('Signal disabled on another device');
function _e2eRememberDisabledDraft(key) {
  // A discarded draft may release this marker. An independent session repair
  // must still go through its normal recovery, even if its revision is empty.
  if (!E2E._sessionSyncRepair.has(key)) E2E._sessionSyncRepair.set(key,E2E_DISABLED_DRAFT_REPAIR);
}

function e2eDiscardDisabledDraft(target,connId) {
  if (!E2E.keyReady) return;
  const nick = _e2eCanon(target,connId);
  if (nick === null || _e2eIsChan(nick)) return;
  const key = _e2eDmKey(nick,connId);
  if (E2E.state?.dm?.[key]?.on===0 && !E2E.dmSessions[key] && E2E._sessionSyncRepair.get(key)===E2E_DISABLED_DRAFT_REPAIR)
    E2E._sessionSyncRepair.delete(key);
}

async function saveSession(nick, session, opts = null) {
  nick = _e2eK(nick);
  const generation = E2E._lockGen, user = _e2eUser(), identity = E2E.identityKeys;
  const serverGeneration = E2E._serverLockGen;
  const current = () => E2E.keyReady && !_e2eBootStale(generation) && _e2eUser() === user && E2E.identityKeys === identity;
  if (!current()) throw new Error('Unlock encrypted chats before updating this session.');
  if (!await _e2eUsesCurrentIdentity(session) || !current())
    throw new E2ESessionUnconfirmed('Your encryption identity changed. Use /encrypt restart to establish a new session.');
  const tombstone = E2E._sessionTombstones.get(nick);
  const closedEpoch = Math.max(tombstone ?? -1,E2E.state?.dm?.[nick]?.closedEpoch ?? -1);
  if (Number.isInteger(session.epoch) && session.epoch <= closedEpoch) {
    throw new Error('The Signal session was closed while this message was being processed.');
  }
  // SECURITY chokepoint: never persist a PEER session under the reserved internal
  // namespace ('__spk__' / '__otpk__<id>' / '__state__'). Test the SERVER-SANITIZED form.
  if (_e2eReservedNamespace(_e2eDmNick(nick))) {
    console.warn('[E2E] refusing to store peer session under reserved name:', nick);
    throw new Error('Invalid encrypted conversation.');
  }
  // #12 / MEDIUM (epoch rollback): stamp a per-nick MONOTONIC epoch that survives
  // reloads — it continues from the highest epoch this device has seen (the loaded
  // blob's and the device high-water mark), so a stored blob from an earlier page can
  // never out-rank a newer session, and an older blob is refused on load.
  const dev = _e2eDev();
  const previous = E2E.dmSessions[nick];
  const { skipped, skippedMeta, recent, restartPrev, _storeRevision, ...persist } = session;
  const expect = opts?.replaceRevision ?? _storeRevision ?? previous?._storeRevision ?? '';
  const mayPersist = () => _e2eUser() === user && !E2E._serverLocked && E2E._serverLockGen === serverGeneration &&
    E2E._sessionTombstones.get(nick) === tombstone;
  const stillCurrent = () => current() && mayPersist() && E2E.dmSessions[nick] === previous;
  // A verified receive can advance the old ratchet while a manual restart is
  // waiting for its bundle. Only that exact local commit may move its CAS base.
  const restart = opts?.liveReceive && E2E._pendingOn?.[nick];
  const fingerprint = restart?.restart && E2E.trustStore[nick]?.fingerprint;
  const sameRestart = () => fingerprint && !restart.reopen && E2E._pendingOn?.[nick]===restart &&
    !!expect && previous?._storeRevision===expect && restart.replacementRevision===expect &&
    !!restart.restartFrom && _e2eRestartFrom(previous)===restart.restartFrom && _e2eRestartFrom(session)===restart.restartFrom &&
    _e2eSameSessionIdentity(previous,session) && E2E.state?.dm?.[nick]?.on===1 &&
    !E2E._sessionSyncRepair.has(nick) && !E2E.trustStore[nick]?.keyChanged &&
    E2E.trustStore[nick]?.fingerprint===fingerprint && _e2eSessPinIs(session,fingerprint)===true;
  const confirmFailure = 'Could not confirm the encrypted session update. Try again when connected.';
  const establishing = opts?.create && !opts?.snd;
  // Restarting from a different device can replace a ratchet whose identity
  // is retired. Its chains are unusable, but its authenticated generation
  // still orders this replacement against every device that saw the old one.
  let priorEpoch = previous?._storeRevision === expect ? previous.epoch || 0 : 0;
  let accountFloor = null;
  if (establishing && (!expect || previous?._storeRevision !== expect)) {
    const stored = await _e2eRequestSession(nick,!expect,mayPersist);
    if (!stillCurrent() || !stored || (stored.blob!==null && typeof stored.blob!=='string'))
      throw new E2ESessionUnconfirmed(confirmFailure);
    if (!expect) {
      accountFloor = await _e2eReadSessionFloor(stored.floor_blob,user);
      if (!accountFloor) throw new E2ESessionUnconfirmed(confirmFailure);
    } else if (stored.blob && await _e2eSha256Hex(stored.blob)===expect) {
      const bytes = await aesDecryptBlob(stored.blob,_e2eCtxSession(nick));
      try {
        const prior = JSON.parse(new TextDecoder().decode(bytes));
        priorEpoch = prior?.epoch ?? 0;
        if (!prior?.RK || !_e2eSessionScopeMatches(nick,prior) || !Number.isSafeInteger(priorEpoch) || priorEpoch<0)
          throw new E2ESessionUnconfirmed(confirmFailure);
      } finally { bytes.fill(0); }
    }
  }
  let epoch, revision, reply;
  for (let attempt=0; attempt<64; attempt++) {
    if (!stillCurrent()) throw new Error('Encrypted chats changed while updating this session.');
    const pendingClose = !expect ? _e2ePendingCloseFloor(nick) : 0;
    epoch = Math.max(E2E._sessionEpoch[nick] || 0,dev.ep[nick] || 0,session.epoch || 0,
      priorEpoch,closedEpoch,pendingClose,accountFloor?.epoch || 0) + 1;
    if (!Number.isSafeInteger(epoch)) throw new E2ESessionUnconfirmed(confirmFailure);
    const bytes = new TextEncoder().encode(JSON.stringify({ ...persist, epoch, skipped: {} }));
    let blob;
    try { blob = await aesEncryptBlob(bytes, _e2eCtxSession(nick)); }
    finally { bytes.fill(0); }
    revision = await _e2eSha256Hex(blob);
    const req = crypto.randomUUID();
    reply = await _e2eReq({type:'e2e_commit_session',partner:nick,blob,expect,req,dv:_e2eDeviceId(),id_hash:_e2eIdentityRevisions.get(identity),
      snd:!!opts?.snd,create:!!opts?.create,...(opts?.liveReceive ? {live_receive:true} : {}),
      ...(accountFloor ? {floor_expect:accountFloor.digest} : {})},
      'e2e_session_committed',4000,event=>event.req===req && event.partner===nick,2,mayPersist);
    if (!stillCurrent()) throw new Error('Encrypted chats changed while updating this session.');
    if (reply?.identity_changed) {
      _e2eRefreshChangedIdentity(identity);
      throw new E2ESessionUnconfirmed('Your encryption identity changed on another device. CryptIRC is reloading it. Your message was held.');
    }
    if ((!reply || reply.storage_retry) && sameRestart()) {
      const stored = await _e2eRequestSession(nick,false,()=>stillCurrent() && sameRestart());
      if (!stillCurrent()) throw new E2ESessionUnconfirmed(confirmFailure);
      if (sameRestart() && stored?.blob===blob) reply = {ok:true};
    }
    if (!reply || reply.storage_retry) throw new E2ESessionUnconfirmed(confirmFailure);
    // An unrelated close can raise the account floor between reading and
    // creating an absent session. Re-seal this same candidate above that bound.
    // A real active-session conflict still follows the pin-checked adoption path.
    if (!accountFloor || reply.ok || reply.conflict!=='' || reply.floor_blob===undefined) break;
    const newer = await _e2eReadSessionFloor(reply.floor_blob,user);
    if (!newer || newer.epoch<=accountFloor.epoch || attempt===63)
      throw new E2ESessionUnconfirmed(confirmFailure);
    accountFloor = newer;
  }
  if (!reply?.ok) {
    if (reply?.conflict && await _e2eInstallStoredInner(nick,reply.conflict,null,{hint:true,conflict:true}) !== null) {
      if (current() && mayPersist()) E2E._sessionSyncRepair.delete(nick);
      throw new E2ESessionConflict('Another device updated this Signal session.');
    }
    if (typeof reply?.conflict === 'string') {
      const revision = reply.conflict ? await _e2eSha256Hex(reply.conflict) : '';
      if (current() && mayPersist()) E2E._sessionSyncRepair.set(nick,revision);
    }
    throw new Error(reply?.conflict !== undefined ? 'Restart this Signal session before sending.' : 'Could not confirm the encrypted session update. Try again when connected.');
  }
  if (E2E._sessionSyncRepair.has(nick) && previous?.startEph !== session.startEph) {
    E2E._sessionSyncRepair.delete(nick);
    delete E2E._moved?.[nick];
    delete E2E._maybeMoved?.[nick];
  }
  // Release ciphertext only after this exact transition wins the account-wide
  // compare-and-swap. A losing browser never installs its candidate or emits it.
  session.epoch = epoch;
  session._storeRevision = revision;
  if (sameRestart()) restart.replacementRevision = revision;
  _e2eRememberSessionEpoch(nick,epoch);
  const closing = _e2ePendingCloseFloor(nick);
  if (closing && epoch>closing && (_e2eLsGet(_e2eDevKey())?.ep?.[nick] || 0)>=epoch) _e2ePendingCloseFloor(nick,null);
  _e2eRememberFirstAdoption(previous,session,false);
  E2E.dmSessions[nick] = session;
  await _e2eWriteDeviceSession(nick,session);
  if (!current()) throw new Error('Encrypted chats were locked while updating this session.');
}
function _e2eForgetSessionRuntime(k) {
  _e2eCrossedStarts.delete(k);
  for (const [digest,r] of _e2eLiveReceipts) if (r.peer===k) _e2eLiveReceipts.delete(digest);
  _e2eInitialEchoes.delete(k);
  _e2eForgetEchoKeys(k);
  delete E2E.dmSessions[k];
  _e2ePriorHistorySessions.delete(k);
  E2E._sessionSyncRepair.delete(k);
  if (E2E._glareAlt) delete E2E._glareAlt[k];
  if (E2E._moved) delete E2E._moved[k];
  if (E2E._maybeMoved) delete E2E._maybeMoved[k];
}

// Drop the confirmed-closed session from memory and every tab of this browser.
async function _e2eDropSession(k) {
  const user = _e2eUser(), serverGeneration = E2E._serverLockGen;
  _e2eForgetSessionRuntime(k);
  const remember = ep => {
    if (_e2eUser() !== user || E2E._serverLockGen !== serverGeneration) return;
    E2E._sessionEpoch[k] = Math.max(E2E._sessionEpoch[k] || 0,ep);
    E2E._sessionTombstones.set(k,Math.max(E2E._sessionTombstones.get(k) || 0,ep));
    const dev = _e2eDev();
    if ((dev.ep[k] || 0) < ep) { dev.ep[k] = ep; _e2eDevSave(); }
  };
  const liveFloor = Math.max(E2E._sessionEpoch[k] || 0,_e2eDev().ep[k] || 0);
  const confirmed = E2E._sessionTombstones.get(k);
  const ep = confirmed !== undefined && confirmed>=liveFloor ? confirmed : liveFloor+1;
  remember(ep);
  const committed = await _e2eDevSessPut(k, { ep, del: 1 });
  if (committed !== undefined) remember(committed);
}

// ─── TOFU / trust ─────────────────────────────────────────────────────────────

// #1: explicit out-of-band confirmation for a BRAND-NEW (first-contact) identity.
// An IRC nick is unauthenticated and the server bridges nick→key-bundle via a global
// connection map, so the first party to grab a peer's nick can offer its own key.
// Never silently auto-pin — force the local user to eyeball the fingerprint and confirm
// it out-of-band before it is pinned and used. Returns true iff the user approves.
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
async function e2eConfirmNewIdentity(nick, fingerprint, opts = null) {
  try {
    const network = opts?.connId && typeof networks !== 'undefined' && networks.find(n => n.config.id === opts.connId);
    const label = network ? ` on ${network.config.label || network.config.server}` : '';
    const discovery = opts?.bridge ? 'This identity was discovered over IRC.\n\n' : '';
    const msg =
      `🔐 New encryption identity for ${nick}${label}\n\n` + discovery +
      `Fingerprint:\n${fingerprint}\n\n` +
      `Anyone can claim this IRC nick. Confirm this fingerprint with ${nick} over a ` +
      `trusted channel (voice/in person) BEFORE accepting.\n\n` +
      `Accept and start encrypting with ${nick}?`;
    return await _e2eAskIdentity(opts?.peerKey || _e2eDmKey(nick, opts?.connId), fingerprint, msg, !!opts?.solicited, opts?.connId);
  } catch (e) { console.warn('[E2E] identity confirmation unavailable:', e); return false; }
}
E2E._idAsk = Object.create(null);       // peer → pending trust question
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
  try { return typeof isIgnored === 'function' && !!isIgnored(_e2eDmNick(k), E2E._senderPfx.get(k) || null); } catch (_) { return false; }
}
// r4 (verifier w3-web N3): session end (auth_failed / sign-out) and vault lock (server or
// this device) close the open identity question and drop the queued ones — as Cancel
// for the caller (nothing pinned), WITHOUT recording a decline. It used to stay over the
// login screen, and the queued questions kept appearing one after another.
function _e2eCloseIdentityQuestions() {
  E2E._idGen++;
  for (const entry of Object.values(E2E._idAsk)) entry.finish?.(null);
  E2E._idAsk = Object.create(null);
  E2E._idDialogClose?.(null);
}
const E2E_BUNDLE_REPLY_MS = 60 * 1000;   // a bundle reply must come ≤60 s after the request went out

function e2eIdentityViewChanged() {
  const view = typeof active !== 'undefined' ? active : null;
  const dm = view && view.target !== 'status' && !_e2eIsChan(view.target) &&
    typeof networks !== 'undefined' && networks.some(n => n.config.id === view.conn_id);
  const nick = dm && _e2eRealTarget(view.target);
  const composer = typeof document !== 'undefined' && document?.getElementById('msg-input');
  const composing = composer && (document.activeElement === composer || composer.value.trim());
  const matches = entry => dm ? entry.cid === view.conn_id &&
    _e2eK(_e2eCanon(nick,view.conn_id) || nick) === _e2eDmNick(entry.key) : entry.solicited || !composing;
  const displayed = E2E._idDisplayed;
  if (displayed && matches(displayed) && E2E._idAsk[displayed.key] === displayed && !displayed.done) return;
  E2E._idDialogClose?.(null);
  const next = Object.values(E2E._idAsk).find(entry => entry.finish && !entry.done && matches(entry));
  if (!next) return;
  E2E._idDisplayed = next;
  void _e2eIdentityDialog(next.msg).then(answer => {
    if (answer !== null) next.finish(answer);
  }, () => next.finish(null));
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
    function done(v) {
      clearTimeout(focusTimer); clearTimeout(acceptTimer);
      document.removeEventListener('keydown', key, true);
      ov.remove();
      if (E2E._idDialogClose === done) { E2E._idDialogClose = null; E2E._idDisplayed = null; }
      resolve(v);
    }
    E2E._idDialogClose = done;
    no.onclick = () => done(false);
    yes.onclick = () => { if (!yes.disabled && Date.now() - opened >= 800) done(true); };
    document.addEventListener('keydown', key, true);
    document.body.appendChild(ov);
    const focusTimer = setTimeout(() => { try { no.focus(); } catch (_) {} }, 0);
    const acceptTimer = setTimeout(() => { yes.disabled = false; yes.style.opacity = ''; }, 800);
  });
}
function _e2eAskIdentity(k, fp, msg, solicited, cid) {
  const useDialog = typeof customConfirm === 'function' && typeof document !== 'undefined' && document?.body;
  cid ||= _e2eDmScope(k)?.[1];
  if (useDialog && !cid) return Promise.resolve(false);
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
  const entry = { key:k, cid, fp, msg, solicited, p:null };
  const run = useDialog ? new Promise(resolve => {
    const timer = setTimeout(() => entry.finish(null), E2E_BUNDLE_REPLY_MS);
    entry.finish = answer => { entry.done = true; clearTimeout(timer); resolve(answer); };
  }) : E2E._idQueue.then(() => gen === E2E._idGen && typeof confirm === 'function' && !!confirm(msg));
  if (!useDialog) E2E._idQueue = run.catch(() => false);
  entry.p = run.catch(() => null).then((ok) => {
    E2E._idWaiting--;
    if (E2E._idAsk[k] === entry) delete E2E._idAsk[k];
    if (gen !== E2E._idGen) return false;
    if (useDialog) e2eIdentityViewChanged();
    if (ok) delete E2E._idDeclined[k]; else if (ok === false) E2E._idDeclined[k] = Date.now();
    return !!ok;
  });
  E2E._idAsk[k] = entry;
  if (useDialog) {
    e2eIdentityViewChanged();
    if (E2E._idDisplayed !== entry && cid) {
      const nick=_e2eDmNick(k);
      sysMsg(cid,_dmTarget(nick),'🔐 Encryption request received. Verify the sender’s Signal identity to read it.','system',
        {e2eSetupAction:'verify',e2eSetupConn:cid,e2eSetupNick:nick});
    }
  }
  return entry.p;
}

function e2eCanReviewIncomingIdentity(connId,target,row) {
  const nick=_e2eRealTarget(target);
  const age=Date.now()-row.ts*1000;
  if(!connId||!_e2eSetupNick(nick,true)||_e2eK(row.from)!==_e2eK(nick)||
      !row._dmHistoryWire?.startsWith(E2E_DM_PREFIX)||row._dmHistoryState==='ready'||
      !(age>=-60000&&age<E2E_HEADER_TTL_MS)||isIgnored(nick,row.prefix)||!e2eCanRecoverSignalHistory(nick)) return false;
  const key=_e2eDmKey(_e2eRecvName(nick,connId),connId);
  if(E2E.trustStore[key]?.fingerprint||E2E.state?.dm?.[key]?.on===0||_e2eSharedKeyConfigured(nick,connId)) return false;
  try { return _e2eEnvelopeOk(JSON.parse(atob(row._dmHistoryWire.slice(E2E_DM_PREFIX.length)))); }
  catch (_) { return false; }
}

async function e2eReviewIncomingIdentity(connId,target) {
  const view=active, generation=E2E._lockGen;
  if(view?.conn_id!==connId||view.target!==target||!_e2eSetupNick(_e2eRealTarget(target),true)) return;
  if(!E2E.keyReady) await e2ePromptDeviceUnlock();
  if(active!==view||_e2eBootStale(generation)||!E2E.keyReady) return;
  const nick=_e2eRealTarget(target), key=_e2eDmKey(_e2eRecvName(nick,connId),connId);
  if(E2E._idAsk[key]) { e2eIdentityViewChanged(); return; }
  const previousDecline=E2E._idDeclined[key];
  if(_e2eRecentOffers.has(key)&&_e2eAllowHeldDm(connId,nick)&&
      await _e2eEnqueue(connId,target,()=>active===view&&_e2eRecoverRecentSignal(key,connId,nick))) return;
  if(active===view&&!_e2eBootStale(generation)&&E2E._idDeclined[key]===previousDecline&&
      !E2E.dmSessions[key]&&!E2E.trustStore[key]?.keyChanged) await handleEncryptCommand(['on',nick],connId,target);
}

// C2: the pinned fingerprint is NEVER overwritten by a key change. A different key puts
// the peer in the 'changed' state (pendingFingerprint) — establishment under it is
// refused and every message warns — until the user explicitly accepts (/encrypt accept,
// fingerprints shown) or rejects it. The old code overwrote the pin on the first
// (header) PRIVMSG, so the second (envelope) PRIVMSG "matched" and was silently trusted.
// opts.keys = [dh, sign]: the presented identity keys; `fingerprint` must be their v2
// fingerprint. The result's `pin` is the pin now in force (an earlier release's full
// pin of the same keys stays as it is: no silent rewrite of the account setting).
async function e2eCheckTrust(nick, fingerprint, opts = null) {
  const k = opts?.peerKey || _e2eDmKey(nick, opts?.connId);
  const [dhKey, signKey] = opts?.keys || [];
  if (!fingerprint || !await e2eValidIdentityKeys(dhKey, signKey) ||
      fingerprint !== await computeIdentityFingerprint(dhKey, signKey)) return { status:'rejected', keyChanged:false };
  const existing = E2E.trustStore[k];
  if (!existing) {
    const gen = E2E._lockGen;
    const confirmed = await e2eConfirmNewIdentity(nick, fingerprint, opts);
    if (!confirmed || _e2eBootStale(gen)) return { status:'rejected', keyChanged:false };
    if (E2E.trustStore[k]) return e2eCheckTrust(nick, fingerprint, opts);
    E2E.trustStore[k] = { fingerprint, verified:false, keyChanged:false, pendingFingerprint:null };
    _e2eStateSetTrust(k);
    return { status:'tofu', keyChanged:false, pin:fingerprint };
  }
  const pin = existing.fingerprint;
  if (!await e2ePinMatchesIdentity(pin, dhKey, signKey)) {
    if (E2E.trustStore[k] !== existing || existing.fingerprint !== pin) return e2eCheckTrust(nick, fingerprint, opts);
    const firstWarning = existing.pendingFingerprint !== fingerprint;
    existing.keyChanged = true;
    existing.pendingFingerprint = fingerprint;
    return { status:'changed', keyChanged:true, firstWarning };
  }
  if (E2E.trustStore[k] !== existing || existing.fingerprint !== pin) return e2eCheckTrust(nick, fingerprint, opts);
  // The PINNED key is presented again: any pending (unaccepted) change is moot.
  if (existing.keyChanged || existing.pendingFingerprint) { existing.keyChanged = false; existing.pendingFingerprint = null; }
  return { status: existing.verified ? 'verified' : 'trusted', keyChanged:false, pin };
}

function e2eMarkVerified(nick, cid) {
  const k = _e2eDmKey(nick, cid);
  const t = E2E.trustStore[k];
  if (!t || t.keyChanged) return false;
  t.verified = true;
  _e2eStateSetTrust(k);
  return true;
}

async function computeFingerprint(b64PubKey) {
  const digest = await crypto.subtle.digest('SHA-256', base64ToBytes(b64PubKey));
  const hex    = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2,'0')).join('');
  return hex.match(/.{1,4}/g).join(' ').toUpperCase();
}

// #11: TOFU must pin BOTH identity keys (sign + dh) so that swapping the sign
// key (while keeping the dh key) also trips the key-change warning.
// Identity fingerprint v2 (every pin made from now on, and what peers are shown):
// SHA-256 over a domain label and both raw P-256 identity keys, each 4-byte
// big-endian length-prefixed, displayed as "v2:" + 16 groups of 4 hex digits. Both
// keys must be valid uncompressed P-256 points. Local only: no wire format carries it.
// Pins made by earlier releases (the unprefixed digest of dhKey||signKey, or of the
// DH key alone before #11) are matched by e2ePinMatchesIdentity / _e2eSessPinIs.
const E2E_FP_V2_DOMAIN = 'CryptIRC identity fingerprint v2';
const E2E_FP_V2_PREFIX = 'v2:';
function _e2eFingerprintHex(digest) {
  const hex = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2,'0')).join('');
  return hex.match(/.{1,4}/g).join(' ').toUpperCase();
}
async function e2eValidIdentityKeys(b64DhKey, b64SignKey) {
  try {
    if (typeof b64DhKey !== 'string' || typeof b64SignKey !== 'string') return false;
    const dh = base64ToBytes(b64DhKey), sign = base64ToBytes(b64SignKey);
    if (dh.length !== 65 || sign.length !== 65 || dh[0] !== 4 || sign[0] !== 4) return false;
    await importPub(b64DhKey, 'ECDH');      // WebCrypto refuses points off the curve
    await importPub(b64SignKey, 'ECDSA');
    return true;
  } catch (_) { return false; }
}
async function computeIdentityFingerprint(b64DhKey, b64SignKey) {
  if (!await e2eValidIdentityKeys(b64DhKey, b64SignKey)) throw new Error('invalid identity keys');
  const field = bytes => { const n = bytes.length; return concat(new Uint8Array([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]), bytes); };
  const digest = await crypto.subtle.digest('SHA-256', concat(field(new TextEncoder().encode(E2E_FP_V2_DOMAIN)),
    field(base64ToBytes(b64DhKey)), field(base64ToBytes(b64SignKey))));
  return E2E_FP_V2_PREFIX + _e2eFingerprintHex(digest);
}
// The fingerprint earlier releases pinned (and still record as this account's own
// `idfp` setting, which older open tabs compare). Compatibility only: never a new pin.
// A null signing key gives the pre-#11 DH-only form (see /encrypt accept).
async function e2eLegacyIdentityFingerprint(b64DhKey, b64SignKey) {
  const dh   = base64ToBytes(b64DhKey);
  const sign = b64SignKey ? base64ToBytes(b64SignKey) : new Uint8Array(0);
  return _e2eFingerprintHex(await crypto.subtle.digest('SHA-256', concat(dh, sign)));
}
function e2eIsLegacyFingerprint(fp) { return typeof fp === 'string' && /^[0-9A-F]{4}( [0-9A-F]{4}){15}$/.test(fp); }
// Does `pin` confirm exactly these two identity keys? A v2 pin by its own digest; a
// full pin from an earlier release by the earlier digest — unambiguous only because
// both keys are validated 65-byte points first. A DH-only pin never matches: it says
// nothing about the signing key, which the user confirms through the key-change flow.
async function e2ePinMatchesIdentity(pin, b64DhKey, b64SignKey) {
  if (typeof pin !== 'string' || !pin || !await e2eValidIdentityKeys(b64DhKey, b64SignKey)) return false;
  if (pin.startsWith(E2E_FP_V2_PREFIX)) return pin === await computeIdentityFingerprint(b64DhKey, b64SignKey);
  return e2eIsLegacyFingerprint(pin) && pin === await e2eLegacyIdentityFingerprint(b64DhKey, b64SignKey);
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

// Safety phrase v2: covers BOTH identity keys of BOTH sides (the DH-only phrase above
// says nothing about the signing keys). Each identity is encoded as its length-prefixed
// DH key then signing key; the two encodings are sorted so both sides hash the same
// bytes, after a domain label. Both identities must be valid P-256 key pairs. Shown
// next to the earlier DH-only phrase, which stays labelled as the value earlier
// releases display.
const E2E_PHRASE_V2_DOMAIN = 'CryptIRC safety phrase v2';
async function safetyPhraseV2(myDh, mySign, theirDh, theirSign) {
  if (!await e2eValidIdentityKeys(myDh, mySign) || !await e2eValidIdentityKeys(theirDh, theirSign))
    throw new Error('invalid identity keys');
  const field = bytes => { const n = bytes.length; return concat(new Uint8Array([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]), bytes); };
  const mine = concat(field(base64ToBytes(myDh)), field(base64ToBytes(mySign)));
  const theirs = concat(field(base64ToBytes(theirDh)), field(base64ToBytes(theirSign)));
  let mineFirst = mine.length <= theirs.length;
  for (let i = 0; i < Math.min(mine.length, theirs.length); i++) {
    if (mine[i] !== theirs[i]) { mineFirst = mine[i] < theirs[i]; break; }
  }
  const digest = await crypto.subtle.digest('SHA-256', concat(field(new TextEncoder().encode(E2E_PHRASE_V2_DOMAIN)),
    mineFirst ? mine : theirs, mineFirst ? theirs : mine));
  return bytesToMnemonic(new Uint8Array(digest).slice(0, 16)).slice(0, 12).join(' ');
}

// ─── Event router ─────────────────────────────────────────────────────────────

async function e2eHandleEvent(ev) {
  switch (ev.type) {

    case 'e2e_keyring':
    case 'e2e_keyring_stored':
    case 'e2e_blob_rewrapped':
    case 'e2e_key_deleted':
    case 'e2e_session_closed':
    case 'e2e_session_committed':
    case 'e2e_session_list':
    case 'e2e_plain_reply_checked':
      _e2eResolveWaiter(ev);
      break;

    case 'e2e_identity_moved':
      if (E2E.keyReady && (E2E.identityReady || E2E._booting) && /^[a-f0-9]{64}$/.test(ev.revision) &&
          _e2eIdentityRevisions.get(E2E.identityKeys)!==ev.revision) {
        E2E._resyncTicket = Symbol();
        E2E._resyncPending=true;
        _e2eKickResync();
      }
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

    case 'e2e_setup_needed': {
      const nick = String(ev.from || '');
      _e2eSetupRow(ev.conn_id,nick,`🔐 ${nick} would like to send you an encrypted DM. Set up encryption, then ask them to try again. You can also run /encrypt unlock.`,'setup',ev.prefix);
      break;
    }
    case 'e2e_signal_suggestion': {
      const nick=String(ev.nick||'');
      if (!_e2eSetupNick(nick,true) || !networks.some(net=>net.config.id===ev.conn_id&&net.connected)) break;
      if (ev.sent) sysMsg(ev.conn_id,_dmTarget(nick),'🔐 Signal suggestion sent to IRC. Once you’ve agreed, both people should select Signal in this DM’s Encryption panel.');
      else _e2eSetupRow(ev.conn_id,nick,`🔐 IRC received a suggestion from ${nick} to use Signal for future private messages. Confirm with them before switching.`, 'method-request',ev.prefix);
      break;
    }
    case 'e2e_bundle_missing': {
      if (_e2eResolveChatProbe(ev)) break;
      const connId = String(ev.conn_id || '').toLowerCase();
      const found = Object.entries(E2E._pendingOn || {}).find(([, pending]) => pending.req === ev.req && String(pending.cid).toLowerCase() === connId);
      if (!found || found[1].answered) break;
      const [k, pending] = found;
      if (ev.reason === 'peer-busy') _e2eNotePeerBusy(connId + '\n' + k);
      if (pending.done) {
        pending.answered = Date.now();
        pending.done(ev.reason);
      } else {
        delete E2E._pendingOn[k];
        const nick = _e2eDmNick(k);
        let notice=_e2eBundleFailure(nick,ev.reason,pending.restart&&!pending.reopen);
        if(pending.restart&&!pending.reopen&&e2eTargetState(nick,{conn_id:pending.cid}).mode==='dm')
          notice+=' The existing Signal session stays active.';
        _e2eSys(pending.target, '🔐 ' + notice, pending.cid);
        if (['unsupported','unconfirmed'].includes(ev.reason) && !E2E.trustStore[k]) {
          _e2eSetupRow(pending.cid,pending.nick||nick,'You can send them a private note with setup instructions.','send');
        }
      }
      updateE2EIndicator(pending.target);
      break;
    }
    case 'e2e_bundle': {
      if (_e2eResolveChatProbe(ev)) break;
      const nick   = String(ev.username || '');
      const canonical = _e2eCanon(nick, ev.conn_id) || _e2eK(nick);
      const k      = _e2eDmKey(canonical, ev.conn_id);
      const bundle = ev.bundle;
      // r2 (NEW-3): the /encrypt on request is answered (whatever happens below).
      // r3 (security review of bff53f9): a bundle is only used as the answer to THIS
      // page's own recent /encrypt on (the only sender of e2e_fetch_bundle is
      // _e2eFetchBundleQueued, which registers _pendingOn and stamps when the request
      // went out). Anything else — a bundle the server pushed unasked, or one arriving
      // after the request expired — is dropped: no identity question, no pin, no session
      // (same rule as an unsolicited e2e_identity_blob).
      const pend = E2E._pendingOn && E2E._pendingOn[k];
      if (pend && (ev.req !== pend.req || (pend.cid && String(ev.conn_id || '').toLowerCase() !== String(pend.cid).toLowerCase()))) break;
      const sentAt = pend ? (pend.sentAt || pend.t) : 0;
      if (!pend || pend.answered || Date.now() - sentAt > E2E_BUNDLE_REPLY_MS) {
        console.warn('[E2E] ignoring an e2e_bundle nobody on this page asked for (or a late one):', nick);
        if (pend && !pend.answered) {
          delete E2E._pendingOn[k];
          pend.done?.('blocked');
        }
        break;
      }
      // r6 (codex-p3 e2e.js:3042): the pending entry is what keeps sends to `nick` BLOCKED
      // — it used to be deleted here, BEFORE the awaits below (ratchet lock, fingerprint,
      // the first-contact identity question, session creation), so a previously plain peer
      // was 'none' (cleartext, e.g. an upload link auto-sent) while the question was open.
      // It now stays (marked answered: a second bundle is ignored) until setup finished or
      // was cancelled, whatever way this handler ends (finally below).
      pend.answered = Date.now();
      const gen = E2E._lockGen;
      const stillPending = () => E2E._pendingOn[k] === pend && !_e2eBootStale(gen) && E2E.keyReady;
      try {
        if (!E2E.keyReady || !E2E.identityReady) {
          pend.done?.('unlock');
          _e2eSys(nick, '🔐 E2E not ready on this device — /encrypt unlock', pend.cid);
          break;
        }
        if (!pend.settingsChecked && !(await _e2eRefreshAccountState(gen))) {
          if (stillPending()) e2eSysMsg(nick,'🔐 Could not confirm the account’s encryption settings. Try again when connected.',pend.cid);
          break;
        }
        if (!stillPending()) break;
        if (pend.done && E2E.state?.dm?.[k]?.on===0) {
          _e2eRememberDisabledDraft(k);
          pend.done('disabled-elsewhere');
          break;
        }
        await _withRatchetLock(k, async () => {});    // another tab may have set it up already
        // Guard: if a usable session already exists (e.g. both users initiated simultaneously), skip
        // (r7: unless it is bound to a replaced identity — then this bundle replaces it)
        const cur = E2E.dmSessions[k];
        if (cur && !cur._unusable) { try { await _e2eSessFp(cur); } catch (_) {} }
        if (!pend.restart && cur && !cur._unusable && _e2eSessPinMismatch(k, cur) !== true) {
          e2eSysMsg(nick, `🔐 Session with ${nick} already active — skipping duplicate initiation`, pend.cid);
          break;
        }

        const { sharedSecret, ephemeralPub, usedOTPKId, identityAD } = await x3dhInitiate(bundle);
        if (!stillPending()) break;

        // #11: TOFU pins BOTH identity keys (dh + sign), validated P-256 points.
        const fp    = await computeIdentityFingerprint(bundle.identity_dh_key, bundle.identity_sign_key).catch(() => null);
        if (!fp) { e2eSysMsg(nick, `🔐 Encryption with ${nick} cancelled — the published identity keys are invalid`, pend.cid); return; }
        const trust = await e2eCheckTrust(nick, fp, { solicited: !pend.done, bridge: ev.bridge, connId: pend.cid, peerKey: k,
          keys: [bundle.identity_dh_key, bundle.identity_sign_key] });

        if (trust.keyChanged) {
          e2eShowKeyChangeWarning(nick, fp, trust.firstWarning, pend.cid);
          return;
        }
        // #1: first-contact identity was not confirmed out-of-band — abort with no
        // pin/session (e2eCheckTrust already recorded nothing on a 'rejected' return).
        if (trust.status === 'rejected') {
          e2eSysMsg(nick, `🔐 Encryption with ${nick} cancelled — identity not confirmed`, pend.cid);
          return;
        }

        if (!stillPending()) break;
        // Every initiation, including a retry after a failed save, must publish
        // the accepted fingerprint before creating the ratchet. A device copy
        // can already say "on" while the server still holds the earlier opt-out.
        const setting=E2E.state?.dm?.[k], requireOn=pend.reopen || setting?.on===1;
        if (pend.reopen && setting?.on===0 && setting.n===pend.reopeningVersion)
          _e2eStateSetDm(k,true,false,setting.n);
        await e2eSaveState();
        const settings=await _e2eRequestSession('__state__',false,stillPending);
        const saved=settings?.blob && await _e2eDecodeState(settings.blob);
        if (!stillPending()) break;
        const on=saved?.dm?.[k]?.on;
        if (!trust.pin || saved?.trust?.[k]?.fp!==trust.pin || on===0 || (requireOn && on!==1)) {
          e2eSysMsg(nick,`🔐 Could not confirm that this chat switched to Signal. Check Encryption and retry /encrypt on ${nick}.`,pend.cid);
          break;
        }
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
        const session = await _withRatchetLock(k, async () => {
          const previous = E2E.dmSessions[k];
          const canStart = () => stillPending() && (!pend.migration || pend.migration.current()) &&
            (_e2ePrefersSignal(k) || !_e2eSharedKeyConfigured(canonical,pend.cid)) &&
            (!pend.restart || _e2eRestartFrom(E2E.dmSessions[k]) === pend.restartFrom);
          if (!canStart()) return null;
          if (!pend.restart && previous?.RK && !previous._unusable) {
            if (previous.theirIdentityPub !== bundle.identity_dh_key || previous.theirSignPub !== bundle.identity_sign_key ||
                _e2eSessPinMismatch(k,previous) !== false || E2E.trustStore[k]?.keyChanged) return null;
            return previous;
          }
          const repair = E2E._sessionSyncRepair.get(k);
          const repairRevision = repair===E2E_DISABLED_DRAFT_REPAIR ? '' : repair;
          const predecessor=pend.restart && !pend.reopen && pend.replacementRevision!=='' ? previous : null;
          if (predecessor?.startEph && !predecessor._unusable && predecessor.identityAD===identityAD &&
              predecessor.theirIdentityPub===bundle.identity_dh_key && predecessor.theirSignPub===bundle.identity_sign_key &&
              !E2E.trustStore[k]?.keyChanged && _e2eSessPinMismatch(k,predecessor)===false) {
            const legacyAnchor=_e2eLegacyPendingStart(predecessor);
            const proof=legacyAnchor ? {identityAD:predecessor.identityAD,startEph:legacyAnchor} : predecessor;
            const signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},E2E.identityKeys.signKeyPair.privateKey,
              _e2eRestartSignatureData(proof,x3dhHeader));
            if (!canStart() || E2E.dmSessions[k]!==predecessor) return null;
            x3dhHeader.restart_sig=bytesToBase64(new Uint8Array(signature));
          }
          return ratchetInitSend(k, sharedSecret, bundle.signed_prekey.public_key, bundle.identity_dh_key, identityAD,
            { x3dhHeader, theirSignPub: bundle.identity_sign_key, connId: _e2eDmScope(k)?.[1], stillPending: canStart,
              reuseConfirmed:!pend.restart,
              replaceRevision:pend.replacementRevision ?? (pend.restart ? repairRevision : undefined),
              previous: predecessor });
        });
        if (!session) {
          if (pend.restart && stillPending() && _e2eRestartFrom(E2E.dmSessions[k]) !== pend.restartFrom) {
            e2eSysMsg(nick, '🔐 The Signal session was updated while reconnecting. Using the updated session.', pend.cid);
          }
          break;
        }
        await _e2eSessFp(session);
        if (!stillPending()) break;
        if (E2E._hdrSent) delete E2E._hdrSent[k];

        updateE2EIndicator(nick);
        const readyMessage = session.x3dhPending
          ? `🔐 Signal encryption with ${nick} is ready to send. An encrypted reply will confirm the session.`
          : session.CKs || session.DHr
            ? `🔐 Signal encryption with ${nick} is active and ready to send.`
            : `🔐 Waiting for ${nick}'s first encrypted message to finish Signal setup.`;
        e2eSysMsg(nick, readyMessage, pend.cid);
        // Refresh encryption panel if it's open for this nick
        if (typeof showEncryptPanel === 'function' && active?.conn_id === pend.cid && _e2eDmKey(active.target, pend.cid) === k) {
          const overlay = document.getElementById('encrypt-overlay');
          if (overlay && overlay.classList.contains('show')) showEncryptPanel();
        }
      } catch(e) {
        if (e instanceof E2ESessionConflict) {
          if (stillPending()) e2eSysMsg(nick, `🔐 Another device updated Signal encryption with ${nick} while this setup was in progress. Open Encryption to check this chat's status.`, pend.cid);
        } else if (e instanceof E2ESessionUnconfirmed || E2E._sessionSyncRepair.has(k)) {
          if (stillPending()) e2eSysMsg(nick, `🔐 Could not confirm the saved Signal session with ${nick}. Reconnect, then use /encrypt restart ${nick}.`, pend.cid);
        } else {
          console.warn('[E2E] Failed to process bundle:', nick, e);
          e2eSysMsg(nick, '🔐 Failed to establish E2E session with ' + nick + ' (invalid key bundle)', pend.cid);
        }
      } finally {
        if (E2E._pendingOn && E2E._pendingOn[k] === pend) delete E2E._pendingOn[k];
        pend.done?.(e2eTargetState(nick, { conn_id: pend.cid }).mode === 'dm' ? 'ready' : 'blocked');
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
          await _e2eRecordPskKey(key,rec.raw);
          if (lockedMeanwhile()) { _e2eResolveWaiter({ type: 'e2e_channel_key_done', channel: ev.channel, ok: false, locked: true }); break; }
          if (rec.g < _e2eKnownChanGen(k) || (rec.scope && !_e2ePskScopeAvailable(k,rec.scope))) {
            rec.raw.fill(0);
            _e2eResolveWaiter({type:'e2e_channel_key_done',channel:ev.channel,ok:false,v2:true});
            break;
          }
          if (rec.g <= E2E.chanRemoved[k]?.confirmedGeneration) {
            rec.raw.fill(0);
            _e2eResolveWaiter({type:'e2e_channel_key_done',channel:ev.channel,ok:false,v2:true});
            break;
          }
          if (rec.scope) _e2ePskScopes.set(key,rec.scope);
          E2E.channelKeys[k] = key;
          const inventory = _e2ePskInventoryChecks.get(k);
          if (!inventory || rec.g > inventory.write.generation) {
            _e2ePskInventoryChecks.delete(k);
            delete E2E.chanRemoved[k];
          }
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
          updateE2EIndicator(_e2eDmNick(ev.channel));
          // History may have replayed from logs as ciphertext before this key arrived.
          if (typeof redecryptChannelHistory === 'function') {
            try { await redecryptChannelHistory(ev.channel); }
            catch(e) { console.error('[E2E] history re-decrypt failed', e); }
          }
          // Announce ONLY for a genuinely new key learned during a live session.
          if (!wasBulk && !hadKey && !rec.legacy) {
            const target = _e2eDmNick(ev.channel);
            const chLabel = _e2eIsChan(target) ? 'Channel' : 'DM';
            e2eSysMsg(target,`🔐 ${chLabel} encryption active for ${target}`,_e2eDmScope(ev.channel)?.[1]);
          }
        }
      }
      _e2eResolveWaiter({ type: 'e2e_channel_key_done', channel: ev.channel, legacyUnreadable, ok: !!rec,
                          v2: typeof ev.blob === 'string' && _e2eWrappedBlob(ev.blob) });
      break;
    }

    case 'e2e_channel_list': {
      if (ev.req) { _e2eResolveWaiter(ev); break; }
      const listed = new Set((Array.isArray(ev.channels) ? ev.channels : []).map(_e2eK));
      if (E2E._serverHints) E2E._serverHints.disabledPsk = (ev.disabled_channels || []).map(_e2eK);
      // MEDIUM: the server's list can no longer DELETE keys. A key we hold that is
      // missing from the list (deleted on another device — or a server lying) keeps the
      // channel in the BLOCKED state until the user confirms with /encrypt off here.
      for (const ch of Object.keys(E2E.channelKeys)) {
        if (listed.has(ch)) continue;
        const pending = _e2ePskInventoryChecks.get(ch);
        if (pending) { pending.revision++; continue; }
        if (!E2E.chanRemoved[ch]) {
          E2E.chanRemoved[ch] = true;
          if (!_e2eRecheckWrittenPsk(ch)) _e2eAnnounceMissingPsk(ch);
          else updateE2EIndicator(ch);
        }
      }
      // Bulk (re)load: no "encryption active" announcement per channel.
      E2E._bulkKeyLoad = new Set(listed);
      for (const ch of (ev.channels || [])) _e2eWs({ type:'e2e_load_channel_key', channel:ch });
      _e2eResolveWaiter(ev);   // r6: the reconnect re-sync waits for the list
      break;
    }

    case 'e2e_otpk_low':
      if (!E2E.identityReady) break;
      console.warn('[E2E] OTPKs low:', ev.remaining, '— replenishing');
      await e2eReplenishOTPKs();
      break;

    case 'e2e_x3dh_header': {
      const nick = String(ev.from_nick || '');
      if (!nick || typeof ev.conn_id!=='string' || !_e2eDmScope(`@${ev.conn_id}:${nick}`)) break;
      if (!E2E.identityReady || !E2E.identityKeys) { _e2eHoldLocked({ kind: 'relay', from: nick, header: ev.header, conn_id:ev.conn_id }); break; }
      if(networks.some(net=>net.config.id===ev.conn_id&&net.connected)) await _e2eHandleHeader(nick, ev.header, 'relay',ev.conn_id);
      break;
    }

    case 'e2e_live_receipt':
      _e2eNoteLiveReceipt(ev);
      break;

    case 'e2e_history_sync':
      await _e2eHandleHistorySync(ev);
      break;

    case 'e2e_live_receive': {
      const pending=E2E._pendingOn?.[ev.partner];
      if (pending?.resumeResult && !pending.beforeAdvance && pending.current() && Date.now()-pending.t<30000 &&
          E2E.trustStore[ev.partner]?.fingerprint && !E2E.trustStore[ev.partner].keyChanged &&
          typeof ev.previous==='string' && ev.previous.startsWith(E2E_BLOB_PREFIX) && ev.previous.length<=65536) {
        // The desktop can open the first message before this phone's settings
        // request even reaches the server. Keep one pre-advance revision only
        // for the explicit Resume already in progress on this phone.
        pending.beforeAdvance=ev.previous;
      }
      break;
    }
    case 'e2e_session_moved': {
      // r2 (NEW-7): another DEVICE of this account sent on this session. Tabs of this
      // browser share one device id and coordinate through IndexedDB instead.
      const k = _e2eK(ev.partner);
      if (!k || k.startsWith('__') || ev.dv === _e2eDeviceId()) break;
      if (ev.initial) { await _e2eNoteInitialEcho(k,ev.initial); break; }
      E2E._moved = E2E._moved || Object.create(null);
      E2E._moved[k] = {at:E2E._moved[k]?.at || Date.now()};
      if (E2E.dmSessions[k]) _e2eAdoptMoved(k).catch(() => {});
      else _e2eScheduleOwnEchoes(k);
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
async function _e2eHandleHeader(nick, hdr, via, connId = null) {
  const k = _e2eDmKey(nick, connId);
  const generation = E2E._lockGen;
  if (!hdr || typeof hdr !== 'object' || !await _e2eVerifyOffer(hdr) || _e2eBootStale(generation)) return;
  if (E2E.dmSessions[k]?.connId && E2E.dmSessions[k].connId !== connId) return;
  _e2eNoteCrossedStart(k,hdr,connId);
  E2E._pendingIncomingX3DH = E2E._pendingIncomingX3DH || Object.create(null);
  if (!E2E._pendingIncomingX3DH[k]) _e2eSweepStrangerState();   // r9: bounded (see the sweep)
  E2E._pendingIncomingX3DH[k] = hdr; _e2ePendHdrAt.set(hdr, Date.now());
  if (connId) _e2eHeaderNetworks.set(hdr, connId);
  if (E2E._x3dhWaiters && E2E._x3dhWaiters[k]) E2E._x3dhWaiters[k](hdr);
  // A web relay lacks the sender's IRC prefix. Wait for the IRC message
  // before presenting an identity, so host-based ignores still apply.
  if (via === 'relay') return;
  try {
    const r = await e2eEstablishResponderSession(nick, hdr, {connId});
    if (!r.ok) {
      if (r.why === 'deferred') {
        const trust = E2E.trustStore[k];
        if (trust?.fingerprint && !trust.keyChanged && _e2eRecentOffers.has(k) && _e2eDmScope(k)?.[1] === connId) {
          await _e2eRecoverRecentSignal(k,connId,nick,trust.fingerprint);
        } else await _e2eRetryHeldDm(k,connId);
      }
      else if (r.why !== 'changed' && r.why !== 'shared-key') _e2eForgetPendingHeader(k,hdr);
      return;
    }
    _e2eForgetPendingHeader(k,hdr);
    updateE2EIndicator(nick);
    if (r.why !== 'replay') e2eSysMsg(nick, `🔐 Signal keys received from ${nick}. Waiting for their first encrypted message.`, connId);
    await _e2eRetryHeldDm(k,connId);
  } catch (e) {
    if (/^E2E_(SPK|OTPK)_MISSING/.test(e?.message || '')) _e2eForgetPendingHeader(k,hdr);
    console.error('[E2E] x3dh pre-init failed (' + via + '):', e && (e.message || e.name));
    e2eSysMsg(nick, `🔐 X3DH setup failed: ${e && (e.message || e.name || String(e))}`, connId);
  }
}

function _e2eAllowHeldDm(connId,from,prefix,fromHistory = false) {
  return !!connId && !(typeof isIgnored === 'function' && isIgnored(from,prefix)) &&
    !(typeof getPmSettings === 'function' && getPmSettings(connId).enabled && !isPmAllowedFor(connId,from)) &&
    (!fromHistory || typeof e2eCanRecoverSignalHistory !== 'function' || e2eCanRecoverSignalHistory(from));
}

function _e2eHoldDm(k,envelope,connId,t = Date.now()) {
  const wire = _e2eDmHistoryWires.get(envelope);
  if (!wire || !_e2eAllowHeldDm(connId,wire.from,wire.prefix,wire.fromHistory)) return false;
  _e2eSweepStrangerState();
  const pending = E2E._orphans ||= Object.create(null);
  const messages = pending[k] ||= [];
  if (messages.some(m => m.conn_id === connId && _e2eDmHistoryWires.get(m.envelope)?.text === wire.text)) return true;
  if (messages.length >= 20) {
    const oldest = messages.reduce((i,m,j)=>m.t < messages[i].t ? j : i,0);
    if (t < messages[oldest].t) return false;
    messages.splice(oldest,1);
  }
  messages.push({t,envelope,conn_id:connId});
  return true;
}

async function _e2eRetryHeldDm(k,connId,expectedFingerprint = null) {
  const generation = E2E._lockGen;
  const current = () => E2E.keyReady && !_e2eBootStale(generation) && E2E.state?.dm?.[k]?.on !== 0 &&
    (!expectedFingerprint || (E2E.trustStore[k]?.fingerprint === expectedFingerprint && !E2E.trustStore[k].keyChanged));
  const pending = E2E._orphans?.[k] || [];
  const items = pending.filter(o => !connId || o.conn_id === connId);
  if (!items.length || !current()) return false;
  let decrypted = false;
  const remove = item => {
    const queue = E2E._orphans?.[k];
    const index = queue?.indexOf(item) ?? -1;
    if (index >= 0) {
      queue.splice(index,1);
      if (!queue.length) delete E2E._orphans[k];
    }
  };
  for (const item of items) {
    if (!current()) break;
    if (_e2eHeldInFlight.has(item) || !E2E._orphans?.[k]?.includes(item)) continue;
    const {t,envelope,conn_id} = item;
    const wire = _e2eDmHistoryWires.get(envelope);
    if (!wire || Date.now()-t >= E2E_HEADER_TTL_MS || !_e2eAllowHeldDm(conn_id,wire.from,wire.prefix,wire.fromHistory) ||
        _e2eDmKey(wire.from,conn_id) !== k) { remove(item); continue; }
    _e2eHeldInFlight.add(item);
    let r;
    try {
      // An already trusted contact's first signed replacement can arrive while
      // this browser is closed. Only this still-unread, recent IRC row may
      // establish it, after the first ordinary ciphertext authenticates.
      const historySuccessor=wire.fromHistory && expectedFingerprint ? ()=>current() &&
        E2E.state?.dm?.[k]?.on===1 && Date.now()-t<E2E_HEADER_TTL_MS && _e2eHeldInFlight.has(item) &&
        E2E._orphans?.[k]?.includes(item) && _e2eAllowHeldDm(conn_id,wire.from,wire.prefix,true) &&
        typeof isUnreadSignalHistory==='function' && isUnreadSignalHistory(conn_id,wire.target,wire.from,wire.text) : null;
      r = await e2eDecryptIncoming(wire.from,wire.target,wire.text,
        {conn_id,prefix:wire.prefix,held:true,recovering:true,expectedFingerprint,historySuccessor});
    } finally { _e2eHeldInFlight.delete(item); }
    if (r.reactionReady && current() && _e2eAllowHeldDm(conn_id,wire.from,wire.prefix,wire.fromHistory)) {
      remove(item);
      _e2eShowDecrypted(conn_id,wire.target,wire.from,r.plaintext,null,wire);
      decrypted = true;
    } else if (current() && !r.historyPending) remove(item);
  }
  return decrypted;
}

// Catch up while the current ratchet can still open missed incoming messages.
// History never creates a session, enters a trust prompt, or sends a receipt here.
async function _e2eCatchUpSignalHistory(key,connId,target,lines,fingerprint,sameHistory,newer) {
  const eligible = () => !!fingerprint && E2E.keyReady && E2E.identityReady && sameHistory() &&
    E2E.state?.dm?.[key]?.on !== 0 && _e2eDmKey(target,connId) === key &&
    E2E.trustStore[key]?.fingerprint === fingerprint && !E2E.trustStore[key].keyChanged &&
    _e2eAllowHeldDm(connId,target,null,true);
  const current = () => eligible() && e2eTargetState(target,{conn_id:connId}).mode === 'dm';
  if (E2E._resyncPending) await _e2eResyncWait(8000);
  if (!eligible()) return;
  await _withRatchetLock(key,async () => {
    const previous = E2E.dmSessions[key];
    if (_e2eMovedPending(key)) await _e2eAdoptMovedInner(key);
    const session = E2E.dmSessions[key];
    if (!session || session._unusable || (session.connId && session.connId !== connId)) return;
    await _e2eSessFp(session);
    if (!current() || _e2eSessPinMismatch(key,session) !== false) return;
    // Another device may have already consumed these ciphertexts. Keep the keys
    // this browser had before the adoption only while opening this history batch.
    // Deriving keys from this copy must never publish or replace the live ratchet.
    const entry = _e2ePriorHistorySessions.get(key);
    let local = _e2eSameSessionIdentity(entry?.session,session) ? entry.session :
      previous !== session && _e2eSameSessionIdentity(previous,session) ? previous : null;
    for (const line of lines) {
      if (!current()) break;
      const unread = () => current() && isUnreadSignalHistory(connId,target,line.from,line.text);
      if (!unread()) continue;
      let plaintext, nextLocal;
      try {
        const envelope = JSON.parse(atob(line.text.slice(E2E_DM_PREFIX.length)));
        if (!_e2eEnvelopeOk(envelope) || envelope.x3dh_header) continue;
        const opts = {historyCurrent:unread,historyPast:!newer(line)};
        try { plaintext = await _ratchetDecryptInner(key,envelope,opts); }
        catch (error) {
          if (!local || !unread()) throw error;
          plaintext = await _ratchetDecryptInner(key,envelope,{...opts,candidate:local,historySave:next=>{nextLocal=next;}});
        }
        if (unread() && applyHeldDmHistory(connId,target,line.from,line.text,plaintext)) {
          if (nextLocal) {
            local=nextLocal;
            if (entry && _e2ePriorHistorySessions.get(key) === entry) entry.session=nextLocal;
          }
          await e2eRememberDmHistory(connId,target,line.from,line.text,plaintext);
        }
      } catch (_) { continue; }
    }
  });
}

// Keep recent incoming ciphertext and setup frames for an explicit method change,
// or automatic retry on an already trusted Signal conversation.
function e2eStageSignalHistory(connId,target,lines,readable) {
  const key = _e2eDmKey(target,connId);
  if (_e2eDmScope(key)?.[1] !== connId || !_e2eAllowHeldDm(connId,target)) return;
  const now = Date.now();
  let confirmed = null;
  for (const line of lines) {
    if (line && _e2eK(line.from) === _e2eK(target) && readable.has(line) &&
        (!confirmed || line.ts > confirmed.ts || (line.ts === confirmed.ts && (line.id||0) > (confirmed.id||0)))) confirmed = line;
  }
  const newer = line => !confirmed || line.ts > confirmed.ts || (line.ts === confirmed.ts && (line.id||0) > (confirmed.id||0));
  const order = (a,b) => a.ts-b.ts||a.id-b.id;
  const incoming = lines.filter(line => line && _e2eK(line.from) === _e2eK(target) && Number.isFinite(line.ts) &&
    line.ts > 0 && line.ts*1000 <= now+60000 &&
    typeof line.text === 'string' && line.text.length <= 4096);
  const trust = E2E.trustStore[key];
  const session=E2E.dmSessions[key];
  const trusted=!!trust?.fingerprint && !trust.keyChanged && !!session && E2E.state?.dm?.[key]?.on===1;
  if (trust?.fingerprint && !trust.keyChanged && session && typeof _e2eEnqueue === 'function') {
    const missed = incoming.filter(line => (trusted || now-line.ts*1000<E2E_HEADER_TTL_MS) &&
      !readable.has(line) && line.text.startsWith(E2E_DM_PREFIX)).sort(order).slice(-60);
    if (missed.length) {
      const generation = E2E._lockGen;
      const sameHistory = _e2eHistoryCurrent(_e2eUser(),_e2eHistoryScope(connId,target));
      _e2eEnqueue(connId,target,()=>_e2eCatchUpSignalHistory(key,connId,target,missed,trust.fingerprint,
        ()=>!_e2eBootStale(generation) && sameHistory(),newer));
    }
  }
  // An ordinary ratchet can still open messages missed during a long absence.
  // An old offer must prove it replaced the exact session this device saved.
  // Keep only the bounded pages viewed together during this catch-up.
  const archived=trusted && !!session.startEph && !!session._storeRevision && !session._unusable;
  const keep = new Map((_e2eRecentOffers.get(key) || []).filter(l => now-l.ts*1000 < E2E_HEADER_TTL_MS ||
    (archived && l.sessionStart===session.startEph && now-l.seenAt<E2E_HEADER_TTL_MS))
    .filter(newer)
    .map(l => [l.text,l]));
  for (const line of incoming) {
    if (!newer(line)) continue;
    if (!line.text.startsWith(E2E_HDR_PREFIX) && !line.text.startsWith(E2E_DM_PREFIX)) continue;
    if (now-line.ts*1000 >= E2E_HEADER_TTL_MS && !archived) continue;
    keep.set(line.text,{from:line.from,text:line.text,ts:line.ts,id:line.id||0,
      sessionStart:archived ? session.startEph : null,seenAt:now});
  }
  if (!keep.size) { _e2eRecentOffers.delete(key); return; }
  _e2eRecentOffers.delete(key);
  if (_e2eRecentOffers.size >= 32) _e2eRecentOffers.delete(_e2eRecentOffers.keys().next().value);
  const sorted = [...keep.values()].sort(order);
  const rows = [...sorted.filter(l=>l.text.startsWith(E2E_HDR_PREFIX)).slice(-16),
    ...sorted.filter(l=>l.text.startsWith(E2E_DM_PREFIX)).slice(-32)].sort(order);
  _e2eRecentOffers.set(key,rows);
  const last = rows.findLast(line=>line.text.startsWith(E2E_DM_PREFIX)) ||
    (E2E._orphans?.[key]?.length && rows.at(-1));
  const savedHeaders = rows.filter(line=>line.text.startsWith(E2E_HDR_PREFIX));
  const liveOffer = _e2ePendingHeader(key);
  if (!last || !trust?.fingerprint || trust.keyChanged ||
      !E2E.identityReady || !(E2E.dmSessions[key] || _e2ePrefersSignal(key)) ||
      (!_e2ePrefersSignal(key) && _e2eSharedKeyConfigured(_e2eCanon(target,connId) || _e2eK(target),connId))) return;
  if (!liveOffer && !savedHeaders.length && !rows.some(line=>{
    try { return !!JSON.parse(atob(line.text.slice(E2E_DM_PREFIX.length))).x3dh_header; } catch (_) { return false; }
  })) return;
  // A later history page can supply a missing setup fragment for the same message.
  const marker = JSON.stringify([last.id||last.text,liveOffer?.ephemeral_pub,archived ? session.startEph : null,...savedHeaders.map(l=>l.id||l.text)]);
  if (_e2eHistoryAttempts.get(key) === marker) return;
  _e2eHistoryAttempts.delete(key);
  if (_e2eHistoryAttempts.size >= 32) _e2eHistoryAttempts.delete(_e2eHistoryAttempts.keys().next().value);
  _e2eHistoryAttempts.set(key,marker);
  const generation = E2E._lockGen;
  const recover = () => {
    if (!_e2eBootStale(generation)) return _e2eRecoverRecentSignal(key,connId,target,trust.fingerprint);
  };
  if (typeof _e2eEnqueue === 'function') _e2eEnqueue(connId,target,recover);
}

async function _e2eRecoverRecentSignal(key,connId,target,expectedFingerprint = null) {
  const generation = E2E._lockGen;
  const current = () => E2E.keyReady && E2E.identityReady && !_e2eBootStale(generation) &&
    E2E.state?.dm?.[key]?.on !== 0 &&
    (_e2ePrefersSignal(key) || !_e2eSharedKeyConfigured(_e2eCanon(target,connId) || _e2eK(target),connId)) &&
    _e2eDmScope(key)?.[1] === connId && _e2eDmKey(target,connId) === key && _e2eAllowHeldDm(connId,target) &&
    (!expectedFingerprint || (E2E.trustStore[key]?.fingerprint === expectedFingerprint && !E2E.trustStore[key].keyChanged));
  if (!current()) return false;
  const liveOffer = _e2ePendingHeader(key) || null;
  const currentOffer = () => current() && (_e2ePendingHeader(key) || null) === liveOffer;
  if (liveOffer && expectedFingerprint &&
      !await e2ePinMatchesIdentity(expectedFingerprint,liveOffer.sender_ik,liveOffer.sender_sign_ik)) return false;
  if (!currentOffer()) return false;
  if ((liveOffer || (!expectedFingerprint && E2E._orphans?.[key]?.some(o=>o.envelope.x3dh_header))) &&
      await _e2eRetryHeldDm(key,connId,expectedFingerprint)) return true;
  const historyAllowed = () => typeof e2eCanRecoverSignalHistory !== 'function' || e2eCanRecoverSignalHistory(target);
  if (!currentOffer() || !historyAllowed()) return false;
  const rows = _e2eRecentOffers.get(key) || [];
  const fragments = Object.create(null);
  const previous=E2E.dmSessions[key];
  const sameHistory=_e2eHistoryCurrent(_e2eUser(),_e2eHistoryScope(connId,target));
  const archivedCurrent=()=>!!expectedFingerprint && currentOffer() && !liveOffer &&
    E2E.state?.dm?.[key]?.on===1 && sameHistory() && _e2eAllowHeldDm(connId,target,null,true);
  let offer = liveOffer, offerTime = 0, archivedOffer = null;
  const messages = [];
  for (const line of rows) {
    const aged=Date.now()-line.ts*1000 >= E2E_HEADER_TTL_MS;
    if (aged && (!previous?.startEph || line.sessionStart!==previous.startEph || !archivedCurrent())) continue;
    let hdr;
    try {
      if (line.text.startsWith(E2E_HDR_PREFIX)) {
        hdr = line.text.startsWith(E2E_HDR_FRAG) ? _e2eHdrFragment(line.from,line.text,connId,fragments) :
          JSON.parse(atob(line.text.slice(E2E_HDR_PREFIX.length)));
      } else {
        const envelope = JSON.parse(atob(line.text.slice(E2E_DM_PREFIX.length)));
        if (!_e2eEnvelopeOk(envelope)) continue;
        messages.push({line,envelope});
        hdr = envelope.x3dh_header;
      }
    } catch (_) { continue; }
    if (liveOffer || !hdr || _e2eSessionHasOffer(E2E.dmSessions[key],hdr) || !await _e2eVerifyOffer(hdr)) continue;
    if (expectedFingerprint && !await e2ePinMatchesIdentity(expectedFingerprint,hdr.sender_ik,hdr.sender_sign_ik)) continue;
    if (aged && !await _e2eIsSignedSuccessor(key,previous,hdr,connId,true)) continue;
    if (!currentOffer()) return false;
    offer = hdr;
    offerTime = line.ts*1000;
    archivedOffer=aged ? line : null;
  }
  if (!offer || (!messages.length && !E2E._orphans?.[key]?.length) || !currentOffer() || !historyAllowed()) return false;
  if (archivedOffer) {
    // Work directly against the actual unread row. An archived header never
    // enters the live pending queue or contributes a new trust decision.
    const afterOffer=line=>line.ts>archivedOffer.ts || (line.ts===archivedOffer.ts && line.id>=archivedOffer.id);
    const later=messages.filter(({line})=>afterOffer(line));
    for (const {line,envelope} of later) {
      const unread=()=>archivedCurrent() && isUnreadSignalHistory(connId,target,line.from,line.text);
      if (E2E.dmSessions[key]!==previous || !archivedCurrent()) break;
      if (!unread()) continue;
      try {
        const opened=await _e2eEstablishAndDecrypt(target,offer,envelope,{connId,alt:true,requireSuccessor:true,
          expectedFingerprint,historySuccessor:unread});
        if (!opened.ok || !unread() || !applyHeldDmHistory(connId,target,line.from,line.text,opened.pt)) continue;
        await e2eRememberDmHistory(connId,target,line.from,line.text,opened.pt);
        await _e2eCatchUpSignalHistory(key,connId,target,later.map(item=>item.line),expectedFingerprint,
          ()=>current() && sameHistory(),afterOffer);
        return true;
      } catch (_) { /* A different ciphertext or a changed conversation cannot authorize a restart. */ }
    }
    return false;
  }
  if (!liveOffer) {
    (E2E._pendingIncomingX3DH ||= Object.create(null))[key] = offer;
    _e2ePendHdrAt.set(offer,offerTime);
    _e2eHeaderNetworks.set(offer,connId);
  }
  for (const {line,envelope} of messages.slice(-20)) {
    if (Date.now()-line.ts*1000>=E2E_HEADER_TTL_MS) continue;
    _e2eDmHistoryWires.set(envelope,{from:line.from,target,text:line.text,fromHistory:true});
    _e2eHoldDm(key,envelope,connId,line.ts*1000);
  }
  const recovered = await _e2eRetryHeldDm(key,connId,expectedFingerprint);
  if (recovered && _e2eRecentOffers.get(key) === rows) _e2eRecentOffers.delete(key);
  if (!recovered && !liveOffer && expectedFingerprint && !E2E.trustStore[key]?.keyChanged) _e2eForgetPendingHeader(key,offer);
  return recovered;
}

// H6: reassembly of fragmented headers ([e2ex3dh]~id~i~n~data). Caps: ≤8 fragments of
// ≤600 chars, ≤4 KiB total, ≤4 open ids per sender, ≤64 senders, 120 s TTL; a fragment
// index seen twice with different data poisons that id.
E2E._hdrFrags = Object.create(null);
function _e2eHdrFragment(from, text, cid, fragments = E2E._hdrFrags) {
  const m = /^\[e2ex3dh\]~([a-z0-9]{4,12})~([1-8])~([1-8])~([A-Za-z0-9+/=]{1,600})$/.exec(text);
  if (!m) return null;
  const k = _e2eDmKey(from, cid), id = m[1], i = +m[2], n = +m[3], data = m[4];
  if (i > n) return null;
  const now = Date.now();
  for (const s of Object.keys(fragments)) {
    for (const fid of Object.keys(fragments[s])) if (now - fragments[s][fid].t > 120000) delete fragments[s][fid];
    if (!Object.keys(fragments[s]).length) delete fragments[s];
  }
  if (!fragments[k]) {
    if (Object.keys(fragments).length >= 64) return null;
    fragments[k] = Object.create(null);
  }
  const per = fragments[k];
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
  if (!cid && [..._e2eKnownNames(null, true)].some(nick => _e2eFoldWide(nick) === _e2eFoldWide(canon))) {
    return { mode:'blocked', reason:`Encryption for ${t} requires its IRC network.` };
  }
  const st0 = _e2eTargetStateOf(canon, t, opts);
  if (st0.mode !== 'none' || (opts && opts._alias)) return st0;
  for (const a of _e2eAliasesOf(t, cid)) {
    if (e2eTargetState(a, { ...(opts || {}), _alias: true }).mode !== 'none') {
      return { mode:'blocked', reason:`End-to-end encryption is on for ${a} — a message to ${t} can't be encrypted; send it to ${a} itself` };
    }
  }
  return st0;
}
function _e2eSharedKeyConfigured(k,cid,hinted = _e2eHints().ch) {
  k = _e2ePskSlot(k,cid,hinted);
  const state = E2E.state?.ch[k];
  if (E2E.keyReady && state?.legacyOff === 1 && E2E._serverHints?.disabledPsk?.includes(k) &&
      !E2E.channelKeys[k] && !E2E.chanRemoved[k] && !E2E._serverHints.channels.includes(k)) return false;
  return !!(E2E.channelKeys[k] || state?.on || hinted.includes(k) ||
    (E2E._serverHints?.channels?.includes(k) && !(state && !state.on)));
}
function _e2ePrefersSignal(key) {
  return !!_e2eDmScope(key) && E2E.state?.dm[key]?.on === 1 && E2E.state.dm[key].signal === 1;
}
// The E2E state of the resolved name `k` (lowercased); `t` = the name as written.
function _e2eTargetStateOf(k, t, opts) {
  const isDM = !_e2eIsChan(k);
  const hints = _e2eHints();
  const sh = E2E._serverHints;
  const srvPeers = (sh && sh.peers) || [];
  const keysLoading = E2E._bootPhase === 'loading';
  // r6 (codex-p3 HIGH e2e.js:1007): reconnected, not re-synced yet → nothing goes out
  // (E2E may have been turned on, or a key rotated, on another device meanwhile).
  // `discovery`: app.js holds queued lines instead of failing them; sends wait for it.
  if (E2E._resyncPending && E2E.keyReady && !opts?.incoming && !opts?.scopedPlainCheck) {
    _e2eKickResync();
    return { mode:'blocked', discovery: true, reason:'E2E status is being re-checked after the reconnect — message not sent; try again in a moment' };
  }
  const slot = _e2ePskSlot(k,opts?.conn_id,hints.ch);
  const stCh = E2E.state && E2E.state.ch[slot];
  const dmKey = isDM ? _e2eDmKey(k, opts?.conn_id) : null;
  const preferSignal = dmKey && _e2ePrefersSignal(dmKey);
  if (E2E.channelKeys[slot] && !preferSignal) {
    if (E2E.chanRemoved[slot] && _e2ePskInventoryChecks.has(slot))
      return {mode:'blocked',pskInventory:slot,reason:'Checking this chat’s saved shared key — try again in a moment'};
    if (E2E.chanRemoved[slot]) return { mode:'blocked', reason:`The encryption key for ${t} was removed on another device or by the server — run /encrypt off to send unencrypted, or re-add the key` };
    // r6: the E2E state says a NEWER key generation is in use (rotated on another
    // device) than the key installed here — never encrypt with the replaced key.
    const kg = E2E._chanKeyGen[slot];
    if (kg !== undefined && stCh && Number.isInteger(stCh.g) && stCh.g > kg) return { mode:'blocked', reason:`The encryption key for ${t} was rotated on another device and the new key has not loaded here yet — message not sent; reload if this persists` };
    return { mode:'psk' };
  }
  const chOn = _e2eSharedKeyConfigured(k,opts?.conn_id,hints.ch);
  if (isDM) k = dmKey;
  const stDm = E2E.state && E2E.state.dm[k];
  // r2 (NEW-3): /encrypt on is in progress (bundle requested, maybe queued in an outage).
  const pend = E2E._pendingOn && E2E._pendingOn[k];
  // r6 (codex-p3 e2e.js:3042): also while the answered bundle is being set up (identity
  // question open, session being created) — for as long as that takes: the bundle
  // handler removes the entry when it ends (any way), a lock wipes it, /encrypt off too.
  if (pend?.closing) return {mode:'blocked',reason:`Confirming that Signal is off for ${t}. Your message was held.`};
  // A failed manual enable restores the previous off setting. A draft sent
  // during the attempt must retain its encryption requirement when retried.
  const enablingDisabled = stDm?.on===0 && !!pend && !pend.done;
  const s = isDM && E2E.dmSessions[k], tr = isDM && E2E.trustStore[k];
  // An incoming gesture may use the previously approved session during manual
  // setup. Sending, first contact and disputed identities still wait.
  const receiveOnPinnedSession = opts?.receivedReaction && stDm?.on===1 && !!tr?.fingerprint &&
    !tr.keyChanged && _e2eSessPinIs(s,tr.fingerprint)===true;
  // Checking an ordinary nick for the first time does not turn the chat on.
  const receivingDuringDiscovery = opts?.incomingPlain && pend?.settled && !pend.answered &&
    !s && !stDm?.on && !tr?.fingerprint && !E2E.state?.trust?.[k]?.fp && !srvPeers.includes(k);
  if (pend?.checking && !receiveOnPinnedSession) return {mode:'blocked',signalDisabled:enablingDisabled,reason:`Checking the saved Signal session with ${t} — message held. Try again when encryption is ready.`};
  if (pend && !receiveOnPinnedSession && !receivingDuringDiscovery && (pend.answered || Date.now() - pend.t < 120000)) {
    return { mode:'blocked', signalDisabled:enablingDisabled, reason: pend.answered ? `Encryption with ${t} is still being set up (confirm ${t}'s identity first) — message not sent` : `Encryption with ${t} is still being set up (waiting for ${t}'s key bundle) — message not sent; try again in a moment` };
  }
  if (!E2E.keyReady) {
    const dmOn = isDM && (hints.dm.includes(k) || srvPeers.includes(k));
    if (chOn || dmOn) {
      if (keysLoading && E2E._krReceived) {
        return { mode:'blocked', readiness:'loading', reason:'E2E keys are still loading — try again in a moment' };
      }
      if (keysLoading) {
        return { mode:'blocked', readiness:'checking', reason:'Checking encryption settings — try again in a moment' };
      }
      return { mode:'blocked', readiness:'unlock', reason:'E2E is locked on this device — run /encrypt unlock' };
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
  if (chOn && !preferSignal) return { mode:'blocked', readiness:keysLoading?'loading':undefined,
    reason:keysLoading?'E2E keys are still loading — try again in a moment':`Encryption is on for ${t} but its key is missing (the server did not return it) — re-add the key, or /encrypt off to send unencrypted` };
  if (!isDM) return { mode:'none' };
  const repair = !opts?.incoming && E2E._sessionSyncRepair.has(k);
  if (stDm?.on===0 && (s || repair))
    return {mode:'blocked',signalDisabled:true,reason:_e2eBundleFailure(t,'disabled-elsewhere')};
  if (stDm?.on===0 && srvPeers.includes(k) && !opts?.incoming)
    return {mode:'blocked',signalInventory:true,waitable:true,reason:_e2eBundleFailure(t,'active-while-off')};
  if (repair) {
    return { mode:'blocked', reason:'Signal session needs attention. Open Encryption and select Restart Signal session.' };
  }
  if (s && !s._unusable) {
    if (s.connId && opts?.conn_id && s.connId !== opts.conn_id) {
      return { mode:'blocked', reason:`The encrypted session for ${t} belongs to another network — message not sent.` };
    }
    if (!E2E.identityReady) return { mode:'blocked', readiness:keysLoading?'loading':undefined, reason:'E2E identity not loaded on this device' };
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
  if (preferSignal) return { mode:'blocked', reason:'Signal was selected for this chat. Open Encryption to start or retry the Signal session.' };
  if (on) return { mode:'blocked', readiness:keysLoading?'loading':undefined,
    reason:keysLoading?'E2E keys are still loading — try again in a moment':`E2E is on for ${t} but there is no session — /encrypt on ${t} to re-establish, or /encrypt off ${t} to send unencrypted` };
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
function _e2eBlock(reason, readiness) {
  E2E.lastBlockReason = reason || 'Encrypted session not ready';
  return readiness ? { e2eBlocked:true, readiness, reason:E2E.lastBlockReason } : E2E_ENCRYPT_BLOCKED;
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
function e2eWithQueuedSignal(target,cid,dispatch) {
  const key = _e2eDmKey(_e2eCanon(target,cid) || _e2eK(target),cid);
  return _withRatchetLock(key,async()=>{
    if (_e2eMovedPending(key)) await _e2eAdoptMovedInner(key);
    dispatch(!_e2eMovedPending(key));
  });
}
function _e2eQueuedPinMatches(key,session,fingerprint) {
  const pin = E2E.trustStore[key];
  return !!(fingerprint && pin?.fingerprint && !pin.keyChanged &&
    _e2eSessFpCached(session) === fingerprint && _e2eSessPinMismatch(key,session) === false);
}
// r8 (codex-p3 + agy-flash e2e.js:3689): also HELD — not refused — while this device's
// E2E keys are locked or still loading (vault / device lock: they come back with the
// unlock, which re-checks the line then), and for a waitable state (the session check
// still computing, a pending handshake) for up to 2 minutes (`heldMs` = how long app.js
// has held it). E2E locked by choice with the vault up is refused (holding the head of
// the queue there would block every later line).
function e2eQueuedWireVerdict(target, cid, text, heldMs, canRetry = false) {
  const meta = E2E._wireMeta.get(text);
  const st = e2eTargetState(target, { conn_id: cid });
  if (st.mode === 'blocked' && (st.discovery || st.pskInventory)) return 'hold';
  if (!E2E.keyReady && (E2E._vaultUp !== true || E2E._booting || E2E._promptOpen)) return 'hold';
  if (st.mode === 'blocked' && st.waitable && !((heldMs || 0) > 120000)) return 'hold';
  E2E._wireMeta.delete(text);
  if (!meta) return { refuse: true, reason: 'what it was encrypted with is not known on this page any more' };
  if (st.mode !== meta.mode) return { refuse: true, reason: st.mode === 'blocked' ? (st.reason || 'E2E is blocked for it now') : 'its encryption changed since it was queued' };
  if (meta.mode === 'psk') {
    // By key GENERATION (a rotation always raises it): the reconnect re-sync re-imports
    // the same key as a new CryptoKey object, which must not refuse lines encrypted
    // with it. Object identity only when a generation is not known.
    const canonical = _e2eCanon(target,cid);
    if (!canonical || _e2ePskSlot(canonical,cid) !== meta.k || !_e2ePskKeyCurrent(meta.k,meta.key,meta.gen) ||
        _e2ePskConversation(canonical,getNick(cid),canonical,cid,_e2ePskSendBinding(meta.k,cid,E2E.channelKeys[meta.k])) !== meta.scope) {
      return {refuse:true,reason:'the shared key or IRC conversation changed after the message was encrypted'};
    }
  }
  if (meta.mode === 'dm') {
    if ((meta.ownRevision && meta.ownRevision !== _e2eIdentityRevisions.get(E2E.identityKeys)) ||
        (meta.ownFingerprint && meta.ownFingerprint !== E2E.state?.idfp))
      return {refuse:true,reason:'your encryption identity changed before the message was delivered'};
    if (_e2eDmKey(_e2eCanon(target,cid) || _e2eK(target),cid) !== meta.k) {
      return { refuse:true, reason:'the IRC nickname no longer maps to the same Signal conversation' };
    }
    const session = E2E.dmSessions[meta.k];
    const cur = _e2eSessFpCached(session);
    if (st.changed && (!meta.disputedFingerprint || meta.disputedFingerprint !== E2E.trustStore[meta.k]?.pendingFingerprint ||
        !meta.fp || cur !== meta.fp)) return { refuse:true, reason:'the recipient identity changed while it was queued' };
    if (meta.requiresPin && !_e2eQueuedPinMatches(meta.k,session,meta.fp)) {
      return { refuse:true, reason:'the confirmed Signal identity is no longer available' };
    }
    if (meta.fp && cur && cur !== meta.fp) return { refuse: true, reason: 'the identity of the other side changed after it was encrypted' };
    if (session?.startEph !== meta.startEph || (!meta.committed && _e2eAdoptedEpochs[meta.k] !== meta.adoptedEpoch)) {
      if (canRetry && meta.sealed && _e2eQueuedPinMatches(meta.k,session,meta.fp)) return { retry: meta };
      return { refuse: true, reason: 'the Signal session changed after it was encrypted' };
    }
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
function _e2eMarkHeaderQueued(key,header) {
  (E2E._hdrSent ||= Object.create(null))[key] = {ephemeral:header.ephemeral_pub,at:Date.now()};
}
function _e2eSendHeader(target, sess, cid) {
  const hdr = sess.x3dhPending;
  if (!hdr?.ephemeral_pub) return;
  const k = _e2eDmKey(_e2eCanon(target,cid) || target,cid);
  const last = E2E._hdrSent?.[k];
  // A sibling can install a new session for the same peer. It still needs to
  // transmit that session's offer even if this device sent the previous one.
  if (last?.ephemeral === hdr.ephemeral_pub && Date.now() - last.at < 5 * 60 * 1000) return;
  // Fast path: the server relays it to the peer's CryptIRC sessions (no IRC limits).
  const identityRevision = _e2eIdentityRevisions.get(E2E.identityKeys);
  if (!sess.connId) _e2eWs({ type:'e2e_relay_x3dh', target_nick: target, header: hdr, conn_id: cid || undefined,
    e2e_identity_revision:identityRevision });
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
    const m = { type:'send', conn_id:cid, raw:`PRIVMSG ${target} :${line}`, e2e_identity_revision:identityRevision };
    if (typeof rateLimitedSend === 'function') rateLimitedSend(m);
    else if (wsend(m) === false) queued = false;
  }
  if (queued) _e2eMarkHeaderQueued(k,hdr);
}

function _e2eQueuedDmAAD(key,wire) {
  return _e2eBlobAAD('queued-signal\n'+key+'\n'+wire);
}

// Called under the peer's ratchet lock so the queue metadata describes the exact
// session that produced the ciphertext, including if a new session was just adopted.
const E2E_QUEUED_RETRIES = 2;
async function _e2eEncryptDmWire(key,target,cid,plaintext,canRetry,canCommit = null, retries = 0) {
  const session = E2E.dmSessions[key];
  const master = E2E.e2eEncKey, generation = E2E._lockGen;
  const trust = E2E.trustStore[key];
  const disputedFingerprint = trust?.keyChanged ? trust.pendingFingerprint : null;
  const meta = {mode:'dm',k:key,fp:_e2eSessFpCached(session) || null,ownFingerprint:E2E.state?.idfp,
    ownRevision:_e2eIdentityRevisions.get(E2E.identityKeys),startEph:session.startEph,
    adoptedEpoch:_e2eAdoptedEpochs[key],requiresPin:!!canCommit,disputedFingerprint,retries};
  const wire = E2E_DM_PREFIX + btoa(JSON.stringify(await _ratchetEncryptInner(key,plaintext,false,canCommit)));
  meta.committed = true;
  if (canRetry && master && meta.fp && !E2E.trustStore[key]?.keyChanged) {
    const data = new TextEncoder().encode(plaintext);
    try { meta.sealed = await _e2eGcmEnc(master,data,_e2eQueuedDmAAD(key,wire)); }
    finally { data.fill(0); }
  }
  if (!E2E.keyReady || _e2eBootStale(generation)) throw new Error('Encrypted chats were locked while preparing the message');
  _e2eNoteWires([wire],meta);
  const from = cid && typeof getNick === 'function' ? getNick(cid) : null;
  void e2eRememberDmHistory(cid,target,from,wire,plaintext);
  return wire;
}

async function e2eRetryQueuedDm(target,cid,oldWire,meta,isQueued) {
  const key = meta.k;
  const generation = E2E._lockGen;
  const eligible = () => isQueued() && E2E.keyReady && !_e2eBootStale(generation) &&
    _e2eDmKey(_e2eCanon(target,cid) || _e2eK(target),cid) === key && E2E.state?.dm?.[key]?.on !== 0 &&
    !!E2E.trustStore[key]?.fingerprint && !E2E.trustStore[key]?.keyChanged &&
    e2eTargetState(target,{conn_id:cid}).mode === 'dm';
  const current = () => eligible() && _e2eQueuedPinMatches(key,E2E.dmSessions[key],meta.fp);
  if (!eligible()) return null;
  return _withRatchetLock(key,async () => {
    if (_e2eMovedPending(key)) {
      await _e2eAdoptMovedInner(key);
      if (_e2eMovedPending(key)) { _e2eNoteWires([oldWire],meta); return {wait:true}; }
    }
    if (E2E._sessionSyncRepair.has(key)) return null;
    const session = E2E.dmSessions[key];
    if (!session) return null;
    const fingerprint = await _e2eSessFp(session);
    if (fingerprint !== meta.fp || !current()) return null;
    const data = await _e2eGcmDec(E2E.e2eEncKey,meta.sealed,_e2eQueuedDmAAD(key,oldWire));
    try {
      if (!current() || data.byteLength > _e2eMaxPlain('dm',_e2eWireBudget(target,cid))) return null;
      const header = session.x3dhPending;
      const identityRevision = _e2eIdentityRevisions.get(E2E.identityKeys);
      const headers = header && !_e2eRetriedHeaders.has(header) ? _e2eHeaderLines(header,target,cid) : [];
      if (E2E.dmSessions[key] !== session) return null;
      const retries = (meta.retries || 0) + 1;
      const wire = await _e2eEncryptDmWire(key,target,cid,new TextDecoder().decode(data),retries < E2E_QUEUED_RETRIES,current,retries);
      if (!current()) return null;
      return {wire,headers,identityRevision,isCurrent:current,markHeaderQueued:()=>{
        if (headers.length) {
          _e2eRetriedHeaders.add(header);
          _e2eMarkHeaderQueued(key,header);
        }
      }};
    } catch (error) {
      if (current() && _e2eMovedPending(key)) { _e2eNoteWires([oldWire],meta); return {wait:true}; }
      throw error;
    } finally { data.fill(0); }
  });
}
const _e2eRetriedHeaders = new WeakSet();

// A pre-upgrade recipient may already have consumed the old one-time prekey
// in a page that has since closed. Its next ordinary send needs a fresh offer.
// Let the normal restart path confirm the account and saved revision first.
async function _e2eRefreshLegacyRestart(target,peer,cid) {
  const previous=E2E.dmSessions[peer], anchor=_e2eLegacyPendingStart(previous);
  if (!anchor) return true;
  const identity=E2E.identityKeys, generation=E2E._lockGen, account=_e2eUser();
  const pin=E2E.trustStore[peer]?.fingerprint;
  const trusted=()=>E2E.keyReady && !_e2eBootStale(generation) && E2E.identityKeys===identity && _e2eUser()===account &&
    E2E.state?.dm?.[peer]?.on===1 && pin && E2E.trustStore[peer]?.fingerprint===pin && !E2E.trustStore[peer].keyChanged;
  const current=()=>trusted() && E2E.dmSessions[peer]?.startEph===previous.startEph &&
    _e2eLegacyPendingStart(E2E.dmSessions[peer])===anchor && _e2eSessPinMismatch(peer,E2E.dmSessions[peer])===false;
  const valid=session=>trusted() && !!session?.startEph && _e2eSameSessionIdentity(previous,session) &&
    _e2eSessPinMismatch(peer,session)===false;
  const confirmed=session=>valid(session) && session.startEph===previous.startEph && !!session.CKr && !session.x3dhPending;
  const ready=()=>e2eTargetState(target,{conn_id:cid}).mode==='dm';
  if (!await _e2eUsesCurrentIdentity(previous)) return false;
  if (!current()) return confirmed(E2E.dmSessions[peer]) && ready();
  const migration={current,confirmed};
  const result=new Promise(resolve=>{migration.done=resolve;});
  let timer;
  try {
    await _e2eRunEncryptCommand(['restart',target],cid,target,_dmTarget(target),migration);
    if (migration.pending && E2E._pendingOn?.[peer]===migration.pending) {
      await Promise.race([result,new Promise(resolve=>{timer=setTimeout(resolve,E2E_BRIDGE_CLIENT_WAIT+5000);})]);
    }
    const next=E2E.dmSessions[peer];
    return (confirmed(next) || (valid(next) && next.startEph!==previous.startEph && !_e2eLegacyPendingStart(next))) && ready();
  } finally {
    clearTimeout(timer);
    if (migration.pending && E2E._pendingOn?.[peer]===migration.pending) {
      delete E2E._pendingOn[peer];
      updateE2EIndicator(target);
    }
  }
}

async function e2eEncryptReaction(target, plaintext, connId, mode) {
  const canonical = _e2eCanon(target,connId) || _e2eK(target);
  if (mode === 'psk') return channelEncrypt(_e2ePskSlot(canonical,connId),plaintext,getNick(connId),true,connId);
  const key = _e2eDmKey(canonical,connId);
  return E2E_REACTION_DM_PREFIX + btoa(JSON.stringify(await ratchetEncrypt(key,plaintext,true)));
}

// connId: the connection the caller sends on (r2 NEW-8 — the async senders, e.g. an
// upload finishing while another window is active, pass theirs; default: the active
// one, captured BEFORE any await). opts.verb: 'NOTICE' for /notice (default PRIVMSG).
async function e2eEncryptOutgoing(target, plaintext, connId, opts) {
  E2E.lastBlockReason = null;
  let cid = connId || null;
  if (!cid) { try { cid = (active && active.conn_id) || null; } catch (_) {} }
  const verb = opts && String(opts.verb || '').toUpperCase() === 'NOTICE' ? 'NOTICE' : 'PRIVMSG';
  if (opts?.auto && opts.approval && !opts.approval.signalHeld &&
      (!String(plaintext).startsWith('\x01') || String(plaintext).startsWith('\x01ACTION ')) &&
      await _e2eTryPlainReply(target,cid,opts.approval)) return null;
  // r6: right after a reconnect, wait (≤ 8 s) for the E2E re-sync instead of refusing.
  if (E2E._resyncPending && E2E.keyReady) { _e2eKickResync(); await _e2eResyncWait(8000); }
  // r3 (codex-p3 HIGH e2e.js:2816): the E2E name this spelling resolves to on this
  // network (#foo{ → the key held for #foo[ on an RFC1459 network). e2eTargetState
  // blocks an ambiguous one and STATUSMSG / nick@host forms of E2E targets.
  const canonical = _e2eCanon(target, cid) || _e2eK(target);
  const isDM = !_e2eIsChan(canonical) && !String(target || '').includes(',');
  let k = isDM ? _e2eDmKey(canonical, cid) : canonical;
  // A manual enable can fail while the send waits for a stored session.
  // Retain the protected draft before that wait can hide the pending enable.
  let pending = isDM && E2E._pendingOn?.[k];
  const draftCurrent = opts?.approval?.draftCurrent;
  if (pending?.settled && draftCurrent && pending.draftCurrent && !pending.draftCurrent()) {
    // An edited and resubmitted draft can use the in-flight discovery after the
    // previous attempt releases it. Keep manual Signal setup independent.
    await pending.settled;
    if (!draftCurrent()) return _e2eBlock(null, 'superseded');
    pending = E2E._pendingOn?.[k];
  }
  if (pending && !pending.done) {
    const state=e2eTargetState(target,{conn_id:cid});
    if (!pending.closing && state.mode==='blocked') opts?.approval?.holdSignal?.(cid,target);
    if (pending.checking || state.signalDisabled) {
      return _e2eBlock(state.reason || 'Checking Signal encryption. Your message was held.');
    }
  }
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
  if (isDM) k = _e2eDmKey(canonical, cid);
  if (isDM && E2E.dmSessions[k]) { try { await _e2eSessFp(E2E.dmSessions[k]); } catch (_) {} }   // r7: for the pin comparison
  let st = e2eTargetState(target, { conn_id: cid });
  // A late off setting can outlive another device's newly saved ratchet.
  // Check the canonical slot before making an explicitly off DM plaintext.
  if (isDM && E2E.keyReady && E2E.state?.dm?.[k]?.on===0 && (st.mode==='none' || st.signalInventory)) {
    const slot=await e2eCheckOptOutSlot(target,cid,k);
    if (slot==='unknown')
      return _e2eBlock('Could not confirm the Signal setting for this chat. Your draft is still here. Try again when connected.');
    if (slot==='active'||slot==='enabling') {
      opts?.approval?.holdSignal?.(cid,target);
      return _e2eBlock(_e2eBundleFailure(target,slot==='enabling'?'enabling':'active-while-off'));
    }
    st=e2eTargetState(target,{conn_id:cid});
    if (st.mode==='none') opts?.approval?.confirmedOff?.(k);
  }
  if (st.pskInventory) {
    const slot = st.pskInventory, generation = E2E._lockGen;
    const check = _e2ePskInventoryChecks.get(slot);
    await check?.promise;
    st = e2eTargetState(target, { conn_id: cid });
    const key = E2E.channelKeys[slot];
    if (!check || _e2eBootStale(generation) || st.mode !== 'psk' || _e2ePskSlot(canonical,cid) !== slot ||
        E2E._chanKeyGen[slot] !== check.write.generation || _e2ePskIds.get(key) !== check.write.id ||
        _e2ePskScopes.get(key) !== check.write.scope) {
      return _e2eBlock(st.reason || 'The shared key changed while preparing this message. Try sending it again.');
    }
  }
  // A responder session can be mid-establishment (its first incoming message being
  // decrypted under the ratchet lock): wait for in-flight ratchet work, then re-check.
  if (st.mode === 'blocked' && st.waitable) {
    await _withRatchetLock(k, async () => {});
    if (isDM) k = _e2eDmKey(canonical, cid);
    if (isDM && E2E.dmSessions[k]) { try { await _e2eSessFp(E2E.dmSessions[k]); } catch (_) {} }
    st = e2eTargetState(target, { conn_id: cid });
  }
  const approvedPart = opts?.approval?.plain;
  if (approvedPart && !_e2ePlainApprovalValid(approvedPart,cid,target)) {
    return _e2eBlock('Encryption changed while preparing this message. Try sending it again.');
  }
  if (st.signalDisabled) opts?.approval?.holdSignal?.(cid,target);
  if (st.mode === 'none' && opts?.approval?.signalHeld) return _e2eBlock(_e2eBundleFailure(target,'disabled-elsewhere'));
  if (!approvedPart && st.mode === 'none' && isDM && opts?.auto && (!String(plaintext).startsWith('\x01') || String(plaintext).startsWith('\x01ACTION '))) {
    const gen = E2E._lockGen;
    const result = await _e2eAutoStart(target, k, cid, opts.approval, opts.namedStatusQuery);
    if (result === 'approval-expired' && draftCurrent && !draftCurrent()) return _e2eBlock(null, 'superseded');
    if (result === 'unlock') {
      void e2ePromptDeviceUnlock();
      return _e2eBlock('Unlock encrypted chats, then send this message again.');
    }
    if (result === 'settings-locked') return _e2eBlock('Unlock encrypted chats to confirm this chat’s encryption settings.', 'unlock');
    if (result === 'peer-offline') return _e2eBlock(_e2eBundleFailure(target,result), 'offline');
    if (result === 'disabled-elsewhere') opts.approval?.holdSignal?.(cid,target);
    if ((result !== 'ready' && result !== 'missing') || _e2eBootStale(gen)) {
      return _e2eBlock(_e2eBundleFailure(target, result));
    }
    st = e2eTargetState(target, { conn_id: cid });
    k = _e2eDmKey(canonical, cid);
    if (result === 'ready' && st.mode !== 'dm') return _e2eBlock('The encrypted session is no longer available.');
  }
  if (st.mode === 'none') return null;
  if (st.mode === 'blocked') return _e2eBlock(st.reason, st.discovery ? 'checking' : st.readiness);
  const budget = _e2eWireBudget(target, cid);
  if (st.mode === 'psk') {
    try {
      let me = null;
      try { if (typeof getNick === 'function' && cid) me = getNick(cid) || null; } catch (_) {}
      const pieces = _e2eSplit(String(plaintext), _e2eMaxPlain('psk', budget));
      const slot = _e2ePskSlot(canonical,cid);
      const scope = _e2ePskConversation(canonical,me,canonical,cid,_e2ePskSendBinding(slot,cid,E2E.channelKeys[slot]));
      if (!scope) return _e2eBlock('Shared-key network scope is unavailable. Generate and share a new key code for this network.');
      const meta = {mode:'psk',k:slot,key:E2E.channelKeys[slot],gen:E2E._chanKeyGen[slot],
        scope};
      return await _e2eEmitPieces(target,pieces,p=>channelEncrypt(slot,p,me,false,cid),cid,verb,opts?.defer,meta);
    } catch(e) { console.error('[E2E] PSK encrypt failed:', e); return _e2eBlock('Encryption failed — message not sent'); }
  }
  // Signal-style DM encryption.
  try {
    if (_e2eLegacyPendingStart(E2E.dmSessions[k]) && !await _e2eRefreshLegacyRestart(target,k,cid)) {
      return _e2eBlock('The previous Signal session could not be refreshed. Your message was held. Try again when connected.');
    }
    const pieces = _e2eSplit(String(plaintext), _e2eMaxPlain('dm', budget));
    const wire = await _withRatchetLock(k,async () => {
      if (!await _e2eReadyToSendInner(k)) throw new Error('Signal is syncing with another device. Try again shortly.');
      const session = E2E.dmSessions[k];
      if (!session) throw new Error('Signal session changed');
      await _e2eSessFp(session);
      if (E2E.dmSessions[k] !== session || e2eTargetState(target,{conn_id:cid}).mode !== 'dm') throw new Error('Signal session changed');
      if (session.x3dhPending) _e2eSendHeader(target,session,cid);
      return _e2eEmitPieces(target,pieces,p=>_e2eEncryptDmWire(k,target,cid,p,true),cid,verb,opts?.defer);
    });
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
  const generation=E2E._lockGen;
  const release=async it=>{
    if (_e2eBootStale(generation) || !E2E.identityReady || Date.now()-it.t>30*60*1000) return;
    try {
      if (it.kind === 'relay') {
        if(it.prefix) _e2eNoteSenderPrefix(_e2eDmKey(it.from,it.conn_id),it.prefix);
        await _e2eHandleHeader(it.from, it.header, it.via || 'relay', it.conn_id);
        return;
      }
      const r = await e2eDecryptIncoming(it.from, it.target, it.text, { conn_id: it.conn_id, live: false, held: true, prefix:it.prefix });
      if (!_e2eBootStale(generation) && r && r.encrypted && typeof r.plaintext === 'string' && !r.duplicate) {
        _e2eShowDecrypted(it.conn_id,it.target,it.from,r.plaintext,`🔐 The next message from ${it.from} arrived while E2E was locked here:`,
          r.reactionReady?it:null);
      }
    } catch (e) { console.warn('[E2E] held message failed:', e && e.message); }
  };
  for (const item of items) {
    if(typeof _e2eEnqueue==='function') void _e2eEnqueue(item.conn_id,item.from,()=>release(item));
    else await release(item);
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
function _e2eShowDecrypted(connId, peer, from, text, note, history) {
  const a = e2eSplitAction(text);
  let cid = connId || null;
  if (!cid) { try { cid = (active && active.conn_id) || null; } catch (_) {} }
  const wire = history?.text;
  if (wire && (!E2E.keyReady || (typeof isIgnored === 'function' && isIgnored(history.from,history.prefix)))) return;
  if (note) { try { sysMsg(cid, peer, note, 'system'); } catch (_) { _e2eSys(peer, note); } }
  try {
    if (typeof addMessage === 'function' && cid) {
      const blocked = wire && typeof getPmSettings === 'function' && getPmSettings(cid).enabled && !isPmAllowedFor(cid,history.from);
      if (wire && !blocked) void e2eRememberDmHistory(connId,history.target,history.from,wire,text);
      if (wire && typeof applyHeldDmHistory === 'function' && applyHeldDmHistory(connId,history.target,history.from,wire,text)) return;
      const row={ts:Math.floor(Date.now()/1000),from,text:a.text,kind:a.action?'action':'privmsg',encrypted:true,
        _dmHistoryWire:wire,_dmHistoryState:wire?'ready':undefined};
      addMessage(cid,peer,row);
      if (wire && !blocked && typeof restoreSignalReactionReference==='function') {
        void restoreSignalReactionReference(cid,row).then(()=>{ if(row.reactionRef) refreshReactionRows(cid,peer,row.reactionRef); });
      }
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

function e2eLiveResumeCheck(from,cid) {
  const pending=E2E._pendingOn?.[_e2eDmKey(from,cid)];
  return pending?.resumeResult && pending.cid===cid && pending.current() ? pending : null;
}

function _e2eResumeMessageId(envelope,reaction) {
  const header=envelope.h || envelope.header;
  if (!Number.isSafeInteger(header.n) || header.n<0) return null;
  try {
    const ratchet=bytesToBase64(base64ToBytes(header.d || header.dh));
    return JSON.stringify([reaction ? 'reaction' : 'message',ratchet,header.n]);
  } catch (_) { return null; }
}

async function _e2eWaitForResumeDecision(request,ms=10000) {
  let timer;
  try {
    return await Promise.race([request.resumeResult,new Promise(resolve=>{
      timer=setTimeout(()=>resolve('blocked'),Math.max(0,ms));
    })])==='resumed';
  } finally { clearTimeout(timer); }
}

function _e2eAcceptedResumeCurrent(key,from,opts) {
  const request=opts.resume, ticket=request?.accepted;
  return !!ticket && request.current() && request.peer===key && request.cid===opts.conn_id &&
    Date.now()-request.t<30000 && E2E.identityKeys===ticket.identity && E2E.state?.dm?.[key]?.on===1 &&
    !E2E._pendingOn?.[key]?.closing && _e2eAllowHeldDm(opts.conn_id,from,opts.prefix) &&
    E2E.trustStore[key]?.fingerprint===ticket.pin && !E2E.trustStore[key].keyChanged &&
    E2E.dmSessions[key]?.startEph===ticket.start && !E2E.dmSessions[key]?._unusable;
}

// An already-open sibling may have consumed this authentic live message while
// Resume was checking the account. Use only the state from the start of this
// user's request and leave the newer live sending and receiving chains intact.
async function _e2eOpenResumeEnvelope(key,from,messageId,envelope,opts) {
  const request=opts.resume, ticket=request?.accepted;
  if (!opts.live || !ticket) return null;
  const allowed=()=>_e2eAcceptedResumeCurrent(key,from,opts);
  return _withRatchetLock(key,async()=>{
    if (!allowed() || request.opened.has(messageId) || request.opened.size>=E2E_MAX_SKIP) return null;
    for (const blob of new Set([request.beforeAdvance,request.before])) {
      if (!blob || !allowed()) continue;
      const source=await _e2eInstallStoredInner(key,blob,null,{
        allowed,candidateOnly:true,enableFromOff:true,resumeAgainst:E2E.dmSessions[key]
      });
      if (!source || !allowed()) continue;
      try {
        const result=await _ratchetDecryptInner(key,envelope,{
          candidate:source,reaction:!!opts.reaction,historyCurrent:allowed,historySave:()=>{}
        });
        if (!allowed()) return null;
        request.opened.add(messageId);
        return result;
      } catch (_) { /* A snapshot taken on the other side of this message can still open it. */ }
    }
    return null;
  });
}

// opts: { conn_id: the connection it arrived on, live: a message arriving now (not
// history / a daemon replay), held: re-processing something held while locked }.
// Result: { plaintext, encrypted, duplicate? } — duplicate: an exact repeat of a live
// encrypted channel message already shown (drop it).
async function e2eDecryptIncoming(from, target, text, opts = {}) {
  if (opts.reaction && !E2E.keyReady) return { plaintext:null, encrypted:false };
  const isDM = !_e2eIsChan(target);
  let fk = _e2eK(from);
  let me = '';
  try { if (typeof getNick === 'function') { const cid = opts.conn_id || (active && active.conn_id); if (cid) me = _e2eK(getNick(cid)); } } catch (_) {}

  // Pre-shared key decryption — works for both channels and DMs
  if (text.startsWith(opts.reaction ? E2E_REACTION_PSK_PREFIX : E2E_CHAN_PREFIX)) {
    // r6 (codex-p3 e2e.js:3129): never with E2E locked here — a key that slipped back
    // into memory after the wipe must not decrypt anything while the device is locked.
    if (!E2E.keyReady) return { plaintext:'🔐 [encrypted — E2E is locked on this device: /encrypt unlock]', encrypted:true, pskStatus:'locked' };
    // For DMs, the PSK is stored under the sender's nick. r3: resolved under the
    // network's casemapping (the server relays its own spelling of the channel).
    // r4 (SEC-HOOK-W1): receive side → the network's REAL casemapping (_e2eRecvName).
    const pskTarget = _e2eRecvName(isDM ? from : target, opts.conn_id);
    const po = {live:!!opts.live,self:!!me && fk === me,reaction:!!opts.reaction,conn_id:opts.conn_id,recipient:opts.recipient ?? me};
    const generation = E2E._lockGen;
    let name = _e2ePskSlot(pskTarget,opts.conn_id), key = E2E.channelKeys[name], keyGeneration = E2E._chanKeyGen[name];
    let r = await channelDecryptEx(name, text, from, po);
    const targetSlot = _e2ePskSlot(target,opts.conn_id);
    if ((!r || r.authFailed || r.pending) && isDM && targetSlot!==name && E2E.channelKeys[targetSlot] && !_e2eBootStale(generation)) {
      name = targetSlot; key = E2E.channelKeys[name]; keyGeneration = E2E._chanKeyGen[name];
      r = await channelDecryptEx(name, text, from, po);
    }
    if (!E2E.keyReady || _e2eBootStale(generation)) return opts.reaction ? {plaintext:null,encrypted:false} :
      {plaintext:'🔐 [encrypted — E2E is locked on this device: /encrypt unlock]',encrypted:true,pskStatus:'locked'};
    if (key && !_e2ePskKeyCurrent(name,key,keyGeneration)) return opts.reaction ? {plaintext:null,encrypted:false} :
      {plaintext:'🔐 The shared key changed while opening this message. It requires the shared key used when it was sent.',encrypted:true,pskStatus:'needs-key'};
    if (r) {
      if (r.replay) return { plaintext: null, encrypted: true, duplicate: true };
      if (opts.reaction && (!r.verified || r.old)) return { plaintext:null, encrypted:false };
      if (r.old && opts.live) return {plaintext:'🔐 A shared-key message was withheld because its timestamp is outside the allowed window. Check the device clocks or open chat history.',encrypted:true,pskStatus:'old'};
      return { plaintext:_e2ePskShown(r,from),encrypted:!r.bad,reactionReady:r.verified&&!r.old,
        pskStatus:r.bad?'refused':(r.pending||r.authFailed)?'needs-key':'ready' };
    }
    if (opts.reaction) return { plaintext:null, encrypted:false };
    if (!E2E.keyReady) return { plaintext:'🔐 [encrypted — E2E is locked on this device: /encrypt unlock]', encrypted:true, pskStatus:'locked' };
    return { plaintext:isDM
      ? '🔐 Shared-key message could not be opened. Check that both sides use the same shared key or agree to use Signal encryption.'
      : '🔐 Shared-key message could not be opened. Check the channel’s shared key.', encrypted:true, methodConflict:isDM, pskStatus:'needs-key' };
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
  const fkExact = _e2eDmKey(fk, opts.conn_id);
  const fromNick = fk;
  fk = fkExact;
  let remapped = false;
  if (isDM && opts.prefix && (text.startsWith(E2E_HDR_PREFIX) || text.startsWith(E2E_DM_PREFIX))) _e2eNoteSenderPrefix(fkExact, opts.prefix);   // r4 (N5): /ignore check
  const dmPrefix = opts.reaction ? E2E_REACTION_DM_PREFIX : E2E_DM_PREFIX;
  if (isDM && text.startsWith(dmPrefix)) {
    const c = _e2eDmKey(_e2eRecvName(from, opts.conn_id), opts.conn_id);
    if (c && c !== fk) { fk = c; remapped = true; }
  }

  // X3DH header (sent before the first encrypted message): fragmented or single-line.
  if (!opts.reaction && isDM && text.startsWith(E2E_HDR_PREFIX)) {
    let hdr = null;
    if (text.startsWith(E2E_HDR_FRAG)) hdr = _e2eHdrFragment(from, text, opts.conn_id);
    else { try { hdr = JSON.parse(atob(text.slice(E2E_HDR_PREFIX.length))); } catch (e) { console.error('[E2E] x3dh header parse failed:', e); } }
    if (hdr && E2E.identityReady && E2E.identityKeys) await _e2eHandleHeader(from, hdr, 'irc', opts.conn_id);
    else if (hdr && !opts.held) _e2eHoldLocked({ kind: 'relay', from, header: hdr, conn_id:opts.conn_id, via:'irc', prefix:opts.prefix });
    return { plaintext: null, encrypted: false }; // don't display the header message
  }

  if (isDM && text.startsWith(dmPrefix)) {
    let envelope;
    try { envelope = JSON.parse(atob(text.slice(dmPrefix.length))); } catch (_) { envelope = null; }
    const valid=_e2eEnvelopeOk(envelope);
    const messageId=valid && opts.resume ? _e2eResumeMessageId(envelope,opts.reaction) : null;
    if (!valid || (opts.resume && !messageId)) {
      return opts.reaction ? { plaintext:null, encrypted:false } :
        { plaintext:'🔐 [invalid encrypted message — ignored]', encrypted:true };
    }
    const liveReceive=!!opts.live && !opts.held && !opts.recovering;
    if (opts.resume?.opened.has(messageId)) return {plaintext:null,encrypted:true,duplicate:true};
    // A reaction can use an established session, but cannot start one or queue a trust prompt.
    if (opts.reaction) {
      const session = E2E.dmSessions[fk];
      if (!E2E.keyReady || !E2E.identityReady || E2E.state?.dm?.[fk]?.on === 0 || !session || session._unusable || envelope.x3dh_header ||
          (session.connId && session.connId !== opts.conn_id) || (opts.resume && (remapped ||
            !_e2eAcceptedResumeCurrent(fk,from,opts) || opts.resume.opened.size>=E2E_MAX_SKIP))) {
        return { plaintext:null, encrypted:false };
      }
      try {
        const plaintext=await _e2eDecryptWithFallback(fk,envelope,liveReceive,{from,opts,remapped});
        if (opts.resume && opts.resume.opened.size<E2E_MAX_SKIP) opts.resume.opened.add(messageId);
        return {plaintext,encrypted:true};
      } catch (_) {
        if (opts.resume) try {
          const plaintext=await _e2eOpenResumeEnvelope(fk,from,messageId,envelope,opts);
          if (plaintext!==null) return {plaintext,encrypted:true};
        } catch (_) { /* The gesture could not be authenticated. */ }
        return {plaintext:null,encrypted:false};
      }
    }
    if (!E2E.identityReady || !E2E.identityKeys) {
      if (!opts.held) _e2eHoldLocked({ kind: 'dm', from, target, text, conn_id: opts.conn_id, prefix:opts.prefix });
      if (opts.live && !opts.held && !E2E.keyReady) {
        _e2eSetupRow(opts.conn_id,from,`🔐 ${from} sent an encrypted DM. Unlock encryption to read it. You can also run /encrypt unlock.`,'unlock',opts.prefix);
      }
      return { plaintext: E2E.keyReady ? '🔐 [E2E identity not loaded on this device — it will be shown when it is]' : '🔐 [encrypted — E2E is locked on this device: /encrypt unlock (it will be shown then)]', encrypted:true, historyPending:true };
    }
    _e2eDmHistoryWires.set(envelope,{from,target,text,prefix:opts.prefix,live:liveReceive && !remapped && !opts.resume});
    let x3dh = null;
    try {
      // #47: x3dh header comes inline (envelope.x3dh_header, legacy) or via a preceding
      // header line / the server relay.
      // r4 (SEC-HOOK-W1): a remapped sender may only use the existing session.
      x3dh = remapped ? null : (envelope.x3dh_header || _e2ePendingHeader(fk));
      const generation = E2E._lockGen;
      const disabled = () => E2E.state?.dm?.[fk]?.on === 0;
      const allowed = () => E2E.keyReady && !_e2eBootStale(generation) && !disabled();
      // Synchronize with other tabs and lazily recover stored sessions only while
      // this conversation is allowed to resume. An explicit opt-out wins over an old slot.
      const archivePlaintext = !x3dh && !disabled() ? await _withRatchetLock(fk, async () => {
        if (!allowed() || E2E.dmSessions[fk]) return;
        E2E._lazyTried = E2E._lazyTried || Object.create(null);
        if (!E2E._lazyTried[fk] && Object.keys(E2E._lazyTried).length >= E2E_STRANGER_MAX) E2E._lazyTried = Object.create(null);   // r8: bounded
        const slot = '__legacy__' + fk;
        if (!E2E._lazyTried[fk]) {
          const lookup = E2E._lazyTried[fk] = {};
          const blob = await _e2eFetchSession(fk);
          if (!allowed()) return;
          if (blob && await _e2eInstallStoredInner(fk, blob, null, {allowed})) {
            if (allowed()) _e2eStateSetDm(fk, true);
          } else if (allowed() && !_e2eReservedNamespace(fk)) {
            lookup.archive = await _e2eFetchSession(slot);
          }
        }
        const lookup = E2E._lazyTried[fk];
        if (!allowed() || !lookup?.archive) return;
        const candidate = await _e2eInstallStoredInner(fk,lookup.archive,slot,{allowed,candidateOnly:true});
        if (!candidate || !allowed()) return;
        // An archived ratchet is only a candidate until the current message
        // authenticates. A failure keeps the sealed lookup available for retry.
        delete candidate.recent;
        const plaintext = await _ratchetDecryptInner(fk,envelope,{candidate,create:true,historyCurrent:allowed});
        if (!allowed() || !E2E.dmSessions[fk]) return;
        delete lookup.archive;
        _e2eStateSetDm(fk,true);
        _e2eWs({type:'e2e_delete_session',v:E2E_STORAGE_VERSION,partner:slot},allowed);
        return plaintext;
      }) : undefined;
      if (archivePlaintext !== undefined) return {plaintext:archivePlaintext,encrypted:true,reactionReady:true};
      // r2 (codex-p3 MED e2e.js:2485): at most ONE header wait per peer at a time, and
      // none for a minute after a wait for that peer timed out (a sender spraying
      // envelopes); those are held as orphans right away (shown if a header ever arrives
      // — a late header still decrypts them). app.js
      // now also queues per conversation, so a wait never delays anybody else's chat.
      E2E._hdrWait = E2E._hdrWait || Object.create(null);
      if (!E2E._hdrWait[fk]) _e2eSweepStrangerState();   // r8
      const hw = E2E._hdrWait[fk] || (E2E._hdrWait[fk] = { busy: false, fails: [] });
      hw.fails = hw.fails.filter(t => Date.now() - t < 60000);
      if (!opts.recovering && !remapped && !x3dh && !disabled() && !E2E.dmSessions[fk] && !hw.busy && hw.fails.length < 1) {
        hw.busy = true;
        try {
          x3dh = await new Promise(resolve => {
            const pending = _e2ePendingHeader(fk);
            if (pending) { resolve(pending); return; }
            if (!E2E._x3dhWaiters) E2E._x3dhWaiters = Object.create(null);
            const timeout = setTimeout(() => { delete E2E._x3dhWaiters[fk]; resolve(null); }, 3000);
            E2E._x3dhWaiters[fk] = (hdr) => { clearTimeout(timeout); delete E2E._x3dhWaiters[fk]; resolve(hdr); };
          });
        } finally { hw.busy = false; }
        if (!x3dh) hw.fails.push(Date.now());
      }

      if (x3dh && _e2eHeaderNetworks.has(x3dh) && _e2eHeaderNetworks.get(x3dh) !== opts.conn_id) x3dh = null;
      if (!x3dh && disabled()) {
        // A live reply may arrive after the user clicks Resume but before the
        // saved ratchet comes back. Keep it in the conversation's receive queue
        // until that particular decision finishes. It cannot initiate a session.
        const request = opts.resume || E2E._pendingOn?.[fk], pin = E2E.trustStore[fk]?.fingerprint;
        let resumed = false;
        if (opts.live && !remapped && request?.resumeResult && request.current() && request.cid===opts.conn_id &&
            pin && !E2E.trustStore[fk].keyChanged && _e2eAllowHeldDm(opts.conn_id,from,opts.prefix)) {
          resumed = await _e2eWaitForResumeDecision(request);
        }
        const resumedSession = E2E.dmSessions[fk];
        if (!resumed || !request.current() || !allowed() || E2E.trustStore[fk]?.fingerprint!==pin || E2E.trustStore[fk]?.keyChanged ||
            E2E._pendingOn?.[fk]?.closing || !resumedSession?.RK || resumedSession._unusable || _e2eSessPinIs(resumedSession,pin)!==true ||
            !_e2eAllowHeldDm(opts.conn_id,from,opts.prefix)) {
          return {plaintext:`🔐 Signal is off for ${from}. Run /encrypt on ${from} if you want to resume encrypted messages.`,encrypted:true};
        }
      }
      const scoped = E2E.dmSessions[fk];
      if (scoped?.connId && scoped.connId !== opts.conn_id) {
        return { plaintext:'🔐 [encrypted message on a different network — ignored]', encrypted:true };
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
            const pt = await _e2eDecryptWithFallback(fk, envelope,liveReceive);
            if (existing.establishEph === x3dh.ephemeral_pub) _e2eForgetPendingHeader(fk,x3dh);
            const tr0 = E2E.trustStore[fk];
            if (tr0 && tr0.keyChanged) _e2eSys(from, `⚠️ ${from} recently presented a DIFFERENT identity key (not accepted). The message above was authenticated with the key you already trust. /encrypt accept ${from} or /encrypt reject ${from}`);
            return { plaintext:pt, encrypted:true, reactionReady:true };
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
            const r = await _e2eEstablishAndDecrypt(from,x3dh,envelope,{alt:true,live:liveReceive,connId:opts.conn_id,
              expectedFingerprint:opts.expectedFingerprint,historySuccessor:opts.historySuccessor});
            if (!r.ok) return _e2eRefusedResult(fk,r,x3dh,envelope,from,opts);
            _e2eForgetPendingHeader(fk,x3dh);
            return { plaintext:r.pt, encrypted:true, reactionReady:true };
          }
        }
        // #1: authenticate the sender identity (TOFU pin / key-change refusal) BEFORE
        // establishing and decrypting. #3: the new session is bound to this first message
        // (the prior session is restored if it doesn't decrypt), and establishment +
        // first decrypt run under ONE ratchet lock, so an outgoing message can't slip in
        // between and find a half-built (not yet send-ready) responder session.
        const r = await _e2eEstablishAndDecrypt(from,x3dh,envelope,{connId:opts.conn_id,live:liveReceive,expectedFingerprint:opts.expectedFingerprint});
        if (!r.ok) return _e2eRefusedResult(fk,r,x3dh,envelope,from,opts);
        _e2eForgetPendingHeader(fk,x3dh);
        if (E2E._glareAlt) delete E2E._glareAlt[fk];
        updateE2EIndicator(from);
        return { plaintext:r.pt, encrypted:true, reactionReady:true };
      }

      const live = E2E.dmSessions[fk];
      if (!live && !_e2ePrefersSignal(fk) && _e2eSharedKeyConfigured(_e2eCanon(from,opts.conn_id) || _e2eK(from),opts.conn_id)) {
        return { plaintext:E2E_SHARED_KEY_CONFLICT, encrypted:true, methodConflict:true,
          historyPending:!remapped&&(opts.recovering||_e2eHoldDm(fk,envelope,opts.conn_id)) };
      }
      if (!live && remapped) return { plaintext:`🔐 [encrypted — cannot decrypt: no encryption session with ${from}]`, encrypted:true };
      if (!live) {
        // Header not here (yet): hold the envelope (≤20/peer, 10 min) and decrypt it as
        // soon as a header for this peer establishes a session.
        const waiting = opts.recovering || _e2eHoldDm(fk,envelope,opts.conn_id);
        return { plaintext:'🔐 [encrypted — waiting for the key exchange]', encrypted:true, historyPending:waiting };
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
      try { pt = await _e2eDecryptWithFallback(fk, envelope,liveReceive); }
      catch (e) {
        // r2 (NEW-7): another device of this account answered on this session: adopt
        // its copy and try once more.
        if (_e2eMovedPending(fk) && await _e2eAdoptMoved(fk)) {
          try { pt = await _e2eDecryptWithFallback(fk,envelope,liveReceive); }
          catch (retryError) { if (!opts.resume) throw retryError; }
        }
        if (pt===undefined && opts.live && !remapped && opts.resume) {
          pt=await _e2eOpenResumeEnvelope(fk,from,messageId,envelope,opts);
        }
        if (pt==null) throw e;
      }
      if (opts.resume && opts.resume.opened.size<E2E_MAX_SKIP) opts.resume.opened.add(messageId);
      const tr = E2E.trustStore[fk];
      if (tr && tr.keyChanged) _e2eSys(from, `⚠️ ${from} recently presented a DIFFERENT identity key (not accepted). The message above was authenticated with the key you already trust. /encrypt accept ${from} or /encrypt reject ${from}`);
      return { plaintext:pt, encrypted:true, reactionReady:true };
    } catch(e) {
      const errMsg = e.message || e.name || String(e);
      if (liveReceive && !remapped && !opts.resume && (e.name==='OperationError' || /^E2E_OTPK_MISSING/.test(errMsg))) {
        try {
          const pt=await _e2eOpenLiveReceipt(fk,from,envelope,opts);
          if (pt!==undefined) return {plaintext:pt,encrypted:true,reactionReady:true};
        } catch (_) { /* Fall through to the original receive failure. */ }
      }
      console.error('[E2E] DM decrypt FAILED:', errMsg, e.stack || e);
      if (/^E2E_(SPK|OTPK)_MISSING/.test(errMsg)) {
        _e2eForgetPendingHeader(fk,x3dh);
        return { plaintext:`🔐 ${from} started Signal encryption with a key this account no longer has. Ask them to restart the Signal session.`, encrypted:true,
          historyPending:!!_e2eDmHistoryWires.get(envelope)?.receiptPending };
      }
      if (e.name === 'OperationError') {
        if (!remapped && (opts.recovering || (!envelope.x3dh_header && _e2eHoldDm(fk,envelope,opts.conn_id)))) {
          return { plaintext:'🔐 Signal message could not be authenticated yet. CryptIRC will retry if the key exchange arrives. You can also restart the Signal session from Encryption.', encrypted:true,historyPending:true };
        }
        return { plaintext:'🔐 Signal message could not be authenticated. To reconnect, use Restart Signal Session in this chat’s encryption menu.', encrypted:true };
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
  if (isDM && text && fromNick !== me && e2eTargetState(from, { incoming: true, incomingPlain: true, conn_id: opts.conn_id }).mode !== 'none') {
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

// Two open profiles can receive the same competing restart. The first profile
// authenticates the message and retires its one-time prekey for the account.
// Share only that message key with currently unlocked siblings, sealed for the
// exact IRC body. Both competing offers must also be observed on this profile.
const _e2eCrossedStarts = new Map();
const _e2eLiveReceipts = new Map();
const E2E_LIVE_RECEIPT_MS = 60000;
function _e2eKeepLiveReceipt(map,key,value,limit) {
  map.delete(key);
  if (map.size>=limit) map.delete(map.keys().next().value);
  map.set(key,value);
  setTimeout(()=>{if(map.get(key)===value)map.delete(key);},E2E_LIVE_RECEIPT_MS);
}
function _e2eReceiptEnabled(peer,publishing) {
  const dm=E2E.state?.dm;
  // A sibling can have the persisted, pinned initiator and authenticate the
  // peer's message before a separate settings update supplies its DM entry.
  // Opening a receipt on this browser still requires explicit enablement.
  return !!dm && (dm[peer]?.on===1 || (publishing && dm[peer]?.on===undefined));
}
function _e2eNoteCrossedStart(peer,header,cid) {
  const s=E2E.dmSessions[peer],pin=E2E.trustStore[peer];
  if (!s?.isInitiator || s.CKr || !s.x3dhPending?.restart_sig || !s.startEph || s.connId!==cid ||
      header.used_otpk_id==null || !header.ephemeral_pub || header.ephemeral_pub===s.startEph ||
      s.theirIdentityPub!==header.sender_ik || s.theirSignPub!==header.sender_sign_ik ||
      !s.identityAD || !pin?.fingerprint || pin.keyChanged || !s._storeRevision || !_e2eReceiptEnabled(peer,true)) return;
  const old=_e2eCrossedStarts.get(peer);
  if (old?.ours===s.startEph && old.theirs===header.ephemeral_pub) return;
  _e2eKeepLiveReceipt(_e2eCrossedStarts,peer,{ours:s.startEph,theirs:header.ephemeral_pub,header,ad:s.identityAD,
    pin:pin.fingerprint,generation:E2E._lockGen,tombstone:E2E._sessionTombstones.get(peer),
    until:performance.now()+E2E_LIVE_RECEIPT_MS},32);
}
function _e2eCrossedCurrent(peer,pair,from,cid,prefix,publishing=false) {
  const s=E2E.dmSessions[peer], pin=E2E.trustStore[peer];
  return !!pair && _e2eCrossedStarts.get(peer)===pair && pair.until>performance.now() && !_e2eBootStale(pair.generation) &&
    E2E.keyReady && E2E.identityReady && E2E._sessionTombstones.get(peer)===pair.tombstone &&
    _e2eDmKey(from,cid)===peer && _e2eReceiptEnabled(peer,publishing) && !E2E._pendingOn?.[peer]?.closing &&
    _e2eAllowHeldDm(cid,from,prefix) && (_e2ePrefersSignal(peer) || !_e2eSharedKeyConfigured(_e2eCanon(from,cid)||_e2eK(from),cid)) &&
    !!s && !s._unusable && s.connId===cid && s.identityAD===pair.ad &&
    (s.startEph===pair.ours || s.startEph===pair.theirs) && s.theirIdentityPub===pair.header.sender_ik &&
    s.theirSignPub===pair.header.sender_sign_ik && pin?.fingerprint===pair.pin && !pin.keyChanged &&
    _e2eSessPinMismatch(peer,s)===false;
}
function _e2eReceiptContext(peer,digest) {
  return _e2eBlobAAD(JSON.stringify(['live-receipt',_e2eUser(),peer,digest]));
}
async function _e2eShareLiveReceipt(peer,opened,envelope) {
  const wire=_e2eDmHistoryWires.get(envelope),pair=_e2eCrossedStarts.get(peer);
  if (!wire?.live || !pair || !opened || opened.startEph!==pair.theirs || opened.identityAD!==pair.ad) return;
  const cid=opened.connId,scope=()=>_e2eCrossedCurrent(peer,pair,wire.from,cid,wire.prefix,true);
  if (!scope() || !await _e2eUsesCurrentIdentity(opened) || !scope()) return;
  const h=envelope.h, mk=h && opened.recent?.[peer+'/'+h.d+'/'+h.n]?.k;
  if (!mk) return;
  const idHash=_e2eIdentityRevisions.get(E2E.identityKeys), digest=await _e2eSha256Hex(wire.text);
  if (!idHash || !scope()) return;
  const data=new TextEncoder().encode(JSON.stringify({ours:pair.ours,theirs:pair.theirs,ad:pair.ad,mk}));
  try {
    const sealed=await _e2eGcmEnc(E2E.e2eEncKey,data,_e2eReceiptContext(peer,digest));
    if (scope()) _e2eWs({type:'e2e_live_receipt',partner:peer,digest,blob:E2E_BLOB_PREFIX+bytesToBase64(sealed),id_hash:idHash},scope);
  } finally {data.fill(0);}
}
function _e2eNoteLiveReceipt(ev) {
  const k=ev.partner,s=E2E.dmSessions[k],pin=E2E.trustStore[k],scope=_e2eDmScope(k);
  if (!E2E.keyReady || !E2E.identityReady || !scope || !s || s.connId!==scope[1] ||
      E2E.state?.dm?.[k]?.on!==1 || !pin?.fingerprint || pin.keyChanged || !_e2eAllowHeldDm(scope[1],scope[2]) ||
      typeof ev.digest!=='string' || !/^[0-9a-f]{64}$/.test(ev.digest) || typeof ev.blob!=='string' ||
      !ev.blob.startsWith(E2E_BLOB_PREFIX) || ev.blob.length>4096) return;
  const prior=_e2eLiveReceipts.get(ev.digest);
  // Several siblings may seal the same key with different nonces. Keep a
  // single outstanding receipt stable while its authentication is in flight.
  if (prior?.peer===k && prior.blob && prior.until>performance.now()) return;
  _e2eKeepLiveReceipt(_e2eLiveReceipts,ev.digest,{peer:k,blob:ev.blob,until:performance.now()+E2E_LIVE_RECEIPT_MS},64);
  if (prior?.peer===k && prior.until>performance.now()) prior.retry?.();
}
async function _e2eOpenLiveReceipt(peer,from,envelope,opts,stillUnread=null) {
  const pair=_e2eCrossedStarts.get(peer), wire=_e2eDmHistoryWires.get(envelope), h=envelope.h;
  const scope=()=>_e2eCrossedCurrent(peer,pair,from,opts.conn_id,opts.prefix) && (!stillUnread || stillUnread());
  if (!wire?.live || !h || !scope()) return;
  const skipKey=peer+'/'+h.d+'/'+h.n;
  if (E2E._consumed?.has(skipKey)) return;
  const digest=await _e2eSha256Hex(wire.text);
  if (!scope()) return;
  const receipt=_e2eLiveReceipts.get(digest);
  if (!receipt?.blob || receipt.peer!==peer || receipt.until<=performance.now()) {
    if (!stillUnread && typeof _e2eEnqueue==='function' && typeof isUnreadSignalHistory==='function') {
      const sameHistory=_e2eHistoryCurrent(_e2eUser(),_e2eHistoryScope(opts.conn_id,wire.target));
      const unread=()=>sameHistory() && _e2eCrossedStarts.get(peer)===pair &&
        isUnreadSignalHistory(opts.conn_id,wire.target,from,wire.text);
      // A receipt can follow the IRC body on a separate WebSocket stream.
      // Queue behind the ordinary renderer, and replace only that extant row.
      const retry=()=>_e2eEnqueue(opts.conn_id,from,async()=>{
        if (!unread()) return;
        const pt=await _e2eOpenLiveReceipt(peer,from,envelope,opts,unread);
        if (pt!==undefined && unread() && applyHeldDmHistory(opts.conn_id,wire.target,from,wire.text,pt))
          await e2eRememberDmHistory(opts.conn_id,wire.target,from,wire.text,pt);
      }).catch(()=>{});
      _e2eKeepLiveReceipt(_e2eLiveReceipts,digest,{peer,retry,until:performance.now()+E2E_LIVE_RECEIPT_MS},64);
      wire.receiptPending=true;
    }
    return;
  }
  return _withRatchetLock(peer,async()=>{
    const fresh=()=>scope() && receipt.until>performance.now() && !E2E._consumed?.has(skipKey);
    if (!fresh() || !await _e2eUsesCurrentIdentity(E2E.dmSessions[peer]) || !fresh()) return;
    const data=await _e2eGcmDec(E2E.e2eEncKey,base64ToBytes(receipt.blob.slice(E2E_BLOB_PREFIX.length)),_e2eReceiptContext(peer,digest));
    let msg;
    try {msg=JSON.parse(new TextDecoder().decode(data));} finally {data.fill(0);}
    if (msg.ours!==pair.ours || msg.theirs!==pair.theirs || msg.ad!==pair.ad ||
        typeof msg.mk!=='string' || msg.mk.length!==44 || !fresh()) return;
    const mk=base64ToBytes(msg.mk);
    let bytes;
    try {
      if (mk.length!==32) return;
      bytes=await messageDecrypt(mk,base64ToBytes(envelope.c),{dh:h.d,pn:h.p,n:h.n},base64ToBytes(pair.ad));
      if (!fresh()) return;
      const [ownDh]=await _e2ePublicIdentity(E2E.identityKeys);
      if (_e2eCmpBytes(base64ToBytes(ownDh),base64ToBytes(pair.header.sender_ik))>0 && E2E.dmSessions[peer].startEph===pair.ours) {
        // The peer's lower identity won. Its responder ratchet is already
        // committed by the sibling. Use normal epoch and pin checks, and
        // only adopt the account revision for this exact remote offer.
        const stored=await _e2eRequestSession(peer,false,fresh,null,2500);
        if (stored?.blob && fresh() && await _e2eInstallStoredInner(peer,stored.blob,null,{hint:true,allowed:fresh,receiptStart:pair.theirs})===true) {
          E2E._sessionSyncRepair.delete(peer);
        }
      }
      if (!fresh()) return;
      _e2eLiveReceipts.delete(digest);
      _e2eMarkConsumed(skipKey);
      return new TextDecoder().decode(bytes);
    } finally {mk.fill(0);bytes?.fill(0);}
  });
}

async function _e2eEstablishAndDecrypt(from, x3dh, envelope, opts) {
  const fk = _e2eDmKey(from, opts.connId);
  return _withRatchetLock(fk, () => _e2eEstablishInner(from, x3dh, { ...opts, peerKey:fk, envelope }));
}

// A normal message can resolve simultaneous initiation. A reaction can also be
// in flight on the old receive chain while an authenticated restart is pending.
async function _e2eDecryptWithFallback(fk, envelope, liveReceive=false, gesture=null) {
  try {
    const pt = await ratchetDecrypt(fk,envelope,false,!!gesture,liveReceive);
    if (!gesture && E2E._glareAlt?.[fk]) delete E2E._glareAlt[fk];
    return pt;
  } catch (e) {
    if (!gesture && E2E._glareAlt?.[fk]) {
      try {
        const pt=await ratchetDecrypt(fk,envelope,true);
        if (liveReceive) {
          try {await _e2eShareLiveReceipt(fk,E2E._glareAlt?.[fk],envelope);} catch (_) {}
        }
        return pt;
      } catch (_) {}
    }
    if (!E2E.dmSessions[fk]?.x3dhPending) throw e;
    return _withRatchetLock(fk, async () => {
      const restartBase = E2E.dmSessions[fk];
      const gen = E2E._lockGen;
      if (!restartBase?.x3dhPending) throw e;
      const pin=E2E.trustStore[fk]?.fingerprint;
      const allowGesture=()=>!_e2eBootStale(gen) && E2E.keyReady && !gesture.remapped &&
        E2E.dmSessions[fk]?.x3dhPending && E2E.dmSessions[fk].startEph===restartBase.startEph &&
        E2E.state?.dm?.[fk]?.on===1 && pin && E2E.trustStore[fk]?.fingerprint===pin && !E2E.trustStore[fk].keyChanged &&
        restartBase.connId===gesture.opts.conn_id &&
        _e2eAllowHeldDm(gesture.opts.conn_id,gesture.from,gesture.opts.prefix) &&
        (!gesture.opts.resume || _e2eAcceptedResumeCurrent(fk,gesture.from,gesture.opts));
      await _e2eSessFp(restartBase);
      if (_e2eBootStale(gen) || _e2eSessPinMismatch(fk,restartBase) !== false) throw e;
      if (gesture && (!allowGesture() || !await _e2eUsesCurrentIdentity(restartBase))) throw e;
      const alt=gesture && E2E._glareAlt?.[fk];
      if (alt && alt.connId===restartBase.connId && alt.theirIdentityPub===restartBase.theirIdentityPub &&
          alt.theirSignPub===restartBase.theirSignPub && await _e2eUsesCurrentIdentity(alt)) {
        // In simultaneous starts these two established chains have opposite
        // initiators. Verify the pinned identities in each chain's own order.
        const until=_e2eReactionAltExpiry.get(alt);
        const allowed=()=>until>Date.now() && allowGesture() && E2E._glareAlt?.[fk]?.startEph===alt.startEph;
        if (allowed()) try {
          const plaintext=await _ratchetDecryptInner(fk,envelope,{useAlt:true,reaction:true,historyCurrent:allowed});
          if (allowed()) return plaintext;
        } catch (_) { /* The gesture may belong to the pre-restart receive chain. */ }
      }
      const previous=restartBase.restartPrev;
      if (!(previous?.until>Date.now()) || (gesture && !_e2eSameSessionIdentity(restartBase,previous))) throw e;
      const allowedPrevious=()=>previous.until>Date.now() && allowGesture();
      const plaintext=await _ratchetDecryptInner(fk,envelope,{
        restartBase,reaction:!!gesture,historyCurrent:gesture ? allowedPrevious : null
      });
      if (gesture && !allowedPrevious()) throw e;
      return plaintext;
    });
  }
}

function _e2eRefusedResult(fk,r,x3dh,envelope,from,opts) {
  const connId = opts.conn_id;
  if (r.why === 'disabled') return {plaintext:`🔐 Signal is off for this chat. Use /encrypt on ${from} to enable it.`,encrypted:true};
  if (r.why === 'invalid' || r.why === 'rejected') _e2eForgetPendingHeader(fk,x3dh);
  if (r.why === 'shared-key') {
    return { plaintext:E2E_SHARED_KEY_CONFLICT, encrypted:true, methodConflict:true,
      historyPending:opts.recovering||_e2eHoldDm(fk,envelope,connId) };
  }
  if (r.why === 'changed') {
    _e2eStashChanged(fk, x3dh, envelope, connId);
    return { plaintext:`🔐 [message under a CHANGED identity key for ${from} — not decrypted. Verify it, then /encrypt accept ${from}]`, encrypted:true, historyPending:true };
  }
  if (r.why === 'rejected') return { plaintext:'🔐 [encrypted message — identity not accepted]', encrypted:true };
  if (r.why === 'ratelimited') return { plaintext:'🔐 [encrypted message — too many re-handshakes, ignored]', encrypted:true };
  return { plaintext:'🔐 [encrypted message — key exchange refused (invalid header)]', encrypted:true };
}

// ─── /encrypt command ─────────────────────────────────────────────────────────

// Retry while the socket is down (≤2 min). Allow time for the server's 25 s
// IRC bridge lookup and for its reply to reach a briefly delayed browser.
// The target stays blocked while discovery is pending.
const E2E_BRIDGE_CLIENT_WAIT = 45000;
async function _e2eFetchBundleQueued(nick, k, cid) {
  const started = Date.now();
  for (;;) {
    const p = E2E._pendingOn && E2E._pendingOn[k];
    if (!p || p.t > started) return;                     // answered / cancelled / superseded
    if (await _e2eWs({ type:'e2e_fetch_bundle', username:nick, conn_id: cid, req:p.req, wait_for_peer:true }, () => E2E._pendingOn[k] === p)) { p.sentAt = Date.now(); break; }
    if (E2E._pendingOn[k] !== p) return;
    if (Date.now() - started > 120000) {
      delete E2E._pendingOn[k];
      _e2eSys(p.target, p.restart && !p.reopen && e2eTargetState(nick,{conn_id:p.cid}).mode==='dm'
        ? `🔐 Could not reach the server to restart Signal encryption with ${nick}. The existing session stays active.`
        : `🔓 Could not reach the server to set up encryption with ${nick}. Try /encrypt on ${nick} again.`,p.cid);
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
    _e2eSys(p.target, p.restart && !p.reopen && e2eTargetState(nick,{conn_id:p.cid}).mode==='dm'
      ? `🔐 The server did not answer the Signal restart for ${nick}. The existing session stays active.`
      : `🔓 No answer from the server for ${nick}'s key bundle. Try /encrypt on ${nick} again.`,p.cid);
    try { updateE2EIndicator(p.target); } catch (_) {}
  }, Math.max(1000, E2E_BRIDGE_CLIENT_WAIT - (Date.now() - sentAt)));
}

const _e2eAutoBusy = new Map();
const _e2ePlainConnections = new Map();
const _e2eChatProbes = new Map();
const _E2E_CHAT_PROBE_MS = 15000;
const _E2E_NO_BRIDGE_MS = 5 * 60 * 1000;
const _E2E_FIRST_LOOKUP_WAIT = 8000;

function _e2eChatProbeKey(cid,k){
  return String(cid).toLowerCase()+'\n'+k;
}
function _e2eChatProbeCurrent(probe,requireFresh=true){
  return !!probe && _e2eChatProbes.get(probe.key)===probe &&
    _e2ePlainConnections.get(probe.netId)===probe.connection && _e2eUser()===probe.user &&
    !_e2eBootStale(probe.generation) && (!requireFresh || Date.now()<probe.expires);
}
function _e2eDropChatProbe(probe){
  if(_e2eChatProbes.get(probe.key)!==probe) return;
  _e2eChatProbes.delete(probe.key);
  clearTimeout(probe.timer);
  probe.finish?.(null);
}
function e2eForgetChatProbe(cid,...nicks){
  for(const nick of nicks){
    const key=_e2eChatProbeKey(cid,_e2eDmKey(_e2eCanon(nick,cid)||_e2eK(nick),cid));
    const probe=_e2eChatProbes.get(key);
    if(probe) _e2eDropChatProbe(probe);
  }
}
function _e2eResolveChatProbe(ev){
  const netId=String(ev.conn_id||'').toLowerCase();
  for(const probe of _e2eChatProbes.values()){
    if(!probe.finish||probe.req!==ev.req||probe.netId!==netId) continue;
    if(!_e2eChatProbeCurrent(probe)){ _e2eDropChatProbe(probe); return true; }
    if(ev.type==='e2e_bundle' && _e2eChatProbeKey(ev.conn_id,_e2eDmKey(_e2eCanon(ev.username,ev.conn_id)||_e2eK(ev.username),ev.conn_id))!==probe.key)
      return true;
    if(ev.reason==='peer-busy') _e2eNotePeerBusy(probe.key);
    if(ev.reason==='peer-no-bridge') {
      probe.noBridge=true;
      probe.expires=Date.now()+_E2E_NO_BRIDGE_MS;
    }
    clearTimeout(probe.timer);
    probe.finish(ev);
    probe.finish=null;
    return true;
  }
  return false;
}
function _e2eMakeChatProbe(key,netId,connection){
  const old=_e2eChatProbes.get(key);
  if(old) _e2eDropChatProbe(old);
  if(_e2eChatProbes.size>=24) _e2eDropChatProbe(_e2eChatProbes.values().next().value);
  const probe={key,netId,connection,user:_e2eUser(),generation:E2E._lockGen,expires:Date.now()+_E2E_CHAT_PROBE_MS};
  _e2eChatProbes.set(key,probe);
  return probe;
}
function e2ePrepareChatProbe(nick,cid,namedStatusQuery=false,reply=false){
  nick=_e2eRealTarget(nick);
  const scoped=reply&&E2E._vaultUp&&!E2E._serverLocked;
  if(!_wsReady()||(!scoped&&!_e2eCanAllowPlain())||!networks.some(n=>n.config.id===cid&&n.connected)) return;
  const k=_e2eDmKey(_e2eCanon(nick,cid)||_e2eK(nick),cid);
  const netId=String(cid).toLowerCase(), key=_e2eChatProbeKey(cid,k);
  if(_e2eChatProbeCurrent(_e2eChatProbes.get(key))||E2E._pendingOn?.[k]||E2E.trustStore[k]||
      E2E.state?.trust?.[k]?.fp||(_e2eAutoBusy.get(key)||0)>Date.now()||
      !_e2eAutoEligible(nick,k,cid,namedStatusQuery)||
      e2eTargetState(nick,{conn_id:cid,scopedPlainCheck:scoped,incoming:scoped&&!E2E.keyReady}).mode!=='none') return;
  if(!_e2ePlainConnections.has(netId)) _e2ePlainConnections.set(netId,{});
  const probe=_e2eMakeChatProbe(key,netId,_e2ePlainConnections.get(netId));
  probe.reply=reply;
  if(scoped&&(!E2E.keyReady||E2E._bootPhase!=='ready')) probe.deviceKey=_e2eIdbGetKey(probe.user);
  probe.req=_e2eBundleRequestId();
  probe.result=new Promise(resolve=>{probe.finish=resolve;});
  probe.timer=setTimeout(()=>_e2eDropChatProbe(probe),_E2E_FIRST_LOOKUP_WAIT);
  if(!wsend({type:'e2e_fetch_bundle',username:nick,conn_id:cid,req:probe.req,wait_for_peer:false})) {
    _e2eDropChatProbe(probe);
    return;
  }
  return probe;
}
function e2eOnNetworkTransition(connId) {
  const netId=String(connId).toLowerCase();
  _e2ePlainConnections.delete(netId);
  for(const probe of _e2eChatProbes.values()) if(probe.netId===netId) _e2eDropChatProbe(probe);
}
const _e2eRestartRequested = new Map();
const E2E_BRIDGE_RETRY_WINDOW = 60000;
function _e2eNotePeerBusy(key){
  if(_e2eAutoBusy.size>=128) _e2eAutoBusy.delete(_e2eAutoBusy.keys().next().value);
  _e2eAutoBusy.set(key,Date.now()+E2E_BRIDGE_RETRY_WINDOW);
}
function _e2eBundleFailure(nick, reason, restart = false) {
  const retry = `/encrypt ${restart ? 'restart' : 'on'} ${nick}`;
  if (reason === 'peer-offline') return `${nick} is offline.`;
  if (reason === 'identity-changed') return `The identity for ${nick} has changed. Open Encryption and verify this contact before sending.`;
  if (reason === 'unconfirmed') return `The IRC network hasn't delivered a key reply from ${nick}. Check that they're connected, then retry ${retry}.`;
  if (reason === 'disabled-elsewhere') return `Signal isn’t active for this chat. Your draft is still here. Use /encrypt on ${nick} to send encrypted messages, or /encrypt off ${nick} here to allow plaintext.`;
  if (reason === 'active-while-off') return `A saved Signal session still exists for ${nick}. Your draft is still here. Use /encrypt on ${nick} to resume Signal, or /encrypt off ${nick} here to confirm unencrypted chat.`;
  if (reason === 'enabling') return `Encryption or the saved identity for ${nick} changed. Your draft is still here. Use /encrypt on ${nick} for Signal or /encrypt off ${nick} to allow unencrypted messages.`;
  if (reason === 'settings-unavailable') return 'Could not confirm your account’s encryption settings. Try again when connected.';
  if (reason === 'rate-limited') return 'Pause a moment before trying encryption again.';
  if (reason === 'peer-busy') return `${nick}'s encryption is temporarily busy. Try again in a moment.`;
  if (reason === 'peer-setup') return `${nick} needs to set up encryption. Send your message when they’re ready.`;
  if (reason === 'unavailable') return `Encryption with ${nick} is unavailable right now. Ask them to check their encryption settings, then try again.`;
  if (reason === 'loading') return 'Wait for encryption to finish loading, then try your message again.';
  if (reason === 'approval-expired') return 'The encryption check is no longer current. Try sending your draft again.';
  if (reason === 'account-setup-changed') return 'Your account’s encryption setup changed. Open Encryption or run /encrypt unlock on this device, then send your draft again.';
  if (reason === 'ambiguous') return `CryptIRC found more than one possible match for ${nick}.`;
  return `Could not establish encryption with ${nick}.`;
}
function _e2eBundleRequestId() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join('');
}

function _e2eAutoEligible(nick, k, cid, namedStatusQuery=false) {
  const peer = _e2eDmNick(k);
  return !!cid && _e2eSetupNick(nick,namedStatusQuery) && !_e2eReservedNamespace(peer) &&
    _e2eK(getNick(cid)) !== peer && E2E.state?.dm[k]?.on !== 0;
}

function e2eMayAutoEncrypt(nick, cid, namedStatusQuery=false) {
  const canonical = _e2eCanon(nick,cid) || _e2eK(nick);
  return _e2eAutoEligible(nick,_e2eDmKey(canonical,cid),cid,namedStatusQuery);
}

// An off preference can arrive after a sibling created a newer Signal session.
// The send path confirms the actual slot before the composer shares its text.
function e2eSignalOptOutKey(nick,cid) {
  if (!cid || _e2eIsChan(nick)) return null;
  const k=_e2eDmKey(_e2eCanon(nick,cid)||_e2eK(nick),cid);
  return E2E.state?.dm?.[k]?.on===0 ? k : null;
}

async function e2eCheckOptOutSlot(target,cid,key,stillPending,approvedPlain=null) {
  const gen=E2E._lockGen, identity=E2E.identityKeys;
  // A clear send can be queued after discovery but before a first Signal
  // session exists. Check its exact slot again before it leaves.
  const eligible=()=>approvedPlain
    ? _e2eCanAllowPlain()&&_e2eDmKey(_e2eCanon(target,cid)||_e2eK(target),cid)===key
    : E2E.keyReady&&e2eSignalOptOutKey(target,cid)===key;
  const sameAccount=()=>!_e2eBootStale(gen)&&E2E.identityKeys===identity&&!E2E._resyncPending&&eligible()&&(!stillPending||stillPending());
  const discoveryCurrent=()=>!approvedPlain||_e2ePlainProofCurrent(approvedPlain);
  const current=()=>discoveryCurrent()&&sameAccount()&&!E2E._pendingOn?.[key];
  // Earlier clear chunks wait for an ongoing lookup of the same contact.
  const pendingResult=()=>{
    if (!discoveryCurrent()) return 'approval-expired';
    return sameAccount()&&approvedPlain&&typeof E2E._pendingOn?.[key]?.done==='function'?'waiting':'unknown';
  };
  if (!current()) return pendingResult();
  const saved=await _e2eRequestSession(key,true,current);
  // A confirmed empty slot includes the account floor, even when it is empty.
  if (!current()) return pendingResult();
  if (typeof saved?.blob!=='string' || typeof saved.floor_blob!=='string') return 'unknown';
  if (approvedPlain?.unconfigured && saved.account_unconfigured!==true) return 'account-setup-changed';
  if (!approvedPlain && !saved.blob) {
    // Keep this device's explicit off choice until the user resumes. An empty
    // ratchet alone cannot authorize disclosure during setup on another device.
    await E2E._stateSaving;
    const settings=await _e2eRequestSession('__state__',false,current);
    const state=settings?.blob && await _e2eDecodeState(settings.blob);
    const policy=state?.dm?.[key];
    if (!current() || !policy) return 'unknown';
    if (policy.on!==0) return policy.on===1 ? 'enabling' : 'unknown';
    // Older clients publish the confirmed pin before updating the DM preference.
    const approvedPin=policy.plainFingerprint ?? '';
    if (state.trust?.[key]?.fp && state.trust[key].fp!==approvedPin) return 'enabling';
  }
  if (approvedPlain && !approvedPlain.unconfigured) {
    // First-contact confirmation saves its trust pin before it commits the
    // first ratchet. Another device can still see an empty session in between.
    if (!E2E.keyReady || !await _e2eRefreshAccountState(gen)) return 'unknown';
    if (!current()) return pendingResult();
    if (E2E.state?.dm?.[key]?.on!==0 && E2E.state?.trust?.[key]?.fp) return 'trusted';
  }
  const peers=E2E._serverHints?.peers;
  if (peers && peers.includes(key)!==!!saved.blob) {
    if (saved.blob) peers.push(key);
    else E2E._serverHints.peers=peers.filter(peer=>peer!==key);
    updateE2EIndicator(target);
  }
  return saved.blob?'active':'empty';
}

function _e2ePlainProofCurrent(approval) {
  return _e2eUser() === approval.user && (approval.cold || E2E.keyReady === approval.keyReady) && !_e2eBootStale(approval.generation) &&
    _e2ePlainConnections.get(String(approval.conn_id).toLowerCase()) === approval.connection &&
    (!approval.probe || _e2eChatProbeCurrent(approval.probe,false)) &&
    Date.now() < approval.expires && networks.some(net => net.config.id === approval.conn_id && net.connected);
}

function _e2ePlainContextCurrent(approval) {
  return _e2ePlainProofCurrent(approval) && approval.view && (!approval.draftCurrent || approval.draftCurrent()) &&
    active?.conn_id === approval.view.conn_id && active?.target === approval.view.target;
}

function _e2ePlainAccountCurrent(approval) {
  return !E2E.trustStore[approval.key] && !E2E.state?.trust?.[approval.key]?.fp &&
    _e2ePlainContextCurrent(approval);
}

function _e2eCanAllowPlain() {
  // An existing identity must load its pins before it can authorize plaintext.
  return E2E.keyReady ? E2E._bootPhase === 'ready' && !E2E._resyncPending :
    E2E._recoverySetup && !E2E._offerRecoverySetup && E2E._serverHints?.hasIdentity === false;
}

function _e2ePlainApprovalValid(approval,cid,target) {
  const k = _e2eDmKey(_e2eCanon(target,cid) || _e2eK(target),cid);
  if(approval.reply) return _e2ePlainContextCurrent(approval)&&_e2ePlainReplyCurrent(approval,target,cid);
  return approval.conn_id === cid && approval.key === k && _e2ePlainAccountCurrent(approval) && _e2eCanAllowPlain() &&
    e2eTargetState(target,{conn_id:cid}).mode === 'none';
}

function _e2ePlainReplyCurrent(approval,target,cid) {
  const canonical=_e2eCanon(target,cid);
  return !!canonical&&approval.conn_id===cid&&_e2eDmKey(canonical,cid)===approval.key&&
    approval.probe?.noBridge&&_e2eChatProbeCurrent(approval.probe)&&_e2ePlainProofCurrent(approval)&&
    E2E._vaultUp&&!E2E._serverLocked&&(approval.cold||(E2E.keyReady&&E2E._bootPhase==='ready'&&!!E2E.state))&&
    !E2E.trustStore[approval.key]&&!E2E.state?.trust?.[approval.key]?.fp&&E2E.state?.dm?.[approval.key]?.on!==0&&
    e2eTargetState(target,{conn_id:cid,scopedPlainCheck:true,incoming:approval.cold&&!E2E.keyReady}).mode==='none';
}

function _e2eColdStateAllowsReply(state,target,cid) {
  if(!state) return true;
  const fold=_e2eFoldWide(target);
  const matches=slot=>{
    const scope=_e2eDmScope(_e2eK(slot));
    return (!scope||scope[1]===cid.toLowerCase())&&_e2eFoldWide(scope?.[2]||slot)===fold;
  };
  return !Object.entries(state.trust).some(([slot,pin])=>matches(slot)&&pin?.fp)&&
    !Object.keys(state.dm).some(matches)&&
    !Object.entries(state.ch).some(([slot,policy])=>matches(slot)&&policy?.on);
}

async function e2eCheckPlainReply(approval,target,cid,current) {
  const socket=ws;
  const allowed=()=>_wsReady()&&ws===socket&&current()&&_e2ePlainReplyCurrent(approval,target,cid);
  if(!allowed()) return false;
  const req=crypto.randomUUID();
  const read=_e2eReq({type:'e2e_check_plain_reply',conn_id:cid,target:_e2eRealTarget(target),req,cold:approval.cold===true},
    'e2e_plain_reply_checked',800,ev=>ev.req===req,0,allowed);
  const [answer,device]=await Promise.all([read,approval.cold ?
    (approval.probe.deviceKey||= _e2eIdbGetKey(approval.user)) : null]);
  if(!allowed()||typeof answer?.settings!=='string') return false;
  if(approval.cold && (!device?.k || !await _e2eKeyringCheck(answer.keyring,device.k,approval.user) || !allowed())) return false;
  const settings=answer.settings?await _e2eDecodeState(answer.settings,device?.k):null;
  if(!allowed()||(answer.settings&&!settings)) return false;
  let localBlob;
  if(approval.cold){
    const saved=_e2eDev();
    localBlob=saved.st;
    const local=localBlob?await _e2eDecodeState(localBlob,device.k):null;
    if(!allowed()||saved.st!==localBlob||(localBlob&&!local)||Math.max(local?.seq||0,settings?.seq||0)<saved.seq||
        ![settings,local,E2E.state].every(state=>_e2eColdStateAllowsReply(state,target,cid))) return false;
  }else if(settings&&_e2eMergeStateInto(E2E.state,settings)) _e2eApplyMergedState();
  let revision=answer.settings?await _e2eSha256Hex(answer.settings):'';
  if(approval.cold) revision+='.'+await _e2eSha256Hex(answer.keyring);
  if(!allowed()||(approval.cold&&_e2eDev().st!==localBlob)) return false;
  approval.checkedRevision=revision;
  approval.checkedLocal=localBlob;
  approval.checkedAt=performance.now();
  approval.checkedSocket=socket;
  return true;
}

function e2ePlainReplyRecentlyChecked(approval,target,cid) {
  return typeof approval.checkedRevision==='string'&&approval.checkedSocket===ws&&performance.now()-approval.checkedAt<350&&
    _e2ePlainReplyCurrent(approval,target,cid)&&(!approval.cold||_e2eDev().st===approval.checkedLocal);
}

function _e2ePlainReplyProbe(target,cid) {
  if(!E2E._vaultUp||E2E._serverLocked||!_wsReady()||!_e2eSetupNick(target)) return null;
  const canonical=_e2eCanon(target,cid);
  if(!canonical) return null;
  const peer=_e2eDmKey(canonical,cid);
  const probe=_e2eChatProbes.get(_e2eChatProbeKey(cid,peer));
  return _e2eChatProbeCurrent(probe)&&(probe.noBridge||(probe.reply&&probe.finish)) ? {peer,probe}:null;
}

function e2eCanCheckPlainReply(target,cid){ return !!_e2ePlainReplyProbe(target,cid); }

async function _e2eTryPlainReply(target,cid,approval) {
  if(approval.plain) return approval.plain.reply&&_e2ePlainApprovalValid(approval.plain,cid,target);
  const candidate=_e2ePlainReplyProbe(target,cid);
  if(!candidate) return false;
  const {peer:key,probe}=candidate;
  if(approval.composer) clearTimeout(approval.composer.feedback);
  if(probe.finish){
    let timer;
    await Promise.race([probe.result,new Promise(resolve=>{timer=setTimeout(resolve,250);})]);
    clearTimeout(timer);
  }
  if(!probe?.noBridge) return false;
  const cold=!E2E.keyReady||E2E._bootPhase!=='ready'||!E2E.state;
  const plain={reply:true,cold,conn_id:cid,key,user:_e2eUser(),keyReady:E2E.keyReady,generation:E2E._lockGen,
    expires:probe.expires,connection:probe.connection,probe,view:approval.view,draftCurrent:approval.draftCurrent};
  if(!_e2ePlainApprovalValid(plain,cid,target)) return false;
  if(!await e2eCheckPlainReply(plain,target,cid,()=>_e2ePlainContextCurrent(plain))) return false;
  approval.plain=plain;
  return true;
}

async function e2eConfirmPlainTranslation(approval,target,cid,current,optOutKey=null) {
  if (!current()) return 'approval-expired';
  if(approval?.reply) return await e2eCheckPlainReply(approval,target,cid,current)?null:'approval-expired';
  const slot=await e2eCheckOptOutSlot(target,cid,approval?.key||optOutKey,current,approval);
  if (!current()) return 'approval-expired';
  if (slot==='account-setup-changed') {
    void _e2eRun(()=>_e2eBoot(null));
    return slot;
  }
  if (slot==='active'||slot==='trusted') return optOutKey?'active-while-off':'approval-expired';
  if (slot==='approval-expired'||slot==='waiting') return 'approval-expired';
  if (slot==='enabling') return 'enabling';
  return slot==='empty' ? null : 'settings-unavailable';
}

async function _e2eAutoStart(nick, k, cid, approval = null, namedStatusQuery=false) {
  if (!_e2eAutoEligible(nick,k,cid,namedStatusQuery)) return 'missing';
  const netId = String(cid).toLowerCase();
  const cacheKey = _e2eChatProbeKey(cid,k);
  if ((_e2eAutoBusy.get(cacheKey) || 0) > Date.now()) return 'peer-busy';
  E2E._pendingOn ||= Object.create(null);
  if (E2E._pendingOn[k]) return 'blocked';
  // Start first-contact discovery while the sealed account settings load.
  // A result only authorizes sending after the checks below have completed.
  const startedProbe=e2ePrepareChatProbe(nick,cid,namedStatusQuery);
  const now = Date.now();
  let finish;
  const settled = new Promise(resolve => { finish = resolve; });
  const pending = { t:now, target:nick, nick, cid, req:_e2eBundleRequestId(), settled, draftCurrent:approval?.draftCurrent };
  const account = _e2eUser();
  if (!_e2ePlainConnections.has(netId)) _e2ePlainConnections.set(netId,{});
  const plain = {conn_id:cid,key:k,user:account,keyReady:E2E.keyReady,unconfigured:!E2E.keyReady,generation:E2E._lockGen,expires:now+60000,
    connection:_e2ePlainConnections.get(netId),
    view:approval?.view,
    draftCurrent:approval?.draftCurrent};
  // The caller's discovery is still pending, so check the mode after it finishes.
  const canRelease = () => E2E._pendingOn?.[k] === pending && _e2ePlainAccountCurrent(plain);
  const result = new Promise(resolve => { pending.done = resolve; });
  E2E._pendingOn[k] = pending;
  const expire = () => {
    if (!pending.answered && E2E._pendingOn[k] === pending) {
      delete E2E._pendingOn[k];
      pending.done('blocked');
    }
  };
  let timer;
  try {
    // A desktop that never installed the session may have missed a phone's
    // explicit opt-out. Check the sealed account record before using discovery.
    if (plain.keyReady) {
      if (!(await _e2eRefreshAccountState(plain.generation))) return E2E.keyReady ? 'settings-unavailable' : 'settings-locked';
      if (E2E._pendingOn[k]!==pending || _e2eDmKey(_e2eCanon(nick,cid)||_e2eK(nick),cid)!==k) return 'blocked';
      if (E2E.state?.dm?.[k]?.on===0) {
        _e2eRememberDisabledDraft(k);
        return 'disabled-elsewhere';
      }
      pending.settingsChecked=true;
    }
    if(approval?.composer && typeof _showComposerEncryptionStatus==='function')
      _showComposerEncryptionStatus(approval.composer,'peer-check');
    const waitForPeer = !!(E2E.trustStore[k]?.fingerprint || E2E.state?.trust?.[k]?.fp);
    const replyTimeout = waitForPeer ? E2E_BRIDGE_CLIENT_WAIT : _E2E_FIRST_LOOKUP_WAIT;
    const probe=waitForPeer?null:_e2eChatProbes.get(cacheKey);
    const usingProbe=_e2eChatProbeCurrent(probe);
    const observed=usingProbe?await probe.result:null;
    if(E2E._pendingOn[k]!==pending||!_e2ePlainContextCurrent(plain)) return 'approval-expired';
    if(usingProbe&&!observed) return 'blocked';
    if((_e2eAutoBusy.get(cacheKey)||0)>Date.now()) return 'peer-busy';
    const cachedPlain=['unconfirmed','peer-no-bridge'].includes(observed?.reason);
    const readyProbe=_e2eChatProbeCurrent(probe)&&
      (observed?.type==='e2e_bundle'||cachedPlain||
        (probe===startedProbe&&['unsupported','peer-setup','peer-offline'].includes(observed?.reason)));
    if(readyProbe){
      if(observed.type==='e2e_bundle'){
        _e2eDropChatProbe(probe);
        pending.req=observed.req;
        pending.sentAt=Date.now();
        timer=setTimeout(expire,_E2E_FIRST_LOOKUP_WAIT);
        void e2eHandleEvent(observed).catch(()=>pending.done('blocked'));
      }else{
        if(cachedPlain) plain.probe=probe;
        else _e2eDropChatProbe(probe);
        pending.done(observed.reason);
      }
    }else{
      if(probe) _e2eDropChatProbe(probe);
      timer = setTimeout(expire, _E2E_FIRST_LOOKUP_WAIT);
      void _e2eWs({ type:'e2e_fetch_bundle', username:nick, conn_id:cid, req:pending.req, wait_for_peer:waitForPeer },
        () => E2E._pendingOn[k] === pending).then(ok => {
        if (!ok) pending.done('blocked');
        else if (E2E._pendingOn[k] === pending && !pending.answered) {
          pending.sentAt = Date.now();
          clearTimeout(timer);
          timer = setTimeout(expire, replyTimeout);
        }
      });
    }
    const outcome = await result;
    clearTimeout(timer);
    if (outcome === 'missing') return 'blocked';
    if (outcome === 'peer-offline' && (_e2eUser()!==account || E2E._pendingOn[k]!==pending ||
        !_e2ePlainContextCurrent(plain))) return 'approval-expired';
    if (outcome === 'peer-offline' && E2E.trustStore[k]?.keyChanged) return 'identity-changed';
    const pin = E2E.trustStore[k];
    if (outcome === 'unconfirmed' && (waitForPeer || pin || E2E.state?.trust?.[k]?.fp)) {
      if (!_e2ePlainContextCurrent(plain)) return 'approval-expired';
      return pin?.keyChanged ? 'identity-changed' : 'unconfirmed';
    }
    // A completed IRC bridge timeout joins the existing plaintext outcomes.
    // Socket failures and unavailable keys still require a fresh check.
    if (['peer-setup','unsupported','peer-no-bridge','unconfirmed'].includes(outcome)) {
      if (!canRelease()) return 'approval-expired';
      if (!_e2eCanAllowPlain()) return E2E.keyReady ? 'loading' : 'settings-locked';
      if (!plain.keyReady || outcome === 'unconfirmed') {
        // Recheck the server slot before releasing a timed-out draft. An
        // unconfigured account also needs proof that no sibling has enrolled.
        const saved=await _e2eRequestSession(k,true,canRelease);
        if (!canRelease() || !_e2eCanAllowPlain()) return 'approval-expired';
        if (typeof saved?.floor_blob!=='string' || typeof saved.blob!=='string') return 'settings-unavailable';
        if (!plain.keyReady && (saved.account_unconfigured!==true || saved.blob!=='')) {
          void _e2eRun(()=>_e2eBoot(null));
          return 'account-setup-changed';
        }
        if (saved.blob!=='') return 'approval-expired';
      }
      if (!plain.probe && ['unconfirmed','peer-no-bridge'].includes(outcome)){
        plain.probe=_e2eMakeChatProbe(cacheKey,netId,plain.connection);
        plain.probe.result=Promise.resolve({type:'e2e_bundle_missing',reason:outcome});
        if(outcome==='peer-no-bridge') { plain.probe.noBridge=true; plain.probe.expires=Date.now()+_E2E_NO_BRIDGE_MS; }
      }
      approval.plain = plain;
      return 'missing';
    }
    return outcome;
  } finally {
    clearTimeout(timer);
    if (E2E._pendingOn[k] === pending) delete E2E._pendingOn[k];
    finish();
  }
}

function handleEncryptCommand(args, conn_id, target, viewTarget=target) {
  return _e2eRunEncryptCommand(args,conn_id,target,viewTarget);
}
async function _e2eRunEncryptCommand(args, conn_id, target, viewTarget, migration=null) {
  const sub = (args[0] || '').toLowerCase();
  const commandGen = E2E._lockGen;
  const cid = conn_id || (active && active.conn_id) || undefined;
  // The console and a real nick named status share a wire spelling. Only a
  // query or channel supplies an implicit peer or shared-key slot.
  const serverWindow = viewTarget === 'status';
  if (serverWindow) {
    if (['keygen','add','share','rotate','suggest-signal','use-signal','use-shared-key'].includes(sub)) {
      e2eSysMsg(viewTarget,'Open the channel or private chat whose encryption you want to manage.',cid);
      return;
    }
    if (!args[1] && ['on','start','restart','off','stop','verify','trust','accept','reject','status'].includes(sub)) {
      e2eSysMsg(viewTarget,`Usage: /encrypt ${sub} ${sub==='status'?'<nick or channel>':'<nick>'}`,cid);
      return;
    }
  }
  const dmTarget = !_e2eIsChan(target) && !serverWindow ? target : null;
  const namedStatusQuery = dmTarget==='status' && !serverWindow;
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
      if (E2E.keyReady && E2E.identityReady) { e2eSysMsg(target, '🔐 E2E is already unlocked on this device'); return; }
      await e2ePromptDeviceUnlock();
      break;
    }
    case 'suggest-signal': {
      if (!dmTarget || !_e2eSetupNick(dmTarget,namedStatusQuery)) return;
      if (!_wsReady() || wsend({type:'e2e_suggest_signal',conn_id:cid,nick:dmTarget}) === false) {
        e2eSysMsg(target,'🔐 Could not send the encryption suggestion. Reconnect and try again.',cid);
      }
      break;
    }
    case 'use-signal': case 'use-shared-key': {
      if (!dmTarget || !_e2eSetupNick(dmTarget,namedStatusQuery)) return;
      if (!E2E.keyReady || E2E._bootPhase !== 'ready' || !E2E.state || E2E._resyncPending) {
        e2eSysMsg(target,'🔐 Unlock encrypted chats and wait for them to finish loading before changing the method.',cid);
        return;
      }
      const name = _e2eCanon(dmTarget,cid);
      const key = name && _e2eDmKey(name,cid);
      if (!key || !_e2eSharedKeyConfigured(name,cid)) {
        e2eSysMsg(target,'🔐 This chat no longer has a shared key configured. Open Encryption to see the current options.',cid);
        return;
      }
      if (_e2eDmScope(key)?.[1] !== String(cid).toLowerCase()) {
        e2eSysMsg(target,'🔐 This chat has a legacy Signal session shared across networks. Review the existing session’s safety phrase before choosing how to proceed.',cid);
        return;
      }
      const signal = sub === 'use-signal';
      const view = active;
      const old = E2E.state.dm[key];
      const slot = _e2ePskSlot(name,cid);
      const sharedKey = E2E.channelKeys[slot];
      const keyGeneration = E2E._chanKeyGen[slot];
      if (!signal && (!sharedKey || e2eTargetState(dmTarget,{conn_id:cid}).mode==='psk')) {
        e2eSysMsg(target,'🔐 The shared key is unavailable or already selected. Open Encryption to see the current options.',cid);
        return;
      }
      const text = signal ? `Confirm with ${dmTarget} that they are using Signal for this chat before switching. Compare safety phrases under Verify Identity before sending sensitive messages. Your shared key stays available for older messages.`
        : `Use the saved shared key for new messages to ${dmTarget}? Only do this if ${dmTarget} has agreed to use that same key.`;
      if (!await _e2eKeyCmdConfirm(text,signal?'Use Signal':'Use shared key',true,'Confirm encryption method')) return;
      if (_e2eBootStale(commandGen) || !E2E.keyReady || E2E._resyncPending || active !== view ||
          active?.conn_id !== cid || active?.target !== viewTarget || E2E.state?.dm[key] !== old || E2E._pendingOn?.[key] ||
          !_e2eSharedKeyConfigured(name,cid) || (!signal && (_e2ePskSlot(name,cid)!==slot || !_e2ePskKeyCurrent(slot,sharedKey,keyGeneration)))) {
        e2eSysMsg(target,'🔐 The chat or its encryption state changed while confirming. Open Encryption in this DM and try again.',cid);
        return;
      }
      _e2eStateOp('dm',key,c=>({on:1,n:((c?.n)|0)+1,...(c?.closedEpoch ? {closedEpoch:c.closedEpoch} : {}),...(signal?{signal:1}:{})}));
      updateE2EIndicator(dmTarget);
      if (signal) {
        let receivedOffer = false;
        const recover = () => {
          receivedOffer = !!_e2ePendingHeader(key) || _e2eRecentOffers.get(key)?.some(line=>line.text.startsWith(E2E_HDR_PREFIX));
          return _e2eRecoverRecentSignal(key,cid,dmTarget);
        };
        const recovered = typeof _e2eEnqueue === 'function' ? await _e2eEnqueue(cid,dmTarget,recover) : await recover();
        if (!recovered && !_e2eBootStale(commandGen) && active === view && _e2ePrefersSignal(key)) {
          if (_e2ePendingHeader(key)) e2eSysMsg(target,`🔐 Waiting for ${dmTarget}’s encrypted message to finish the Signal setup.`,cid);
          else if (!receivedOffer && !E2E.trustStore[key]?.keyChanged) await handleEncryptCommand(['on',dmTarget],cid,dmTarget);
        }
      }
      break;
    }
    case 'on': case 'start': case 'restart': {
      const nick = args[1] || dmTarget;
      if (!nick || _e2eIsChan(nick)) { e2eSysMsg(target,`Usage: /encrypt ${sub} <nick>`,cid); return; }
      if (!E2E.keyReady) await e2ePromptDeviceUnlock();
      if (!E2E.keyReady || _e2eBootStale(commandGen)) return;
      if (!E2E.identityReady) { e2eSysMsg(target,'🔐 E2E identity not loaded yet — try again in a moment',cid); return; }
      const canonical = _e2eCanon(nick,cid);
      if (canonical === null) { e2eSysMsg(target,'🔐 Use the exact IRC nick to manage its encryption.',cid); return; }
      const k = _e2eDmKey(canonical, cid);
      E2E._pendingOn ||= Object.create(null);
      if (E2E._pendingOn[k]) {
        e2eSysMsg(target,E2E._pendingOn[k].closing ? `🔐 Disabling encryption with ${nick}. Wait for confirmation before enabling it.` : `🔐 Encryption with ${nick} is already being set up.`,cid);
        return;
      }
      // From the user's click, a send must wait even while the device is
      // checking an off setting. The token also lets /off cancel a slow read.
      const preflight = {t:Date.now(),nick,target,cid,checking:true,req:Symbol()};
      if (E2E.state?.dm?.[k]?.on===0) {
        const socket=typeof ws==='undefined' ? null : ws, user=_e2eUser(), identity=E2E.identityKeys;
        preflight.peer=k;
        preflight.opened=new Set();
        preflight.current=()=>!_e2eBootStale(commandGen) && E2E.keyReady && E2E.identityKeys===identity &&
          _e2eUser()===user && (typeof ws==='undefined'||ws===socket);
        preflight.resumeResult = new Promise(resolve=>{ preflight.finishResume = resolve; });
      }
      E2E._pendingOn[k] = preflight;
      const checking = () => E2E.keyReady && !_e2eBootStale(commandGen) && E2E._pendingOn?.[k]===preflight;
      try {
        // An open desktop may still show the session a phone has just disabled.
        // An explicit command may establish a fresh ratchet after the authenticated
        // off setting. Normal sends cannot recreate a deleted server record.
        if (!await _e2eRefreshAccountState(commandGen,preflight.resumeResult ? preflight : null)) {
          if (!_e2eBootStale(commandGen)) e2eSysMsg(target,'🔐 Could not confirm the account’s encryption settings. Try again when connected.',cid);
          return;
        }
        if (!checking()) return;
        if (!_e2ePrefersSignal(k) && _e2eSharedKeyConfigured(canonical,cid)) {
          e2eSysMsg(target,`🔐 A shared key is configured for ${nick}. Open Encryption to review the methods for this chat.`,cid);
          return;
        }
        // A sibling can create a replacement between a confirmed close and the
        // publication of the off setting. Use that authenticated session if this
        // user enables it, or condition a fresh handshake on its exact revision.
        const reopen = E2E.state?.dm?.[k]?.on===0;
        const repair = !!E2E.dmSessions[k]?._unusable || E2E._sessionSyncRepair.has(k);
        if (migration && (reopen || repair || !migration.current())) return;
        const restartRequested = sub==='restart';
        let replacementRevision;
        if (reopen || repair || restartRequested || (!E2E.dmSessions[k] && E2E.state?.dm?.[k]?.on)) {
          let resumed = false;
          const checked = await _withRatchetLock(k,async()=>{
            if (E2E.dmSessions[k] && !reopen && !repair && !restartRequested) return true;
            const identity = E2E.identityKeys, setting = E2E.state?.dm?.[k];
            const current = () => checking() && E2E.identityKeys===identity &&
              (!reopen || (setting?.on===0 && E2E.state?.dm?.[k]?.on===0 && E2E.state.dm[k].n===setting.n));
            const stored = await _e2eRequestSession(k,false,current);
            if (!current() || !stored || (stored.blob!==null && typeof stored.blob!=='string')) return false;
            // Both close acknowledgments may have been lost. Even a device
            // that still shows its old session must restart from the current slot.
            if (reopen || repair || restartRequested) replacementRevision = stored.blob ? await _e2eSha256Hex(stored.blob) : '';
            if (!current()) return false;
            if (!stored.blob) return true;
            if (!reopen) {
              const local = E2E.dmSessions[k];
              if (!local || repair || (restartRequested && local._storeRevision!==replacementRevision))
                await _e2eInstallStoredInner(k,stored.blob,null,{allowed:current});
              return current();
            }
            if (restartRequested || !current()) return current();
            const session = await _e2eInstallStoredInner(k,stored.blob,null,{allowed:current,candidateOnly:true,enableFromOff:true});
            if (!current()) return false;
            if (!session || !E2E.trustStore[k]?.fingerprint || E2E.trustStore[k].keyChanged || _e2eSessPinMismatch(k,session)!==false) return true;
            const previous = E2E.dmSessions[k];
            E2E.dmSessions[k] = session;
            _e2eRememberFirstAdoption(previous,session,true);
            _e2eRememberSessionEpoch(k,session.epoch);
            E2E._sessionSyncRepair.delete(k);
            _e2eStateSetDm(k,true);
            await _e2eWriteDeviceSession(k,session);
            resumed = checking() && E2E.identityKeys===identity && E2E.dmSessions[k]===session;
            return resumed;
          });
          if (!checked) { if (checking()) e2eSysMsg(target,'🔐 Could not check the saved Signal session. Reconnect and try again.',cid); return; }
          if (resumed) {
            preflight.accepted={identity:E2E.identityKeys,pin:E2E.trustStore[k].fingerprint,start:E2E.dmSessions[k].startEph};
            preflight.finishResume?.('resumed');
            e2eSysMsg(target,`🔐 Signal encryption with ${nick} is active on this device.`,cid);
            return;
          }
        }
        const cur = E2E.dmSessions[k];
        const restart = restartRequested || reopen || repair;
        if (migration && (!replacementRevision || cur?._storeRevision!==replacementRevision || !migration.current())) return;
        // r7: a session bound to a replaced identity (accepted on another device) is replaced.
        if (cur && !cur._unusable) { try { await _e2eSessFp(cur); } catch (_) {} }
        if (!restart && cur && !cur._unusable && _e2eSessPinMismatch(k, cur) !== true) { e2eSysMsg(target,`🔐 Session with ${nick} already active`,cid); return; }
        if (E2E.trustStore[k]?.keyChanged) { e2eSysMsg(target,`⚠️ ${nick}'s identity key changed — /encrypt accept ${nick} (after verifying) or /encrypt reject ${nick} first`,cid); return; }
        if (!checking()) return;
        const now = Date.now();
        if (restart && !reopen && !E2E._sessionSyncRepair.has(k) && cur?.x3dhPending && !_e2eLegacyPendingStart(cur) &&
            !!replacementRevision && cur._storeRevision===replacementRevision && cur.restartPrev?.until > now) {
          if (E2E._hdrSent) delete E2E._hdrSent[k];
          e2eSysMsg(target,`🔐 Still waiting for an encrypted reply from ${nick}. Your next message will retry the key exchange.`,cid);
          return;
        }
        if (restart) {
          const busyKey = String(cid || '').toLowerCase() + '\n' + k;
          if ((_e2eAutoBusy.get(busyKey) || 0) > now) {
            e2eSysMsg(target,'🔐 ' + _e2eBundleFailure(nick,'peer-busy'),cid);
            return;
          }
          const restartKey = JSON.stringify([_e2eUser(),k]);
          if (now - (_e2eRestartRequested.get(restartKey) || 0) < 15000) {
            e2eSysMsg(target,`🔐 Wait a few seconds before restarting Signal encryption with ${nick} again.`,cid);
            return;
          }
          if (_e2eRestartRequested.size >= 128) _e2eRestartRequested.delete(_e2eRestartRequested.keys().next().value);
          _e2eRestartRequested.set(restartKey,now);
        }
        const request = { t:now, target, nick, cid, restart, reopen, reopeningVersion:reopen ? E2E.state.dm[k].n : null, replacementRevision, settingsChecked:true,
          restartFrom:_e2eRestartFrom(cur), req:cid ? _e2eBundleRequestId() : undefined };
        if (migration) {
          request.migration=migration;
          request.done=migration.done;
          migration.pending=request;
        }
        E2E._pendingOn[k]=request;
        updateE2EIndicator(target);
        e2eSysMsg(target,`🔐 Fetching key bundle for ${nick}… (messages to ${nick} are held back until encryption is set up)`,cid);
        _e2eFetchBundleQueued(nick, k, cid);
      } finally {
        preflight.finishResume?.('blocked');
        if (E2E._pendingOn?.[k]===preflight) {
          delete E2E._pendingOn[k];
          updateE2EIndicator(target);
        }
      }
      break;
    }
    case 'keygen': {
      if (!E2E.keyReady) await e2ePromptDeviceUnlock();
      if (!E2E.keyReady || _e2eBootStale(commandGen)) return;
      const kn = await keyName(target, 'Replace'); if (kn === null) return;
      const { keyWords, keyB64, key } = await generateChannelKey();
      if (!E2E.keyReady) { e2eSysMsg(target, '🔐 E2E was locked meanwhile — nothing was changed'); return; }   // r5: locked during the key generation
      if (!_e2ePskNetworkName(cid)) _e2ePskScopes.set(key,crypto.randomUUID().replace(/-/g,''));
      await storeChannelKey(_e2eScopedPskSlot(kn,cid),key,keyB64);
      const label = _e2eIsChan(target) ? 'Channel' : 'DM';
      e2eSysMsg(target,`🔐 ${label} key generated for ${target}.`);
      updateE2EIndicator(target);
      await _e2eShowSharedKey(_e2ePskShareText(key,keyWords));
      break;
    }
    case 'add': {
      const words = args.slice(1);
      const scope = words.length === 33 ? /^scope:([a-f0-9]{32})$/i.exec(words.at(-1))?.[1].toLowerCase() : null;
      if (scope) words.pop();
      if (words.length !== 32) { e2eSysMsg(target,'Usage: /encrypt add <32 words> [scope:code]'); return; }
      if (!scope && !_e2ePskNetworkName(cid)) {
        e2eSysMsg(target,'🔐 This network has no shared name yet. Paste the complete code including its scope, or generate a new key to share.');
        return;
      }
      if (!E2E.keyReady) await e2ePromptDeviceUnlock();
      if (!E2E.keyReady || _e2eBootStale(commandGen)) return;
      const kn = await keyName(target, 'Replace'); if (kn === null) return;
      try {
        const { key, keyB64 } = await importChannelKeyFromWords(words.join(' '));
        if (scope) _e2ePskScopes.set(key,scope);
        if (!E2E.keyReady) { e2eSysMsg(target, '🔐 E2E was locked meanwhile — nothing was changed'); return; }   // r5: locked during the key generation
        await storeChannelKey(_e2eScopedPskSlot(kn,cid),key,keyB64);
        e2eSysMsg(target,`🔐 Key added — messages now encrypted`);
        updateE2EIndicator(target);
      } catch(e) { e2eSysMsg(target,`❌ ${e.message}`); }
      break;
    }
    case 'share': {
      const kn = await keyName(target, 'Show'); if (kn === null) return;
      const slot = _e2ePskSlot(kn,cid);
      const key = E2E.channelKeys[slot];
      if (!key) { e2eSysMsg(target,`No key for ${target} — use /encrypt keygen first`); return; }
      const raw   = await crypto.subtle.exportKey('raw', key);
      const bytes = new Uint8Array(raw);
      const words = bytesToMnemonic(bytes).join(' ');
      bytes.fill(0);
      if (E2E.channelKeys[slot] === key) await _e2eShowSharedKey(_e2ePskShareText(key,words));
      break;
    }
    case 'rotate': {
      if (!E2E.keyReady) { e2eSysMsg(target,'🔐 E2E is locked on this device — /encrypt unlock first'); return; }
      const kn = await keyName(target, 'Replace'); if (kn === null) return;
      const { keyWords, keyB64, key } = await generateChannelKey();
      if (!_e2ePskNetworkName(cid)) _e2ePskScopes.set(key,crypto.randomUUID().replace(/-/g,''));
      if (!E2E.keyReady) { e2eSysMsg(target, '🔐 E2E was locked meanwhile — nothing was changed'); return; }   // r5: locked during the key generation
      await storeChannelKey(_e2eScopedPskSlot(kn,cid),key,keyB64);
      e2eSysMsg(target,`🔐 Key rotated for ${target}.`);
      updateE2EIndicator(target);
      await _e2eShowSharedKey(_e2ePskShareText(key,keyWords));
      break;
    }
    case 'off': case 'stop': {
      if (!E2E.keyReady) {
        e2eSysMsg(target, '🔐 Unlock encrypted chats before disabling encryption.');
        return;
      }
      const nick = _e2eIsChan(target) ? target : (args[1] || target);
      const name = await keyName(nick, 'Remove');
      if (name === null || !E2E.keyReady || _e2eBootStale(commandGen)) return;
      const gen = E2E._lockGen, isChannel = _e2eIsChan(target);
      const k = isChannel ? name : _e2eDmKey(name,cid);
      const scoped = _e2eScopedPskSlot(name,cid);
      if (scoped === name) { e2eSysMsg(target,'🔐 Select an IRC network before disabling its shared key.'); return; }
      const pending = E2E._pendingOn?.[k];
      if (pending?.closing) { e2eSysMsg(target,`🔐 Already disabling encryption with ${nick}.`,cid); return; }
      // Supersede an in-flight enable before waiting for its ratchet lock. Keep
      // sends on hold until the result of the user's disable is known.
      const closing = isChannel ? null : {t:Date.now(),target,nick,cid,checking:true,closing:true,req:Symbol()};
      let savedOff;
      if (closing) {
        (E2E._pendingOn ||= Object.create(null))[k] = closing;
        pending?.done?.('blocked');
        pending?.finishResume?.('blocked');
      }
      try {
        const account = _e2eUser();
        const current = () => E2E.keyReady && !E2E._serverLocked && !_e2eBootStale(gen) && _e2eUser()===account;
        const inventory = isChannel ? await _e2eReadChannelInventory(current) : null;
        const stored = isChannel ? inventory?.list : await _e2eReq({ type: 'e2e_load_keyring' }, 'e2e_keyring');
        if (_e2eBootStale(gen)) return;
        if (!stored) { e2eSysMsg(target, '🔐 Could not check stored keys. Encryption stays on.'); return; }
        const channels = Array.isArray(stored.channels) ? stored.channels : [];
        const peers = Array.isArray(stored.peers) ? stored.peers : [];
        const sh = E2E._serverHints;
        const h = _e2eHints();
        const hasKey = slot=>_e2eSharedKeyConfigured(slot) || E2E.chanRemoved[slot] ||
          channels.some(channel=>_e2eK(channel)===slot);
        const legacy = scoped !== name && hasKey(name);
        const shared = hasKey(scoped) || legacy;
        const storedSessions = peers.filter(name => _e2eK(name) === k);
        const session = !isChannel && (E2E.dmSessions[k] || E2E.state?.dm[k]?.on || sh?.peers.includes(k) || h.dm.includes(k) || storedSessions.length);
        const sameSocket = inventory ? () => current() && _wsReady() && ws===inventory.socket : null;
        if (shared && !(await removeChannelKey(scoped,channels,legacy,sameSocket))) {
          e2eSysMsg(target, '🔐 Could not confirm shared-key removal. Encryption stays on.');
          return;
        }
        if (!isChannel) {
          const removed = await _withRatchetLock(k, async () => {
            const legacySlot = '__legacy__' + k;
            for (const partner of new Set([legacySlot, ...storedSessions.filter(slot=>slot!==k), k])) {
              if (_e2eBootStale(gen) || !(await _e2eCloseSessionSlot(k,partner,gen))) return false;
            }
            delete E2E._sessionCache[legacySlot];
            delete E2E._lazyTried?.[k];
            await _e2eDropSession(k);
            if (_e2eBootStale(gen)) return false;
            _e2eStateSetDm(k, false, true);
            savedOff = E2E._stateSaving;
            return true;
          });
          if (!removed) { e2eSysMsg(target, '🔐 Could not confirm session removal. Encryption stays on.'); return; }
        }
        if (!isChannel) {
          delete E2E._orphans?.[k];
          _e2eForgetPendingHeader(k,_e2ePendingHeader(k));
          _e2eRecentOffers.delete(k);
          _e2eHistoryAttempts.delete(k);
          if (typeof _releaseHeldSignalDraft === 'function') _releaseHeldSignalDraft(cid,nick);
        }
        if (sh) {
          if (session) sh.peers = sh.peers.filter(x => x !== k);
        }
        if (session) {
          const hints = _e2eHints();
          _e2eLsSet(_e2eHintKey(), {dm:hints.dm.filter(x => x !== k),ch:hints.ch});
        }
        if (savedOff && !await savedOff) {
          // A lost acknowledgment may still mean the choice reached storage.
          const current = () => !_e2eBootStale(gen) && E2E._pendingOn?.[k] === closing;
          if (!current()) return;
          const stored = await _e2eRequestSession('__state__',false,current);
          const state = stored?.blob && await _e2eDecodeState(stored.blob);
          if (!current()) return;
          const choice = state?.dm?.[k], pin = state?.trust?.[k]?.fp;
          if (choice?.on !== 0 || (pin && choice.plainFingerprint !== pin)) {
            e2eSysMsg(target,`🔐 Could not confirm unencrypted chat with ${nick}. Retry /encrypt off ${nick} before sending.`,cid);
            return;
          }
        }
        e2eSysMsg(target, shared || session || pending ? '🔓 Encryption disabled for ' + nick : '🔓 No encryption active for ' + nick);
      } finally {
        if (closing && E2E._pendingOn?.[k]===closing) delete E2E._pendingOn[k];
        if (!_e2eBootStale(gen)) updateE2EIndicator(nick);
      }
      break;
    }
    case 'verify': {
      const nick = args[1] || dmTarget;
      if (!nick) { e2eSysMsg(target,'Usage: /encrypt verify <nick>'); return; }
      const k = _e2eDmKey(nick, cid);
      const session = E2E.dmSessions[k];
      if (!session || session._unusable) { e2eSysMsg(target,`No E2E session with ${nick}`); return; }
      // #2: verify the PINNED long-term identity DH key (theirIdentityPub), NOT the ratchet key.
      if (!session.theirIdentityPub) { e2eSysMsg(target,`Session with ${nick} not yet established (no pinned identity)`); return; }
      const [myDh, mySign] = await _e2ePublicIdentity(E2E.identityKeys);
      const legacyPhrase = await safetyPhrase(myDh, session.theirIdentityPub);
      const bothKeys = await e2eValidIdentityKeys(session.theirIdentityPub, session.theirSignPub);
      if (bothKeys) {
        e2eSysMsg(target,`🔐 Safety phrase with ${nick} (both identity keys): ${await safetyPhraseV2(myDh, mySign, session.theirIdentityPub, session.theirSignPub)}`);
        e2eSysMsg(target,`Read this over voice. If they see the same words → /encrypt trust ${nick}`);
        e2eSysMsg(target,`  (earlier CryptIRC releases show a DH-key-only phrase instead: ${legacyPhrase})`);
      } else {
        e2eSysMsg(target,`🔐 Legacy safety phrase with ${nick} (DH key only, does not cover the signing key): ${legacyPhrase}`);
      }
      // Unpinned: show the v2 value peers see under /encrypt fingerprint, never the
      // DH-only digest (which looks like a full pin from an earlier release).
      const pin = E2E.trustStore[k]?.fingerprint;
      if (pin) {
        e2eSysMsg(target,`Their fingerprint: ${pin}`);
        if (e2eIsLegacyFingerprint(pin) && await e2ePinMatchesIdentity(pin, session.theirIdentityPub, session.theirSignPub))
          e2eSysMsg(target,`  (current CryptIRC releases show it as: ${await computeIdentityFingerprint(session.theirIdentityPub, session.theirSignPub)})`);
      } else if (bothKeys) {
        e2eSysMsg(target,`Their fingerprint: ${await computeIdentityFingerprint(session.theirIdentityPub, session.theirSignPub)}`);
        e2eSysMsg(target,`  (earlier CryptIRC releases show it as: ${await e2eLegacyIdentityFingerprint(session.theirIdentityPub, session.theirSignPub)})`);
      } else {
        e2eSysMsg(target,`Their legacy DH-key-only fingerprint (not comparable with /encrypt fingerprint): ${await computeFingerprint(session.theirIdentityPub)}`);
      }
      if (E2E.trustStore[k]?.pendingFingerprint) e2eSysMsg(target,`⚠️ A DIFFERENT key is pending for ${nick}: ${E2E.trustStore[k].pendingFingerprint}`);
      break;
    }
    case 'trust': {
      // Verification requires a live session matching the pin, no pending key
      // change, and confirmation of the fingerprint and safety phrase.
      const nick = args[1] || dmTarget;
      if (!nick) { e2eSysMsg(target,'Usage: /encrypt trust <nick>'); return; }
      const k = _e2eDmKey(nick, cid);
      const t = E2E.trustStore[k];
      const s = E2E.dmSessions[k];
      if (!t) { e2eSysMsg(target,`🔐 No identity for ${nick} has been confirmed on this device yet — start a session first (/encrypt on ${nick})`); return; }
      if (t.keyChanged) { e2eSysMsg(target,`⚠️ ${nick}'s identity key changed — /encrypt accept or /encrypt reject first`); return; }
      if (!s || s._unusable || !s.theirIdentityPub) { e2eSysMsg(target,`🔐 No E2E session with ${nick} — /encrypt on ${nick} first`); return; }
      if (!await e2ePinMatchesIdentity(t.fingerprint, s.theirIdentityPub, s.theirSignPub)) {
        e2eSysMsg(target,`⚠️ The session with ${nick} does not use the pinned identity — not marking verified`); return;
      }
      const [myDh, mySign] = await _e2ePublicIdentity(E2E.identityKeys);
      const phrase = await safetyPhraseV2(myDh, mySign, s.theirIdentityPub, s.theirSignPub);
      const legacyPhrase = await safetyPhrase(myDh, s.theirIdentityPub);
      const ok = typeof confirm === 'function' && confirm(
        `Mark ${nick} as VERIFIED?\n\nFingerprint:\n${t.fingerprint}\n\nSafety phrase (both identity keys):\n${phrase}\n\n` +
        `(Earlier CryptIRC releases show a DH-key-only phrase: ${legacyPhrase})\n\n` +
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
      const k = _e2eDmKey(nick, cid);
      const t = E2E.trustStore[k];
      if (!t || !t.pendingFingerprint) { e2eSysMsg(target,`No pending key change for ${nick}`); return; }
      const prior = t.fingerprint, approved = t.pendingFingerprint;
      const ok = typeof confirm === 'function' && confirm(
        `⚠️ Accept a NEW identity key for ${nick}?\n\nPinned (old) fingerprint:\n${t.fingerprint}\n\nNEW fingerprint:\n${t.pendingFingerprint}\n\n` +
        `Only accept after confirming the NEW fingerprint with ${nick} over a trusted channel. If you did not expect ${nick} to change keys, this may be an attack.`);
      if (!ok) { e2eSysMsg(target,'Key change NOT accepted — messages under the new key stay blocked'); return; }
      const accepted = await _withRatchetLock(k,async()=>{
        const current = () => E2E.keyReady && !_e2eBootStale(commandGen) && E2E.trustStore[k]===t &&
          t.fingerprint===prior && t.pendingFingerprint===approved;
        if (!current()) return null;
        const settings = await _e2eRequestSession('__state__');
        const sealed = settings?.blob ? await _e2eDecodeState(settings.blob) : null;
        if (!settings || (settings.blob && !sealed) || !current()) return null;
        const pin = sealed?.trust?.[k];
        if (pin?.fp && pin.fp!==prior && pin.fp!==approved) return null;
        const retired = await _e2eCloseSessionSlot(k,k,commandGen,async session=>{
          const actual = await _e2eSessFp(session);
          if (actual && actual===approved) return 'keep';
          if (!session.theirIdentityPub) return session.identityAD ? null : 'close';
          // Retiring (never trusting) a session under the old pin: a pre-#11 pin
          // confirmed the DH key alone.
          const dh = await e2eLegacyIdentityFingerprint(session.theirIdentityPub,null);
          return _e2eSessPinIs(session,prior)===true || dh===prior ? 'close' : null;
        },current);
        if (!retired || !current()) return null;
        t.fingerprint = approved; t.pendingFingerprint = null; t.keyChanged = false;
        t.verified = !!(pin?.fp===approved && pin.ver);
        _e2eStateSetTrust(k);
        let established = false;
        if (retired===true) await _e2eDropSession(k);
        else {
          const allowed = () => E2E.trustStore[k]?.fingerprint===approved && !E2E.trustStore[k]?.keyChanged;
          const installed = await _e2eInstallStoredInner(k,retired,null,{hint:true,allowed});
          established = installed!==null && await _e2eSessFp(E2E.dmSessions[k])===approved && allowed();
          if (established) E2E._sessionSyncRepair.delete(k);
        }
        return _e2eBootStale(commandGen) ? null : {established,verified:t.verified};
      });
      if (!accepted) {
        if (!_e2eBootStale(commandGen) && E2E.trustStore[k]?.pendingFingerprint===approved)
          e2eSysMsg(target,`🔐 Could not confirm the previous Signal session for ${nick}. Your pin stays as it was. Try again when connected.`,cid);
        return;
      }
      e2eSysMsg(target,accepted.verified?`🔐 The already verified identity for ${nick} is active.`:
        `🔐 New identity for ${nick} accepted (not verified — compare with /encrypt verify ${nick})`);
      // Decrypt what arrived under the new key while it was pending.
      const stash = (E2E._changedStash && E2E._changedStash[k]) || [];
      if (E2E._changedStash) delete E2E._changedStash[k];
      let established = accepted.established;
      for (const item of stash) {
        try {
          let pt;
          if (!established && item.x3dh) {
            const r = await _e2eEstablishAndDecrypt(nick, item.x3dh, item.envelope, { connId:item.conn_id });
            if (!r.ok) continue;
            established = true; pt = r.pt;
          } else if (!E2E.dmSessions[k]?.connId || E2E.dmSessions[k].connId === item.conn_id) pt = await ratchetDecrypt(k, item.envelope);
          else continue;
          _e2eShowDecrypted(item.conn_id||conn_id,nick,nick,pt,`🔐 The next message from ${nick} was held until you accepted the new key:`,
            _e2eDmHistoryWires.get(item.envelope));
        } catch (e) { console.warn('[E2E] stashed message failed:', e && e.message); }
      }
      if (!established && E2E._pendingIncomingX3DH && E2E._pendingIncomingX3DH[k]) {
        const hdr = E2E._pendingIncomingX3DH[k];
        const r = await e2eEstablishResponderSession(nick, hdr, {connId:_e2eHeaderNetworks.get(hdr)});
        if (r.ok) { delete E2E._pendingIncomingX3DH[k]; established = true; }
      }
      if (!established) e2eSysMsg(target,`🔐 Run /encrypt on ${nick} to start a session with the new key`);
      updateE2EIndicator(nick);
      break;
    }
    case 'reject': {
      const nick = args[1] || dmTarget;
      if (!nick) { e2eSysMsg(target,'Usage: /encrypt reject <nick>'); return; }
      const k = _e2eDmKey(nick, cid);
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
      const former = E2E.identityKeys;
      const oldPub = await _e2ePublicIdentity(former);
      if (_e2eBootStale(commandGen) || E2E.identityKeys!==former) return;
      await e2eGenerateAndPublishIdentity({ replace: true });
      if (_e2eBootStale(commandGen)) return;
      const replacement = E2E.identityKeys;
      if (!E2E.identityReady || !replacement || replacement===former) { e2eSysMsg(target, '🔐 Identity generation failed'); break; }
      const newPub = await _e2ePublicIdentity(replacement);
      const current = () => E2E.keyReady && !_e2eBootStale(commandGen) && E2E.identityKeys===replacement;
      // A different browser can start a replacement session as soon as it sees
      // the new identity. Retire only the old identity's authenticated revision.
      const peers = new Set(Object.keys(E2E.dmSessions));
      for (const [nk, d] of Object.entries(E2E.state?.dm || {})) if (d?.on) peers.add(nk);
      for (const nk of E2E._serverHints?.peers || []) peers.add(nk);
      // All contacts share the durable account floor. Serializing this one
      // reset avoids racing our own independent closes against each other.
      const outcomes = [];
      for (const nk of peers) {
        if (!current()) return;
        if (!nk || nk.startsWith('__')) continue;
        const outcome = await _withRatchetLock(nk,async()=>{
          const retired = await _e2eCloseSessionSlot(nk,nk,commandGen,session=>{
            if (_e2eSessionBoundTo(session,newPub)) return 'keep';
            return !session.identityAD || _e2eSessionBoundTo(session,oldPub) ? 'close' : null;
          },current);
          if (!current()) return false;
          if (retired===true) { await _e2eDropSession(nk); return true; }
          const live = E2E.dmSessions[nk];
          if (live && !_e2eSessionBoundTo(live,newPub)) _e2eForgetSessionRuntime(nk);
          if (!retired) return false;
          return await _e2eInstallStoredInner(nk,retired,null,{allowed:current}) ? retired : false;
        });
        outcomes.push(outcome);
      }
      if (!current()) return;
      const fp = await _e2eOwnFingerprint();
      if (!current()) return;
      e2eSysMsg(target, '🔐 New identity created — your fingerprint: ' + fp);
      const closed = outcomes.filter(result=>result===true).length;
      if (closed) e2eSysMsg(target, `🔐 ${closed} encrypted session${closed === 1 ? '' : 's'} bound to the old identity closed. Use /encrypt on <nick> to set up a new one.`);
      if (outcomes.includes(false)) e2eSysMsg(target, '🔐 Some old encrypted sessions could not be confirmed closed. Use /encrypt restart <nick> to set up a new session.');
      break;
    }
    case 'status': {
      const t = args[1] || target;
      const st = e2eTargetState(t, { conn_id:cid });
      if (st.mode === 'blocked') { e2eSysMsg(target, `⛔ ${t} — encryption ON but unavailable: ${st.reason}`,cid); break; }
      if (_e2eIsChan(t)) {
        e2eSysMsg(target, st.mode === 'psk' ? `🔐 ${t} — encrypted` : `🔓 ${t} — not encrypted`,cid);
      } else {
        const trust = E2E.trustStore[_e2eDmKey(t, cid)];
        const badge = trust?.keyChanged ? '⚠ KEY CHANGED (pending)' : trust?.verified ? '✓ verified' : 'TOFU';
        e2eSysMsg(target, st.mode === 'psk' ? `🔐 DM ${t} — encrypted (shared key)` :
                          st.mode === 'dm'  ? `🔐 DM ${t} — Signal encryption (${badge})` : `🔓 DM ${t} — not encrypted. /encrypt on ${t}`, cid);
      }
      break;
    }
    case 'fingerprint': case 'fp': {
      if (!E2E.identityKeys) { e2eSysMsg(target, E2E.keyReady ? 'E2E not initialised' : '🔐 E2E is locked on this device — /encrypt unlock'); return; }
      // #11: show the combined (dh+sign) identity fingerprint — the same value
      // peers pin via TOFU — so an out-of-band match is meaningful.
      e2eSysMsg(target,`🔑 Your fingerprint: ${await _e2eOwnFingerprint()}`);
      // Contacts pinned by an earlier CryptIRC release see this identity in that form.
      e2eSysMsg(target,`   (shown by earlier CryptIRC releases as: ${await e2eLegacyIdentityFingerprint(...await _e2ePublicIdentity(E2E.identityKeys))})`);
      break;
    }
    default:
      e2eSysMsg(target,[
        '🔐 /encrypt commands:',
        '  on <nick>       — start E2E DM session',
        '  restart [nick]  — set up a fresh Signal session while keeping encryption on',
        '  off [nick]      — end session or remove channel key',
        '  keygen          — generate channel key (in channel)',
        '  add <32 words> [scope:code]  — paste the complete shared-key code',
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

function e2eSysMsg(target, text, cid) {
  if (cid) {
    for (const line of text.split('\n')) sysMsg(cid, target, line, 'system');
    return;
  }
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

function e2eUpdateSetupButton(button) {
  button.disabled = E2E.keyReady && (E2E.identityReady || E2E._booting);
  if (!E2E.keyReady) button.textContent = button.dataset.e2eUnlock;
  else if (E2E.identityReady) button.textContent = 'Encryption ready';
  else button.textContent = E2E._booting ? 'Setting up encryption…' : 'Retry Signal setup';
}

function updateE2EIndicator(target) {
  for (const button of document.querySelectorAll?.('[data-e2e-unlock]') || []) {
    e2eUpdateSetupButton(button);
  }
  try { _e2eFlushSysQueue(); } catch (_) {}
  const banner = document.getElementById('e2e-unlock-banner');
  const offer = document.getElementById('e2e-setup-offer');
  const activeTarget = active?.target;
  const protectedChat = !!(activeTarget && activeTarget !== 'status' &&
    typeof _isE2eConversation === 'function' && _isE2eConversation(activeTarget, active.conn_id));
  if (banner) banner.hidden = E2E.keyReady || !protectedChat;
  if (offer) offer.hidden = E2E.keyReady || protectedChat || !E2E._vaultUp || !E2E._offerRecoverySetup ||
    E2E._setupIgnoredUser === _e2eUser() || !!_e2eLsGet(_e2eSetupPreference());
  // Always update lock icon based on current active view
  const lock = document.getElementById('e2e-lock');
  if (lock && active) {
    const t = active.target;
    const st = (t && t !== 'status') ? e2eTargetState(t, { conn_id: active.conn_id }) : { mode:'none' };
    const trust = E2E.trustStore[_e2eDmKey(t, active.conn_id)];
    const lockedSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4" fill="none" stroke-width="2"/></svg>';
    const unlockedSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9 0" fill="none"/></svg>';
    const encActive = st.mode === 'psk' || st.mode === 'dm';
    const blocked = st.mode === 'blocked';
    const waitingForReply = st.mode === 'dm' && E2E.dmSessions[_e2eDmKey(t,active.conn_id)]?.x3dhPending;
    lock.innerHTML = (encActive || blocked) ? lockedSvg : unlockedSvg;
    // H5: the icon reflects reality — accent = usable; red = E2E on but sends blocked.
    lock.style.color = blocked ? 'var(--red, #e5484d)' : (encActive && !(trust && trust.keyChanged)) ? 'var(--accent)' : encActive ? 'var(--red, #e5484d)' : 'var(--text2)';
    lock.title = blocked
      ? ('Encryption ON but unavailable — messages are blocked: ' + st.reason)
      : encActive
        ? (trust?.keyChanged ? 'KEY CHANGED (not accepted) — verify, then /encrypt accept' : st.mode === 'psk' ? 'Encrypted (shared key)' : waitingForReply ? 'Signal encryption ready to send — awaiting an encrypted reply' : trust?.verified ? 'E2E verified' : 'E2E encrypted (TOFU)')
        : 'Not encrypted — click to set up';
  }
  try { if (typeof renderSidebar === 'function') renderSidebar(); } catch (_) {}
}

function e2eShowKeyChangeWarning(nick, fp, first = true, cid) {
  const k = _e2eDmKey(nick, cid);
  const t = E2E.trustStore[k];
  const pinned = t ? t.fingerprint : '(none)';
  // r3 (agy-flash P3 HIGH, same class): the warning is the app's NON-blocking in-app
  // alert, and a peer cycling keys can't stack them: no new one while that peer's alert
  // is still on screen, at most 5 per peer per 10 minutes (the system line below is
  // always written).
  const now = Date.now();
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
  _e2eSys(nick, `⚠️ KEY CHANGED for ${nick} — new key ${fp} NOT accepted. Verify, then /encrypt accept ${nick} (or /encrypt reject ${nick})`, cid);
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
