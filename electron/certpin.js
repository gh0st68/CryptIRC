'use strict';
// Trust-on-first-use certificate pins for self-hosted servers on a LAN (or on
// this computer) whose certificate no authority vouches for, e.g. the installer's
// self-signed certificate. main.js decides WHEN a host may use this (LAN/local
// hosts only); this module only remembers and compares certificates. It has no
// Electron dependency, so it can be tested with plain Node.
//
// A pin is per host AND port ("192.168.1.5:443"): two services on one machine
// may well have different certificates. It records the SHA-256 of the
// certificate's public key (SPKI) and of the whole certificate. A connection
// matches when the public key is the same, so a certificate re-issued with the
// same key (new expiry, new name) still matches; a TLS handshake proves the
// server holds that key's private half, which an impostor does not.

const crypto = require('crypto');
const fs = require('fs');

const STORE_VERSION = 1;
// How long the one-time silent pin of an existing install may wait for its
// first connection (it also ends with that launch, see initStore).
const AUTOPIN_MAX_AGE_MS = 24 * 60 * 60 * 1000;

// Certificate-supplied text (subject, issuer) is shown to the user next to the
// fingerprint. Strip what could fake extra lines or reorder text — C0/C1
// controls (CR/LF included), the Unicode line/paragraph separators and the bidi
// marks/overrides/isolates — then collapse whitespace and cap the length.
const UNSAFE_TEXT = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;
function cleanText(v, max = 120) {
  const t = String(v == null ? '' : v).replace(UNSAFE_TEXT, ' ').replace(/\s+/g, ' ').trim();
  return t.length > max ? t.slice(0, max - 1) + '…' : t;
}

// "host:port" for a URL; the default port is filled in, so https://h/ and
// wss://h/ share a pin. IPv6 literals keep their brackets ("[::1]:443").
function hostKey(u) {
  let x;
  try { x = new URL(String(u)); } catch { return null; }
  if (!x.hostname) return null;
  const port = x.port || ((x.protocol === 'http:' || x.protocol === 'ws:') ? '80' : '443');
  return `${x.hostname.toLowerCase()}:${port}`;
}

// The host part of a hostKey.
function keyHost(key) {
  const i = String(key).lastIndexOf(':');
  return i > 0 ? key.slice(0, i) : String(key);
}

// What we remember about a certificate (Electron's Certificate structure:
// data = PEM, fingerprint = "sha256/<base64>", subjectName/issuerName = CNs,
// validStart/validExpiry = seconds). sha256 is the "AB:CD:…" form that
// `openssl x509 -noout -fingerprint -sha256` prints, so a user can compare it.
// When the PEM cannot be parsed, Electron's own fingerprint is used, and spki
// stays empty (then only the exact certificate matches).
function certIdentity(cert) {
  const c = cert || {};
  const id = {
    sha256: '',
    spki: '',
    subject: cleanText(c.subjectName),
    issuer: cleanText(c.issuerName),
    validStart: Number(c.validStart) || 0,
    validExpiry: Number(c.validExpiry) || 0,
  };
  try {
    const x = new crypto.X509Certificate(String(c.data || ''));
    id.sha256 = x.fingerprint256;
    id.spki = crypto.createHash('sha256')
      .update(x.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
    if (!id.subject) id.subject = cleanText(x.subject.replace(/\n/g, ', '));
    if (!id.issuer) id.issuer = cleanText(x.issuer.replace(/\n/g, ', '));
  } catch {
    id.sha256 = typeof c.fingerprint === 'string' ? c.fingerprint : '';
  }
  return id;
}

// Does this certificate match the pin? Public key first; the whole-certificate
// fingerprint only when either side has no public-key hash.
function matchPin(pin, id) {
  if (!pin || !id) return false;
  if (pin.spki && id.spki) return pin.spki === id.spki;
  return !!pin.sha256 && pin.sha256 === id.sha256;
}

function emptyStore() { return { version: STORE_VERSION, pins: Object.create(null), autoPin: [] }; }

// Read the pin file. `existed` is false only when there is no file at all —
// that, and nothing else, is the first run of a version that pins. A file that
// exists but cannot be read or parsed gives an empty store with existed=true:
// every host then asks again, and nothing is ever trusted silently because of it.
function loadStore(file) {
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch (e) {
    if (e && e.code === 'ENOENT') return { data: emptyStore(), existed: false };
    console.error('[cert] cannot read', file, e && e.message);
    return { data: emptyStore(), existed: true };
  }
  try {
    const d = JSON.parse(raw);
    const out = emptyStore();
    if (d && typeof d.pins === 'object' && d.pins) {
      for (const [k, v] of Object.entries(d.pins)) {
        if (!/^\S+:\d+$/.test(k)) continue;   // only "host:port" keys
        if (v && typeof v === 'object' && (typeof v.spki === 'string' || typeof v.sha256 === 'string')) out.pins[k] = v;
      }
    }
    if (d && Array.isArray(d.autoPin)) {
      out.autoPin = d.autoPin.filter((e) => e && typeof e.key === 'string' && /^\S+:\d+$/.test(e.key) && Number.isFinite(e.armedAt))
        .map((e) => ({ key: e.key, armedAt: e.armedAt }));
    }
    return { data: out, existed: true };
  } catch (e) {
    console.error('[cert] ignoring unreadable', file, e && e.message);
    return { data: emptyStore(), existed: true };
  }
}

// Atomic write (temp file + rename), readable by this user only.
function saveStore(file, data) {
  const tmp = `${file}.tmp-${process.pid}`;
  try {
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, file);
    return true;
  } catch (e) {
    console.error('[cert] cannot save', file, e && e.message);
    try { fs.unlinkSync(tmp); } catch {}
    return false;
  }
}

// First run of a version that pins: an install that was ALREADY using a LAN
// server over https (the saved server URL) had every certificate accepted for it
// without a question. Its certificate may be pinned without a prompt, but only on
// the FIRST connection after the update, whatever that connection's outcome:
//  - armed for the saved URL's host:port only, with the time it was armed;
//  - main.js ends it at the first finished or failed load of the app;
//  - it never survives this launch (the next start finds the file and clears it)
//    nor AUTOPIN_MAX_AGE_MS;
//  - it is not armed when the pin file cannot be written (then the prompt asks).
// Every other host, and that one afterwards, asks first.
function initStore(file, savedUrl, isLanHost, now = Date.now()) {
  const { data, existed } = loadStore(file);
  if (existed) {
    if (data.autoPin.length) { data.autoPin = []; saveStore(file, data); }
    return data;
  }
  try {
    const u = new URL(String(savedUrl));
    if (u.protocol === 'https:' && isLanHost(u.hostname.toLowerCase())) data.autoPin = [{ key: hostKey(u.href), armedAt: now }];
  } catch {}
  if (!saveStore(file, data)) data.autoPin = [];
  return data;
}

// Take the one-time silent pin for host:port `key`. True only when it is armed
// for exactly that key and not older than AUTOPIN_MAX_AGE_MS. Any attempt uses it up.
function takeAutoPin(data, key, now = Date.now()) {
  const i = data.autoPin.findIndex((e) => e.key === key);
  if (i < 0) return false;
  const age = now - data.autoPin[i].armedAt;
  data.autoPin.splice(i, 1);
  return age >= 0 && age <= AUTOPIN_MAX_AGE_MS;
}

// End the silent-pin window (first load of the app done, server changed, …).
// Returns true when something was cleared.
function endAutoPin(data) {
  if (!data.autoPin.length) return false;
  data.autoPin = [];
  return true;
}

function pinRecord(id) {
  return {
    spki: id.spki, sha256: id.sha256, subject: cleanText(id.subject), issuer: cleanText(id.issuer),
    validExpiry: id.validExpiry, pinnedAt: new Date().toISOString(),
  };
}

module.exports = {
  AUTOPIN_MAX_AGE_MS, cleanText, hostKey, keyHost, certIdentity, matchPin, emptyStore, loadStore, saveStore,
  initStore, takeAutoPin, endAutoPin, pinRecord,
};
