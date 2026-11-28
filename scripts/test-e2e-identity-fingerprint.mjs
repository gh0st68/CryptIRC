#!/usr/bin/env node
// Identity pins (static/e2e.js): new pins cover BOTH validated P-256 identity keys with
// a versioned, domain-separated, length-prefixed digest; pins made by earlier releases
// over both keys keep matching the same keys; a pre-#11 pin over the DH key alone never
// vouches for a signing key. Extracts the REAL shipped functions and runs them in a bare
// context (Node's WebCrypto) with synthetic keys — no network, no user data.
import assert from 'node:assert/strict';
import {createHash, webcrypto} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import vm from 'node:vm';

const here = path.dirname(fileURLToPath(import.meta.url));
const SRC = fs.readFileSync(path.join(here, '..', 'static', 'e2e.js'), 'utf8');

function extract(name) {
  const m = new RegExp(`(?:^|\\n)((?:async )?function ${name}\\s*\\()`).exec(SRC);
  if (!m) throw new Error(`function ${name} not found in static/e2e.js`);
  const start = m.index + m[0].indexOf(m[1]);
  let depth = 0;
  for (let i = SRC.indexOf('{', start); i < SRC.length; i++) {
    if (SRC[i] === '{') depth++;
    else if (SRC[i] === '}' && --depth === 0) return SRC.slice(start, i + 1);
  }
  throw new Error(`could not brace-match ${name}`);
}
function extractConst(name) {
  const m = new RegExp(`\\nconst ${name}\\s*=[^\\n]*;`).exec(SRC);
  if (!m) throw new Error(`const ${name} not found in static/e2e.js`);
  return m[0];
}

let failures = 0, passes = 0;
async function check(label, fn) {
  try { await fn(); passes++; console.log('ok   ', label); }
  catch (e) { failures++; console.log('FAIL ', label, '—', e.message.split('\n')[0]); }
}

const ctx = {
  crypto: webcrypto, atob, btoa, TextEncoder, TextDecoder, Uint8Array, Map, Promise, console,
  E2E: {trustStore: Object.create(null), _lockGen: 1, _fpCache: new Map(), _fpLegacyCache: new Map()},
  stateWrites: [],
  _e2eDmKey: (nick) => String(nick).toLowerCase(),
  _e2eBootStale: () => false,
  e2eConfirmNewIdentity: async () => true,
  _e2eStateSetTrust: (k) => { ctx.stateWrites.push(k); },
  WORDLIST: Array.from({length: 256}, (_, i) => `w${i}`),
};
vm.createContext(ctx);
const names = ['base64ToBytes', 'bytesToBase64', 'concat', 'importPub', 'computeFingerprint',
  'computeIdentityFingerprint', 'e2eLegacyIdentityFingerprint', 'e2eValidIdentityKeys', 'e2eIsLegacyFingerprint',
  'e2ePinMatchesIdentity', 'e2eCheckTrust', '_e2eSessFpKey', '_e2eSessFpCached', '_e2eSessFp', '_e2eSessPinIs',
  '_e2eSessPinMismatch', '_e2eFingerprintHex', 'safetyPhrase', 'safetyPhraseV2', 'bytesToMnemonic'];
const consts = ['E2E_FP_V2_DOMAIN', 'E2E_FP_V2_PREFIX', 'E2E_PHRASE_V2_DOMAIN'];
const missing = [];
for (const c of consts) { try { vm.runInContext(extractConst(c), ctx); } catch (e) { missing.push(c); } }
for (const n of names) { try { vm.runInContext(extract(n), ctx); } catch (e) { missing.push(n); } }
await check('the identity pin helpers ship in static/e2e.js', () => assert.deepEqual(missing, []));
const run = (code) => vm.runInContext(code, ctx);

const subtle = webcrypto.subtle;
const b64 = (bytes) => Buffer.from(bytes).toString('base64');
async function identity() {
  const dh = await subtle.generateKey({name: 'ECDH', namedCurve: 'P-256'}, true, ['deriveBits']);
  const sign = await subtle.generateKey({name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify']);
  return {dh: b64(new Uint8Array(await subtle.exportKey('raw', dh.publicKey))),
          sign: b64(new Uint8Array(await subtle.exportKey('raw', sign.publicKey)))};
}
const A = await identity(), B = await identity();
const group = (hex) => hex.toUpperCase().match(/.{4}/g).join(' ');
const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest('hex');
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const raw = (s) => Buffer.from(s, 'base64');
const domain = Buffer.from('CryptIRC identity fingerprint v2');
const v2 = (id) => 'v2:' + group(sha(u32(domain.length), domain, u32(65), raw(id.dh), u32(65), raw(id.sign)));
const legacyFull = (id) => group(sha(raw(id.dh), raw(id.sign)));
const legacyDh = (id) => group(sha(raw(id.dh)));
const call = (fn, ...args) => ctx[fn](...args);

await check('new pins are versioned, domain-separated and length-prefixed over both keys', async () => {
  const fp = await call('computeIdentityFingerprint', A.dh, A.sign);
  assert.equal(fp, v2(A));
  assert.match(fp, /^v2:[0-9A-F]{4}( [0-9A-F]{4}){15}$/);
  assert.notEqual(fp, legacyFull(A));
  assert.notEqual(fp, await call('computeIdentityFingerprint', B.dh, B.sign));
  assert.notEqual(fp, await call('computeIdentityFingerprint', A.dh, B.sign));
});

await check('new pins require both validated P-256 identity keys', async () => {
  const compressed = b64(Buffer.concat([Buffer.from([2 + (raw(A.sign)[64] & 1)]), raw(A.sign).subarray(1, 33)]));
  const offCurve = b64(Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 1)]));
  const joined = b64(Buffer.concat([raw(A.dh), raw(A.sign)]));
  for (const [dh, sign, why] of [[A.dh, null, 'DH key only'], [A.dh, '', 'empty signing key'],
    [A.dh, compressed, 'compressed signing key'], [offCurve, A.sign, 'DH point not on the curve'],
    [A.dh, offCurve, 'signing point not on the curve'], [joined, '', 'both keys passed as one'],
    [A.dh, 'not base64 !', 'malformed']]) {
    assert.equal(await call('e2eValidIdentityKeys', dh, sign), false, why);
    await assert.rejects(Promise.resolve().then(() => call('computeIdentityFingerprint', dh, sign)), why);
  }
  assert.equal(await call('e2eValidIdentityKeys', A.dh, A.sign), true);
});

await check('the earlier full-pin computation is unchanged for compatibility', async () => {
  assert.equal(await call('e2eLegacyIdentityFingerprint', A.dh, A.sign), legacyFull(A));
  assert.equal(await call('e2eIsLegacyFingerprint', legacyFull(A)), true);
  assert.equal(await call('e2eIsLegacyFingerprint', v2(A)), false);
});

await check('a pin matches only the identity it confirmed', async () => {
  const m = (pin, dh, sign) => call('e2ePinMatchesIdentity', pin, dh, sign);
  assert.equal(await m(v2(A), A.dh, A.sign), true);
  assert.equal(await m(legacyFull(A), A.dh, A.sign), true, 'an existing full pin stays valid');
  assert.equal(await m(legacyDh(A), A.dh, A.sign), false, 'a DH-only pin never vouches for a signing key');
  assert.equal(await m(legacyDh(A), A.dh, B.sign), false);
  assert.equal(await m(v2(A), A.dh, B.sign), false);
  assert.equal(await m(legacyFull(A), A.dh, B.sign), false);
  assert.equal(await m(v2(B), A.dh, A.sign), false);
  // The unprefixed digest of dh||sign is ambiguous unless both keys are validated.
  const joined = b64(Buffer.concat([raw(A.dh), raw(A.sign)]));
  assert.equal(await m(legacyFull(A), joined, ''), false);
  assert.equal(await m(legacyFull(A), joined, null), false);
  assert.equal(await m('', A.dh, A.sign), false);
});

function resetTrust(pins) {
  ctx.E2E.trustStore = Object.create(null);
  for (const [k, fingerprint] of Object.entries(pins))
    ctx.E2E.trustStore[k] = {fingerprint, verified: true, keyChanged: false, pendingFingerprint: null};
  ctx.stateWrites.length = 0;
}
const trust = async (nick, id) => call('e2eCheckTrust', nick,
  await call('computeIdentityFingerprint', id.dh, id.sign).catch(() => null), {keys: [id.dh, id.sign]});

await check('first contact pins the v2 fingerprint of validated keys', async () => {
  resetTrust({});
  const r = await trust('alice', A);
  assert.equal(r.status, 'tofu');
  assert.equal(ctx.E2E.trustStore.alice.fingerprint, v2(A));
  assert.equal(r.pin, v2(A));
  const bad = await call('e2eCheckTrust', 'mallory', legacyFull(A), {keys: [A.dh, null]});
  assert.equal(bad.status, 'rejected');
  assert.equal(ctx.E2E.trustStore.mallory, undefined);
  const forged = await call('e2eCheckTrust', 'mallory', legacyFull(A), {keys: [A.dh, A.sign]});
  assert.equal(forged.status, 'rejected', 'a new pin must be the v2 fingerprint of the presented keys');
  assert.equal(ctx.E2E.trustStore.mallory, undefined);
});

await check('an existing full pin keeps matching the same keys without a silent rewrite', async () => {
  resetTrust({alice: legacyFull(A)});
  const r = await trust('alice', A);
  assert.equal(r.status, 'verified');
  assert.equal(r.keyChanged, false);
  assert.equal(r.pin, legacyFull(A));
  assert.equal(ctx.E2E.trustStore.alice.fingerprint, legacyFull(A));
  assert.deepEqual(ctx.stateWrites, []);
  const swapped = await trust('alice', {dh: A.dh, sign: B.sign});
  assert.equal(swapped.status, 'changed');
  assert.equal(ctx.E2E.trustStore.alice.fingerprint, legacyFull(A));
  assert.equal(ctx.E2E.trustStore.alice.pendingFingerprint, v2({dh: A.dh, sign: B.sign}));
});

await check('a DH-only pin asks before a signing key is trusted', async () => {
  resetTrust({alice: legacyDh(A)});
  const r = await trust('alice', A);
  assert.equal(r.status, 'changed');
  assert.equal(ctx.E2E.trustStore.alice.fingerprint, legacyDh(A));
  assert.equal(ctx.E2E.trustStore.alice.pendingFingerprint, v2(A));
});

await check('a v2 pin trusts exactly its keys', async () => {
  resetTrust({alice: v2(A)});
  assert.equal((await trust('alice', A)).status, 'verified');
  assert.equal((await trust('alice', B)).status, 'changed');
});

await check('sessions are compared with the pin in either format, never by the DH key alone', async () => {
  const sess = (id) => ({theirIdentityPub: id.dh, theirSignPub: id.sign});
  const mismatch = async (pin, s) => { resetTrust({alice: pin}); await call('_e2eSessFp', s); return call('_e2eSessPinMismatch', 'alice', s); };
  assert.equal(await call('_e2eSessFp', sess(A)), v2(A));
  assert.equal(await mismatch(v2(A), sess(A)), false);
  assert.equal(await mismatch(legacyFull(A), sess(A)), false);
  assert.equal(await mismatch(legacyDh(A), sess(A)), true);
  assert.equal(await mismatch(legacyDh(A), sess({dh: A.dh, sign: B.sign})), true);
  assert.equal(await mismatch(v2(B), sess(A)), true);
  assert.equal(call('_e2eSessPinIs', sess(A), legacyFull(A)), true);
  assert.equal(call('_e2eSessPinIs', sess(A), legacyDh(A)), false);
  assert.equal(call('_e2eSessPinIs', sess(B), v2(B)), undefined, 'not computed yet');
});

await check('no other code path computes a DH-only fingerprint', async () => {
  assert.doesNotMatch(SRC, /computeIdentityFingerprint\([^)]*,\s*null\)/);
  assert.doesNotMatch(SRC, /'dh\|'/);
  const legacyDhUses = SRC.match(/e2eLegacyIdentityFingerprint\([^)]*,\s*null\)/g) || [];
  assert.equal(legacyDhUses.length, 1, 'only /encrypt accept retires sessions under a DH-only pin');
});

await check('the safety phrase covers both identity keys of both sides, in either order', async () => {
  const p = (me, them) => call('safetyPhraseV2', me.dh, me.sign, them.dh, them.sign);
  const phrase = await p(A, B);
  assert.equal(phrase.split(' ').length, 12);
  assert.equal(await p(B, A), phrase, 'both sides compute the same words');
  assert.notEqual(await p(A, {dh: B.dh, sign: A.sign}), phrase, 'a swapped peer signing key changes the words');
  assert.notEqual(await p({dh: A.dh, sign: B.sign}, B), phrase, 'a swapped own signing key changes the words');
  assert.notEqual(phrase, await call('safetyPhrase', A.dh, B.dh), 'distinct from the DH-only phrase');
  await assert.rejects(Promise.resolve().then(() => call('safetyPhraseV2', A.dh, null, B.dh, B.sign)));
  await assert.rejects(Promise.resolve().then(() => call('safetyPhraseV2', A.dh, A.sign, B.dh, '')));
});

await check('DH-only fingerprints and phrases are only shown labelled as legacy', async () => {
  const lines = SRC.split('\n');
  for (const [i, line] of lines.entries()) {
    if (/\bcomputeFingerprint\(/.test(line) && !/^async function computeFingerprint/.test(line))
      assert.match(line, /legacy/i, `line ${i + 1}`);
    if (/\bsafetyPhrase\(/.test(line) && !/^async function safetyPhrase/.test(line))
      assert.match(line, /legacyPhrase\s*=/, `line ${i + 1}`);
  }
  const verify = SRC.slice(SRC.indexOf("case 'verify':"), SRC.indexOf("case 'trust':"));
  assert.match(verify, /safetyPhraseV2\(/);
  assert.match(verify, /computeIdentityFingerprint\(session\.theirIdentityPub, session\.theirSignPub\)/);
});

console.log(`\n${passes} passed, ${failures} failed`);
process.exit(failures ? 1 : 0);
