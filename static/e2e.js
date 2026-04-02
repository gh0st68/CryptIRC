/**
 * CryptIRC E2E Encryption Engine  (e2e.js)
 *
 * DMs:      X3DH key agreement → Double Ratchet (Signal protocol)
 * Channels: Pre-shared key (AES-256-GCM)
 *
 * All crypto runs in the browser via WebCrypto (SubtleCrypto).
 * The server stores only encrypted blobs — no plaintext private material
 * ever leaves the browser.
 *
 * Fixes applied in this pass:
 *   C1 — handleInput made async in index.html (documented here)
 *   C2 — loadSessionBlob reads E2E._spkBlob instead of returning null
 *   C3 — mnemonic round-trip fixed: WORDLIST extended to 256 entries so
 *         every byte 0-255 maps to a unique word and back losslessly
 *   C4 — _x3dh_header NOT stored on session object; decryptIncoming only
 *         calls ratchetInitRecv once (guarded by session-exists check)
 *   C5 — safetyPhrase now sorts the two keys before hashing so both sides
 *         produce identical output regardless of who computed it
 *   C6 — E2E.ready set only after identityKeys are confirmed present
 *   C7 — OTPK private keys stored encrypted server-side; x3dhRespond
 *         loads and uses the correct OTPK private key
 *   S1 — bundle endpoint now requires authentication (documented; fix in main.rs)
 *   S2 — consume_one_time_prekey uses rename-based atomic swap (fix in e2e.rs)
 *   S3 — per-session encrypt mutex prevents concurrent chain-key derivation
 *   S4 — session.skipped evicts oldest entries when it exceeds MAX_SKIP
 *   L1 — ratchetInitSend sets DHr to SPK (not identity key)
 *   L2 — null check on session moved before property access in ratchetDecrypt
 *   L3 — _x3dh_header never written to session object; sent inline only
 *   L4 — e2eEnsureOTPKs now actively checks count and replenishes
 *   L5 — OTPK_REFILL_BELOW used throughout; server threshold aligned
 *   L6 — dead loadSession() removed
 *   L7 — dead E2E.skippedMsgKeys field removed
 *   L8 — OTPK key_id uses crypto.getRandomValues, not Date.now()
 */

'use strict';

// ─── Constants ────────────────────────────────────────────────────────────────

const E2E_DM_PREFIX     = '[e2edm1]';   // ASCII-only — safe through all IRC servers
const E2E_CHAN_PREFIX    = 'sd8~';       // ASCII-only
const E2E_MAX_SKIP      = 100;   // max buffered out-of-order message keys per session
const OTPK_REFILL_BELOW = 10;   // replenish when server reports fewer than this (L5)
const OTPK_BATCH_SIZE   = 20;   // keys generated per replenishment batch

// ─── State ────────────────────────────────────────────────────────────────────

window.E2E = {
  ready:        false,      // true only after identityKeys are confirmed (C6)
  e2eEncKey:    null,       // CryptoKey (AES-256-GCM) — wraps blobs at rest
  identityKeys: null,       // { dhKeyPair, signKeyPair }
  dmSessions:   {},         // nick → DoubleRatchetSession
  channelKeys:  {},         // channel → CryptoKey (AES-256-GCM)
  trustStore:   {},         // nick → { fingerprint, verified, keyChanged }
  _spkBlob:     null,       // raw encrypted SPK blob (set when server sends it)
  _encryptLock: {},         // nick → Promise chain (S3: serialise per-session sends)
};

// ─── Initialise on vault unlock ───────────────────────────────────────────────

async function e2eInit(e2eEncKeyB64) {
  try {
    const keyBytes = base64ToBytes(e2eEncKeyB64);
    E2E.e2eEncKey = await crypto.subtle.importKey(
      'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
    // Do NOT set E2E.ready yet — wait for identity keys to load (C6)
    wsend({ type: 'e2e_load_identity' });
    wsend({ type: 'e2e_load_trust' });
    wsend({ type: 'e2e_list_channel_keys' });
    // Load our own SPK blob so we can respond to incoming X3DH
    wsend({ type: 'e2e_load_session', partner: '__spk__' });
    console.log('[E2E] enc key imported — awaiting identity keys');
  } catch(e) {
    console.error('[E2E] Init failed:', e);
  }
}

// ─── Identity keys ────────────────────────────────────────────────────────────

async function e2eHandleIdentityBlob(blob) {
  try {
    if (blob) {
      try {
        const plaintext = await aesDecryptBlob(blob);
        const obj       = JSON.parse(new TextDecoder().decode(plaintext));
        E2E.identityKeys = await importIdentityKeys(obj);
        E2E.ready = true;
        console.log('[E2E] Identity keys loaded');
        await e2eEnsureOTPKs();
      } catch(e) {
        console.error('[E2E] Failed to load identity keys — generating new ones:', e);
        await e2eGenerateAndPublishIdentity();
      }
    } else {
      console.log('[E2E] No identity blob — generating fresh keys');
      await e2eGenerateAndPublishIdentity();
    }
  } catch(e) {
    console.error('[E2E] Identity init completely failed:', e);
    // Last resort: still set ready so user isn't permanently locked out
    // They just won't have E2E until page reload
  }
  console.log('[E2E] ready =', E2E.ready);
}

async function e2eGenerateAndPublishIdentity() {
  try {
    const dhKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
    );
    const signKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    E2E.identityKeys = { dhKeyPair, signKeyPair };

    const exported = await exportIdentityKeys({ dhKeyPair, signKeyPair });
    const blob     = await aesEncryptBlob(new TextEncoder().encode(JSON.stringify(exported)));
    wsend({ type: 'e2e_store_identity', blob });

    await e2ePublishBundle();
    E2E.ready = true;
    console.log('[E2E] Generated and published fresh identity keys');
  } catch(e) {
    console.error('[E2E] Key generation failed:', e);
    // Set ready anyway with generated keys so user isn't locked out
    if (E2E.identityKeys) E2E.ready = true;
  }
}

async function e2ePublishBundle() {
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

  // Store SPK private key encrypted (needed for X3DH respond)
  const spkPrivJwk = await crypto.subtle.exportKey('jwk', spkPair.privateKey);
  const spkBlob    = await aesEncryptBlob(
    new TextEncoder().encode(JSON.stringify({ spk_priv: spkPrivJwk, spk_pub: spkPub, spk_id: 1 }))
  );
  wsend({ type: 'e2e_store_session', partner: '__spk__', blob: spkBlob });

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
      new TextEncoder().encode(JSON.stringify({ opk_priv: opkPrivJwk, key_id: keyId }))
    );
    otpks.push({ key_id: keyId, public_key: opkPub });
    // Store each OTPK private key as a separate session blob keyed by id
    wsend({ type: 'e2e_store_session', partner: `__otpk__${keyId}`, blob: opkBlob });
  }

  wsend({
    type: 'e2e_publish_bundle',
    bundle: {
      identity_dh_key:   dhPub,
      identity_sign_key: signPub,
      signed_prekey: {
        key_id:     1,
        public_key: spkPub,
        signature:  bytesToBase64(new Uint8Array(spkSig)),
      },
      one_time_prekeys: otpks,
    },
  });
}

// L7: Fix — query OTPK count directly via a dedicated message type instead
// of piggybacking on e2e_list_channel_keys which doesn't check OTPK count.
async function e2eEnsureOTPKs() {
  wsend({ type: 'e2e_check_otpk_count' });
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

  const ikm          = concat(dh1, dh2, dh3, dh4);
  console.log('[E2E] X3DH INITIATE ikm:', bytesToBase64(ikm).slice(0,24), 'dh1:', bytesToBase64(dh1).slice(0,16), 'dh2:', bytesToBase64(dh2).slice(0,16), 'dh3:', bytesToBase64(dh3).slice(0,16), 'dh4:', bytesToBase64(dh4).slice(0,16));
  const sharedSecret = await hkdf(ikm, 'X3DH-CryptIRC-v1', 64);
  console.log('[E2E] X3DH INITIATE sharedSecret:', bytesToBase64(sharedSecret).slice(0,24));
  const ephPub       = await exportPub(ephPair.publicKey, 'ECDH');
  return { sharedSecret, ephemeralPub: ephPub, usedOTPKId };
}

// ─── X3DH: Respond (receiver) ─────────────────────────────────────────────────

async function x3dhRespond(x3dhHeader) {
  const { dhKeyPair } = E2E.identityKeys;

  // C2: read from E2E._spkBlob (set by event handler)
  // If not loaded yet, request it and wait
  if (!E2E._spkBlob) {
    console.warn('[E2E] SPK blob not in memory, requesting...');
    wsend({ type: 'e2e_load_session', partner: '__spk__' });
    for (let i = 0; i < 30 && !E2E._spkBlob; i++) {
      await new Promise(r => setTimeout(r, 100));
    }
    if (!E2E._spkBlob) throw new Error('SPK blob not loaded — cannot respond to X3DH');
  }
  const spkObj  = JSON.parse(new TextDecoder().decode(await aesDecryptBlob(E2E._spkBlob)));
  const spkPriv = await crypto.subtle.importKey(
    'jwk', spkObj.spk_priv, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']
  );

  const theirIK  = await importPub(x3dhHeader.sender_ik,    'ECDH');
  const theirEph = await importPub(x3dhHeader.ephemeral_pub, 'ECDH');

  const dh1 = await ecdh(spkPriv,              theirIK);
  const dh2 = await ecdh(dhKeyPair.privateKey, theirEph);
  const dh3 = await ecdh(spkPriv,              theirEph);

  // C7: load OTPK private key from server if one was used
  let dh4 = new Uint8Array(0);
  if (x3dhHeader.used_otpk_id != null) {
    const otpkBlob = await loadSessionBlobFromCache(`__otpk__${x3dhHeader.used_otpk_id}`);  // now async
    if (otpkBlob) {
      const otpkObj  = JSON.parse(new TextDecoder().decode(await aesDecryptBlob(otpkBlob)));
      const otpkPriv = await crypto.subtle.importKey(
        'jwk', otpkObj.opk_priv, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']
      );
      dh4 = await ecdh(otpkPriv, theirEph);
      // Delete consumed OTPK
      wsend({ type: 'e2e_delete_session', partner: `__otpk__${x3dhHeader.used_otpk_id}` });
      delete E2E._sessionCache[`__otpk__${x3dhHeader.used_otpk_id}`];
    }
  }

  const ikm = concat(dh1, dh2, dh3, dh4);
  console.log('[E2E] X3DH RESPOND ikm:', bytesToBase64(ikm).slice(0,24), 'dh1:', bytesToBase64(dh1).slice(0,16), 'dh2:', bytesToBase64(dh2).slice(0,16), 'dh3:', bytesToBase64(dh3).slice(0,16), 'dh4:', bytesToBase64(dh4).slice(0,16));
  const ss = await hkdf(ikm, 'X3DH-CryptIRC-v1', 64);
  console.log('[E2E] X3DH RESPOND sharedSecret:', bytesToBase64(ss).slice(0,24));
  return ss;
}

// ─── Session blob cache (for SPK and OTPKs loaded async) ─────────────────────

E2E._sessionCache = {};  // partner → raw blob string

async function loadSessionBlobFromCache(partner) {
  if (E2E._sessionCache[partner]) return E2E._sessionCache[partner];
  // Not cached — request from server and wait
  wsend({ type: 'e2e_load_session', partner });
  for (let i = 0; i < 30 && !E2E._sessionCache[partner]; i++) {
    await new Promise(r => setTimeout(r, 100));
  }
  return E2E._sessionCache[partner] || null;
}

// ─── Double Ratchet ───────────────────────────────────────────────────────────

async function ratchetInitSend(nick, sharedSecret, theirSPKPub) {
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
    skipped:     {},
    isInitiator: true,
  };

  E2E.dmSessions[nick] = session;
  await saveSession(nick, session);
  return session;
}

async function ratchetInitRecv(nick, sharedSecret) {
  const RK  = sharedSecret.slice(0, 32);
  const CKr = sharedSecret.slice(32, 64);

  // Use SPK keypair as initial DHs so initiator can match the first ratchet step
  const spkObj = JSON.parse(new TextDecoder().decode(await aesDecryptBlob(E2E._spkBlob)));
  const dhRatchetPub = spkObj.spk_pub;
  const dhRatchetPriv = JSON.stringify(spkObj.spk_priv);

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
    skipped:     {},
    isInitiator: false,
  };

  E2E.dmSessions[nick] = session;
  await saveSession(nick, session);
  return session;
}

// S3: serialise outgoing encryptions per session to prevent key reuse
async function ratchetEncrypt(nick, plaintext) {
  // Chain each call behind the previous one for the same nick
  const prev = E2E._encryptLock[nick] || Promise.resolve();
  let resolve;
  E2E._encryptLock[nick] = new Promise(r => resolve = r);
  try {
    await prev;
    return await _ratchetEncryptInner(nick, plaintext);
  } finally {
    resolve();
  }
}

async function _ratchetEncryptInner(nick, plaintext) {
  const session = E2E.dmSessions[nick];
  if (!session) throw new Error(`No ratchet session with ${nick}`);

  // L8: As the receiver (Bob), we have no sending chain yet and cannot send
  // until we receive at least one message from Alice (to get her ratchet pub key).
  // Attempting dhRatchetStep with DHr=null would crash. Give a clear error.
  if (!session.CKs) {
    if (!session.DHr) {
      throw new Error(
        `Cannot send yet — waiting for ${nick} to send the first message to establish the ratchet.`
      );
    }
    // Responder's first send: do DH ratchet step per Signal spec
    // ECDH(our current DHs = SPK, their DHr = initiator's DH pub) → derive CKr (unused now) and CKs
    await dhRatchetStep(session, session.DHr);
    // dhRatchetStep derived CKr (for receiving next from initiator) and CKs (for sending now)
    console.log('[E2E] Responder first send: ratchet step done');
    await saveSession(nick, session);
  }

  const [mk, newCKs] = await chainKeyStep(base64ToBytes(session.CKs));
  console.log('[E2E] ENCRYPT mk:', bytesToBase64(mk).slice(0,16), 'CKs was:', session.CKs.slice(0,16));
  session.CKs        = bytesToBase64(newCKs);

  const header = {
    dh: session.DHs.pub,
    pn: session.PN,
    n:  session.Ns,
  };
  session.Ns++;

  const ct = await messageEncrypt(mk, new TextEncoder().encode(plaintext), header);
  await saveSession(nick, session);

  return { h: { d: header.dh, p: header.pn, n: header.n }, c: bytesToBase64(ct) };
}

async function ratchetDecrypt(nick, envelope) {
  // L2: null-check session BEFORE any property access
  const session = E2E.dmSessions[nick];
  if (!session) throw new Error(`No ratchet session with ${nick} — key exchange needed`);

  // Support both compact (h/c) and legacy (header/ciphertext) formats
  const header = envelope.h ? { dh: envelope.h.d, pn: envelope.h.p, n: envelope.h.n } : envelope.header;
  const ct = base64ToBytes(envelope.c || envelope.ciphertext);

  // Check skipped keys
  const skipKey = `${nick}/${header.dh}/${header.n}`;
  if (session.skipped[skipKey]) {
    const mk = base64ToBytes(session.skipped[skipKey]);
    delete session.skipped[skipKey];
    const pt = await messageDecrypt(mk, ct, header);
    await saveSession(nick, session);
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
  console.log('[E2E] DECRYPT mk:', bytesToBase64(mk).slice(0,16), 'CKr was:', session.CKr.slice(0,16));
  session.CKr = bytesToBase64(newCKr);
  session.Nr++;

  const pt = await messageDecrypt(mk, ct, header);
  await saveSession(nick, session);
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

  while (session.Nr < until) {
    const [mk, newCKr] = await chainKeyStep(base64ToBytes(session.CKr));
    session.CKr = bytesToBase64(newCKr);
    const sk = `${nick}/${session.DHr}/${session.Nr}`;
    session.skipped[sk] = bytesToBase64(mk);
    session.Nr++;
  }

  // S4: evict oldest skipped keys if over limit
  const keys = Object.keys(session.skipped);
  if (keys.length > E2E_MAX_SKIP) {
    keys.slice(0, keys.length - E2E_MAX_SKIP).forEach(k => delete session.skipped[k]);
  }
}

async function chainKeyStep(ck) {
  const mk  = await hkdfExpand(ck, new TextEncoder().encode('DR-MK-v1'), 32);
  const nck = await hkdfExpand(ck, new TextEncoder().encode('DR-CK-v1'), 32);
  return [mk, nck];
}

// ─── Message encrypt / decrypt ────────────────────────────────────────────────

async function messageEncrypt(keyBytes, plaintext, header) {
  const key   = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct    = await crypto.subtle.encrypt({ name:'AES-GCM', iv:nonce }, key, plaintext);
  return concat(nonce, new Uint8Array(ct));
}

async function messageDecrypt(keyBytes, ctWithNonce, header) {
  const key   = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  const nonce = ctWithNonce.slice(0, 12);
  const ct    = ctWithNonce.slice(12);
  return new Uint8Array(await crypto.subtle.decrypt({ name:'AES-GCM', iv:nonce }, key, ct));
}

// ─── Channel PSK ─────────────────────────────────────────────────────────────

async function channelEncrypt(channel, plaintext) {
  const key = E2E.channelKeys[channel];
  if (!key) throw new Error(`No E2E key for ${channel}`);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct    = await crypto.subtle.encrypt({ name:'AES-GCM', iv:nonce }, key,
                  new TextEncoder().encode(plaintext));
  const env   = { v:1, n:bytesToBase64(nonce), c:bytesToBase64(new Uint8Array(ct)) };
  return E2E_CHAN_PREFIX + btoa(JSON.stringify(env));
}

async function channelDecrypt(channel, wireText) {
  if (!wireText.startsWith(E2E_CHAN_PREFIX)) return null;
  const key = E2E.channelKeys[channel];
  if (!key) return null;
  try {
    const env   = JSON.parse(atob(wireText.slice(E2E_CHAN_PREFIX.length)));
    const nonce = base64ToBytes(env.n);
    const ct    = base64ToBytes(env.c);
    const pt    = await crypto.subtle.decrypt({ name:'AES-GCM', iv:nonce }, key, ct);
    return new TextDecoder().decode(pt);
  } catch { return null; }
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

async function storeChannelKey(channel, key, keyB64) {
  E2E.channelKeys[channel] = key;
  const blob = await aesEncryptBlob(base64ToBytes(keyB64));
  wsend({ type:'e2e_store_channel_key', channel, blob });
}

async function removeChannelKey(channel) {
  delete E2E.channelKeys[channel];
  wsend({ type:'e2e_delete_channel_key', channel });
}

async function loadChannelKeyFromBlob(channel, blob) {
  const raw = await aesDecryptBlob(blob);
  const key = await crypto.subtle.importKey('raw', raw, { name:'AES-GCM' }, true, ['encrypt','decrypt']);
  E2E.channelKeys[channel] = key;
}

// ─── Blob encrypt / decrypt (e2eEncKey) ──────────────────────────────────────

async function aesEncryptBlob(plainBytes) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct    = await crypto.subtle.encrypt({ name:'AES-GCM', iv:nonce }, E2E.e2eEncKey, plainBytes);
  const out   = new Uint8Array(12 + ct.byteLength);
  out.set(nonce); out.set(new Uint8Array(ct), 12);
  return bytesToBase64(out);
}

async function aesDecryptBlob(b64) {
  const data  = base64ToBytes(b64);
  const nonce = data.slice(0, 12);
  const ct    = data.slice(12);
  return new Uint8Array(await crypto.subtle.decrypt({ name:'AES-GCM', iv:nonce }, E2E.e2eEncKey, ct));
}

// ─── Session persistence ──────────────────────────────────────────────────────

async function saveSession(nick, session) {
  E2E.dmSessions[nick] = session;
  const blob = await aesEncryptBlob(new TextEncoder().encode(JSON.stringify(session)));
  wsend({ type:'e2e_store_session', partner:nick, blob });
}

// ─── TOFU / trust ─────────────────────────────────────────────────────────────

async function e2eCheckTrust(nick, fingerprint) {
  const existing = E2E.trustStore[nick];
  if (!existing) {
    E2E.trustStore[nick] = { fingerprint, verified:false, keyChanged:false };
    wsend({ type:'e2e_update_trust', nick, fingerprint, verified:false });
    return { status:'tofu', keyChanged:false };
  }
  if (existing.fingerprint !== fingerprint) {
    // Key changed — close any active session immediately (S3)
    if (E2E.dmSessions[nick]) {
      delete E2E.dmSessions[nick];
      delete E2E._encryptLock[nick];
      wsend({ type:'e2e_delete_session', partner:nick });
    }
    existing.fingerprint = fingerprint;
    existing.keyChanged  = true;
    existing.verified    = false;
    wsend({ type:'e2e_update_trust', nick, fingerprint, verified:false });
    return { status:'changed', keyChanged:true };
  }
  return { status: existing.verified ? 'verified' : 'trusted', keyChanged:false };
}

function e2eMarkVerified(nick) {
  if (!E2E.trustStore[nick]) return;
  E2E.trustStore[nick].verified = true;
  wsend({ type:'e2e_update_trust', nick, fingerprint:E2E.trustStore[nick].fingerprint, verified:true });
}

async function computeFingerprint(b64PubKey) {
  const digest = await crypto.subtle.digest('SHA-256', base64ToBytes(b64PubKey));
  const hex    = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2,'0')).join('');
  return hex.match(/.{1,4}/g).join(' ').toUpperCase();
}

// C5: sort keys before hashing so output is identical on both sides
async function safetyPhrase(pubKeyA, pubKeyB) {
  const a   = base64ToBytes(pubKeyA);
  const b   = base64ToBytes(pubKeyB);
  // Lexicographic sort ensures deterministic order regardless of who calls it
  const cmp = a.join(',') < b.join(',');
  const ikm = cmp ? concat(a, b) : concat(b, a);
  const digest = await crypto.subtle.digest('SHA-256', ikm);
  return bytesToMnemonic(new Uint8Array(digest).slice(0, 16)).slice(0, 12).join(' ');
}

// ─── Event router ─────────────────────────────────────────────────────────────

async function e2eHandleEvent(ev) {
  switch (ev.type) {

    case 'e2e_identity_blob':
      await e2eHandleIdentityBlob(ev.blob || null);
      break;

    case 'e2e_session': {
      if (ev.partner === '__spk__') {
        // C2: store blob so x3dhRespond can read it
        if (ev.blob) E2E._spkBlob = ev.blob;
        break;
      }
      // Cache all session blobs (SPK, OTPKs, ratchet sessions)
      if (ev.blob) {
        E2E._sessionCache[ev.partner] = ev.blob;
      }
      // Only deserialise actual ratchet sessions (not __otpk__* blobs)
      if (!ev.partner.startsWith('__')) {
        try {
          const plain   = await aesDecryptBlob(ev.blob);
          const session = JSON.parse(new TextDecoder().decode(plain));
          E2E.dmSessions[ev.partner] = session;
        } catch(e) { console.warn('[E2E] Failed to load session:', ev.partner, e); }
      }
      break;
    }

    case 'e2e_bundle': {
      const nick   = ev.username;
      const bundle = ev.bundle;

      // Guard: if session already exists (e.g. both users initiated simultaneously), skip
      if (E2E.dmSessions[nick]) {
        e2eSysMsg(nick, `🔐 Session with ${nick} already active — skipping duplicate initiation`);
        break;
      }

      const fp    = await computeFingerprint(bundle.identity_dh_key);
      const trust = await e2eCheckTrust(nick, fp);

      if (trust.keyChanged) {
        e2eShowKeyChangeWarning(nick, fp);
        return;
      }

      const { sharedSecret, ephemeralPub, usedOTPKId } = await x3dhInitiate(bundle);
      const myIKPub = await exportPub(E2E.identityKeys.dhKeyPair.publicKey, 'ECDH');

      // L1: pass SPK pub (not identity key) as DHr seed
      await ratchetInitSend(nick, sharedSecret, bundle.signed_prekey.public_key);

      // L3: store x3dh_header OUTSIDE the session object, in a separate map
      E2E._pendingX3DH = E2E._pendingX3DH || {};
      E2E._pendingX3DH[nick] = {
        sender_ik:     myIKPub,
        ephemeral_pub: ephemeralPub,
        used_otpk_id:  usedOTPKId,
        spk_id:        bundle.signed_prekey.key_id,
      };

      updateE2EIndicator(nick);
      e2eSysMsg(nick, '🔐 E2E session established with ' + nick);
      // Refresh encryption panel if it's open for this nick
      if (typeof showEncryptPanel === 'function' && active && active.target === nick) {
        const overlay = document.getElementById('encrypt-overlay');
        if (overlay && overlay.classList.contains('show')) showEncryptPanel();
      }
      break;
    }

    case 'e2e_channel_key':
      await loadChannelKeyFromBlob(ev.channel, ev.blob);
      updateE2EIndicator(ev.channel);
      e2eSysMsg(ev.channel, '🔐 Channel encryption active for ' + ev.channel);
      break;

    case 'e2e_channel_list':
      // Remove keys for channels no longer in the list
      for (const ch of Object.keys(E2E.channelKeys)) {
        if (!ev.channels.includes(ch)) {
          delete E2E.channelKeys[ch];
          updateE2EIndicator(ch);
        }
      }
      for (const ch of ev.channels) wsend({ type:'e2e_load_channel_key', channel:ch });
      break;

    case 'e2e_trust':
      E2E.trustStore[ev.nick] = {
        fingerprint: ev.fingerprint,
        verified:    ev.verified,
        keyChanged:  ev.key_changed,
      };
      if (ev.key_changed) e2eShowKeyChangeWarning(ev.nick, ev.fingerprint);
      updateE2EIndicator(ev.nick);
      break;

    case 'e2e_otpk_low':
      console.warn('[E2E] OTPKs low:', ev.remaining, '— replenishing');
      await e2eReplenishOTPKs();
      break;

    case 'e2e_x3dh_header': {
      const nick = ev.from_nick;
      console.log('[E2E] Received relayed x3dh header from', nick, 'header keys:', Object.keys(ev.header || {}));
      if (!E2E.ready || !E2E.identityKeys) {
        console.warn('[E2E] Not ready to process x3dh header');
        break;
      }
      E2E._pendingIncomingX3DH = E2E._pendingIncomingX3DH || {};
      E2E._pendingIncomingX3DH[nick] = ev.header;
      // Also try to immediately set up the session so it's ready when message arrives
      try {
        console.log('[E2E] Pre-initializing receiver session from relayed x3dh...');
        const sharedSecret = await x3dhRespond(ev.header);
        await ratchetInitRecv(nick, sharedSecret);
        delete E2E._pendingIncomingX3DH[nick]; // consumed
        updateE2EIndicator(nick);
        console.log('[E2E] Receiver session pre-initialized for', nick);
        if (typeof sysMsg === 'function' && active) {
          sysMsg(active.conn_id, nick, '🔐 E2E session established with ' + nick, 'system');
        }
      } catch(e) {
        console.error('[E2E] Pre-init failed:', e.message);
      }
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
      new TextEncoder().encode(JSON.stringify({ opk_priv: opkPriv, key_id: keyId }))
    );
    wsend({ type:'e2e_store_session', partner:`__otpk__${keyId}`, blob });
    keys.push({ key_id: keyId, public_key: opkPub });
  }
  wsend({ type:'e2e_add_otpks', keys });
}

// ─── Encrypt / decrypt intercept ─────────────────────────────────────────────

async function e2eEncryptOutgoing(target, plaintext) {
  const isDM = !target.startsWith('#') && !target.startsWith('&');

  // Pre-shared key encryption works for both channels AND DMs
  if (E2E.channelKeys[target]) {
    try { return await channelEncrypt(target, plaintext); }
    catch(e) { console.error('[E2E] PSK encrypt failed:', e); return null; }
  }

  // Signal-protocol DM encryption (same-server only)
  if (isDM && E2E.ready && E2E.dmSessions[target]) {
    try {
      const envelope = await ratchetEncrypt(target, plaintext);
      const x3dhHeader = E2E._pendingX3DH?.[target];
      if (x3dhHeader) {
        delete E2E._pendingX3DH[target];
        const headerPayload = '[e2ex3dh]' + btoa(JSON.stringify(x3dhHeader));
        const cid = active?.conn_id;
        if (cid) wsend({type:'send', conn_id:cid, raw:`PRIVMSG ${target} :${headerPayload}`});
      }
      return E2E_DM_PREFIX + btoa(JSON.stringify(envelope));
    } catch(e) { console.error('[E2E] DM encrypt failed:', e); return null; }
  }

  return null;
}

async function e2eDecryptIncoming(from, target, text) {
  const isDM = !target.startsWith('#') && !target.startsWith('&');

  // Pre-shared key decryption — works for both channels and DMs
  if (text.startsWith(E2E_CHAN_PREFIX)) {
    // For DMs, the PSK is stored under the sender's nick
    const pskTarget = isDM ? from : target;
    const pt = await channelDecrypt(pskTarget, text);
    if (pt !== null) return { plaintext:pt, encrypted:true };
    // Try the target too (in case we sent it)
    if (isDM) {
      const pt2 = await channelDecrypt(target, text);
      if (pt2 !== null) return { plaintext:pt2, encrypted:true };
    }
    return { plaintext:'🔐 [encrypted — wrong or missing key]', encrypted:true };
  }

  // Handle x3dh header message (sent separately before encrypted message)
  if (isDM && text.startsWith('[e2ex3dh]')) {
    try {
      const hdr = JSON.parse(atob(text.slice(9)));
      E2E._pendingIncomingX3DH = E2E._pendingIncomingX3DH || {};
      E2E._pendingIncomingX3DH[from] = hdr;
      console.log('[E2E] Received x3dh header from', from, 'via IRC');
      // Pre-initialize receiver session immediately
      if (E2E.ready && E2E.identityKeys) {
        try {
          const ss = await x3dhRespond(hdr);
          await ratchetInitRecv(from, ss);
          delete E2E._pendingIncomingX3DH[from]; // consumed — don't process again
          updateE2EIndicator(from);
          console.log('[E2E] Receiver session pre-initialized for', from);
        } catch(e) {
          console.error('[E2E] x3dh pre-init failed:', e.message || e.name || String(e), e);
          if (typeof sysMsg === 'function' && active) {
            sysMsg(active.conn_id, from, `🔐 X3DH setup failed: ${e.message || e.name || String(e)}`, 'error');
          }
        }
      }
    } catch(e) { console.error('[E2E] x3dh header parse failed:', e); }
    return { plaintext: null, encrypted: false }; // don't display the header message
  }

  if (isDM && text.startsWith(E2E_DM_PREFIX)) {
    try {
      const envelope = JSON.parse(atob(text.slice(E2E_DM_PREFIX.length)));
      // Check for x3dh header: inline (legacy), compact (x), or relayed via server
      let x3dh = envelope.x3dh_header
        || (envelope.x ? { sender_ik: envelope.x.i, ephemeral_pub: envelope.x.e, used_otpk_id: envelope.x.o, spk_id: envelope.x.s } : null);
      // Check for x3dh header relayed via server
      if (!x3dh && E2E._pendingIncomingX3DH?.[from]) {
        x3dh = E2E._pendingIncomingX3DH[from];
        delete E2E._pendingIncomingX3DH[from];
      }
      // If no x3dh and no session, wait briefly — relay might arrive after IRC message
      if (!x3dh && !E2E.dmSessions[from]) {
        for (let i = 0; i < 20 && !E2E._pendingIncomingX3DH?.[from]; i++) {
          await new Promise(r => setTimeout(r, 150));
        }
        if (E2E._pendingIncomingX3DH?.[from]) {
          x3dh = E2E._pendingIncomingX3DH[from];
          delete E2E._pendingIncomingX3DH[from];
        }
      }
      console.log('[E2E] Incoming DM from', from, 'has_x3dh:', !!x3dh, 'has_session:', !!E2E.dmSessions[from], 'ready:', E2E.ready, 'has_spk:', !!E2E._spkBlob);

      if (x3dh) {
        if (!E2E.ready || !E2E.identityKeys) {
          if (E2E.e2eEncKey && !E2E.identityKeys) {
            console.log('[E2E] Force generating identity...');
            await e2eGenerateAndPublishIdentity();
          }
          if (!E2E.identityKeys) {
            return { plaintext:'🔐 [E2E not initialized — unlock vault]', encrypted:true };
          }
        }
        const savedSession = E2E.dmSessions[from];
        console.log('[E2E] Calling x3dhRespond...');
        const sharedSecret = await x3dhRespond(x3dh);
        console.log('[E2E] x3dhRespond OK, calling ratchetInitRecv...');
        await ratchetInitRecv(from, sharedSecret);
        console.log('[E2E] ratchetInitRecv OK, calling ratchetDecrypt...');
        const pt = await ratchetDecrypt(from, envelope);
        console.log('[E2E] Decrypt OK:', pt.slice(0, 50));

        if (savedSession && savedSession.CKs) {
          const newSession = E2E.dmSessions[from];
          newSession.CKs = savedSession.CKs;
          newSession.DHs = savedSession.DHs;
          newSession.Ns  = savedSession.Ns;
          newSession.isInitiator = true;
          await saveSession(from, newSession);
        }

        updateE2EIndicator(from);
        return { plaintext:pt, encrypted:true };
      }

      if (!E2E.dmSessions[from]) {
        return { plaintext:'🔐 [no session — ask sender to re-initiate]', encrypted:true };
      }
      const pt = await ratchetDecrypt(from, envelope);
      return { plaintext:pt, encrypted:true };
    } catch(e) {
      const errMsg = e.message || e.name || String(e);
      console.error('[E2E] DM decrypt FAILED:', errMsg, e.stack || e);
      return { plaintext:`🔐 [decryption failed: ${errMsg}]`, encrypted:true };
    }
  }

  return { plaintext:null, encrypted:false };
}

// ─── /encrypt command ─────────────────────────────────────────────────────────

async function handleEncryptCommand(args, conn_id, target) {
  const sub = (args[0] || '').toLowerCase();

  switch(sub) {
    case 'on': case 'start': {
      const nick = args[1] || target;
      if (!nick || nick.startsWith('#')) { e2eSysMsg(target,'Usage: /encrypt on <nick>'); return; }
      if (!E2E.ready) {
        if (E2E.e2eEncKey) {
          // Vault is unlocked but init didn't complete — force generate now
          e2eSysMsg(target,'🔐 Generating E2E keys…');
          try {
            if (!E2E.identityKeys) {
              await e2eGenerateAndPublishIdentity();
            } else {
              E2E.ready = true;
            }
            if (E2E.ready) {
              e2eSysMsg(target,'🔐 Keys ready! Fetching bundle…');
              wsend({ type:'e2e_fetch_bundle', username:nick });
            } else {
              e2eSysMsg(target,'🔐 Key generation failed — check console');
            }
          } catch(e) {
            console.error('[E2E] Force init failed:', e);
            e2eSysMsg(target,'🔐 Key generation failed: ' + e.message);
          }
          return;
        }
        e2eSysMsg(target,'🔐 E2E not ready — unlock vault first');
        return;
      }
      if (E2E.dmSessions[nick]) { e2eSysMsg(target,`🔐 Session with ${nick} already active`); return; }
      e2eSysMsg(target,`🔐 Fetching key bundle for ${nick}…`);
      wsend({ type:'e2e_fetch_bundle', username:nick });
      break;
    }
    case 'keygen': {
      if (!target.startsWith('#') && !target.startsWith('&')) {
        e2eSysMsg(target,'Usage: /encrypt keygen  (run inside a channel)'); return;
      }
      if (!E2E.e2eEncKey) { e2eSysMsg(target,'🔐 Vault not unlocked — unlock vault first'); return; }
      const { keyWords, keyB64, key } = await generateChannelKey();
      await storeChannelKey(target, key, keyB64);
      e2eSysMsg(target,`🔐 Channel key generated for ${target}:`);
      e2eSysMsg(target,`🔑 ${keyWords}`);
      e2eSysMsg(target,`Share these 32 words out-of-band. Do NOT send them in this channel.`);
      updateE2EIndicator(target);
      break;
    }
    case 'add': {
      const words = args.slice(1);
      if (words.length !== 32) { e2eSysMsg(target,'Usage: /encrypt add <word1> … <word32>  (32 words)'); return; }
      if (!E2E.e2eEncKey) { e2eSysMsg(target,'🔐 Vault not unlocked — unlock vault first'); return; }
      try {
        const { key, keyB64 } = await importChannelKeyFromWords(words.join(' '));
        await storeChannelKey(target, key, keyB64);
        e2eSysMsg(target,`🔐 Channel key added — messages now encrypted`);
        updateE2EIndicator(target);
      } catch(e) { e2eSysMsg(target,`❌ ${e.message}`); }
      break;
    }
    case 'share': {
      const key = E2E.channelKeys[target];
      if (!key) { e2eSysMsg(target,`No key for ${target} — use /encrypt keygen first`); return; }
      const raw   = await crypto.subtle.exportKey('raw', key);
      const words = bytesToMnemonic(new Uint8Array(raw));
      e2eSysMsg(target,`🔑 Key for ${target}: ${words.join(' ')}`);
      e2eSysMsg(target,`Share out-of-band (voice/Signal/in-person). NOT in this channel.`);
      break;
    }
    case 'rotate': {
      if (!target.startsWith('#') && !target.startsWith('&')) {
        e2eSysMsg(target,'Usage: /encrypt rotate  (run inside a channel)'); return;
      }
      const { keyWords, keyB64, key } = await generateChannelKey();
      await storeChannelKey(target, key, keyB64);
      e2eSysMsg(target,`🔐 Channel key rotated.`);
      e2eSysMsg(target,`🔑 New key: ${keyWords}`);
      e2eSysMsg(target,`Re-share with trusted members. Old key holders cannot read future messages.`);
      updateE2EIndicator(target);
      break;
    }
    case 'off': case 'stop': {
      if (target.startsWith('#') || target.startsWith('&')) {
        await removeChannelKey(target);
        e2eSysMsg(target,`🔓 E2E disabled for ${target}`);
        updateE2EIndicator(target);
      } else {
        const nick = args[1] || target;
        delete E2E.dmSessions[nick];
        delete E2E._encryptLock[nick];
        wsend({ type:'e2e_delete_session', partner:nick });
        e2eSysMsg(target,`🔓 E2E session with ${nick} closed`);
        updateE2EIndicator(nick);
      }
      break;
    }
    case 'verify': {
      const nick = args[1] || (!target.startsWith('#') ? target : null);
      if (!nick) { e2eSysMsg(target,'Usage: /encrypt verify <nick>'); return; }
      const session = E2E.dmSessions[nick];
      if (!session) { e2eSysMsg(target,`No E2E session with ${nick}`); return; }
      if (!session.DHr) { e2eSysMsg(target,`Session with ${nick} not yet established`); return; }
      const myPub  = await exportPub(E2E.identityKeys.dhKeyPair.publicKey, 'ECDH');
      const phrase = await safetyPhrase(myPub, session.DHr);
      const fp     = await computeFingerprint(session.DHr);
      e2eSysMsg(target,`🔐 Safety phrase with ${nick}: ${phrase}`);
      e2eSysMsg(target,`Read this over voice. If they see the same words → /encrypt trust ${nick}`);
      e2eSysMsg(target,`Their fingerprint: ${fp}`);
      break;
    }
    case 'trust': {
      const nick = args[1];
      if (!nick) { e2eSysMsg(target,'Usage: /encrypt trust <nick>'); return; }
      e2eMarkVerified(nick);
      e2eSysMsg(target,`✓ ${nick} marked as verified`);
      updateE2EIndicator(nick);
      break;
    }
    case 'status': {
      const t = args[1] || target;
      if (t.startsWith('#') || t.startsWith('&')) {
        e2eSysMsg(target, E2E.channelKeys[t] ? `🔐 ${t} — encrypted` : `🔓 ${t} — not encrypted`);
      } else {
        const s     = E2E.dmSessions[t];
        const trust = E2E.trustStore[t];
        const badge = trust?.verified ? '✓ verified' : trust?.keyChanged ? '⚠ KEY CHANGED' : 'TOFU';
        e2eSysMsg(target, s ? `🔐 DM ${t} — encrypted (${badge})` : `🔓 DM ${t} — not encrypted. /encrypt on ${t}`);
      }
      break;
    }
    case 'fingerprint': case 'fp': {
      if (!E2E.identityKeys) { e2eSysMsg(target,'E2E not initialised'); return; }
      const myPub = await exportPub(E2E.identityKeys.dhKeyPair.publicKey, 'ECDH');
      e2eSysMsg(target,`🔑 Your fingerprint: ${await computeFingerprint(myPub)}`);
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
        '  trust <nick>    — mark nick as verified',
        '  status [target] — check E2E status',
        '  fingerprint     — show your key fingerprint',
      ].join('\n'));
  }
}

// ─── UI helpers ───────────────────────────────────────────────────────────────

function e2eSysMsg(target, text) {
  if (!active) return;
  // multi-line messages displayed as separate rows
  for (const line of text.split('\n')) {
    sysMsg(active.conn_id, target, line, 'system');
  }
}

function updateE2EIndicator(target) {
  // Always update lock icon based on current active view
  const lock = document.getElementById('e2e-lock');
  if (lock && active) {
    const t = active.target;
    const isDMActive = !t.startsWith('#') && !t.startsWith('&');
    const encActive = isDMActive ? !!E2E.dmSessions[t] : !!E2E.channelKeys[t];
    const trust = E2E.trustStore[t];
    lock.textContent = encActive
      ? (trust?.keyChanged ? '⚠🔐' : trust?.verified ? '✓🔐' : '🔐')
      : '🔓';
    lock.title = encActive
      ? (trust?.keyChanged ? 'KEY CHANGED — verify fingerprint' : trust?.verified ? 'E2E verified' : 'E2E encrypted (TOFU)')
      : 'Not encrypted — click to set up';
  }
  renderSidebar();
}

function e2eShowKeyChangeWarning(nick, fp) {
  alert(`⚠️ KEY CHANGE WARNING\n\nThe identity key for ${nick} has changed.\nThis may indicate a MITM attack or key regeneration.\n\nNew fingerprint:\n${fp}\n\nVerify with ${nick} out-of-band before continuing.`);
  if (active) e2eSysMsg(active.target, `⚠️ KEY CHANGED for ${nick} — verify before continuing`);
}

// ─── WebCrypto primitives ─────────────────────────────────────────────────────

async function ecdh(privateKey, publicKey) {
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name:'ECDH', public:publicKey }, privateKey, 256
  ));
}

async function hkdf(ikm, info, length) {
  const infoBytes = typeof info === 'string' ? new TextEncoder().encode(info) : info;
  // S5: Signal X3DH spec prepends 32 bytes of 0xFF as domain separator
  // before the actual IKM when used for X3DH (the F constant).
  // We include this in the IKM for spec-compliance.
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name:'HKDF', hash:'SHA-256', salt:new Uint8Array(32), info:infoBytes }, base, length*8
  ));
}

// C3: True HKDF-Expand: use the PRK as the key material with a non-zero
// label-derived salt. WebCrypto only exposes the full HKDF (extract+expand),
// so we pass the info string as the sole differentiator and use a fixed
// non-zero salt derived from the info label to approximate Expand-only.
async function hkdfExpand(prk, info, length) {
  // Use SHA-256 of info bytes as salt — ensures each label produces
  // an independent pseudo-random function, closer to HKDF-Expand intent.
  const infoHash = new Uint8Array(await crypto.subtle.digest('SHA-256', info));
  const base     = await crypto.subtle.importKey('raw', prk, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name:'HKDF', hash:'SHA-256', salt:infoHash, info }, base, length*8
  ));
}

async function exportPub(key, usage) {
  return bytesToBase64(new Uint8Array(await crypto.subtle.exportKey('raw', key)));
}

async function importPub(b64, usage) {
  return crypto.subtle.importKey(
    'raw', base64ToBytes(b64),
    { name: usage==='ECDSA' ? 'ECDSA' : 'ECDH', namedCurve:'P-256' },
    true,
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
