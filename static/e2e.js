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

// E2E protocol v2 marker (audit #26/#81/#3/#24/#25/#29). v2 changes the message-key
// KDF to the Signal-spec KDF_CK (HMAC(CK,0x01)/HMAC(CK,0x02)) and prepends the X3DH F
// constant, so v1 ([e2edm1]) sessions cannot continue and peers transparently
// re-establish a fresh session on first contact (a one-time re-encrypt).
const E2E_DM_PREFIX     = '[e2edm2]';   // ASCII-only — safe through all IRC servers
const E2E_CHAN_PREFIX    = 'sd8~';       // ASCII-only
const E2E_MAX_SKIP      = 100;   // max buffered out-of-order message keys per session
const OTPK_REFILL_BELOW = 10;   // replenish when server reports fewer than this (L5)
const OTPK_BATCH_SIZE   = 20;   // keys generated per replenishment batch
// #F4: distinguished return from e2eEncryptOutgoing meaning "a DM E2E session EXISTS but
// is not yet send-ready" (typically the responder has no sending chain until it receives
// the peer's first message → ratchetEncrypt throws 'Cannot send yet'). Callers MUST treat
// this as BLOCKED: drop the outbound message and warn — NEVER fall back to sending
// plaintext, which would leak cleartext on an "encrypted" DM. It is a frozen sentinel so
// it can never collide with a real (string) wire payload or the null "no E2E → plaintext"
// result; identify it by strict === or the duck-typed marker `.e2eBlocked === true`.
const E2E_ENCRYPT_BLOCKED = Object.freeze({ e2eBlocked: true });
// #81: X3DH "F" domain-separation constant — 32 bytes of 0xFF prepended to the IKM
// before the X3DH KDF, per the Signal X3DH spec. Applied at both X3DH call sites.
const X3DH_F_CONSTANT   = new Uint8Array(32).fill(0xFF);

// ─── State ────────────────────────────────────────────────────────────────────

window.E2E = {
  ready:        false,      // true only after identityKeys are confirmed (C6)
  e2eEncKey:    null,       // CryptoKey (AES-256-GCM) — wraps blobs at rest
  identityKeys: null,       // { dhKeyPair, signKeyPair }
  dmSessions:   Object.create(null),  // nick → DoubleRatchetSession (null prototype to prevent pollution)
  channelKeys:  Object.create(null),  // channel → CryptoKey (AES-256-GCM)
  trustStore:   Object.create(null),  // nick → { fingerprint, verified, keyChanged }
  _spkBlob:     null,       // raw encrypted SPK blob (set when server sends it)
  _encryptLock: Object.create(null),  // nick → Promise chain (S3: serialise ALL per-session ratchet ops — encrypt AND decrypt — via _withRatchetLock)
  _sessionEpoch: Object.create(null),  // #12: nick → monotonic epoch high-water mark (per page session; survives re-handshakes) so stale server-pushed session blobs can be rejected
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

  // #25/#84: persist the SPK private key keyed by a stable spk_id, and select it by
  // the header's spk_id on respond (instead of blindly using "the current SPK"). The
  // id-keyed blob (`__spk__<id>`) lets us retain a short window of prior SPKs so an
  // initiator that fetched a slightly-stale bundle still resolves the right private
  // half. We also keep the legacy `__spk__` alias as the current SPK for the load path.
  // (Scheduled rotation would generate a new keypair under spk_id+1 and expire old ids;
  // the id-keyed storage + header selection here is the mechanism that makes that safe.)
  let spkId = 1;
  if (E2E._spkBlob) {
    try { const o = JSON.parse(new TextDecoder().decode(await aesDecryptBlob(E2E._spkBlob))); if (Number.isInteger(o.spk_id)) spkId = o.spk_id + 1; } catch(_) {}
  }
  const spkPrivJwk = await crypto.subtle.exportKey('jwk', spkPair.privateKey);
  const spkBlob    = await aesEncryptBlob(
    new TextEncoder().encode(JSON.stringify({ spk_priv: spkPrivJwk, spk_pub: spkPub, spk_id: spkId }))
  );
  wsend({ type: 'e2e_store_session', partner: '__spk__', blob: spkBlob });
  wsend({ type: 'e2e_store_session', partner: `__spk__${spkId}`, blob: spkBlob });
  E2E._spkBlob = spkBlob;

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
  let spkRaw = null;
  if (x3dhHeader.spk_id != null) {
    spkRaw = await loadSessionBlobFromCache(`__spk__${x3dhHeader.spk_id}`);
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
  const spkObj  = JSON.parse(new TextDecoder().decode(await aesDecryptBlob(spkRaw)));
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
    const otpkBlob = await loadSessionBlobFromCache(`__otpk__${x3dhHeader.used_otpk_id}`);  // now async
    if (!otpkBlob) {
      throw new Error('E2E_OTPK_MISSING: consumed one-time prekey blob unavailable — cannot complete X3DH (try re-establishing)');
    }
    const otpkObj  = JSON.parse(new TextDecoder().decode(await aesDecryptBlob(otpkBlob)));
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
// #1: Every responder path (inline [e2ex3dh], relayed e2e_x3dh_header, and the
// embedded-in-envelope path) MUST authenticate the claimed sender identity
// BEFORE establishing — otherwise the server (which distributes bundles AND
// relays X3DH headers) can substitute its own identity_ik and silently MITM the
// responder direction while the user sees "session established".
//
// This single helper is used by all three so they cannot drift apart:
//   * computes the TOFU fingerprint over BOTH identity keys (dh + sign, #11),
//   * on a CHANGED key: shows the key-change warning and REFUSES to establish
//     (returns false — caller must NOT print "session established"),
//   * on first-use (tofu): records the pin exactly like the initiator side,
//   * runs x3dhRespond + ratchetInitRecv, pinning theirIdentityPub (#2) and the
//     identity-binding AD (#12) on the session.
// Returns true on success, false if establishment was refused/failed.
// True if `name` SANITIZES (the server's exact filter: keep [A-Za-z0-9_-]) to a key
// in the reserved internal namespace ('__spk__' / '__otpk__<id>'). Used to refuse a
// peer nick that would collide with the user's own private-key blob filenames. The
// ASCII keep-set is a subset of the server's (Unicode-alnum + _ -), so this can never
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
async function e2eEstablishResponderSession(from, header, opts = {}) {
  // SECURITY: peer ratchet sessions share the server-side e2e/sessions namespace with
  // the user's OWN internal key blobs ('__spk__', '__otpk__<id>'). A peer whose nick
  // SANITIZES to a reserved name could otherwise overwrite the victim's own private-key
  // blob → permanent inbound-E2E self-DoS. Test the SERVER-SANITIZED form (the server
  // strips every char except [A-Za-z0-9_-] before using it as the filename), NOT the
  // raw nick — e.g. '[__spk__' passes a raw startsWith but the server stores it as
  // '__spk__'. (saveSession enforces the same below.)
  if (_e2eReservedNamespace(from)) {
    console.warn('[E2E] refusing reserved-namespace peer:', from);
    return false;
  }
  if (!header || !header.sender_ik) {
    console.warn('[E2E] responder establish: missing sender_ik');
    return false;
  }
  // REPLAY GUARD: every responder path (relayed e2e_x3dh_header, inline
  // [e2ex3dh], and the [e2edm1]-with-x3dh path) calls this and then runs
  // ratchetInitRecv, which OVERWRITES E2E.dmSessions[from] with a blank
  // receiving session (CKr fresh, CKs/DHr/Nr/skipped reset). The server relays
  // X3DH headers verbatim with no dedup, so any authenticated user — or the
  // peer itself replaying its own captured header — can resend the SAME header
  // that already established the live session and silently reset/corrupt an
  // ESTABLISHED session's receive chain (paths 1 & 2 have no restore at all;
  // the [e2edm1] path's restore only re-applies CKs/DHs/Ns, leaving CKr/Nr/DHr/
  // skipped destroyed). A genuine re-handshake (peer lost ratchet state, re-ran
  // /encrypt on) ALWAYS carries a fresh ephemeral_pub (x3dhInitiate generates a
  // new ephemeral every time), whereas a replay reuses the captured one. So if a
  // session already exists AND it was established from this exact ephemeral, this
  // header is a replay/duplicate of the one that built it — the session is
  // already that session; skip re-establishment (return success, idempotent).
  // Behaviour-preserving: first contact and genuine re-handshake (new ephemeral)
  // are unaffected; only a byte-replayed header stops resetting the live session.
  const _existing = E2E.dmSessions[from];
  if (_existing && header.ephemeral_pub
      && (_existing.establishEph === header.ephemeral_pub
          || (Array.isArray(_existing.priorEstablishEphs)
              && _existing.priorEstablishEphs.includes(header.ephemeral_pub)))) {
    console.warn('[E2E] ignoring replayed X3DH header (known ephemeral) for established session:', from);
    return true;
  }
  // #25: REQUIRE a non-empty signing identity key. v1 tolerated an empty
  // sender_sign_ik (a relay could strip it and make the victim pin a dh-only
  // fingerprint); v2 refuses to establish without it, so the pin always covers
  // BOTH identity keys.
  if (!header.sender_sign_ik || !header.sender_ik) {
    console.warn('[E2E] refusing X3DH from', from, '— missing identity key(s)');
    return false;
  }
  // #47: sender_sign_ik is never DH-bound (only feeds the pin/AAD/HKDF-info), so require
  // an ECDSA signature over sender_ik||ephemeral_pub||spk_id||used_otpk_id and verify it
  // BEFORE pinning; refuse on any missing/invalid/error so a relay-tampered sign key can
  // never become the pinned TOFU fingerprint.
  if (!header.sender_sign_sig) {
    console.warn('[E2E] refusing X3DH from', from, '— missing header signature');
    return false;
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
      return false;
    }
  } catch (e) {
    console.warn('[E2E] refusing X3DH from', from, '— header signature verify error:', e && e.message);
    return false;
  }
  // #11/#25: pin BOTH identity keys (dh + sign).
  const fp    = await computeIdentityFingerprint(header.sender_ik, header.sender_sign_ik);
  const trust = await e2eCheckTrust(from, fp);

  // #1: a changed identity must NOT silently re-establish. Warn and refuse.
  if (trust.keyChanged) {
    e2eShowKeyChangeWarning(from, fp);
    return false;
  }
  // #1: first-contact identity was not confirmed out-of-band — abort cleanly
  // (no pin, no session) exactly like a key change.
  if (trust.status === 'rejected') {
    console.warn('[E2E] responder establish refused — unconfirmed identity:', from);
    return false;
  }
  // status 'tofu' already recorded the pin inside e2eCheckTrust (first contact),
  // mirroring the initiator side; 'trusted'/'verified' mean the pin matches.

  // #3: DoS hardening for X3DH RE-establishment over an ALREADY-LIVE session. The
  // header is unauthenticated (only the SPK is signed, verified by the INITIATOR); a
  // fresh ephemeral bypasses the byte-replay guard above, and the server relays headers
  // verbatim with no dedup, so a compromised server or any peer can craft a header with
  // the real peer's PINNED identity keys but a new ephemeral to silently reset a working
  // receive chain (inbound-DM DoS).
  if (_existing) {
    // (a) A header that arrives ALONE (relayed e2e_x3dh_header or inline [e2ex3dh], with
    // NO accompanying ciphertext — opts.withEnvelope !== true) cannot be authenticated, so
    // it must NOT overwrite a live session. Defer: leave the caller's pending header for
    // the [e2edm2] path, which commits the new session only if its first message decrypts.
    if (!opts.withEnvelope) {
      console.warn('[E2E] deferring header-only X3DH re-establishment for live session:', from);
      return false;
    }
    // (b) Envelope-driven re-establishment IS allowed (the caller commits only on a
    // successful decrypt below), but rate-limit it per peer — the inline path was
    // previously unbounded. A genuine re-handshake is a handful; a forgery flood is capped
    // at 10/60s. First contact and byte-replays never reach here.
    const _now = Date.now();
    E2E._reestablishLog = E2E._reestablishLog || Object.create(null);
    const _log = (E2E._reestablishLog[from] || []).filter(t => _now - t < 60000);
    if (_log.length >= 10) {
      console.warn('[E2E] refusing X3DH re-establishment — rate limit exceeded for', from);
      E2E._reestablishLog[from] = _log;
      return false;
    }
    _log.push(_now);
    E2E._reestablishLog[from] = _log;
  }

  const { sharedSecret, identityAD, consumedOtpkId, selectedSpk } = await x3dhRespond(header);
  // #2: pin the initiator's long-term identity DH pub (header.sender_ik).
  // Pin the establishing ephemeral so the replay guard above can recognise a
  // resend of this exact header on the next call.
  // P4: seed the ratchet's initial DHs from the spk_id-selected SPK (returned by
  // x3dhRespond), so the initiator's pinned DHr matches.
  await ratchetInitRecv(from, sharedSecret, header.sender_ik, identityAD, header.ephemeral_pub, selectedSpk);
  // #29: now that the session is established (and x3dhRespond didn't abort on a
  // missing OTPK), it's safe to consume the one-time prekey.
  if (consumedOtpkId != null) {
    wsend({ type: 'e2e_delete_session', partner: `__otpk__${consumedOtpkId}` });
    delete E2E._sessionCache[`__otpk__${consumedOtpkId}`];
  }
  return true;
}

// ─── Session blob cache (for SPK and OTPKs loaded async) ─────────────────────

E2E._sessionCache = Object.create(null);  // partner → raw blob string (null prototype)

async function loadSessionBlobFromCache(partner) {
  if (E2E._sessionCache[partner]) return E2E._sessionCache[partner];
  // #48: event-driven, not a 3s spin-poll. The server ALWAYS replies to
  // e2e_load_session with an e2e_session event (the blob on a hit, an empty
  // string on a miss), so resolve the instant that reply is handled instead of
  // sleeping 30x100ms. Previously a header naming a nonexistent __otpk__/__spk__
  // id forced the full 3s wait before throwing, letting a peer stream such
  // headers to stall the (globally-serialised) incoming-decrypt pipeline. The
  // timeout is now only a dead-connection backstop.
  wsend({ type: 'e2e_load_session', partner });
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
// soon as the server's e2e_session reply is handled (hit -> blob, miss -> null),
// so no caller has to spin-poll. Called from the e2e_session event handler.
function _e2eResolveBlobWaiters(partner, blob) {
  const arr = E2E._sessionBlobWaiters && E2E._sessionBlobWaiters[partner];
  if (!arr) return;
  delete E2E._sessionBlobWaiters[partner];
  for (const cb of arr) { try { cb(blob); } catch (_) {} }
}

// ─── Double Ratchet ───────────────────────────────────────────────────────────

async function ratchetInitSend(nick, sharedSecret, theirSPKPub, theirIdentityPub, identityAD) {
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
    // #12: pin the canonical identity-binding AD for the per-message AEAD.
    identityAD:  identityAD || null,
    skipped:     {},
    isInitiator: true,
  };

  E2E.dmSessions[nick] = session;
  await saveSession(nick, session);
  return session;
}

async function ratchetInitRecv(nick, sharedSecret, theirIdentityPub, identityAD, establishEph, selectedSpk) {
  const RK  = sharedSecret.slice(0, 32);
  const CKr = sharedSecret.slice(32, 64);

  // Carry forward EVERY ephemeral that has previously established this session — not just
  // the most recent — so the replay guard in e2eEstablishResponderSession recognises a
  // re-delivered OLDER genuine header (whose ephemeral differs from the current one, e.g.
  // a header from before a legitimate re-handshake) and treats it as an idempotent no-op
  // instead of letting it overwrite/desync the live ratchet. Bounded to 32 + deduped; the
  // current establishEph is tracked in its own field so it's excluded from this list.
  const _old = E2E.dmSessions[nick];
  const _prior = [];
  if (_old) {
    if (_old.establishEph) _prior.push(_old.establishEph);
    if (Array.isArray(_old.priorEstablishEphs)) for (const e of _old.priorEstablishEphs) _prior.push(e);
  }
  const _priorDedup = [...new Set(_prior.filter(e => e && e !== establishEph))].slice(-32);

  // Use SPK keypair as initial DHs so initiator can match the first ratchet step.
  // P4 (#25/#84): prefer the spk_id-selected SPK the caller resolved in x3dhRespond
  // (the SPK the initiator pinned as DHr); only fall back to the current _spkBlob
  // when no selected SPK was threaded through (e.g. legacy callers).
  let dhRatchetPub, dhRatchetPriv;
  if (selectedSpk && selectedSpk.pub && selectedSpk.priv) {
    dhRatchetPub = selectedSpk.pub;
    dhRatchetPriv = JSON.stringify(selectedSpk.priv);
  } else {
    const spkObj = JSON.parse(new TextDecoder().decode(await aesDecryptBlob(E2E._spkBlob)));
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
    // #2: pin the initiator's LONG-TERM identity DH pubkey (header.sender_ik,
    // after the #1 trust check) so /encrypt verify matches on both peers.
    theirIdentityPub: theirIdentityPub || null,
    // #12: pin the canonical identity-binding AD for the per-message AEAD.
    identityAD:  identityAD || null,
    // Replay guard: record the X3DH ephemeral this session was established from,
    // so a verbatim resend of the same header (relayed by the untrusted server
    // or replayed by the peer) is recognised and does NOT reset the live session.
    establishEph: establishEph || null,
    // ...and every ephemeral that established a PRIOR generation of this session, so a
    // stale-but-genuine header replayed after a re-handshake is also caught (see above).
    priorEstablishEphs: _priorDedup,
    skipped:     {},
    isInitiator: false,
  };

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
  const prev = E2E._encryptLock[nick] || Promise.resolve();
  let resolve;
  E2E._encryptLock[nick] = new Promise(r => resolve = r);
  return (async () => {
    try {
      await prev;
      return await fn();
    } finally {
      resolve();
    }
  })();
}

async function ratchetEncrypt(nick, plaintext) {
  return _withRatchetLock(nick, () => _ratchetEncryptInner(nick, plaintext));
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
    await saveSession(nick, session);
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
  await saveSession(nick, session);

  return { h: { d: header.dh, p: header.pn, n: header.n }, c: bytesToBase64(ct) };
}

async function ratchetDecrypt(nick, envelope) {
  // Serialise with the send path (and other decrypts) per nick — see _withRatchetLock.
  return _withRatchetLock(nick, () => _ratchetDecryptInner(nick, envelope));
}

async function _ratchetDecryptInner(nick, envelope) {
  // L2: null-check session BEFORE any property access
  const live = E2E.dmSessions[nick];
  if (!live) throw new Error(`No ratchet session with ${nick} — key exchange needed`);
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
  if (session.skipped[skipKey]) {
    const mk = base64ToBytes(session.skipped[skipKey]);
    delete session.skipped[skipKey];
    if (session.skippedMeta) delete session.skippedMeta[skipKey];  // #39: keep eviction side-table in sync
    const pt = await messageDecrypt(mk, ct, header, identAD);
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
  session.CKr = bytesToBase64(newCKr);
  session.Nr++;

  const pt = await messageDecrypt(mk, ct, header, identAD);
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
  // SECURITY chokepoint: never persist a PEER session under the reserved internal
  // namespace ('__spk__' / '__otpk__<id>' — the user's own private-key blobs, which
  // are written directly elsewhere, NOT via saveSession). Test the SERVER-SANITIZED
  // form so a nick like '[__spk__' (server stores it as '__spk__') can't slip past.
  // Legit peer nicks never sanitize to a '__' prefix, so real sessions are unaffected.
  if (_e2eReservedNamespace(nick)) {
    console.warn('[E2E] refusing to store peer session under reserved name:', nick);
    return;
  }
  // #12: stamp a per-nick MONOTONIC epoch (high-water mark; never decreases within
  // this page session, so a re-handshake generation is never "older" than a prior one).
  // The e2e_session loader uses this to reject a stale/rolled-back blob the server replays.
  E2E._sessionEpoch[nick] = (E2E._sessionEpoch[nick] || 0) + 1;
  session.epoch = E2E._sessionEpoch[nick];
  E2E.dmSessions[nick] = session;
  // #39: never persist buffered skipped message keys (session.skipped) to the untrusted
  // server — they are up to 100 live AES message keys whose lifetime would otherwise
  // extend far beyond use (a future e2eEncKey compromise would expose them). Keep them
  // in-memory ONLY: the live E2E.dmSessions[nick] above retains the full buffer; the
  // persisted blob carries an EMPTY skipped map (schema preserved so reloads still index
  // session.skipped safely). skippedMeta (the #39 eviction-order side table) is dropped too.
  const { skipped, skippedMeta, ...persist } = session;
  const blob = await aesEncryptBlob(new TextEncoder().encode(JSON.stringify({ ...persist, skipped: {} })));
  wsend({ type:'e2e_store_session', partner:nick, blob });
}

// ─── TOFU / trust ─────────────────────────────────────────────────────────────

// #1: explicit out-of-band confirmation for a BRAND-NEW (first-contact) identity.
// An IRC nick is unauthenticated and the server bridges nick→key-bundle via a global
// connection map, so the first party to grab a peer's nick can offer its own key.
// Never silently auto-pin — force the local user to eyeball the fingerprint and confirm
// it out-of-band before it is pinned and used. Returns true iff the user approves.
async function e2eConfirmNewIdentity(nick, fingerprint) {
  try {
    if (typeof confirm !== 'function') return false;
    return confirm(
      `🔐 New encryption identity for ${nick}\n\n` +
      `Fingerprint:\n${fingerprint}\n\n` +
      `Anyone can claim this IRC nick. Confirm this fingerprint with ${nick} over a ` +
      `trusted channel (voice/in person) BEFORE accepting.\n\n` +
      `Accept and start encrypting with ${nick}?`
    );
  } catch (e) { console.warn('[E2E] identity confirmation unavailable:', e); return false; }
}

async function e2eCheckTrust(nick, fingerprint) {
  const existing = E2E.trustStore[nick];
  // #F1: a server_seeded pin (delivered via e2e_trust with NO local out-of-band
  // confirmation) must NEVER stand in for a user-confirmed pin — otherwise a malicious
  // server preseeds an attacker fingerprint and the checks below see a "match" and skip
  // the confirm() gate (silent MITM). Treat such a pin exactly like first contact:
  // require confirmation of the ACTUAL locally-derived fingerprint (authoritative) before
  // pinning/using it. On approval it is re-recorded WITHOUT server_seeded (now locally
  // owned); on rejection the seeded record is left in place and will re-prompt next time.
  if (!existing || existing.server_seeded) {
    // #1: no SILENT TOFU auto-pin — require explicit out-of-band confirmation first.
    const confirmed = await e2eConfirmNewIdentity(nick, fingerprint);
    if (!confirmed) return { status:'rejected', keyChanged:false };
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
  // P1 fix (#27/#3): the fingerprint matches the pinned one, so the pin has
  // re-stabilised. Clear any stuck keyChanged flag set during a prior rotation,
  // otherwise continuing header-less ratchet messages stay wedged behind the
  // line-1385 guard forever after a verified re-establishment.
  if (existing.keyChanged) existing.keyChanged = false;
  return { status: existing.verified ? 'verified' : 'trusted', keyChanged:false };
}

function e2eMarkVerified(nick) {
  if (!E2E.trustStore[nick]) return;
  E2E.trustStore[nick].verified = true;
  // P1 fix: a manual verification re-establishes trust in the new key — clear
  // the key-change wedge so continuing messages can be read again.
  E2E.trustStore[nick].keyChanged = false;
  // #F1: /encrypt trust is an explicit local confirmation act, so this pin is now
  // locally owned — drop the server_seeded flag so e2eCheckTrust won't redundantly
  // re-prompt (and downgrade `verified`) on the next establishment.
  delete E2E.trustStore[nick].server_seeded;
  wsend({ type:'e2e_update_trust', nick, fingerprint:E2E.trustStore[nick].fingerprint, verified:true });
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
// failure rather than a silently-established session.
//
// The two peers' identity pairs are sorted into a CANONICAL order (by the raw
// bytes of the dh key, same comparison safetyPhrase uses) BEFORE encoding, so
// the result is identical regardless of which peer is the initiator. This makes
// initiator and responder derive byte-identical AD unconditionally — even under
// simultaneous-initiation (glare), where the local "role" can differ between the
// two ends. Both identity keys (dh + sign) of each peer are bound. Each
// component is 4-byte big-endian length-prefixed to prevent field-boundary
// ambiguity. Returns a Uint8Array.
//
// NOTE: This intentionally breaks wire compatibility with OLD clients and any
// in-flight sessions established before this change (their messages bound a
// different AD). That is expected and acceptable per the audit (#12).
function e2eIdentityAD(aDhB64, aSignB64, bDhB64, bSignB64) {
  const aDh = base64ToBytes(aDhB64 || ''), aSign = base64ToBytes(aSignB64 || '');
  const bDh = base64ToBytes(bDhB64 || ''), bSign = base64ToBytes(bSignB64 || '');
  // Deterministic order: peer whose dh key sorts first (byte-by-byte) goes first.
  // Identical comparison logic to safetyPhrase so the two stay consistent.
  // (P-256 raw pubkeys are fixed-length, so the common-prefix scan is total.)
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
  // Length-prefix (4-byte big-endian) every component for unambiguous framing.
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
  // Proper byte-by-byte comparison for deterministic ordering
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

    case 'e2e_identity_blob':
      await e2eHandleIdentityBlob(ev.blob || null);
      break;

    case 'e2e_session': {
      if (ev.partner === '__spk__') {
        // C2: store blob so x3dhRespond can read it
        if (ev.blob) E2E._spkBlob = ev.blob;
        _e2eResolveBlobWaiters('__spk__', ev.blob || null);  // #48: wake SPK-reload waiter
        break;
      }
      // Cache all session blobs (SPK, OTPKs, ratchet sessions)
      if (ev.blob) {
        E2E._sessionCache[ev.partner] = ev.blob;
      }
      // Only deserialise actual ratchet sessions (not __otpk__* blobs)
      if (!ev.partner.startsWith('__')) {
        // #12: the server can't read/forge this blob (AEAD-encrypted under the user's
        // key) but it fully controls WHICH version and WHEN it is delivered. Treat a
        // server-pushed session as CACHE-FILL ONLY — never authoritative over live
        // ratchet state: install under the per-nick ratchet lock, and only when there
        // is no in-memory session OR the blob is STRICTLY NEWER (higher monotonic
        // epoch). Blocks a rollback push from reverting the live send/receive chains
        // (forward-secrecy regression / message-key reuse / ciphertext replay / desync DoS).
        const _partner = ev.partner, _blob = ev.blob;
        await _withRatchetLock(_partner, async () => {
          try {
            const plain   = await aesDecryptBlob(_blob);
            const session = JSON.parse(new TextDecoder().decode(plain));
            const live    = E2E.dmSessions[_partner];
            if (!live || (session.epoch || 0) > (live.epoch || 0)) {
              E2E.dmSessions[_partner] = session;
              // Keep the high-water mark >= any installed epoch so a later save/re-handshake
              // always advances strictly past it and a re-pushed copy of this blob is rejected.
              E2E._sessionEpoch[_partner] = Math.max(E2E._sessionEpoch[_partner] || 0, session.epoch || 0);
            }
          } catch(e) { console.warn('[E2E] Failed to load session:', _partner, e); }
        });
      }
      _e2eResolveBlobWaiters(ev.partner, ev.blob || null);  // #48: wake blob waiters (hit or miss)
      break;
    }

    case 'e2e_bundle': {
      const nick   = ev.username;
      const bundle = ev.bundle;
      try {
        // Guard: if session already exists (e.g. both users initiated simultaneously), skip
        if (E2E.dmSessions[nick]) {
          e2eSysMsg(nick, `🔐 Session with ${nick} already active — skipping duplicate initiation`);
          break;
        }

        // #11: TOFU now pins BOTH identity keys (dh + sign) so swapping either
        // trips the key-change warning. Must match the compare path used here.
        const fp    = await computeIdentityFingerprint(bundle.identity_dh_key, bundle.identity_sign_key);
        const trust = await e2eCheckTrust(nick, fp);

        if (trust.keyChanged) {
          e2eShowKeyChangeWarning(nick, fp);
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

        // L1: pass SPK pub (not identity key) as DHr seed.
        // #2: pin the partner's long-term identity DH pub (bundle.identity_dh_key).
        // #12: pin the identity-binding AD.
        await ratchetInitSend(nick, sharedSecret, bundle.signed_prekey.public_key, bundle.identity_dh_key, identityAD);

        // L3: store x3dh_header OUTSIDE the session object, in a separate map
        E2E._pendingX3DH = E2E._pendingX3DH || {};
        E2E._pendingX3DH[nick] = {
          sender_ik:      myIKPub,
          // #12: include our SIGN identity so the responder can reconstruct the
          // identical identity AD and pin BOTH our keys via TOFU (#11).
          sender_sign_ik: mySignIKPub,
          // #47: ECDSA signature over sender_ik||ephemeral_pub||spk_id||used_otpk_id.
          sender_sign_sig: bytesToBase64(_hdrSig),
          ephemeral_pub:  ephemeralPub,
          used_otpk_id:   usedOTPKId,
          spk_id:         bundle.signed_prekey.key_id,
        };

        updateE2EIndicator(nick);
        e2eSysMsg(nick, '🔐 E2E session established with ' + nick);
        // Refresh encryption panel if it's open for this nick
        if (typeof showEncryptPanel === 'function' && active && active.target === nick) {
          const overlay = document.getElementById('encrypt-overlay');
          if (overlay && overlay.classList.contains('show')) showEncryptPanel();
        }
      } catch(e) {
        console.warn('[E2E] Failed to process bundle:', nick, e);
        e2eSysMsg(nick, '🔐 Failed to establish E2E session with ' + nick + ' (invalid key bundle)');
      }
      break;
    }

    case 'e2e_channel_key': {
      // Was this key part of the bulk reload that fires on every (re)connect?
      const wasBulk = E2E._bulkKeyLoad && E2E._bulkKeyLoad.has(ev.channel);
      if (E2E._bulkKeyLoad) E2E._bulkKeyLoad.delete(ev.channel);
      // Did we ALREADY hold a key for this channel (case-insensitive)? The
      // server fans E2EChannelKey out to ALL of the user's sessions and even
      // re-delivers the same key multiple times during a reconnect storm, so a
      // notice must only fire for a genuinely NEW key — never a re-delivery of
      // one we already have. Read this BEFORE loadChannelKeyFromBlob().
      const _lc = String(ev.channel).toLowerCase();
      let hadKey = !!E2E.channelKeys[ev.channel];
      if (!hadKey) for (const k in E2E.channelKeys) { if (k.toLowerCase() === _lc) { hadKey = true; break; } }
      await loadChannelKeyFromBlob(ev.channel, ev.blob);
      updateE2EIndicator(ev.channel);
      // History may have replayed from logs as ciphertext before this key
      // arrived (get_logs races e2e_channel_key on a fresh session). Re-decrypt
      // any buffered sd8~ lines now that the PSK is loaded.
      if (typeof redecryptChannelHistory === 'function') {
        try { await redecryptChannelHistory(ev.channel); }
        catch(e) { console.error('[E2E] history re-decrypt failed', e); }
      }
      // Announce ONLY for a genuinely new key learned during a live session
      // (another device just ran /e2e keygen|add). Suppressed for: the
      // per-connect bulk reload (wasBulk) and any redundant re-delivery of a key
      // we already had (hadKey). The keygen/add command prints its own
      // confirmation on the device that created the key; the topbar lock icon
      // always reflects current status via updateE2EIndicator.
      if (!wasBulk && !hadKey) {
        const chLabel = ev.channel.startsWith('#') || ev.channel.startsWith('&') ? 'Channel' : 'DM';
        e2eSysMsg(ev.channel, `🔐 ${chLabel} encryption active for ${ev.channel}`);
      }
      break;
    }

    case 'e2e_channel_list':
      // Remove keys for channels no longer in the list
      for (const ch of Object.keys(E2E.channelKeys)) {
        if (!ev.channels.includes(ch)) {
          delete E2E.channelKeys[ch];
          updateE2EIndicator(ch);
        }
      }
      // Mark this as a bulk (re)load. e2eInit re-requests the full key list on
      // every (re)connect, so the per-key handler must NOT announce "encryption
      // active" for these — otherwise reconnects (esp. the iOS PWA WS watchdog)
      // spam one line per channel every time the app is reopened.
      E2E._bulkKeyLoad = new Set(ev.channels);
      for (const ch of ev.channels) wsend({ type:'e2e_load_channel_key', channel:ch });
      break;

    case 'e2e_trust': {
      // #3: the local TOFU pin is AUTHORITATIVE. The server distributes bundles and
      // relays this event, so it must not be able to silently re-pin an already-pinned
      // peer to an attacker fingerprint (which would defeat the only guarantee TOFU
      // adds). Rules:
      //   • Never accept verified:true FROM the server — verification is a local act
      //     (e2eMarkVerified) only. Server-sourced records are always verified:false.
      //   • If we already hold a pin and the server sends a DIFFERENT fingerprint,
      //     treat it as a key change: surface the warning and DO NOT overwrite the
      //     existing pin (reject the silent overwrite), regardless of ev.key_changed.
      //   • First contact (no local pin) records the pin as unverified.
      const existing = E2E.trustStore[ev.nick];
      if (existing) {
        // #46: a server-relayed e2e_trust must NEVER flip the decryption-gating
        // keyChanged flag or raise the key-change warning. A compromised server
        // could otherwise forge a mismatched fingerprint for every pinned peer,
        // wedging each DM into a permanent 'key changed' state (no-content DoS)
        // and luring a blind re-trust. Genuine key changes are detected ONLY from
        // locally-derived fingerprints in e2eCheckTrust (X3DH establishment /
        // bundle fetch) and the continuing-ratchet guard. Keep the authoritative
        // local pin; ignore the server's conflicting fingerprint (this also still
        // refuses the silent overwrite from the #3 fix by doing nothing).
      } else {
        E2E.trustStore[ev.nick] = {
          fingerprint: ev.fingerprint,
          verified:    false,        // never trust a server-supplied verified flag
          keyChanged:  false,
          // #F1: this pin arrived from the SERVER (e2e_trust relay/load) and was NOT
          // confirmed out-of-band on THIS device. A server is untrusted here, so it must
          // not be able to preseed a pin that later silently satisfies the TOFU gate — a
          // malicious server could preseed the attacker's fingerprint and the first real
          // establishment (initiator/responder) would see a "matching" pin and SKIP the
          // e2eConfirmNewIdentity() confirm() dialog → silent MITM. Mark it server-seeded
          // so e2eCheckTrust still routes the first establishment through confirmation.
          // Genuine multi-device sync is preserved: the fingerprint still propagates and
          // shows in the UI; the user just confirms it once on this device before use.
          server_seeded: true,
        };
      }
      updateE2EIndicator(ev.nick);
      break;
    }

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
      E2E._pendingIncomingX3DH = E2E._pendingIncomingX3DH || Object.create(null);
      E2E._pendingIncomingX3DH[nick] = ev.header;
      // Notify any waiting decryptor
      if (E2E._x3dhWaiters?.[nick]) E2E._x3dhWaiters[nick](ev.header);
      // Also try to immediately set up the session so it's ready when message arrives
      try {
        console.log('[E2E] Pre-initializing receiver session from relayed x3dh...');
        // #1: authenticate sender identity (TOFU/key-change) BEFORE establishing.
        const ok = await e2eEstablishResponderSession(nick, ev.header);
        if (!ok) {
          // Changed/unverified key — e2eEstablishResponderSession warned.
          // Do NOT print "session established" or consume the pending header.
          console.warn('[E2E] Relayed x3dh refused (key change / invalid) for', nick);
          break;
        }
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
    } catch(e) {
      console.error('[E2E] DM encrypt failed:', e);
      // #F4: we are INSIDE the E2E.dmSessions[target] branch, so a DM session EXISTS —
      // the encrypt just failed (most often 'Cannot send yet': a responder has no sending
      // chain until it receives the peer's first message). Returning null here would make
      // callers silently transmit this message in CLEARTEXT on an encrypted DM. Signal the
      // distinct BLOCKED outcome so the caller drops+warns instead of leaking plaintext.
      return E2E_ENCRYPT_BLOCKED;
    }
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
          // #1: authenticate sender identity (TOFU/key-change) BEFORE establishing.
          const ok = await e2eEstablishResponderSession(from, hdr);
          if (!ok) {
            // Changed/unverified key — warned already; leave header pending and
            // do NOT establish or claim success.
            console.warn('[E2E] Inline x3dh refused (key change / invalid) for', from);
          } else {
            delete E2E._pendingIncomingX3DH[from]; // consumed — don't process again
            updateE2EIndicator(from);
            console.log('[E2E] Receiver session pre-initialized for', from);
          }
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
      // #47: x3dh header comes inline (envelope.x3dh_header) or relayed via server. The
      // dead compact-`envelope.x` decoder was removed: no encoder ever produced it, and it
      // omitted sender_sign_ik/sender_sign_sig (a latent unsigned-header path).
      let x3dh = envelope.x3dh_header || null;
      // Check for x3dh header relayed via server
      if (!x3dh && E2E._pendingIncomingX3DH?.[from]) {
        x3dh = E2E._pendingIncomingX3DH[from];
        delete E2E._pendingIncomingX3DH[from];
      }
      // If no x3dh and no session, wait up to 3s for relay header using event-driven approach
      if (!x3dh && !E2E.dmSessions[from]) {
        x3dh = await new Promise(resolve => {
          if (E2E._pendingIncomingX3DH?.[from]) { resolve(E2E._pendingIncomingX3DH[from]); delete E2E._pendingIncomingX3DH[from]; return; }
          if (!E2E._x3dhWaiters) E2E._x3dhWaiters = Object.create(null);
          const timeout = setTimeout(() => { delete E2E._x3dhWaiters[from]; resolve(null); }, 3000);
          E2E._x3dhWaiters[from] = (hdr) => { clearTimeout(timeout); delete E2E._x3dhWaiters[from]; resolve(hdr); };
        });
        if (x3dh) {
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
        // #1: authenticate the sender identity (TOFU pin / key-change refusal)
        // BEFORE establishing and decrypting. e2eEstablishResponderSession runs
        // x3dhRespond + ratchetInitRecv internally, pinning the identity pub (#2)
        // and the identity-binding AD (#12).
        const ok = await e2eEstablishResponderSession(from, x3dh, { withEnvelope: true });
        if (!ok) {
          // Changed identity, or rate-limited re-establishment — refuse to silently
          // decrypt under an unverified key.
          return { plaintext:'🔐 [identity unverified — run /encrypt verify before reading]', encrypted:true };
        }
        console.log('[E2E] responder session established, calling ratchetDecrypt...');
        // #3: BIND re-establishment to the first message. e2eEstablishResponderSession may
        // have overwritten a pre-existing live session with a fresh (blank) receive chain
        // from this unauthenticated X3DH header. A valid first message under the new root is
        // NOT forgeable without the peer's private identity key (X3DH DH1), so if the decrypt
        // fails, restore the session we clobbered — a forged/replayed fresh-ephemeral header
        // can no longer wipe a working session. On genuine first contact savedSession is
        // null / unchanged, so nothing is restored.
        let pt;
        try {
          pt = await ratchetDecrypt(from, envelope);
        } catch (e) {
          if (savedSession && E2E.dmSessions[from] !== savedSession) {
            await saveSession(from, savedSession);
            console.warn('[E2E] X3DH re-establishment failed to authenticate — restored prior session for', from);
          }
          throw e;
        }
        console.log('[E2E] Decrypt OK');

        // #28: glare handling. Previously, if we were ALSO an initiator
        // (savedSession.CKs present), the old send chain (CKs/DHs/Ns) was grafted onto
        // the fresh responder session and isInitiator forced true. That send chain came
        // from a DIFFERENT root key, so its DH-ratchet outputs can't be matched by the
        // peer, and re-emitting under a reset Ns/CKs risks reusing an (mk,nonce). The
        // correct behavior is to DISCARD the loser's send chain entirely: the new X3DH
        // root replaces both directions, and our next outbound message rebuilds a fresh
        // send chain via a DH-ratchet step from the new root (deterministic — no forked
        // chain, no key reuse). We simply do not carry CKs/DHs/Ns across the
        // re-establishment.
        if (savedSession && savedSession.CKs) {
          console.warn('[E2E] glare detected for', from, '— discarding stale send chain; new X3DH root is authoritative');
        }

        updateE2EIndicator(from);
        return { plaintext:pt, encrypted:true };
      }

      if (!E2E.dmSessions[from]) {
        return { plaintext:'🔐 [no session — ask sender to re-initiate]', encrypted:true };
      }
      // #27: defense-in-depth re-verification. A continuing ratchet message (no X3DH
      // header) skips the establishment-time TOFU check, so re-confirm the live
      // session's pinned identity still matches the current trust pin before
      // decrypting. If a key change was flagged for this peer (see the #3
      // client-authoritative e2e_trust handler), refuse rather than decrypt under a
      // pin that diverged. (The mandatory identity AD #24 would also fail the AEAD on a
      // substituted identity; this surfaces a clear message instead of a generic error.)
      if (E2E.trustStore[from]?.keyChanged) {
        return { plaintext:'🔐 [identity unverified — run /encrypt verify before reading]', encrypted:true };
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
      if (!E2E.e2eEncKey) { e2eSysMsg(target,'🔐 Vault not unlocked — unlock vault first'); return; }
      const { keyWords, keyB64, key } = await generateChannelKey();
      await storeChannelKey(target, key, keyB64);
      const label = target.startsWith('#') || target.startsWith('&') ? 'Channel' : 'DM';
      e2eSysMsg(target,`🔐 ${label} key generated for ${target}:`);
      e2eSysMsg(target,`🔑 ${keyWords}`);
      e2eSysMsg(target,`Share these 32 words privately with ${target.startsWith('#')?'channel members':target}.`);
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
        e2eSysMsg(target,`🔐 Key added — messages now encrypted`);
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
      const { keyWords, keyB64, key } = await generateChannelKey();
      await storeChannelKey(target, key, keyB64);
      e2eSysMsg(target,`🔐 Key rotated for ${target}.`);
      e2eSysMsg(target,`🔑 New key: ${keyWords}`);
      e2eSysMsg(target,`Re-share with ${target.startsWith('#')?'trusted members':'the other person'}. Old key holders cannot read future messages.`);
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
        // Remove PSK key if exists
        if (E2E.channelKeys[nick]) {
          await removeChannelKey(nick);
          e2eSysMsg(target,`🔓 Encryption disabled for ${nick}`);
        }
        // Remove Signal session if exists
        if (E2E.dmSessions[nick]) {
          delete E2E.dmSessions[nick];
          delete E2E._encryptLock[nick];
          wsend({ type:'e2e_delete_session', partner:nick });
          e2eSysMsg(target,`🔓 E2E session with ${nick} closed`);
        }
        if (!E2E.channelKeys[nick] && !E2E.dmSessions[nick]) {
          e2eSysMsg(target,`🔓 No encryption active for ${nick}`);
        }
        updateE2EIndicator(nick);
      }
      break;
    }
    case 'verify': {
      const nick = args[1] || (!target.startsWith('#') ? target : null);
      if (!nick) { e2eSysMsg(target,'Usage: /encrypt verify <nick>'); return; }
      const session = E2E.dmSessions[nick];
      if (!session) { e2eSysMsg(target,`No E2E session with ${nick}`); return; }
      // #2: verify the PINNED long-term identity DH key (theirIdentityPub), NOT
      // the ratchet key (session.DHr, which is the SPK/ephemeral and differs per
      // peer and per ratchet step). safetyPhrase() sorts the two identity keys so
      // BOTH peers derive identical words; computeFingerprint() over the same
      // pinned key gives both peers the same fingerprint.
      if (!session.theirIdentityPub) { e2eSysMsg(target,`Session with ${nick} not yet established (no pinned identity)`); return; }
      const myPub  = await exportPub(E2E.identityKeys.dhKeyPair.publicKey, 'ECDH');
      const phrase = await safetyPhrase(myPub, session.theirIdentityPub);
      // #11: show the pinned combined (dh+sign) TOFU fingerprint — the value the
      // peer also shows via /encrypt fingerprint — so the displayed fingerprints
      // match. Fall back to the dh-only fingerprint if no pin is recorded.
      const fp     = E2E.trustStore[nick]?.fingerprint || await computeFingerprint(session.theirIdentityPub);
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
      const myDhPub   = await exportPub(E2E.identityKeys.dhKeyPair.publicKey,   'ECDH');
      const mySignPub = await exportPub(E2E.identityKeys.signKeyPair.publicKey, 'ECDSA');
      // #11: show the combined (dh+sign) identity fingerprint — the same value
      // peers pin via TOFU — so an out-of-band match is meaningful.
      e2eSysMsg(target,`🔑 Your fingerprint: ${await computeIdentityFingerprint(myDhPub, mySignPub)}`);
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
    // Case-insensitive lookup for DM sessions and channel keys
    const _e2eLookup = (obj, key) => { if (obj[key]) return obj[key]; const lk=key.toLowerCase(); for (const k in obj) if (k.toLowerCase()===lk) return obj[k]; return null; };
    const encActive = !!_e2eLookup(E2E.channelKeys, t) || (isDMActive && !!_e2eLookup(E2E.dmSessions, t));
    const trust = _e2eLookup(E2E.trustStore, t);
    const lockedSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4" fill="none" stroke-width="2"/></svg>';
    const unlockedSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9 0" fill="none"/></svg>';
    lock.innerHTML = encActive ? lockedSvg : unlockedSvg;
    lock.style.color = encActive ? 'var(--accent)' : 'var(--text2)';
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
