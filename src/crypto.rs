/// crypto.rs — Per-user vault key management
///
/// Each user has their own vault with their own passphrase, salt, and canary.
/// Unlocking one user's vault does not affect any other user's vault.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{bail, Result};
use argon2::{Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::RngCore;
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use std::path::{Path, PathBuf};
use dashmap::DashMap;

const NONCE_LEN: usize = 12;
const KEY_LEN:   usize = 32;
const SALT_LEN:  usize = 16;
const CANARY_PT: &[u8] = b"cryptirc-vault-canary-v1";

// Argon2id KDF parameters used to derive the passphrase wrapping key. They are
// persisted inside each vault.mkey bundle (audit #106) so the cost can be raised
// in a future release without bricking existing vaults: unwrap reads the stored
// params, while new/re-wrapped bundles always use the current defaults below.
const ARGON2_M: u32 = 65536; // 64 MiB
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 1;

/// Write a secret file with 0600 (owner-only) permissions so the data dir
/// being world-traversable (audit #7) cannot leak salts/canary/master-key
/// material to other local users. On non-unix the mode is a no-op.
async fn write_secret(path: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
    let path = path.as_ref();
    tokio::fs::write(path, bytes).await?;
    set_secret_mode(path).await;
    Ok(())
}

/// Best-effort chmod 0600 on an existing secret file (audit #7).
async fn set_secret_mode(path: impl AsRef<Path>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o600)).await;
    }
    #[cfg(not(unix))]
    { let _ = path; }
}

pub struct CryptoManager {
    data_dir: String,
    /// Per-user derived keys. Only populated while user's vault is unlocked.
    keys: DashMap<String, [u8; KEY_LEN]>,
    /// Per-user lock serializing vault writers (unlock-legacy-migration and
    /// change_passphrase both write vault.mkey). Without it, two concurrent sockets
    /// for the same user could interleave their read-master → derive → write_master_bundle
    /// → rename sequences and commit the wrong wrapped-master bundle.
    vault_locks: DashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>,
}

impl CryptoManager {
    pub fn new(data_dir: &str) -> Result<Self> {
        Ok(Self {
            data_dir: data_dir.to_string(),
            keys: DashMap::new(),
            vault_locks: DashMap::new(),
        })
    }

    fn vault_lock(&self, username: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
        self.vault_locks.entry(username.to_string())
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    // ─── Per-user vault paths ─────────────────────────────────────────────────

    fn vault_dir(&self, username: &str) -> PathBuf {
        PathBuf::from(&self.data_dir).join("vaults").join(sanitize_username(username))
    }
    fn salt_path(&self, username: &str) -> PathBuf {
        self.vault_dir(username).join("vault.salt")
    }
    fn canary_path(&self, username: &str) -> PathBuf {
        self.vault_dir(username).join("vault.canary")
    }
    /// Wrapped random per-user master key (audit #8). The master key is what
    /// actually encrypts at-rest blobs and seeds derive_e2e_enc_key; it is
    /// wrapped by the passphrase-derived KDF key. Decoupling the at-rest key
    /// from the passphrase means a passphrase change only re-wraps THIS file,
    /// leaving every cert/log/.enc/e2e blob valid and the e2e enc key stable.
    fn mkey_path(&self, username: &str) -> PathBuf {
        self.vault_dir(username).join("vault.mkey")
    }

    // ─── Vault operations ─────────────────────────────────────────────────────

    pub async fn unlock(&self, username: &str, passphrase: &str) -> Result<()> {
        // Serialize with change_passphrase (and concurrent unlocks) for this user, so the
        // legacy-migration write_master_bundle below can't interleave with a concurrent
        // passphrase change and commit a stale wrapped-master bundle. Bind the Arc to a
        // local first so it outlives the guard (E0716).
        let _vault_lock = self.vault_lock(username);
        let _vault_guard = _vault_lock.lock().await;
        // ── Master-key vault (audit #8) ──────────────────────────────────────
        // Once vault.mkey exists it is the single authoritative, crash-atomic
        // record: it embeds the salt under which it was wrapped, so unlocking
        // never depends on the legacy vault.salt/vault.canary being in sync.
        let mkey_path = self.mkey_path(username);
        if let Ok(bundle) = tokio::fs::read_to_string(&mkey_path).await {
            let master = unwrap_master_bundle(&bundle, passphrase)
                .map_err(|_| anyhow::anyhow!("Incorrect passphrase"))?;
            self.keys.insert(username.to_string(), master);
            return Ok(());
        }

        // ── Legacy vault (no mkey yet) ───────────────────────────────────────
        // Verify the passphrase against the existing canary, then adopt the
        // passphrase-derived KDF key as the master key so every blob existing
        // users already wrapped under it stays decryptable. Materialize the
        // wrapped master bundle so the NEXT passphrase change is a one-file swap.
        let salt = self.get_or_create_salt(username).await?;
        let kdf_key = derive_key(passphrase, &salt)?;

        let canary = self.canary_path(username);
        if tokio::fs::metadata(&canary).await.is_ok() {
            let enc = tokio::fs::read_to_string(&canary).await?;
            let plaintext = decrypt_with_key(&kdf_key, &enc)
                .map_err(|_| anyhow::anyhow!("Incorrect passphrase"))?;
            // Constant-time compare (audit #87) — GCM auth already gates this, but
            // keep secret-equality checks constant-time as a matter of hygiene.
            if plaintext.ct_eq(CANARY_PT).unwrap_u8() == 0 {
                bail!("Incorrect passphrase");
            }
        } else {
            // First unlock — write canary
            let dir = self.vault_dir(username);
            tokio::fs::create_dir_all(&dir).await?;
            let enc = encrypt_with_key(&kdf_key, CANARY_PT)?;
            write_secret(&canary, enc.as_bytes()).await?;
        }

        // master == kdf_key for the legacy cohort (keeps existing blobs valid).
        let master = kdf_key;
        self.write_master_bundle(username, &salt, &kdf_key, &master).await?;
        self.keys.insert(username.to_string(), master);
        Ok(())
    }

    /// Atomically write the wrapped-master bundle (salt + master wrapped by the
    /// passphrase KDF key) via tmp+rename so a crash can never leave a bundle
    /// that the passphrase cannot unwrap (audit #8, #29).
    async fn write_master_bundle(
        &self,
        username: &str,
        salt: &[u8; SALT_LEN],
        kdf_key: &[u8; KEY_LEN],
        master: &[u8; KEY_LEN],
    ) -> Result<()> {
        let dir = self.vault_dir(username);
        tokio::fs::create_dir_all(&dir).await?;
        let wrapped = encrypt_with_key(kdf_key, master)?;
        // Persist the Argon2 params used (audit #106) so cost can be raised later
        // without invalidating existing vaults. v:2 carries m/t/p; v:1 readers
        // (none remain) assumed the legacy defaults.
        let bundle = serde_json::json!({
            "v": 2,
            "salt": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, salt),
            "wrapped": wrapped,
            "m": ARGON2_M, "t": ARGON2_T, "p": ARGON2_P,
        });
        let mkey_path = self.mkey_path(username);
        // Unique temp (not a fixed vault.mkey.tmp) + cleanup on rename failure, mirroring
        // auth.rs write_user_atomic: even under the per-user vault lock this avoids a
        // shared-tmp clobber and leaves no stale temp behind if the rename fails.
        let tmp = dir.join(format!("vault.mkey.tmp.{}", uuid::Uuid::new_v4()));
        write_secret(&tmp, serde_json::to_string(&bundle)?.as_bytes()).await?;
        if let Err(e) = tokio::fs::rename(&tmp, &mkey_path).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e.into());
        }
        Ok(())
    }

    pub async fn lock(&self, username: &str) {
        if let Some(mut entry) = self.keys.get_mut(username) {
            for b in entry.value_mut().iter_mut() { *b = 0; }
        }
        self.keys.remove(username);
    }

    /// Atomically tear down a user's vault on account deletion: zeroize+drop the
    /// in-memory master key AND remove the on-disk vault dir (salt/canary/mkey) while
    /// holding the SAME per-user vault_lock that unlock()/change_passphrase() take.
    /// Doing the two steps without the lock (as a bare lock()+remove_dir_all pair) lets a
    /// concurrent unlock()/change_passphrase() interleave its keys.insert /
    /// write_master_bundle AFTER the teardown, resurrecting the deleted account's master
    /// key and vault — a cross-owner E2E key disclosure to a re-registered same-name user.
    pub async fn purge_vault(&self, username: &str) {
        let _vault_lock = self.vault_lock(username);
        let _vault_guard = _vault_lock.lock().await;
        if let Some(mut entry) = self.keys.get_mut(username) {
            for b in entry.value_mut().iter_mut() { *b = 0; }
        }
        self.keys.remove(username);
        let _ = tokio::fs::remove_dir_all(self.vault_dir(username)).await;
    }

    pub async fn is_unlocked(&self, username: &str) -> bool {
        self.keys.contains_key(username)
    }

    pub async fn change_passphrase(&self, username: &str, old: &str, new: &str) -> Result<()> {
        // Serialize with unlock (and concurrent passphrase changes) for this user — both
        // write vault.mkey; interleaving could commit a bundle wrapped under the wrong KDF.
        // Bind the Arc to a local first so it outlives the guard (E0716).
        let _vault_lock = self.vault_lock(username);
        let _vault_guard = _vault_lock.lock().await;
        // Authorization is the OLD-passphrase proof below (it must unwrap the
        // master bundle / verify the canary), so this works whether or not the
        // vault is already unlocked — preserving the existing UI flow while the
        // wrong old passphrase is always rejected (audit #70 gating concern).
        //
        // Resolve the existing master key under the OLD passphrase. Because the
        // master key never changes on a passphrase change, every at-rest blob
        // (client certs / *.enc preferences / e2e blobs / logs / network
        // configs) stays valid and derive_e2e_enc_key stays stable — fixing the
        // silent E2E identity loss + partial-migration data loss (audit #8, #29).
        let mkey_path = self.mkey_path(username);
        let master = if let Ok(bundle) = tokio::fs::read_to_string(&mkey_path).await {
            unwrap_master_bundle(&bundle, old)
                .map_err(|_| anyhow::anyhow!("Old passphrase incorrect"))?
        } else {
            // Legacy vault with no bundle yet: verify the old passphrase against
            // the canary and adopt the old KDF key as the master.
            //
            // If there is NO canary (and no mkey above), the vault was never
            // initialized — there is nothing to authenticate the old passphrase
            // against, so accepting any value here would silently adopt it as the
            // master and hand over an uninitialized vault. Refuse: vault setup
            // must go through unlock/init, not change_passphrase.
            let canary  = self.canary_path(username);
            if tokio::fs::metadata(&canary).await.is_err() {
                bail!("Vault not initialized");
            }
            let salt    = self.get_or_create_salt(username).await?;
            let old_key = derive_key(old, &salt)?;
            let enc = tokio::fs::read_to_string(&canary).await?;
            let pt  = decrypt_with_key(&old_key, &enc)
                .map_err(|_| anyhow::anyhow!("Old passphrase incorrect"))?;
            if pt.ct_eq(CANARY_PT).unwrap_u8() == 0 { bail!("Old passphrase incorrect"); } // #87
            old_key
        };

        // Derive a fresh KDF key from a new random salt and re-wrap the SAME
        // master under it. The atomic rename of vault.mkey (which embeds the new
        // salt) is the single commit point — no blob re-encryption needed.
        let mut new_salt = [0u8; SALT_LEN];
        // Explicit OS CSPRNG for nonce/salt material (audit #21).
        OsRng.fill_bytes(&mut new_salt);
        let new_kdf = derive_key(new, &new_salt)?;
        self.write_master_bundle(username, &new_salt, &new_kdf, &master).await?;

        // Keep the legacy vault.salt/vault.canary mirrors in sync (best-effort;
        // the mkey bundle is already authoritative, so failure here is harmless).
        let dir = self.vault_dir(username);
        let _ = tokio::fs::create_dir_all(&dir).await;
        let _ = write_secret(self.salt_path(username), &new_salt).await;
        if let Ok(new_canary) = encrypt_with_key(&new_kdf, CANARY_PT) {
            let _ = write_secret(self.canary_path(username), new_canary.as_bytes()).await;
        }

        // In-memory master key is unchanged; keep it so the session stays usable.
        self.keys.insert(username.to_string(), master);
        Ok(())
    }

    pub async fn encrypt(&self, username: &str, plaintext: &[u8]) -> Result<String> {
        let entry = self.keys.get(username)
            .ok_or_else(|| anyhow::anyhow!("Vault locked"))?;
        encrypt_with_key(entry.value(), plaintext)
    }

    pub async fn decrypt(&self, username: &str, encoded: &str) -> Result<Vec<u8>> {
        let entry = self.keys.get(username)
            .ok_or_else(|| anyhow::anyhow!("Vault locked"))?;
        decrypt_with_key(entry.value(), encoded)
    }

    pub async fn derive_e2e_enc_key(&self, username: &str) -> Result<[u8; KEY_LEN]> {
        let entry = self.keys.get(username)
            .ok_or_else(|| anyhow::anyhow!("Vault locked"))?;
        derive_subkey(entry.value(), b"cryptirc-e2e-enc-v1")
    }

    async fn get_or_create_salt(&self, username: &str) -> Result<[u8; SALT_LEN]> {
        let path = self.salt_path(username);
        if path.exists() {
            let bytes = tokio::fs::read(&path).await?;
            if bytes.len() != SALT_LEN { bail!("Corrupt salt file"); }
            let mut arr = [0u8; SALT_LEN];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        } else {
            let dir = self.vault_dir(username);
            tokio::fs::create_dir_all(&dir).await?;
            let mut salt = [0u8; SALT_LEN];
            OsRng.fill_bytes(&mut salt);
            // Salt is sensitive (enables offline KDF attacks) — write 0600 (#7).
            write_secret(&path, &salt).await?;
            Ok(salt)
        }
    }

    /// Migrate legacy shared vault to per-user vaults.
    /// Copies old vault.salt and vault.canary to each user's vault directory.
    pub async fn migrate_legacy_vault(&self) -> Result<()> {
        let old_salt = PathBuf::from(&self.data_dir).join("vault.salt");
        let old_canary = PathBuf::from(&self.data_dir).join("vault.canary");
        if !old_salt.exists() { return Ok(()); } // No legacy vault

        tracing::info!("Migrating legacy shared vault to per-user vaults...");

        let users_dir = PathBuf::from(&self.data_dir).join("users");
        if let Ok(mut rd) = tokio::fs::read_dir(&users_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Some(uname) = path.file_stem().and_then(|s| s.to_str()) {
                        let user_vault = self.vault_dir(uname);
                        let user_salt = self.salt_path(uname);
                        let user_canary = self.canary_path(uname);
                        if !user_salt.exists() {
                            tokio::fs::create_dir_all(&user_vault).await?;
                            tokio::fs::copy(&old_salt, &user_salt).await?;
                            // Tighten perms on copied secrets — copy preserves the
                            // legacy (possibly world-readable) mode otherwise (#7).
                            set_secret_mode(&user_salt).await;
                            if old_canary.exists() {
                                tokio::fs::copy(&old_canary, &user_canary).await?;
                                set_secret_mode(&user_canary).await;
                            }
                            tracing::info!("  Migrated vault for user: {}", uname);
                        }
                    }
                }
            }
        }

        // Rename old files so migration doesn't run again
        let _ = tokio::fs::rename(&old_salt, PathBuf::from(&self.data_dir).join("vault.salt.migrated")).await;
        let _ = tokio::fs::rename(&old_canary, PathBuf::from(&self.data_dir).join("vault.canary.migrated")).await;
        tracing::info!("Legacy vault migration complete.");
        Ok(())
    }
}

// ─── Pure crypto helpers ──────────────────────────────────────────────────────

pub fn encrypt_with_key(key_bytes: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    // Random 96-bit nonce from the OS CSPRNG (audit #21). AES-GCM with random
    // nonces has a 2^32-message birthday bound per key; the per-user master key
    // is far below that in practice. A future hardening step is to migrate
    // long-lived blob encryption to a nonce-misuse-resistant AEAD (AES-GCM-SIV /
    // XChaCha20-Poly1305) — deferred here because it would require re-encrypting
    // every existing at-rest blob.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce      = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, out))
}

pub fn decrypt_with_key(key_bytes: &[u8; KEY_LEN], encoded: &str) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    let data   = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)?;
    if data.len() < NONCE_LEN + 16 { bail!("Ciphertext too short"); }
    let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
    let pt    = cipher.decrypt(nonce, &data[NONCE_LEN..])
        .map_err(|_| anyhow::anyhow!("Decryption failed"))?;
    Ok(pt)
}

/// Parse a vault.mkey bundle (`{v,salt,wrapped}`), derive the KDF key from the
/// embedded salt + supplied passphrase, and unwrap the random master key.
/// The wrapped value is AES-256-GCM authenticated, so an incorrect passphrase
/// fails decryption — no separate canary is needed inside the bundle (#8).
fn unwrap_master_bundle(bundle: &str, passphrase: &str) -> Result<[u8; KEY_LEN]> {
    let val: serde_json::Value = serde_json::from_str(bundle.trim())?;
    let salt_b64 = val.get("salt").and_then(|s| s.as_str())
        .ok_or_else(|| anyhow::anyhow!("Corrupt master key bundle"))?;
    let wrapped  = val.get("wrapped").and_then(|s| s.as_str())
        .ok_or_else(|| anyhow::anyhow!("Corrupt master key bundle"))?;
    let salt = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, salt_b64)?;
    if salt.len() != SALT_LEN { bail!("Corrupt master key bundle"); }

    // Use the params stored in the bundle (audit #106); fall back to the
    // historical defaults for older v:1 bundles that omitted them.
    let m = val.get("m").and_then(|v| v.as_u64()).map(|v| v as u32).unwrap_or(ARGON2_M);
    let t = val.get("t").and_then(|v| v.as_u64()).map(|v| v as u32).unwrap_or(ARGON2_T);
    let p = val.get("p").and_then(|v| v.as_u64()).map(|v| v as u32).unwrap_or(ARGON2_P);
    let kdf_key = derive_key_params(passphrase, &salt, m, t, p)?;
    let raw = decrypt_with_key(&kdf_key, wrapped)?;
    if raw.len() != KEY_LEN { bail!("Corrupt master key bundle"); }
    let mut master = [0u8; KEY_LEN];
    master.copy_from_slice(&raw);
    Ok(master)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    derive_key_params(passphrase, salt, ARGON2_M, ARGON2_T, ARGON2_P)
}

fn derive_key_params(passphrase: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; KEY_LEN]> {
    let params  = Params::new(m, t, p, Some(KEY_LEN))
        .map_err(|e| anyhow::anyhow!("Argon2 params: {:?}", e))?;
    let argon2  = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2.hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2 hash: {:?}", e))?;
    Ok(key)
}

pub fn derive_subkey(master: &[u8; KEY_LEN], info: &[u8]) -> Result<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; KEY_LEN];
    // Propagate instead of panicking (audit #86) — safe today (fixed 32-byte
    // output) but a future variable-length call must not crash the crypto core.
    hk.expand(info, &mut out)
        .map_err(|e| anyhow::anyhow!("HKDF expand: {:?}", e))?;
    Ok(out)
}

/// Canonical username→path sanitizer. ASCII-alphanumeric plus `_`/`-` only
/// (audit #22): registration enforces an ASCII charset, so this never silently
/// drops bytes for a valid account; Unicode chars are rejected here too, making
/// homograph/NFC path collisions impossible on case-insensitive filesystems.
fn sanitize_username(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect()
}
