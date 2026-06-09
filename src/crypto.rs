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
use std::path::{Path, PathBuf};
use dashmap::DashMap;

const NONCE_LEN: usize = 12;
const KEY_LEN:   usize = 32;
const SALT_LEN:  usize = 16;
const CANARY_PT: &[u8] = b"cryptirc-vault-canary-v1";

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
}

impl CryptoManager {
    pub fn new(data_dir: &str) -> Result<Self> {
        Ok(Self {
            data_dir: data_dir.to_string(),
            keys: DashMap::new(),
        })
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
            if plaintext != CANARY_PT {
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
        let bundle = serde_json::json!({
            "v": 1,
            "salt": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, salt),
            "wrapped": wrapped,
        });
        let mkey_path = self.mkey_path(username);
        let tmp = mkey_path.with_extension("mkey.tmp");
        write_secret(&tmp, serde_json::to_string(&bundle)?.as_bytes()).await?;
        tokio::fs::rename(&tmp, &mkey_path).await?;
        Ok(())
    }

    pub async fn lock(&self, username: &str) {
        if let Some(mut entry) = self.keys.get_mut(username) {
            for b in entry.value_mut().iter_mut() { *b = 0; }
        }
        self.keys.remove(username);
    }

    pub async fn is_unlocked(&self, username: &str) -> bool {
        self.keys.contains_key(username)
    }

    pub async fn change_passphrase(&self, username: &str, old: &str, new: &str) -> Result<()> {
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
            let salt    = self.get_or_create_salt(username).await?;
            let old_key = derive_key(old, &salt)?;
            let canary  = self.canary_path(username);
            if tokio::fs::metadata(&canary).await.is_ok() {
                let enc = tokio::fs::read_to_string(&canary).await?;
                let pt  = decrypt_with_key(&old_key, &enc)
                    .map_err(|_| anyhow::anyhow!("Old passphrase incorrect"))?;
                if pt != CANARY_PT { bail!("Old passphrase incorrect"); }
            }
            old_key
        };

        // Derive a fresh KDF key from a new random salt and re-wrap the SAME
        // master under it. The atomic rename of vault.mkey (which embeds the new
        // salt) is the single commit point — no blob re-encryption needed.
        let mut new_salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut new_salt);
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
        Ok(derive_subkey(entry.value(), b"cryptirc-e2e-enc-v1"))
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
            rand::thread_rng().fill_bytes(&mut salt);
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
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
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

    let kdf_key = derive_key(passphrase, &salt)?;
    let raw = decrypt_with_key(&kdf_key, wrapped)?;
    if raw.len() != KEY_LEN { bail!("Corrupt master key bundle"); }
    let mut master = [0u8; KEY_LEN];
    master.copy_from_slice(&raw);
    Ok(master)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let params  = Params::new(65536, 3, 1, Some(KEY_LEN))
        .map_err(|e| anyhow::anyhow!("Argon2 params: {:?}", e))?;
    let argon2  = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2.hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2 hash: {:?}", e))?;
    Ok(key)
}

pub fn derive_subkey(master: &[u8; KEY_LEN], info: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; KEY_LEN];
    hk.expand(info, &mut out).expect("HKDF expand");
    out
}

fn sanitize_username(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').collect()
}
