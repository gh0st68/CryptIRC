/// crypto.rs — Vault key management
///
/// Fixes applied:
///   C5 — canary blob: vault shows "locked" if passphrase is wrong
///   C6 — re_encrypt_logs(): all log files re-encrypted on passphrase change

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{bail, Result};
use argon2::{Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::RngCore;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::RwLock;

const NONCE_LEN: usize = 12;
const KEY_LEN:   usize = 32;
const SALT_LEN:  usize = 16;
/// Known plaintext stored as encrypted canary to verify a passphrase is correct.
const CANARY_PT: &[u8] = b"cryptirc-vault-canary-v1";

pub struct CryptoManager {
    salt_path:   PathBuf,
    canary_path: PathBuf,
    key: Arc<RwLock<Option<[u8; KEY_LEN]>>>,
}

impl CryptoManager {
    pub fn new(data_dir: &str) -> Result<Self> {
        Ok(Self {
            salt_path:   PathBuf::from(data_dir).join("vault.salt"),
            canary_path: PathBuf::from(data_dir).join("vault.canary"),
            key: Arc::new(RwLock::new(None)),
        })
    }

    /// Derive key from passphrase.  Verifies against stored canary if one exists.
    pub async fn unlock(&self, passphrase: &str) -> Result<()> {
        let salt = self.get_or_create_salt().await?;
        let key  = derive_key(passphrase, &salt)?;

        if self.canary_path.exists() {
            // Verify key is correct before accepting it
            let enc = tokio::fs::read_to_string(&self.canary_path).await?;
            let plaintext = decrypt_with_key(&key, &enc)
                .map_err(|_| anyhow::anyhow!("Incorrect passphrase"))?;
            if plaintext != CANARY_PT {
                bail!("Incorrect passphrase");
            }
        } else {
            // First unlock — write canary
            let enc = encrypt_with_key(&key, CANARY_PT)?;
            tokio::fs::write(&self.canary_path, &enc).await?;
        }

        let mut guard = self.key.write().await;
        *guard = Some(key);
        Ok(())
    }

    pub async fn lock(&self) {
        let mut guard = self.key.write().await;
        // Zero the key bytes before dropping
        if let Some(ref mut k) = *guard {
            for b in k.iter_mut() { *b = 0; }
        }
        *guard = None;
    }

    pub async fn is_unlocked(&self) -> bool {
        self.key.read().await.is_some()
    }

    /// Change passphrase: verify old, re-encrypt all log files, update salt+canary.
    pub async fn change_passphrase(&self, old: &str, new: &str, data_dir: &str) -> Result<()> {
        // Verify old passphrase via canary
        let salt    = self.get_or_create_salt().await?;
        let old_key = derive_key(old, &salt)?;
        if self.canary_path.exists() {
            let enc = tokio::fs::read_to_string(&self.canary_path).await?;
            let pt  = decrypt_with_key(&old_key, &enc)
                .map_err(|_| anyhow::anyhow!("Old passphrase incorrect"))?;
            if pt != CANARY_PT { bail!("Old passphrase incorrect"); }
        }

        // Derive new key
        let mut new_salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut new_salt);
        let new_key = derive_key(new, &new_salt)?;

        // Re-encrypt all log files
        let log_dir = PathBuf::from(data_dir).join("logs");
        re_encrypt_tree(&log_dir, &old_key, &new_key).await?;

        // Persist new salt + canary
        tokio::fs::write(&self.salt_path, &new_salt).await?;
        let new_canary = encrypt_with_key(&new_key, CANARY_PT)?;
        tokio::fs::write(&self.canary_path, new_canary).await?;

        let mut guard = self.key.write().await;
        if let Some(ref mut k) = *guard { for b in k.iter_mut() { *b = 0; } }
        *guard = Some(new_key);
        Ok(())
    }

    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<String> {
        let guard     = self.key.read().await;
        let key_bytes = guard.as_ref().ok_or_else(|| anyhow::anyhow!("Vault locked"))?;
        encrypt_with_key(key_bytes, plaintext)
    }

    pub async fn decrypt(&self, encoded: &str) -> Result<Vec<u8>> {
        let guard     = self.key.read().await;
        let key_bytes = guard.as_ref().ok_or_else(|| anyhow::anyhow!("Vault locked"))?;
        decrypt_with_key(key_bytes, encoded)
    }

    /// Derive a sub-key for E2E client-side encryption.
    /// The client uses this to encrypt/decrypt its private E2E key blobs.
    /// This is derived from the vault master key via HKDF so it is distinct
    /// from the log encryption key but equally protected by the passphrase.
    pub async fn derive_e2e_enc_key(&self) -> Result<[u8; KEY_LEN]> {
        let guard     = self.key.read().await;
        let key_bytes = guard.as_ref().ok_or_else(|| anyhow::anyhow!("Vault locked"))?;
        Ok(derive_subkey(key_bytes, b"cryptirc-e2e-enc-v1"))
    }

    async fn get_or_create_salt(&self) -> Result<[u8; SALT_LEN]> {
        if self.salt_path.exists() {
            let bytes = tokio::fs::read(&self.salt_path).await?;
            if bytes.len() != SALT_LEN { bail!("Corrupt salt file"); }
            let mut arr = [0u8; SALT_LEN];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        } else {
            let mut salt = [0u8; SALT_LEN];
            rand::thread_rng().fill_bytes(&mut salt);
            tokio::fs::write(&self.salt_path, &salt).await?;
            Ok(salt)
        }
    }
}

// ─── Pure crypto helpers (no async, usable with raw key bytes) ────────────────

pub fn encrypt_with_key(key_bytes: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce      = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encrypt failed: {:?}", e))?;
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
        .map_err(|e| anyhow::anyhow!("Decrypt failed: {:?}", e))?;
    Ok(pt)
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

/// Derive a distinct sub-key from the vault master key using HKDF-SHA256.
/// Different `info` values produce independent keys — knowing one reveals nothing
/// about the master key or any other derived key.
pub fn derive_subkey(master: &[u8; KEY_LEN], info: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; KEY_LEN];
    hk.expand(info, &mut out).expect("HKDF expand");
    out
}

/// Walk a directory tree and re-encrypt every .log file with a new key.
async fn re_encrypt_tree(dir: &PathBuf, old: &[u8; KEY_LEN], new: &[u8; KEY_LEN]) -> Result<()> {
    if !dir.exists() { return Ok(()); }
    let mut stack = vec![dir.clone()];
    while let Some(current) = stack.pop() {
        let mut rd = tokio::fs::read_dir(&current).await?;
        while let Ok(Some(entry)) = rd.next_entry().await {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().map(|x| x == "log").unwrap_or(false) {
                re_encrypt_file(&path, old, new).await?;
            }
        }
    }
    Ok(())
}

async fn re_encrypt_file(path: &PathBuf, old: &[u8; KEY_LEN], new: &[u8; KEY_LEN]) -> Result<()> {
    let content = tokio::fs::read_to_string(path).await?;
    let mut new_lines = Vec::new();
    for line in content.lines() {
        if line.is_empty() { continue; }
        let pt  = decrypt_with_key(old, line)?;
        let enc = encrypt_with_key(new, &pt)?;
        new_lines.push(enc);
    }
    // Atomic write: write to .tmp then rename
    let tmp_path = path.with_extension("log.tmp");
    tokio::fs::write(&tmp_path, new_lines.join("\n") + "\n").await?;
    tokio::fs::rename(&tmp_path, path).await?;
    Ok(())
}
