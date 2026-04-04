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
use std::path::PathBuf;
use dashmap::DashMap;

const NONCE_LEN: usize = 12;
const KEY_LEN:   usize = 32;
const SALT_LEN:  usize = 16;
const CANARY_PT: &[u8] = b"cryptirc-vault-canary-v1";

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

    // ─── Vault operations ─────────────────────────────────────────────────────

    pub async fn unlock(&self, username: &str, passphrase: &str) -> Result<()> {
        let salt = self.get_or_create_salt(username).await?;
        let key  = derive_key(passphrase, &salt)?;

        let canary = self.canary_path(username);
        if tokio::fs::metadata(&canary).await.is_ok() {
            let enc = tokio::fs::read_to_string(&canary).await?;
            let plaintext = decrypt_with_key(&key, &enc)
                .map_err(|_| anyhow::anyhow!("Incorrect passphrase"))?;
            if plaintext != CANARY_PT {
                bail!("Incorrect passphrase");
            }
        } else {
            // First unlock — write canary
            let dir = self.vault_dir(username);
            tokio::fs::create_dir_all(&dir).await?;
            let enc = encrypt_with_key(&key, CANARY_PT)?;
            tokio::fs::write(&canary, &enc).await?;
        }

        self.keys.insert(username.to_string(), key);
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
        let salt    = self.get_or_create_salt(username).await?;
        let old_key = derive_key(old, &salt)?;

        let canary = self.canary_path(username);
        if tokio::fs::metadata(&canary).await.is_ok() {
            let enc = tokio::fs::read_to_string(&canary).await?;
            let pt  = decrypt_with_key(&old_key, &enc)
                .map_err(|_| anyhow::anyhow!("Old passphrase incorrect"))?;
            if pt != CANARY_PT { bail!("Old passphrase incorrect"); }
        }

        // Derive new key
        let mut new_salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut new_salt);
        let new_key = derive_key(new, &new_salt)?;

        // Re-encrypt only THIS user's log files (scoped by their network conn_ids)
        let net_dir_path = PathBuf::from(&self.data_dir).join("networks").join(sanitize_username(username));
        if net_dir_path.exists() {
            if let Ok(mut rd) = tokio::fs::read_dir(&net_dir_path).await {
                while let Ok(Some(entry)) = rd.next_entry().await {
                    if let Some(conn_id) = entry.path().file_stem().and_then(|s| s.to_str()) {
                        let user_log_dir = PathBuf::from(&self.data_dir).join("logs").join(conn_id);
                        if user_log_dir.exists() {
                            re_encrypt_tree(&user_log_dir, &old_key, &new_key).await?;
                        }
                    }
                }
            }
        }

        // Re-encrypt network config passwords for this user
        let net_dir = PathBuf::from(&self.data_dir).join("networks").join(sanitize_username(username));
        if net_dir.exists() {
            re_encrypt_network_configs(&net_dir, &old_key, &new_key).await?;
        }

        // Persist new salt + canary
        let dir = self.vault_dir(username);
        tokio::fs::create_dir_all(&dir).await?;
        tokio::fs::write(self.salt_path(username), &new_salt).await?;
        let new_canary = encrypt_with_key(&new_key, CANARY_PT)?;
        tokio::fs::write(&canary, new_canary).await?;

        // Update in-memory key
        if let Some(mut entry) = self.keys.get_mut(username) {
            for b in entry.value_mut().iter_mut() { *b = 0; }
        }
        self.keys.insert(username.to_string(), new_key);
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
            tokio::fs::write(&path, &salt).await?;
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
                            if old_canary.exists() {
                                tokio::fs::copy(&old_canary, &user_canary).await?;
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

pub fn derive_subkey(master: &[u8; KEY_LEN], info: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; KEY_LEN];
    hk.expand(info, &mut out).expect("HKDF expand");
    out
}

fn sanitize_username(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').collect()
}

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
    let tmp_path = path.with_extension("log.tmp");
    tokio::fs::write(&tmp_path, new_lines.join("\n") + "\n").await?;
    tokio::fs::rename(&tmp_path, path).await?;
    Ok(())
}

async fn re_encrypt_network_configs(dir: &PathBuf, old: &[u8; KEY_LEN], new: &[u8; KEY_LEN]) -> Result<()> {
    if !dir.exists() { return Ok(()); }
    let mut rd = tokio::fs::read_dir(dir).await?;
    while let Ok(Some(entry)) = rd.next_entry().await {
        let path = entry.path();
        if path.extension().map(|x| x == "json").unwrap_or(false) {
            let content = tokio::fs::read_to_string(&path).await?;
            let mut val: serde_json::Value = serde_json::from_str(&content)?;
            let mut changed = false;
            // Re-encrypt any "enc:..." string values
            if let Some(obj) = val.as_object_mut() {
                for (_k, v) in obj.iter_mut() {
                    if let Some(s) = v.as_str() {
                        if s.starts_with("enc:") {
                            let enc_data = &s[4..];
                            if let Ok(pt) = decrypt_with_key(old, enc_data) {
                                if let Ok(new_enc) = encrypt_with_key(new, &pt) {
                                    *v = serde_json::Value::String(format!("enc:{}", new_enc));
                                    changed = true;
                                }
                            }
                        }
                    }
                    // Check nested objects (sasl_plain)
                    if let Some(inner) = v.as_object_mut() {
                        for (_ik, iv) in inner.iter_mut() {
                            if let Some(s) = iv.as_str() {
                                if s.starts_with("enc:") {
                                    let enc_data = &s[4..];
                                    if let Ok(pt) = decrypt_with_key(old, enc_data) {
                                        if let Ok(new_enc) = encrypt_with_key(new, &pt) {
                                            *iv = serde_json::Value::String(format!("enc:{}", new_enc));
                                            changed = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if changed {
                let tmp = path.with_extension("json.tmp");
                tokio::fs::write(&tmp, serde_json::to_string_pretty(&val)?).await?;
                tokio::fs::rename(&tmp, &path).await?;
            }
        }
    }
    Ok(())
}
