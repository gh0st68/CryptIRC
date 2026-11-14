/// crypto.rs — Per-user vault key management
///
/// Each user has their own vault with their own passphrase, salt, and canary.
/// Unlocking one user's vault does not affect any other user's vault.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
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
use zeroize::Zeroize;

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

/// Best-effort chmod 0700 on a per-user vault directory (audit #45): create_dir_all
/// honors the umask (~0755) and does not re-chmod a pre-existing dir on upgrade, so
/// tighten it explicitly. No-op on non-unix. Mirrors certs.rs::set_dir_mode.
async fn set_dir_mode(path: impl AsRef<Path>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o700)).await;
    }
    #[cfg(not(unix))]
    { let _ = path.as_ref(); }
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
    /// r4 C1-4: per-user count of vault locks (LockVault, account purge). An unlock or
    /// passphrase change snapshots it when it is REQUESTED and installs the master key only
    /// if no lock happened since: lock() never took vault_lock, so a lock that landed while
    /// an unlock / change_passphrase was deriving (seconds of Argon2) was silently undone
    /// when that operation inserted the key afterwards. The check-and-insert (unlock /
    /// change) and the bump-and-remove (lock) run under this one std mutex, so they are
    /// atomic with respect to each other. No await is ever held under it.
    lock_epochs: std::sync::Mutex<std::collections::HashMap<String, u64>>,
}

/// r4 C1-4: the vault was locked (LockVault from another tab/device, or account deletion)
/// after this unlock / passphrase change was requested, so the master key was NOT
/// installed: the lock stands. `committed` = the new passphrase had already been written
/// (change_passphrase only): it is the valid one now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockedMeanwhile {
    pub committed: bool,
}

impl std::fmt::Display for LockedMeanwhile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.committed {
            f.write_str("Your vault passphrase WAS changed, but the vault was locked while the change was finishing, \
so it stays locked: unlock it with the NEW passphrase.")
        } else {
            f.write_str("The vault was locked (from another tab or device) while this was in progress, so it stays locked \
and nothing was changed. Try again.")
        }
    }
}
impl std::error::Error for LockedMeanwhile {}

impl CryptoManager {
    pub fn new(data_dir: &str) -> Result<Self> {
        Ok(Self {
            data_dir: data_dir.to_string(),
            keys: DashMap::new(),
            vault_locks: DashMap::new(),
            lock_epochs: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    fn epochs(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, u64>> {
        self.lock_epochs.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// r4 C1-4: the user's current lock epoch. Take it when an unlock / passphrase change
    /// is REQUESTED (before queueing for the KDF) and pass it to unlock_since /
    /// change_passphrase_since.
    pub fn lock_epoch(&self, username: &str) -> u64 {
        self.epochs().get(username).copied().unwrap_or(0)
    }

    /// r4 C1-4: Err(LockedMeanwhile) if the vault was locked after `since` was taken.
    fn ensure_not_locked_since(&self, username: &str, since: u64, committed: bool) -> Result<()> {
        if self.lock_epoch(username) != since {
            return Err(anyhow::Error::new(LockedMeanwhile { committed }));
        }
        Ok(())
    }

    /// r4 C1-4: install the master key unless the vault was locked after `since` was taken
    /// — atomically with respect to lock().
    fn install_key_since(&self, username: &str, master: [u8; KEY_LEN], since: u64, committed: bool) -> Result<()> {
        let mut master = master;
        let ep = self.epochs();
        if ep.get(username).copied().unwrap_or(0) != since {
            drop(ep);
            master.zeroize();
            return Err(anyhow::Error::new(LockedMeanwhile { committed }));
        }
        self.keys.insert(username.to_string(), master);
        drop(ep);
        master.zeroize();
        Ok(())
    }

    /// r4 C1-4: bump the lock epoch and wipe the key, atomically w.r.t. install_key_since.
    fn lock_now(&self, username: &str) {
        let mut ep = self.epochs();
        let e = ep.entry(username.to_string()).or_insert(0);
        *e = e.wrapping_add(1);
        if let Some(mut entry) = self.keys.get_mut(username) {
            for b in entry.value_mut().iter_mut() { *b = 0; }
        }
        self.keys.remove(username);
        drop(ep);
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
        let since = self.lock_epoch(username);
        self.unlock_since(username, passphrase, since).await
    }

    /// unlock(), refusing (Err(LockedMeanwhile), nothing installed) when the vault was
    /// locked after `since` (= lock_epoch() taken when the unlock was requested) — r4 C1-4.
    pub async fn unlock_since(&self, username: &str, passphrase: &str, since: u64) -> Result<()> {
        // Serialize with change_passphrase (and concurrent unlocks) for this user, so the
        // legacy-migration write_master_bundle below can't interleave with a concurrent
        // passphrase change and commit a stale wrapped-master bundle. Bind the Arc to a
        // local first so it outlives the guard (E0716).
        let _vault_lock = self.vault_lock(username);
        let _vault_guard = _vault_lock.lock().await;
        // r4 C1-4: a lock (or account purge) that landed while this waited: stop before
        // touching the disk (a purged account's vault must not be re-created below).
        self.ensure_not_locked_since(username, since, false)?;
        // ── Master-key vault (audit #8) ──────────────────────────────────────
        // Once vault.mkey exists it is the single authoritative, crash-atomic
        // record: it embeds the salt under which it was wrapped, so unlocking
        // never depends on the legacy vault.salt/vault.canary being in sync.
        let mkey_path = self.mkey_path(username);
        match tokio::fs::read_to_string(&mkey_path).await {
            Ok(bundle) => {
                let master = unwrap_master_bundle(&bundle, passphrase)
                    .map_err(|_| anyhow::anyhow!("Incorrect passphrase"))?;
                // r4 C1-4: not if the vault was locked meanwhile.
                return self.install_key_since(username, master, since, false);
            }
            // Only a genuinely-missing mkey (NotFound) means "legacy vault". Any
            // other read error (transient I/O, EPERM) must ABORT: falling through
            // to the legacy branch would re-derive master==kdf(salt) and have
            // write_master_bundle OVERWRITE the authoritative bundle with the
            // wrong master — irreversible loss of all at-rest blobs + a silent
            // E2E identity change (audit #F17).
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(anyhow::anyhow!("Reading vault.mkey: {}", e));
            }
            Err(_) => {} // NotFound → fall through to the legacy path below.
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
            set_dir_mode(&dir).await;
            let enc = encrypt_with_key(&kdf_key, CANARY_PT)?;
            write_secret(&canary, enc.as_bytes()).await?;
        }

        // master == kdf_key for the legacy cohort (keeps existing blobs valid).
        let master = kdf_key;
        // Finding #40: legacy migration copied ONE shared vault.salt into every
        // user's vault dir, so the KDF wrapping key derived above is identical for
        // identical passphrases and a single Argon2 dictionary attacks all migrated
        // users at once (and master == kdf_key self-wraps, removing key separation).
        // Now that we hold the passphrase, re-wrap the SAME master (kept == old
        // kdf_key so every existing cert/.enc/e2e/log blob and the E2E key stay
        // valid) under a FRESH per-user random salt: the authoritative vault.mkey
        // then embeds a unique salt and master != wrapping key.
        let mut new_salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut new_salt); // OS CSPRNG (audit #21)
        let new_kdf = derive_key(passphrase, &new_salt)?;
        self.write_master_bundle(username, &new_salt, &new_kdf, &master).await?;

        // Refresh the legacy salt/canary mirrors to the fresh salt so the shared
        // salt no longer sits on disk (best-effort; vault.mkey is already the
        // authoritative record and is all unlock reads once it exists).
        let _ = write_secret(self.salt_path(username), &new_salt).await;
        if let Ok(new_canary) = encrypt_with_key(&new_kdf, CANARY_PT) {
            let _ = write_secret(self.canary_path(username), new_canary.as_bytes()).await;
        }

        // r4 C1-4: not if the vault was locked meanwhile (the migrated bundle re-wraps the
        // same master under the same passphrase, so writing it was harmless either way).
        self.install_key_since(username, master, since, false)
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
        set_dir_mode(&dir).await;
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
        // r4 C1-4: also bumps the lock epoch, so an unlock / passphrase change requested
        // before this lock can no longer re-install the key when it finishes.
        self.lock_now(username);
    }

    /// Atomically tear down a user's vault on account deletion: zeroize+drop the
    /// in-memory master key AND remove the on-disk vault dir (salt/canary/mkey) while
    /// holding the SAME per-user vault_lock that unlock()/change_passphrase() take.
    /// Doing the two steps without the lock (as a bare lock()+remove_dir_all pair) lets a
    /// concurrent unlock()/change_passphrase() interleave its keys.insert /
    /// write_master_bundle AFTER the teardown, resurrecting the deleted account's master
    /// key and vault — a cross-owner E2E key disclosure to a re-registered same-name user.
    pub async fn purge_vault(&self, username: &str) {
        // r4 C1-4: bump the epoch BEFORE waiting for vault_lock, so an unlock /
        // change_passphrase that is still queued (or deriving) refuses instead of
        // installing the key or re-creating the vault after the teardown below.
        self.lock_now(username);
        let _vault_lock = self.vault_lock(username);
        let _vault_guard = _vault_lock.lock().await;
        self.lock_now(username);
        let _ = tokio::fs::remove_dir_all(self.vault_dir(username)).await;
    }

    pub async fn is_unlocked(&self, username: &str) -> bool {
        self.keys.contains_key(username)
    }

    pub async fn change_passphrase(&self, username: &str, old: &str, new: &str) -> Result<()> {
        let since = self.lock_epoch(username);
        self.change_passphrase_since(username, old, new, since).await
    }

    /// change_passphrase(), honouring a vault lock that happened after `since` (= lock_epoch()
    /// taken when the change was requested) — r4 C1-4: before the new bundle is written the
    /// change is abandoned (Err(LockedMeanwhile{committed:false}), nothing changed); after it,
    /// the new passphrase stands but the master key is not re-installed
    /// (Err(LockedMeanwhile{committed:true})) — the vault stays locked.
    pub async fn change_passphrase_since(&self, username: &str, old: &str, new: &str, since: u64) -> Result<()> {
        // Serialize with unlock (and concurrent passphrase changes) for this user — both
        // write vault.mkey; interleaving could commit a bundle wrapped under the wrong KDF.
        // Bind the Arc to a local first so it outlives the guard (E0716).
        let _vault_lock = self.vault_lock(username);
        let _vault_guard = _vault_lock.lock().await;
        self.ensure_not_locked_since(username, since, false)?;
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
        let master = match tokio::fs::read_to_string(&mkey_path).await {
            Ok(bundle) => unwrap_master_bundle(&bundle, old)
                .map_err(|_| anyhow::anyhow!("Old passphrase incorrect"))?,
            // Only a genuinely-missing mkey (NotFound) is a legacy vault. On any
            // other read error (transient I/O, EPERM) ABORT rather than falling
            // into the legacy branch, which would adopt master==kdf(canary salt)
            // and have write_master_bundle OVERWRITE the authoritative bundle
            // with the wrong master — irreversible at-rest data loss (audit #F17).
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(anyhow::anyhow!("Reading vault.mkey: {}", e));
            }
            Err(_) => {
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
            }
        };

        // Derive a fresh KDF key from a new random salt and re-wrap the SAME
        // master under it. The atomic rename of vault.mkey (which embeds the new
        // salt) is the single commit point — no blob re-encryption needed.
        let mut new_salt = [0u8; SALT_LEN];
        // Explicit OS CSPRNG for nonce/salt material (audit #21).
        OsRng.fill_bytes(&mut new_salt);
        let new_kdf = derive_key(new, &new_salt)?;
        // r4 C1-4: a lock during the two derivations above abandons the change cleanly.
        self.ensure_not_locked_since(username, since, false)?;
        self.write_master_bundle(username, &new_salt, &new_kdf, &master).await?;

        // Keep the legacy vault.salt/vault.canary mirrors in sync (best-effort;
        // the mkey bundle is already authoritative, so failure here is harmless).
        let dir = self.vault_dir(username);
        let _ = tokio::fs::create_dir_all(&dir).await;
        set_dir_mode(&dir).await;
        let _ = write_secret(self.salt_path(username), &new_salt).await;
        if let Ok(new_canary) = encrypt_with_key(&new_kdf, CANARY_PT) {
            let _ = write_secret(self.canary_path(username), new_canary.as_bytes()).await;
        }

        // In-memory master key is unchanged; keep it so the session stays usable — unless
        // the vault was locked after this change was requested (r4 C1-4): the lock stands.
        self.install_key_since(username, master, since, true)
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

    pub async fn encrypt_aad(&self, username: &str, plaintext: &[u8], aad: &[u8]) -> Result<String> {
        let entry = self.keys.get(username)
            .ok_or_else(|| anyhow::anyhow!("Vault locked"))?;
        encrypt_with_key_aad(entry.value(), plaintext, aad)
    }

    pub async fn decrypt_aad(&self, username: &str, encoded: &str, aad: &[u8]) -> Result<Vec<u8>> {
        let entry = self.keys.get(username)
            .ok_or_else(|| anyhow::anyhow!("Vault locked"))?;
        decrypt_with_key_aad(entry.value(), encoded, aad)
    }

    /// LEGACY E2E blob-wrapping key (pre-2026-11-01). The server can derive it, so it
    /// only exists to let the browser read + re-wrap blobs written by older app
    /// versions (C1 migration). New blobs are wrapped under a client-held key.
    pub async fn derive_e2e_enc_key(&self, username: &str) -> Result<[u8; KEY_LEN]> {
        let entry = self.keys.get(username)
            .ok_or_else(|| anyhow::anyhow!("Vault locked"))?;
        derive_subkey(entry.value(), b"cryptirc-e2e-enc-v1")
    }

    /// C1: per-user "pepper" mixed (client-side, with HKDF) into the key the browser
    /// derives from the vault passphrase to wrap its E2E master key. Alone it unwraps
    /// nothing — the browser also needs PBKDF2(passphrase) — but it ties the client
    /// keyring to the Argon2-protected vault master, so a stolen data dir can't be
    /// brute-forced through the cheaper browser KDF. Stable across passphrase changes
    /// (the master key never changes). Sent only to a socket that just proved the
    /// passphrase (unlock / re-verify / change-passphrase).
    pub async fn derive_e2e_kek_pepper(&self, username: &str) -> Result<[u8; KEY_LEN]> {
        let entry = self.keys.get(username)
            .ok_or_else(|| anyhow::anyhow!("Vault locked"))?;
        derive_subkey(entry.value(), b"cryptirc-e2e-kek-pepper-v2")
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
            set_dir_mode(&dir).await;
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
                            set_dir_mode(&user_vault).await;
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
    // No AAD — byte-for-byte the historical behavior for canary/master-bundle/
    // prefs/cert blobs. Log lines use encrypt_with_key_aad to bind location (#11).
    encrypt_with_key_aad(key_bytes, plaintext, &[])
}

/// Like `encrypt_with_key`, but authenticates `aad` (AES-GCM additional data).
/// The AAD is tag-covered but NOT stored in the output, so decryption must
/// supply the identical AAD. Used to bind each encrypted log line to its
/// conn/target/date so a ciphertext can't be relocated between files (#11).
pub fn encrypt_with_key_aad(key_bytes: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<String> {
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
    let ciphertext = cipher.encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, out))
}

pub fn decrypt_with_key(key_bytes: &[u8; KEY_LEN], encoded: &str) -> Result<Vec<u8>> {
    decrypt_with_key_aad(key_bytes, encoded, &[])
}

/// Like `decrypt_with_key`, but requires `aad` to match the AAD supplied at
/// encryption time (#11); decryption fails if it differs.
pub fn decrypt_with_key_aad(key_bytes: &[u8; KEY_LEN], encoded: &str, aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    let data   = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)?;
    if data.len() < NONCE_LEN + 16 { bail!("Ciphertext too short"); }
    let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
    let pt    = cipher.decrypt(nonce, Payload { msg: &data[NONCE_LEN..], aad })
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
    // r3 (agy-P1 LOW crypto.rs:510): bounded. Every UnlockVault / ChangePassphrase runs
    // this KDF, so a vault.mkey restored from a bad backup or edited on disk with an
    // extreme cost (m up to 4 GiB, t/p in the billions) pinned a blocking thread and
    // allocated gigabytes on every unlock attempt. The app has only ever written
    // m=65536, t=3, p=1; the bounds leave room for raising the cost later (m ≤ 256 MiB,
    // t ≤ 10, p ≤ 4) and refuse anything beyond — before any memory is allocated.
    let m = val.get("m").and_then(|v| v.as_u64()).unwrap_or(ARGON2_M as u64);
    let t = val.get("t").and_then(|v| v.as_u64()).unwrap_or(ARGON2_T as u64);
    let p = val.get("p").and_then(|v| v.as_u64()).unwrap_or(ARGON2_P as u64);
    let (m, t, p) = check_kdf_params(m, t, p)?;
    let kdf_key = derive_key_params(passphrase, &salt, m, t, p)?;
    let raw = decrypt_with_key(&kdf_key, wrapped)?;
    if raw.len() != KEY_LEN { bail!("Corrupt master key bundle"); }
    let mut master = [0u8; KEY_LEN];
    master.copy_from_slice(&raw);
    Ok(master)
}

/// Upper bounds for the Argon2 parameters read back from a vault.mkey bundle.
const ARGON2_M_MAX: u64 = 262_144; // 256 MiB (KiB units) — 4x the current default
const ARGON2_T_MAX: u64 = 10;
const ARGON2_P_MAX: u64 = 4;

/// Validate stored Argon2 parameters (see unwrap_master_bundle).
fn check_kdf_params(m: u64, t: u64, p: u64) -> Result<(u32, u32, u32)> {
    if !(1..=ARGON2_P_MAX).contains(&p) || !(1..=ARGON2_T_MAX).contains(&t)
        || m < 8 * p || m > ARGON2_M_MAX {
        bail!("Corrupt master key bundle (Argon2 parameters out of range)");
    }
    Ok((m as u32, t as u32, p as u32))
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

#[cfg(test)]
mod kdf_param_tests {
    use super::*;

    #[test]
    fn stored_argon2_params_are_bounded() {
        // every value the app has ever written
        assert_eq!(check_kdf_params(65536, 3, 1).unwrap(), (65536, 3, 1));
        // headroom for a future cost increase
        assert!(check_kdf_params(262_144, 10, 4).is_ok());
        // extreme / nonsensical values are refused (no allocation happens)
        assert!(check_kdf_params(u32::MAX as u64, 3, 1).is_err());
        assert!(check_kdf_params((1u64 << 32) + 65536, 3, 1).is_err()); // was truncated to 65536 by `as u32`
        assert!(check_kdf_params(65536, 1_000_000, 1).is_err());
        assert!(check_kdf_params(65536, 3, 1000).is_err());
        assert!(check_kdf_params(65536, 0, 1).is_err());
        assert!(check_kdf_params(4, 3, 1).is_err());
    }

    #[tokio::test]
    async fn tampered_vault_mkey_cost_is_refused_quickly() {
        let d = std::env::temp_dir().join(format!("cryptirc-kdf-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        let dir = d.to_string_lossy().into_owned();
        let cm = CryptoManager::new(&dir).unwrap();
        cm.unlock("alice", "correct horse").await.unwrap();
        cm.lock("alice").await;
        let p = cm.mkey_path("alice");
        let mut v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!((v["m"].as_u64(), v["t"].as_u64(), v["p"].as_u64()), (Some(65536), Some(3), Some(1)));
        let good = v.clone();
        v["m"] = serde_json::json!(4_194_304u64); // 4 GiB
        std::fs::write(&p, v.to_string()).unwrap();
        let t0 = std::time::Instant::now();
        assert!(cm.unlock("alice", "correct horse").await.is_err());
        assert!(t0.elapsed() < std::time::Duration::from_secs(2));
        // the untouched bundle still unlocks
        std::fs::write(&p, good.to_string()).unwrap();
        cm.unlock("alice", "correct horse").await.unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod r4_lock_race_tests {
    //! r4 C1-4: a vault lock requested after an unlock / passphrase change was requested
    //! wins — the operation finishing afterwards must not re-install the key.
    use super::*;
    use std::sync::Arc;

    fn mgr(tag: &str) -> (Arc<CryptoManager>, std::path::PathBuf) {
        let d = std::env::temp_dir().join(format!("cryptirc-r4lock-{}-{}", tag, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        (Arc::new(CryptoManager::new(&d.to_string_lossy()).unwrap()), d)
    }

    /// The unlock is queued behind the vault lock (as behind another unlock / a KDF slot)
    /// when the Lock arrives. Only existing APIs are used, so the same test shows the
    /// 3b92eaf behaviour (key re-installed after the lock → unlocked).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lock_while_an_unlock_is_queued_wins() {
        let (cm, d) = mgr("q");
        cm.unlock("alice", "correct horse").await.unwrap();   // create the vault
        cm.lock("alice").await;
        let vl = cm.vault_lock("alice");
        let held = vl.lock().await;
        let c = cm.clone();
        let t = tokio::spawn(async move { c.unlock("alice", "correct horse").await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;   // unlock requested + waiting
        cm.lock("alice").await;                                             // the user locks
        drop(held);
        let r = t.await.unwrap();
        assert!(!cm.is_unlocked("alice").await, "the lock must stand");
        let e = r.expect_err("the unlock reports the lock");
        assert_eq!(e.downcast_ref::<LockedMeanwhile>(), Some(&LockedMeanwhile { committed: false }));
        // An unlock requested after the lock works normally.
        cm.unlock("alice", "correct horse").await.unwrap();
        assert!(cm.is_unlocked("alice").await);
        let _ = std::fs::remove_dir_all(d);
    }

    /// Lock landing while the unlock derives (epoch taken at request time, like the WS
    /// handler does): refused whatever the timing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lock_during_the_derivation_wins() {
        let (cm, d) = mgr("derive");
        cm.unlock("alice", "correct horse").await.unwrap();
        cm.lock("alice").await;
        let since = cm.lock_epoch("alice");
        let c = cm.clone();
        let t = tokio::spawn(async move { c.unlock_since("alice", "correct horse", since).await });
        // Right away: before (first check) or during (install check) the 64 MiB Argon2 run.
        cm.lock("alice").await;
        let r = t.await.unwrap();
        assert!(r.is_err() && !cm.is_unlocked("alice").await);
        // A wrong passphrase is still "Incorrect passphrase", not LockedMeanwhile.
        let e = cm.unlock("alice", "wrong").await.unwrap_err();
        assert!(e.downcast_ref::<LockedMeanwhile>().is_none());
        let _ = std::fs::remove_dir_all(d);
    }

    /// change_passphrase queued when the Lock arrives: abandoned cleanly — nothing written,
    /// the OLD passphrase still unlocks, the vault stays locked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lock_while_a_passphrase_change_is_queued_wins() {
        let (cm, d) = mgr("chg");
        cm.unlock("alice", "correct horse").await.unwrap();
        let vl = cm.vault_lock("alice");
        let held = vl.lock().await;
        let c = cm.clone();
        let t = tokio::spawn(async move { c.change_passphrase("alice", "correct horse", "battery staple").await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        cm.lock("alice").await;
        drop(held);
        let r = t.await.unwrap();
        assert!(!cm.is_unlocked("alice").await, "the lock must stand");
        assert_eq!(r.unwrap_err().downcast_ref::<LockedMeanwhile>(), Some(&LockedMeanwhile { committed: false }));
        assert!(cm.unlock("alice", "battery staple").await.is_err(), "nothing was changed");
        cm.unlock("alice", "correct horse").await.unwrap();
        let _ = std::fs::remove_dir_all(d);
    }

    /// A lock that lands after the new bundle was written: the new passphrase stands, the
    /// key is NOT re-installed, and the error says so (committed).
    #[tokio::test]
    async fn lock_after_the_commit_keeps_the_new_passphrase_and_the_lock() {
        let (cm, d) = mgr("commit");
        cm.unlock("alice", "correct horse").await.unwrap();
        let since = cm.lock_epoch("alice");
        // Simulate the lock landing between write_master_bundle and the key install.
        let mut master = *cm.keys.get("alice").unwrap();
        cm.lock("alice").await;
        let e = cm.install_key_since("alice", master, since, true).unwrap_err();
        master.zeroize();
        assert_eq!(e.downcast_ref::<LockedMeanwhile>(), Some(&LockedMeanwhile { committed: true }));
        assert!(e.to_string().contains("NEW passphrase"));
        assert!(!cm.is_unlocked("alice").await);
        let _ = std::fs::remove_dir_all(d);
    }

    /// Account purge bumps the epoch: an unlock queued behind it can neither re-install
    /// the key nor re-create the deleted vault (3b92eaf: the legacy branch re-created
    /// vault.salt/canary under the deleted account's name and unlocked it).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn purge_beats_a_queued_unlock() {
        let (cm, d) = mgr("purge");
        cm.unlock("alice", "correct horse").await.unwrap();
        let vl = cm.vault_lock("alice");
        let held = vl.lock().await;
        let c2 = cm.clone();
        let p = tokio::spawn(async move { c2.purge_vault("alice").await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;   // purge queued first
        let c = cm.clone();
        let t = tokio::spawn(async move { c.unlock("alice", "correct horse").await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;   // then the unlock
        drop(held);
        p.await.unwrap();
        let _ = t.await.unwrap();
        assert!(!cm.is_unlocked("alice").await);
        assert!(!cm.vault_dir("alice").exists(), "the purged vault stays gone");
        let _ = std::fs::remove_dir_all(d);
    }
}
