/// certs.rs — Client TLS certificate management for IRC SASL EXTERNAL auth
///
/// Generates a self-signed X.509 certificate per IRC network.
/// The private key PEM is encrypted with the vault key before being written to disk.
/// Only the certificate PEM (public) is stored unencrypted — it contains no secret.
/// The SHA-256 fingerprint is what IRC services use to identify you.
///
/// Storage layout:
///   data/certs/{cert_id}/cert.pem   — public certificate (plaintext)
///   data/certs/{cert_id}/key.enc    — private key PEM, AES-256-GCM encrypted

use anyhow::{bail, Result};
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, PKCS_ECDSA_P256_SHA256};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroize;

use crate::crypto::CryptoManager;

/// All information about a stored client certificate.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub cert_id:     String,
    /// SHA-256 fingerprint of the DER-encoded certificate (hex, colon-separated).
    pub fingerprint: String,
    /// PEM-encoded certificate (public, safe to share with IRC services).
    pub cert_pem:    String,
}

pub struct CertStore {
    data_dir: String,
    crypto:   Arc<CryptoManager>,
    /// r3 C1-10: one async lock per (sanitized) cert dir, held across a whole
    /// generate / delete, so two of them can never interleave their writes.
    locks:    dashmap::DashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>,
}

impl CertStore {
    pub fn new(data_dir: &str, crypto: Arc<CryptoManager>) -> Self {
        Self { data_dir: data_dir.to_string(), crypto, locks: dashmap::DashMap::new() }
    }

    fn dir_lock(&self, dir: &std::path::Path) -> Arc<tokio::sync::Mutex<()>> {
        self.locks.entry(dir.to_path_buf()).or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))).clone()
    }

    /// Generate a new self-signed ECDSA P-256 certificate for a network connection.
    /// The cert is valid for 10 years and uses the nick as the Common Name.
    /// Returns CertInfo — call `load_identity` later to get the native_tls::Identity.
    pub async fn generate(&self, username: &str, cert_id: &str, nick: &str) -> Result<CertInfo> {
        if !self.crypto.is_unlocked(username).await {
            bail!("Vault must be unlocked to generate certificates");
        }

        let dir = self.cert_dir(cert_id);
        // r3 C1-10: serialise with any other generate/delete of this cert dir.
        let lock = self.dir_lock(&dir);
        let _guard = lock.lock().await;
        tokio::fs::create_dir_all(&dir).await?;
        // Restrict the cert dir (and its parent) to owner-only (audit #142): the
        // world-traversable data dir must not let other local users enumerate or read
        // per-network cert material.
        set_dir_mode(&dir).await;
        if let Some(parent) = dir.parent() { set_dir_mode(parent).await; }

        // Build certificate parameters. Validity is computed from "now" (audit #142):
        // valid from ~1 day ago (clock-skew tolerance) to ~10 years out, rather than a
        // hardcoded 2024..2034 window. rcgen 0.12 takes `time::OffsetDateTime`; we derive
        // the current civil date via chrono (already a dependency) so we don't add a new
        // direct `time` dependency, then use rcgen's `date_time_ymd` constructor.
        let mut params = CertificateParams::default();
        params.alg = &PKCS_ECDSA_P256_SHA256;
        let (ny, nm, nd) = current_ymd();
        params.not_before = rcgen::date_time_ymd(ny, nm, nd) - std::time::Duration::from_secs(24 * 60 * 60);
        // P3 fix (#142): clamp Feb-29 for the +10y not_after. ny+10 is never a leap
        // year (10 ∤ 4), so rcgen's date_time_ymd would internally .expect() a
        // from_calendar_date(non-leap, Feb, 29) → Err → panic. not_before is safe
        // (the current year IS a leap year on Feb 29).
        let end_day = if nm == 2 && nd == 29 { 28 } else { nd };
        params.not_after  = rcgen::date_time_ymd(ny + 10, nm, end_day);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, nick);
        dn.push(DnType::OrganizationName, "CryptIRC");
        params.distinguished_name = dn;

        let cert = Certificate::from_params(params)?;

        let cert_pem = cert.serialize_pem()?;
        let mut key_pem = cert.get_key_pair().serialize_pem();
        // r3 (found with C1-10's tests): the fingerprint must be that of the certificate
        // we STORE. rcgen re-signs on every serialize_* call and ECDSA signatures are
        // randomised, so the old `compute_fingerprint(&cert.serialize_der()?)` described a
        // different certificate than cert.pem — the GenerateCert reply showed a fingerprint
        // that NickServ CERT ADD would never match (reopening the dialog showed the right
        // one, from load_info). Derive it from the stored PEM, like load_info does.
        let fingerprint = compute_fingerprint(&pem_to_der(&cert_pem)?)?;

        // r3 C1-10: encrypt the private key BEFORE touching the stored pair. It used to
        // overwrite cert.pem first and only then encrypt + write key.enc: a vault Lock in
        // between made the encrypt fail and left the NEW certificate beside the OLD key
        // (SASL EXTERNAL broken, old identity already gone), and two concurrent
        // regenerations could interleave their writes. Now nothing is replaced unless both
        // files are fully written + fsynced as temp files; then key.enc is renamed into
        // place first and cert.pem right after, all under the per-dir lock.
        let key_enc = self.crypto.encrypt(username, key_pem.as_bytes()).await;
        // Scrub the plaintext private-key PEM from memory once encrypted (audit #142).
        key_pem.zeroize();
        let key_enc = key_enc?;

        // key.enc is the vault-encrypted client TLS key, cert.pem the public cert (0600
        // anyway — only the service reads it; #7): both owner-only (audit #7).
        // r4 F1-3 / V3S-3: the pair is installed in ONE atomic step. r3 renamed key.enc and
        // then cert.pem into place: a crash between the two renames (or a failed second
        // rename) left the NEW key beside the OLD certificate until the next regenerate, and
        // a reader between them (a dial) saw that mix too. Now both files are written and
        // fsynced into a fresh sibling directory `<id>.gen-<tag>` (cert_dir can never name
        // it: ids lose every '.'), which is then EXCHANGED with the live directory by one
        // renameat2(RENAME_EXCHANGE): the live path shows the old pair or the new pair,
        // never a mix, crash or not. The old pair (now under the temporary name) is deleted.
        // Where the kernel/filesystem can't exchange, the two renames are the fallback, with
        // the old key kept as a hard link so a failed second rename puts it back; readers
        // take this dir's lock (read_pair), so they never see the in-between state either.
        let key_path  = dir.join("key.enc");
        let cert_path = dir.join("cert.pem");
        let tag = uuid::Uuid::new_v4().simple().to_string();
        remove_stale_gen_dirs(&dir).await;
        let gen_dir = gen_dir_for(&dir, &tag);
        let staged = async {
            create_private_dir(&gen_dir).await?;
            write_secret_file(&gen_dir.join("key.enc"), key_enc.as_bytes()).await?;
            write_secret_file(&gen_dir.join("cert.pem"), cert_pem.as_bytes()).await?;
            sync_dir(&gen_dir).await;
            Ok::<(), std::io::Error>(())
        }.await;
        if let Err(e) = staged {
            let _ = tokio::fs::remove_dir_all(&gen_dir).await;
            return Err(e.into());
        }
        let swapped = exchange_dirs(&gen_dir, &dir).await;
        let installed = match swapped {
            Ok(()) => {
                if let Some(parent) = dir.parent() { sync_dir(parent).await; }
                Ok(())
            }
            Err(e) => {
                tracing::debug!("cert dir exchange unavailable ({}), installing the pair by two renames", e);
                install_by_renames(&gen_dir, &key_path, &cert_path).await
            }
        };
        // The old pair (after an exchange) or the staging leftovers (fallback / failure).
        let _ = tokio::fs::remove_dir_all(&gen_dir).await;
        installed?;
        sync_dir(&dir).await;

        Ok(CertInfo { cert_id: cert_id.to_string(), fingerprint, cert_pem })
    }

    /// Load cert info (fingerprint + PEM) without decrypting the private key.
    pub async fn load_info(&self, cert_id: &str) -> Result<CertInfo> {
        let dir      = self.cert_dir(cert_id);
        let cert_pem = tokio::fs::read_to_string(dir.join("cert.pem")).await
            .map_err(|_| anyhow::anyhow!("Certificate not found for id: {}", cert_id))?;
        let der = pem_to_der(&cert_pem)?;
        let fingerprint = compute_fingerprint(&der)?;
        Ok(CertInfo { cert_id: cert_id.to_string(), fingerprint, cert_pem })
    }

    /// r4 F1-3 / V3S-3: cert.pem (bytes) and key.enc (text) read as ONE pair, under this
    /// cert dir's lock, so a regenerate can never hand a reader the new key with the old
    /// certificate (or the reverse). The dial path (ipc_client build_dial_params) and
    /// load_identity read through this.
    pub async fn read_pair(&self, cert_id: &str) -> std::io::Result<(Vec<u8>, String)> {
        let dir = self.cert_dir(cert_id);
        let lock = self.dir_lock(&dir);
        let _guard = lock.lock().await;
        let cert = tokio::fs::read(dir.join("cert.pem")).await?;
        let key = tokio::fs::read_to_string(dir.join("key.enc")).await?;
        Ok((cert, key))
    }

    /// Load a native_tls::Identity (cert + decrypted private key) for TLS handshake.
    pub async fn load_identity(&self, username: &str, cert_id: &str) -> Result<native_tls::Identity> {
        if !self.crypto.is_unlocked(username).await {
            bail!("Vault must be unlocked to use client certificates");
        }
        let (cert_bytes, key_enc) = self.read_pair(cert_id).await
            .map_err(|_| anyhow::anyhow!("Certificate not found"))?;
        let cert_pem = String::from_utf8(cert_bytes).map_err(|_| anyhow::anyhow!("Certificate not readable"))?;
        let key_pem_bytes = self.crypto.decrypt(username, key_enc.trim()).await?;
        let mut key_pem = String::from_utf8(key_pem_bytes)?;

        // native-tls needs PKCS#12; we build it via openssl
        let identity = build_identity(&cert_pem, &key_pem)?;
        // Scrub the decrypted plaintext private-key PEM from memory (audit #142).
        key_pem.zeroize();
        Ok(identity)
    }

    /// Delete a stored certificate.
    pub async fn delete(&self, cert_id: &str) -> Result<()> {
        let dir = self.cert_dir(cert_id);
        // r3 C1-10: never remove the dir under a generate that is writing into it.
        let lock = self.dir_lock(&dir);
        let _guard = lock.lock().await;
        // Use the async non-blocking existence check (audit #142).
        if tokio::fs::try_exists(&dir).await.unwrap_or(false) {
            tokio::fs::remove_dir_all(&dir).await?;
        }
        // r4 F1-3: and any staging dir a crash left behind (it holds this id's cert + key).
        remove_stale_gen_dirs(&dir).await;
        Ok(())
    }

    /// Check whether a cert exists for a given id.
    pub async fn exists(&self, cert_id: &str) -> bool {
        // Use the async non-blocking existence check (audit #142).
        tokio::fs::try_exists(self.cert_dir(cert_id).join("cert.pem"))
            .await
            .unwrap_or(false)
    }

    /// List all stored certificate IDs.
    pub async fn list(&self) -> Vec<String> {
        let base = PathBuf::from(&self.data_dir).join("certs");
        let mut ids = Vec::new();
        if let Ok(mut rd) = tokio::fs::read_dir(&base).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                if entry.path().is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        ids.push(name.to_string());
                    }
                }
            }
        }
        ids
    }

    /// Compute the on-disk directory for a cert id, with the id sanitized.
    ///
    /// Sanitization (audit #48/#142): keep only ASCII-alphanumeric plus `-`/`_`, capped
    /// at 64 chars. This intentionally drops `.`, `/`, `\`, NUL and any non-ASCII so a
    /// crafted cert_id cannot escape the `certs/` base via path traversal. If the result
    /// is empty (id was all-illegal), fall back to a fixed `_invalid` segment so we never
    /// return the bare base dir.
    pub(crate) fn cert_dir(&self, cert_id: &str) -> PathBuf {
        let mut safe: String = cert_id.chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .take(64)
            .collect();
        if safe.is_empty() {
            safe.push_str("_invalid");
        }
        PathBuf::from(&self.data_dir).join("certs").join(safe)
    }

    // (r4 F1-3: `cert_path_for` is gone — its one caller, the dial path, now reads the
    // pair through read_pair, under the dir lock. Nothing outside this module builds a cert
    // path any more.)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Best-effort chmod 0600 on a freshly written cert/key file (audit #7) so the
/// world-traversable data dir cannot expose the encrypted client TLS key to
/// other local users. No-op on non-unix targets.
async fn set_secret_mode(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await;
    }
    #[cfg(not(unix))]
    { let _ = path; }
}

/// r3 C1-10: create `path` 0600 (O_EXCL: a fresh temp name), write `bytes`, fsync.
async fn write_secret_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    { opts.mode(0o600); }
    let mut f = opts.open(path).await?;
    f.write_all(bytes).await?;
    f.flush().await?;
    f.sync_all().await?;
    drop(f);
    set_secret_mode(path).await;
    Ok(())
}

/// r4 F1-3: the staging dir of one generate: `<certs>/<id>.gen-<tag>`.
fn gen_dir_for(dir: &std::path::Path, tag: &str) -> PathBuf {
    let name = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    dir.with_file_name(format!("{}.gen-{}", name, tag))
}

/// r4 F1-3: remove `<id>.gen-*` staging dirs a crash left beside `dir` (call with the dir
/// lock held). Best-effort.
async fn remove_stale_gen_dirs(dir: &std::path::Path) {
    let (Some(parent), Some(name)) = (dir.parent(), dir.file_name().and_then(|n| n.to_str())) else { return };
    let prefix = format!("{}.gen-", name);
    let Ok(mut rd) = tokio::fs::read_dir(parent).await else { return };
    while let Ok(Some(e)) = rd.next_entry().await {
        if e.file_name().to_str().map_or(false, |n| n.starts_with(&prefix)) {
            let _ = tokio::fs::remove_dir_all(e.path()).await;
        }
    }
}

/// r4 F1-3: mkdir 0700 (fails if it exists).
async fn create_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    let mut b = tokio::fs::DirBuilder::new();
    #[cfg(unix)]
    { b.mode(0o700); }
    b.create(path).await?;
    set_dir_mode(path).await;
    Ok(())
}

/// r4 F1-3 test hooks (always false outside tests): force the two-rename fallback / make
/// its second rename fail. Per thread: a `#[tokio::test]` polls on its own thread.
#[derive(Clone, Copy)]
enum Hook { NoExchange, FailCertRename }
#[cfg(test)]
thread_local! {
    static TEST_HOOKS: std::cell::Cell<(bool, bool)> = std::cell::Cell::new((false, false));
}
#[cfg(test)]
fn test_hook(h: Hook) -> bool {
    let (no_x, fail) = TEST_HOOKS.with(|c| c.get());
    match h { Hook::NoExchange => no_x, Hook::FailCertRename => fail }
}
#[cfg(not(test))]
fn test_hook(_h: Hook) -> bool { false }

/// r4 F1-3: atomically exchange two directories (Linux renameat2 RENAME_EXCHANGE, via the
/// raw syscall: glibc only has a wrapper since 2.28). Err where unsupported.
async fn exchange_dirs(a: &std::path::Path, b: &std::path::Path) -> std::io::Result<()> {
    if test_hook(Hook::NoExchange) { return Err(std::io::Error::from(std::io::ErrorKind::Unsupported)); }
    let (a, b) = (a.to_path_buf(), b.to_path_buf());
    tokio::task::spawn_blocking(move || exchange_dirs_sync(&a, &b)).await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
}

#[cfg(target_os = "linux")]
fn exchange_dirs_sync(a: &std::path::Path, b: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let ca = std::ffi::CString::new(a.as_os_str().as_bytes())?;
    let cb = std::ffi::CString::new(b.as_os_str().as_bytes())?;
    // SAFETY: two valid NUL-terminated paths; renameat2 reads them and returns.
    let r = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD as libc::c_long, ca.as_ptr(),
            libc::AT_FDCWD as libc::c_long, cb.as_ptr(),
            libc::RENAME_EXCHANGE as libc::c_long,
        )
    };
    if r == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

#[cfg(not(target_os = "linux"))]
fn exchange_dirs_sync(_a: &std::path::Path, _b: &std::path::Path) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// r4 F1-3 fallback (no RENAME_EXCHANGE): move the staged key.enc, then cert.pem, into the
/// live dir (caller holds the dir lock). The old key is kept as a hard link first, so a
/// failed second rename restores it and the old pair stays intact.
async fn install_by_renames(gen_dir: &std::path::Path, key_path: &std::path::Path, cert_path: &std::path::Path) -> std::io::Result<()> {
    let prev = gen_dir.join("key.enc.prev");
    let had_old = tokio::fs::hard_link(key_path, &prev).await.is_ok();
    tokio::fs::rename(gen_dir.join("key.enc"), key_path).await?;
    let r = if test_hook(Hook::FailCertRename) {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "test: cert rename failed"))
    } else {
        tokio::fs::rename(gen_dir.join("cert.pem"), cert_path).await
    };
    if let Err(e) = r {
        if had_old { let _ = tokio::fs::rename(&prev, key_path).await; }
        else { let _ = tokio::fs::remove_file(key_path).await; }
        return Err(e);
    }
    Ok(())
}

/// Best-effort fsync of a directory so the two renames above are durable.
async fn sync_dir(dir: &std::path::Path) {
    #[cfg(unix)]
    {
        if let Ok(d) = tokio::fs::File::open(dir).await { let _ = d.sync_all().await; }
    }
    #[cfg(not(unix))]
    { let _ = dir; }
}

/// Best-effort chmod 0700 on a cert directory (audit #142) so other local users on the
/// world-traversable data dir cannot list or traverse stored cert material. No-op on
/// non-unix targets.
async fn set_dir_mode(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await;
    }
    #[cfg(not(unix))]
    { let _ = path; }
}

/// Current UTC civil date as (year, month, day), from the system clock via `chrono`
/// (already a project dependency) — used to build the cert validity window from "now"
/// rather than a hardcoded date (audit #142).
fn current_ymd() -> (i32, u8, u8) {
    use chrono::Datelike;
    let now = chrono::Utc::now();
    (now.year(), now.month() as u8, now.day() as u8)
}

/// Compute SHA-256 fingerprint of a DER-encoded certificate.
/// Returns colon-separated uppercase hex, e.g. "AA:BB:CC:..."
pub fn compute_fingerprint(der: &[u8]) -> Result<String> {
    let digest = Sha256::digest(der);
    let hex_parts: Vec<String> = digest.iter().map(|b| format!("{:02X}", b)).collect();
    Ok(hex_parts.join(":"))
}

/// Parse a PEM certificate and return the DER bytes.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let lines: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let der = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        lines.trim(),
    )?;
    Ok(der)
}

/// Build a native_tls::Identity from PEM cert + PEM private key.
/// Uses openssl to create an in-memory PKCS#12 bundle.
///
/// The PKCS#12 round-trip uses an ephemeral random passphrase (audit #49) rather than
/// an empty one, so the private key is never wrapped unencrypted in the DER blob that
/// briefly lives in memory. The same random pass is used for both build and parse, then
/// the DER buffer is zeroized once the Identity has been constructed.
fn build_identity(cert_pem: &str, key_pem: &str) -> Result<native_tls::Identity> {
    use openssl::{pkcs12::Pkcs12, pkey::PKey, rand::rand_bytes, x509::X509};

    // 32 random bytes -> hex passphrase, used only for this in-memory round-trip.
    let mut raw = [0u8; 32];
    rand_bytes(&mut raw).map_err(|e| anyhow::anyhow!("RNG failure: {}", e))?;
    let mut pass: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
    raw.zeroize();

    let cert  = X509::from_pem(cert_pem.as_bytes())?;
    let pkey  = PKey::private_key_from_pem(key_pem.as_bytes())?;
    let p12   = Pkcs12::builder()
        .name("cryptirc-client")
        .pkey(&pkey)
        .cert(&cert)
        .build2(&pass)?;
    let mut der = p12.to_der()?;
    let ident = native_tls::Identity::from_pkcs12(&der, &pass)
        .map_err(|e| anyhow::anyhow!("Identity build failed: {}", e))?;
    // Scrub the encrypted DER and the ephemeral passphrase from memory.
    der.zeroize();
    pass.zeroize();
    Ok(ident)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_format() {
        let fake_der = vec![0xde, 0xad, 0xbe, 0xef];
        let fp = compute_fingerprint(&fake_der).unwrap();
        // Should be 95 chars: 32 * 2 hex + 31 colons
        assert_eq!(fp.len(), 95);
        assert!(fp.contains(':'));
    }

    async fn store(tag: &str) -> (CertStore, String) {
        let dir = std::env::temp_dir().join(format!("cryptirc-certs-{}-{}", tag, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.to_string_lossy().to_string();
        let crypto = Arc::new(CryptoManager::new(&dir).unwrap());
        crypto.unlock("alice", "vault pass for alice").await.unwrap();
        (CertStore::new(&dir, crypto), dir)
    }

    /// The stored cert.pem and key.enc belong together (load_identity builds a PKCS#12,
    /// which openssl refuses for a key that doesn't match the certificate).
    async fn pair_ok(cs: &CertStore, id: &str) -> bool {
        cs.load_identity("alice", id).await.is_ok()
    }

    const ID: &str = "11111111-2222-3333-4444-555555555555";

    /// The fingerprint generate() reports is the stored certificate's (load_info's).
    #[tokio::test]
    async fn generate_reports_the_stored_certificates_fingerprint() {
        let (cs, dir) = store("fp").await;
        for _ in 0..3 {
            let info = cs.generate("alice", ID, "alice").await.unwrap();
            assert_eq!(info.fingerprint, cs.load_info(ID).await.unwrap().fingerprint);
            assert_eq!(info.cert_pem, cs.load_info(ID).await.unwrap().cert_pem);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// r3 C1-10: a regenerate that cannot encrypt the new key (vault locked meanwhile)
    /// must leave the previous cert + key pair untouched. 0d3570d overwrote cert.pem
    /// first, so this left the NEW cert beside the OLD key.
    #[tokio::test]
    async fn failed_regenerate_keeps_the_old_pair() {
        let (cs, dir) = store("lockrace").await;
        cs.generate("alice", ID, "alice").await.unwrap();
        let before = cs.load_info(ID).await.unwrap().fingerprint;
        assert!(pair_ok(&cs, ID).await);
        cs.crypto.lock("alice").await;
        assert!(cs.generate("alice", ID, "alice").await.is_err());
        cs.crypto.unlock("alice", "vault pass for alice").await.unwrap();
        assert!(pair_ok(&cs, ID).await, "cert and key still match");
        assert_eq!(cs.load_info(ID).await.unwrap().fingerprint, before, "cert.pem unchanged");
        // no temp files left behind
        let left: Vec<_> = std::fs::read_dir(cs.cert_dir(ID)).unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
        assert!(left.iter().all(|n| n == "cert.pem" || n == "key.enc"), "{:?}", left);
        assert!(gen_leftovers(&cs, ID).is_empty(), "no staging dir left");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// r3 C1-10: concurrent regenerations (and a delete) never leave a mismatched pair.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_regenerations_keep_a_matching_pair() {
        let (cs, dir) = store("concurrent").await;
        let cs = Arc::new(cs);
        for round in 0..3 {
            let mut hs = Vec::new();
            for _ in 0..8 {
                let c = cs.clone();
                hs.push(tokio::spawn(async move { c.generate("alice", ID, "alice").await.map(|i| i.fingerprint) }));
            }
            let mut fps = Vec::new();
            for h in hs { fps.push(h.await.unwrap().unwrap()); }
            assert!(pair_ok(&cs, ID).await, "round {round}: cert and key match");
            let stored = cs.load_info(ID).await.unwrap().fingerprint;
            assert!(fps.contains(&stored), "round {round}: stored cert is one of the generated ones");
        }
        let (c1, c2) = (cs.clone(), cs.clone());
        let g = tokio::spawn(async move { c1.generate("alice", ID, "alice").await.is_ok() });
        let d = tokio::spawn(async move { c2.delete(ID).await.is_ok() });
        let (_g, _d) = (g.await.unwrap(), d.await.unwrap());
        if cs.exists(ID).await { assert!(pair_ok(&cs, ID).await, "after generate+delete race: pair intact"); }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// r3 C1-10 stress: many simultaneous regenerations of one cert dir, pair checked after
    /// every round (0d3570d: the unlocked cert.pem/key.enc writes of different calls interleave).
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn regeneration_stress_never_mismatches() {
        let (cs, dir) = store("stress").await;
        let cs = Arc::new(cs);
        let mut bad = 0;
        for _ in 0..15 {
            let hs: Vec<_> = (0..32).map(|_| { let c = cs.clone(); tokio::spawn(async move { let _ = c.generate("alice", ID, "alice").await; }) }).collect();
            for h in hs { h.await.unwrap(); }
            if !pair_ok(&cs, ID).await { bad += 1; }
        }
        assert_eq!(bad, 0, "rounds that ended with a cert/key mismatch");
        let _ = std::fs::remove_dir_all(dir);
    }

    fn gen_leftovers(cs: &CertStore, id: &str) -> Vec<String> {
        let dir = cs.cert_dir(id);
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        std::fs::read_dir(dir.parent().unwrap()).unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(&format!("{name}.gen-"))).collect()
    }

    /// r4 F1-3 / V3S-3: regenerate installs the pair by one directory exchange: the live
    /// dir holds exactly the new pair, no staging dir is left, and a staging dir a crash
    /// left behind is cleaned up by the next generate / delete.
    #[tokio::test]
    async fn regenerate_swaps_the_whole_pair_and_cleans_up() {
        let (cs, dir) = store("swap").await;
        let first = cs.generate("alice", ID, "alice").await.unwrap();
        let second = cs.generate("alice", ID, "alice").await.unwrap();
        assert_ne!(first.fingerprint, second.fingerprint);
        assert_eq!(cs.load_info(ID).await.unwrap().fingerprint, second.fingerprint);
        assert!(pair_ok(&cs, ID).await);
        assert!(gen_leftovers(&cs, ID).is_empty());
        let names: Vec<_> = std::fs::read_dir(cs.cert_dir(ID)).unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
        let mut names = names; names.sort();
        assert_eq!(names, vec!["cert.pem", "key.enc"]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(cs.cert_dir(ID)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "live dir stays owner-only after the exchange");
        }
        // A crash leftover (staging dir with a stale pair) is removed by the next generate.
        let stale = gen_dir_for(&cs.cert_dir(ID), "deadbeef");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("key.enc"), "stale").unwrap();
        cs.generate("alice", ID, "alice").await.unwrap();
        assert!(gen_leftovers(&cs, ID).is_empty() && pair_ok(&cs, ID).await);
        std::fs::create_dir_all(&stale).unwrap();
        cs.delete(ID).await.unwrap();
        assert!(gen_leftovers(&cs, ID).is_empty() && !cs.exists(ID).await);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// r4 F1-3: where the directory exchange is unavailable, the fallback's failed second
    /// rename restores the old key — the old pair stays intact (r3 left new key + old cert).
    #[tokio::test]
    async fn fallback_install_rolls_back_a_failed_second_rename() {
        let (cs, dir) = store("fallback").await;
        let old = cs.generate("alice", ID, "alice").await.unwrap();
        TEST_HOOKS.with(|c| c.set((true, false)));
        let newer = cs.generate("alice", ID, "alice").await.unwrap();
        assert_eq!(cs.load_info(ID).await.unwrap().fingerprint, newer.fingerprint, "fallback installs");
        assert!(pair_ok(&cs, ID).await);
        assert_ne!(old.fingerprint, newer.fingerprint);
        TEST_HOOKS.with(|c| c.set((true, true)));
        assert!(cs.generate("alice", ID, "alice").await.is_err());
        TEST_HOOKS.with(|c| c.set((false, false)));
        assert!(pair_ok(&cs, ID).await, "old key restored beside the old cert");
        assert_eq!(cs.load_info(ID).await.unwrap().fingerprint, newer.fingerprint);
        assert!(gen_leftovers(&cs, ID).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The dial path (ipc_client::build_dial_params): read_pair, decrypt the key, and build
    /// the identity the daemon will present (openssl refuses a key that isn't the cert's).
    async fn via_dial_path(c: &CertStore) -> Result<()> {
        let (cert_bytes, key_enc) = c.read_pair(ID).await?;
        let key = c.crypto.decrypt("alice", key_enc.trim()).await?;
        let mut key_pem = String::from_utf8(key)?;
        let r = build_identity(&String::from_utf8_lossy(&cert_bytes), &key_pem).map(|_| ());
        key_pem.zeroize();
        r
    }

    /// GetCertInfo / State: the fingerprint shown is that of the certificate returned.
    async fn via_info(c: &CertStore) -> Result<()> {
        let info = c.load_info(ID).await?;
        if compute_fingerprint(&pem_to_der(&info.cert_pem)?)? != info.fingerprint { bail!("fingerprint mismatch"); }
        Ok(())
    }

    /// r4 F1-3 / V3S-3 (shape of verifier w3-srv's phase-2 race test): 3 concurrent readers
    /// go through EVERY reader path while 400 regenerations run, and must never see a
    /// mismatched or missing pair:
    ///  - load_identity (cert + decrypted key → PKCS#12, openssl refuses a mismatch);
    ///  - read_pair + decrypt + build_identity — exactly what ipc_client::build_dial_params
    ///    hands the daemon for SASL EXTERNAL / client-cert TLS;
    ///  - load_info (GetCertInfo / the State fingerprint): its fingerprint is that of the
    ///    certificate it returns.
    /// 3b92eaf (readers outside the dir lock, two renames): 75 of 124 reads failed in the r4 red run.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn readers_never_see_a_mixed_pair() {
        let (cs, dir) = store("readers").await;
        let cs = Arc::new(cs);
        cs.generate("alice", ID, "alice").await.unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut readers = Vec::new();
        for _ in 0..3 {
            let (c, st) = (cs.clone(), stop.clone());
            readers.push(tokio::spawn(async move {
                let (mut ok, mut bad) = (0u32, Vec::<String>::new());
                let mut path = 0usize;
                while !st.load(std::sync::atomic::Ordering::Relaxed) {
                    path = (path + 1) % 3;
                    let r: Result<()> = match path {
                        0 => c.load_identity("alice", ID).await.map(|_| ()),
                        1 => via_dial_path(&c).await,
                        _ => via_info(&c).await,
                    };
                    match r { Ok(()) => ok += 1, Err(e) => bad.push(format!("path {path}: {e}")) }
                }
                (ok, bad)
            }));
        }
        for _ in 0..400 { cs.generate("alice", ID, "alice").await.unwrap(); }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let (mut ok, mut bad) = (0u32, Vec::new());
        for r in readers { let (o, b) = r.await.unwrap(); ok += o; bad.extend(b); }
        println!("readers_never_see_a_mixed_pair: {} reads during 400 regenerations, {} failed", ok as usize + bad.len(), bad.len());
        assert!(ok > 0);
        assert!(bad.is_empty(), "{} of {} reads got a mismatched / missing pair: {:?}", bad.len(), ok as usize + bad.len(), &bad[..bad.len().min(5)]);
        assert!(pair_ok(&cs, ID).await);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_pem_to_der_roundtrip() {
        // Quick smoke test that base64 decode works
        let sample = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
        let der = pem_to_der(sample).unwrap();
        assert_eq!(der, b"abc");
    }
}
