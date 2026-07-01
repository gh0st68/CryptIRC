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
}

impl CertStore {
    pub fn new(data_dir: &str, crypto: Arc<CryptoManager>) -> Self {
        Self { data_dir: data_dir.to_string(), crypto }
    }

    /// Generate a new self-signed ECDSA P-256 certificate for a network connection.
    /// The cert is valid for 10 years and uses the nick as the Common Name.
    /// Returns CertInfo — call `load_identity` later to get the native_tls::Identity.
    pub async fn generate(&self, username: &str, cert_id: &str, nick: &str) -> Result<CertInfo> {
        if !self.crypto.is_unlocked(username).await {
            bail!("Vault must be unlocked to generate certificates");
        }

        let dir = self.cert_dir(cert_id);
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

        // Write public cert plaintext (0600 anyway — only the service reads it; #7)
        let cert_path = dir.join("cert.pem");
        tokio::fs::write(&cert_path, cert_pem.as_bytes()).await?;
        set_secret_mode(&cert_path).await;

        // Encrypt and write private key. key.enc is the vault-encrypted client
        // TLS key — restrict to owner-only so the world-traversable data dir
        // cannot leak it to other local users (audit #7).
        let key_enc  = self.crypto.encrypt(username, key_pem.as_bytes()).await?;
        let key_path = dir.join("key.enc");
        tokio::fs::write(&key_path, key_enc).await?;
        set_secret_mode(&key_path).await;
        // Scrub the plaintext private-key PEM from memory once encrypted (audit #142).
        key_pem.zeroize();

        let fingerprint = compute_fingerprint(&cert.serialize_der()?)?;

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

    /// Load a native_tls::Identity (cert + decrypted private key) for TLS handshake.
    pub async fn load_identity(&self, username: &str, cert_id: &str) -> Result<native_tls::Identity> {
        if !self.crypto.is_unlocked(username).await {
            bail!("Vault must be unlocked to use client certificates");
        }
        let dir      = self.cert_dir(cert_id);
        let cert_pem = tokio::fs::read_to_string(dir.join("cert.pem")).await
            .map_err(|_| anyhow::anyhow!("Certificate not found"))?;
        let key_enc  = tokio::fs::read_to_string(dir.join("key.enc")).await
            .map_err(|_| anyhow::anyhow!("Encrypted key not found"))?;
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
        // Use the async non-blocking existence check (audit #142).
        if tokio::fs::try_exists(&dir).await.unwrap_or(false) {
            tokio::fs::remove_dir_all(&dir).await?;
        }
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

    /// Public, sanitized cert-directory resolver (audit #48). Callers outside this module
    /// (e.g. irc.rs building a cert path) MUST route through this instead of joining
    /// `cert_id` onto a base path themselves, so the same traversal sanitization always
    /// applies.
    pub fn cert_path_for(&self, cert_id: &str) -> PathBuf {
        self.cert_dir(cert_id)
    }
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

    #[test]
    fn test_pem_to_der_roundtrip() {
        // Quick smoke test that base64 decode works
        let sample = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
        let der = pem_to_der(sample).unwrap();
        assert_eq!(der, b"abc");
    }
}
