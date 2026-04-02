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

        // Build certificate parameters
        let mut params = CertificateParams::default();
        params.alg = &PKCS_ECDSA_P256_SHA256;
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after  = rcgen::date_time_ymd(2034, 1, 1);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, nick);
        dn.push(DnType::OrganizationName, "CryptIRC");
        params.distinguished_name = dn;

        let cert = Certificate::from_params(params)?;

        let cert_pem = cert.serialize_pem()?;
        let key_pem  = cert.get_key_pair().serialize_pem();

        // Write public cert plaintext
        let cert_path = dir.join("cert.pem");
        tokio::fs::write(&cert_path, cert_pem.as_bytes()).await?;

        // Encrypt and write private key
        let key_enc  = self.crypto.encrypt(username, key_pem.as_bytes()).await?;
        let key_path = dir.join("key.enc");
        tokio::fs::write(&key_path, key_enc).await?;

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
        let key_pem = String::from_utf8(key_pem_bytes)?;

        // native-tls needs PKCS#12; we build it via openssl
        let identity = build_identity(&cert_pem, &key_pem)?;
        Ok(identity)
    }

    /// Delete a stored certificate.
    pub async fn delete(&self, cert_id: &str) -> Result<()> {
        let dir = self.cert_dir(cert_id);
        if dir.exists() {
            tokio::fs::remove_dir_all(&dir).await?;
        }
        Ok(())
    }

    /// Check whether a cert exists for a given id.
    pub async fn exists(&self, cert_id: &str) -> bool {
        self.cert_dir(cert_id).join("cert.pem").exists()
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

    fn cert_dir(&self, cert_id: &str) -> PathBuf {
        // Sanitize cert_id — only alphanumeric + dash/underscore
        let safe: String = cert_id.chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .take(64)
            .collect();
        PathBuf::from(&self.data_dir).join("certs").join(safe)
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

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
/// Uses openssl to create a PKCS#12 bundle.
fn build_identity(cert_pem: &str, key_pem: &str) -> Result<native_tls::Identity> {
    use openssl::{pkcs12::Pkcs12, pkey::PKey, x509::X509};

    let cert  = X509::from_pem(cert_pem.as_bytes())?;
    let pkey  = PKey::private_key_from_pem(key_pem.as_bytes())?;
    let p12   = Pkcs12::builder()
        .name("cryptirc-client")
        .pkey(&pkey)
        .cert(&cert)
        .build2("")?;
    let der   = p12.to_der()?;
    let ident = native_tls::Identity::from_pkcs12(&der, "")
        .map_err(|e| anyhow::anyhow!("Identity build failed: {}", e))?;
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
