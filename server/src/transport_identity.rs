use std::{fs, io::BufReader, path::Path, sync::OnceLock};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

use crate::{config::Config, state::SharedState};

static IDENTITY: OnceLock<TransportIdentity> = OnceLock::new();

pub struct TransportIdentity {
    pub certificate: CertificateDer<'static>,
    pub private_key_pem: Vec<u8>,
    pub fingerprint: String,
}

pub fn initialize(config: &Config) -> Result<()> {
    if IDENTITY.get().is_some() {
        return Ok(());
    }
    let identity = load_or_create(&config.transport_cert_dir)?;
    IDENTITY
        .set(identity)
        .map_err(|_| anyhow::anyhow!("transport identity already initialized"))
}

pub fn fingerprint(_state: &SharedState) -> &'static str {
    IDENTITY
        .get()
        .map_or("uninitialized", |identity| identity.fingerprint.as_str())
}

pub fn certificate_base64() -> Result<String> {
    Ok(STANDARD.encode(certificate()?.as_ref()))
}

pub fn certificate() -> Result<CertificateDer<'static>> {
    Ok(IDENTITY
        .get()
        .context("transport identity is not initialized")?
        .certificate
        .clone())
}

pub fn private_key() -> Result<PrivateKeyDer<'static>> {
    let identity = IDENTITY
        .get()
        .context("transport identity is not initialized")?;
    let mut reader = BufReader::new(identity.private_key_pem.as_slice());
    rustls_pemfile::private_key(&mut reader)?.context("transport private key PEM is empty")
}

fn load_or_create(directory: &Path) -> Result<TransportIdentity> {
    fs::create_dir_all(directory).context("create transport identity directory")?;
    let certificate_path = directory.join("certificate.pem");
    let key_path = directory.join("private-key.pem");
    if !certificate_path.exists() || !key_path.exists() {
        let generated = rcgen::generate_simple_self_signed(vec!["tunnelbridge-transport".into()])?;
        fs::write(&certificate_path, generated.cert.pem())?;
        fs::write(&key_path, generated.signing_key.serialize_pem())?;
        set_private_permissions(directory, &key_path)?;
    }
    let certificate_pem = fs::read(&certificate_path)?;
    let private_key_pem = fs::read(&key_path)?;
    let mut reader = BufReader::new(certificate_pem.as_slice());
    let certificate = rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()?
        .context("transport certificate PEM is empty")?;
    let fingerprint = hex::encode(Sha256::digest(certificate.as_ref()));
    Ok(TransportIdentity {
        certificate,
        private_key_pem,
        fingerprint,
    })
}

#[cfg(unix)]
fn set_private_permissions(directory: &Path, key: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(key, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_directory: &Path, _key: &Path) -> Result<()> {
    Ok(())
}
