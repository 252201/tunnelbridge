use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tunnelbridge_protocol::TransportMode;
use url::Url;
use uuid::Uuid;

const KEYCHAIN_SERVICE: &str = "dev.tunnelbridge.desktop";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server_url: String,
    pub device_name: String,
    pub installation_id: Uuid,
    #[serde(default)]
    pub transport_mode: TransportMode,
    #[serde(default = "default_quic_port")]
    pub quic_port: u16,
    #[serde(default = "default_kcp_port")]
    pub kcp_port: u16,
}

fn default_quic_port() -> u16 {
    443
}

fn default_kcp_port() -> u16 {
    4000
}

pub fn normalize_server_url(value: &str) -> Result<String> {
    let mut url = Url::parse(value.trim()).context("服务器地址格式无效")?;
    if url.scheme() != "https"
        && !(url.scheme() == "http" && url.host_str().is_some_and(is_loopback_host))
    {
        bail!("服务器必须使用 HTTPS；仅本机开发地址允许 HTTP");
    }
    if url.host_str().is_none() {
        bail!("服务器地址缺少主机名");
    }
    url.set_path("");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

pub fn load_config(path: &Path) -> Result<Option<AgentConfig>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).context("读取客户端配置")?;
    Ok(Some(
        serde_json::from_slice(&bytes).context("解析客户端配置")?,
    ))
}

pub fn save_config(path: &Path, config: &AgentConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(config)?)?;
    fs::rename(temporary, path)?;
    Ok(())
}

pub fn save_token(installation_id: Uuid, token: &str) -> Result<()> {
    keyring::Entry::new(KEYCHAIN_SERVICE, &installation_id.to_string())?
        .set_password(token)
        .context("将设备令牌写入 macOS 钥匙串")
}

pub fn load_token(installation_id: Uuid) -> Result<String> {
    keyring::Entry::new(KEYCHAIN_SERVICE, &installation_id.to_string())?
        .get_password()
        .context("从 macOS 钥匙串读取设备令牌")
}

pub fn save_transport_fingerprint(installation_id: Uuid, fingerprint: &str) -> Result<()> {
    keyring::Entry::new(
        KEYCHAIN_SERVICE,
        &format!("{installation_id}:transport-fingerprint"),
    )?
    .set_password(fingerprint)
    .context("将传输证书指纹写入 macOS 钥匙串")
}

pub fn load_transport_fingerprint(installation_id: Uuid) -> Result<String> {
    keyring::Entry::new(
        KEYCHAIN_SERVICE,
        &format!("{installation_id}:transport-fingerprint"),
    )?
    .get_password()
    .context("从 macOS 钥匙串读取传输证书指纹")
}

pub fn save_transport_certificate(installation_id: Uuid, certificate_der: &str) -> Result<()> {
    keyring::Entry::new(
        KEYCHAIN_SERVICE,
        &format!("{installation_id}:transport-certificate"),
    )?
    .set_password(certificate_der)
    .context("将传输证书写入 macOS 钥匙串")
}

pub fn load_transport_certificate(installation_id: Uuid) -> Result<String> {
    keyring::Entry::new(
        KEYCHAIN_SERVICE,
        &format!("{installation_id}:transport-certificate"),
    )?
    .get_password()
    .context("从 macOS 钥匙串读取传输证书")
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_https_except_for_local_development() {
        assert!(normalize_server_url("https://relay.example.com/path").is_ok());
        assert!(normalize_server_url("http://127.0.0.1:8080").is_ok());
        assert!(normalize_server_url("http://relay.example.com").is_err());
    }

    #[test]
    fn old_configs_receive_v2_transport_ports() {
        let config: AgentConfig = serde_json::from_str(
            r#"{"server_url":"https://relay.example.com","device_name":"Mac","installation_id":"00000000-0000-0000-0000-000000000001"}"#,
        )
        .unwrap();
        assert_eq!(config.quic_port, 443);
        assert_eq!(config.kcp_port, 4000);
    }
}
