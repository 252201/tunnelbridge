use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub database_url: String,
    pub admin_dist: PathBuf,
    pub admin_password: Option<String>,
    pub port_start: u16,
    pub port_end: u16,
    pub ticket_ttl: Duration,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub session_ttl: Duration,
    pub audit_retention_days: i64,
    pub secure_cookies: bool,
    pub geoip_url: String,
    pub web_base_domain: String,
    pub quic_port: u16,
    pub quic_listen_port: u16,
    pub kcp_port: u16,
    pub udp_session_timeout: Duration,
    pub transport_cert_dir: PathBuf,
    pub trusted_proxy_cidrs: Vec<IpNet>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let listen_addr = env::var("TB_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8080".into())
            .parse()
            .context("TB_LISTEN_ADDR must be a socket address")?;
        let port_start = parse_env("TB_PORT_START", 20_000)?;
        let port_end = parse_env("TB_PORT_END", 20_100)?;
        if port_start == 0 || port_start > port_end {
            bail!("invalid public port range {port_start}..={port_end}");
        }

        Ok(Self {
            listen_addr,
            database_url: env::var("TB_DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://data/tunnelbridge.db?mode=rwc".into()),
            admin_dist: env::var("TB_ADMIN_DIST")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("web/admin/dist")),
            admin_password: env::var("TB_ADMIN_PASSWORD").ok(),
            port_start,
            port_end,
            ticket_ttl: Duration::from_secs(parse_env("TB_TICKET_TTL_SECONDS", 15)?),
            connect_timeout: Duration::from_secs(parse_env("TB_CONNECT_TIMEOUT_SECONDS", 15)?),
            idle_timeout: Duration::from_secs(parse_env("TB_IDLE_TIMEOUT_SECONDS", 600)?),
            session_ttl: Duration::from_secs(parse_env("TB_SESSION_TTL_SECONDS", 43_200)?),
            audit_retention_days: parse_env("TB_AUDIT_RETENTION_DAYS", 30)?,
            secure_cookies: env::var("TB_SECURE_COOKIES").map_or(true, |v| v != "false"),
            geoip_url: env::var("TB_GEOIP_URL").unwrap_or_else(|_| "https://ipwho.is/{ip}".into()),
            web_base_domain: env::var("TB_WEB_BASE_DOMAIN")
                .unwrap_or_else(|_| "tunnelbridge.252202.xyz".into())
                .trim_matches('.')
                .to_ascii_lowercase(),
            quic_port: parse_env("TB_QUIC_PORT", 443)?,
            quic_listen_port: parse_env("TB_QUIC_LISTEN_PORT", 7443)?,
            kcp_port: parse_env("TB_KCP_PORT", 4000)?,
            udp_session_timeout: Duration::from_secs(parse_env(
                "TB_UDP_SESSION_TIMEOUT_SECONDS",
                60,
            )?),
            transport_cert_dir: env::var("TB_TRANSPORT_CERT_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("data/transport")),
            trusted_proxy_cidrs: env::var("TB_TRUSTED_PROXY_CIDRS")
                .unwrap_or_else(|_| "172.16.0.0/12".into())
                .split(',')
                .map(|value| {
                    value
                        .trim()
                        .parse()
                        .context("invalid TB_TRUSTED_PROXY_CIDRS")
                })
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

fn parse_env<T>(key: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    match env::var(key) {
        Ok(value) => value.parse().with_context(|| format!("invalid {key}")),
        Err(_) => Ok(default),
    }
}
