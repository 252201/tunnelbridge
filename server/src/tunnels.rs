use std::{net::IpAddr, str::FromStr};

use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool, sqlite::SqliteRow};
use tunnelbridge_protocol::{
    AccessMode, CreateTunnelRequest, LocalScheme, Tunnel, TunnelKind, TunnelStatus,
    UpdateTunnelRequest,
};
use uuid::Uuid;

use crate::{error::AppError, state::SharedState};

pub async fn list_for_agent(pool: &SqlitePool, agent_id: Uuid) -> Result<Vec<Tunnel>, AppError> {
    let rows = sqlx::query("SELECT * FROM tunnels WHERE agent_id = ? ORDER BY created_at")
        .bind(agent_id.to_string())
        .fetch_all(pool)
        .await?;
    rows.into_iter().map(row_to_tunnel).collect()
}

pub async fn list_all(pool: &SqlitePool) -> Result<Vec<Tunnel>, AppError> {
    let rows = sqlx::query("SELECT * FROM tunnels ORDER BY created_at")
        .fetch_all(pool)
        .await?;
    rows.into_iter().map(row_to_tunnel).collect()
}

pub async fn get(pool: &SqlitePool, id: Uuid) -> Result<Tunnel, AppError> {
    let row = sqlx::query("SELECT * FROM tunnels WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?
        .ok_or(AppError::NotFound)?;
    row_to_tunnel(row)
}

pub async fn get_by_hostname(pool: &SqlitePool, hostname: &str) -> Result<Tunnel, AppError> {
    let row = sqlx::query(
        "SELECT * FROM tunnels WHERE kind = 'web' AND enabled = 1 AND lower(hostname) = lower(?)",
    )
    .bind(hostname.trim_end_matches('.'))
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)?;
    row_to_tunnel(row)
}

pub async fn hostname_is_enabled(pool: &SqlitePool, hostname: &str) -> Result<bool, AppError> {
    let count: i64 = sqlx::query(
        "SELECT COUNT(*) AS count FROM tunnels WHERE kind = 'web' AND enabled = 1 AND lower(hostname) = lower(?)",
    )
    .bind(hostname.trim_end_matches('.'))
    .fetch_one(pool)
    .await?
    .get("count");
    Ok(count == 1)
}

pub async fn create(
    state: &SharedState,
    agent_id: Uuid,
    request: CreateTunnelRequest,
) -> Result<Tunnel, AppError> {
    validate_create(state, &request)?;
    let remote_port = match request.kind {
        TunnelKind::Tcp | TunnelKind::Udp => Some(match request.remote_port {
            Some(port) => {
                validate_remote_port(state, port)?;
                port
            }
            None => allocate_port(state, request.kind).await?,
        }),
        TunnelKind::Web => None,
    };
    let hostname = match request.kind {
        TunnelKind::Web => Some(normalize_hostname(
            state,
            request.hostname.as_deref().unwrap_or(request.name.as_str()),
        )?),
        _ => None,
    };
    let now = Utc::now();
    let tunnel = Tunnel {
        id: Uuid::new_v4(),
        agent_id,
        name: request.name.trim().to_owned(),
        local_host: request.local_host.trim().to_owned(),
        local_port: request.local_port,
        kind: request.kind,
        local_scheme: request.local_scheme,
        remote_port,
        hostname,
        access_mode: request.access_mode,
        allowed_cidrs: request.allowed_cidrs,
        enabled: request.enabled,
        status: TunnelStatus::Stopped,
        created_at: now,
        updated_at: now,
    };
    let cidrs =
        serde_json::to_string(&tunnel.allowed_cidrs).map_err(|e| AppError::Internal(e.into()))?;
    let result = sqlx::query(
        r#"INSERT INTO tunnels
        (id, agent_id, name, local_host, local_port, kind, local_scheme, remote_port, hostname,
         access_mode, allowed_cidrs, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(tunnel.id.to_string())
    .bind(agent_id.to_string())
    .bind(&tunnel.name)
    .bind(&tunnel.local_host)
    .bind(i64::from(tunnel.local_port))
    .bind(kind_str(tunnel.kind))
    .bind(scheme_str(tunnel.local_scheme))
    .bind(tunnel.remote_port.map(i64::from))
    .bind(&tunnel.hostname)
    .bind(access_mode_str(tunnel.access_mode))
    .bind(cidrs)
    .bind(tunnel.enabled)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => Ok(tunnel),
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => Err(
            AppError::Conflict("public endpoint is already allocated".into()),
        ),
        Err(error) => Err(error.into()),
    }
}

pub async fn update(
    state: &SharedState,
    id: Uuid,
    owner: Option<Uuid>,
    request: UpdateTunnelRequest,
) -> Result<Tunnel, AppError> {
    let mut tunnel = get(&state.db, id).await?;
    if owner.is_some_and(|owner| owner != tunnel.agent_id) {
        return Err(AppError::NotFound);
    }
    if let Some(name) = request.name {
        tunnel.name = name.trim().to_owned();
    }
    if let Some(host) = request.local_host {
        validate_local_host(&host, request.allow_lan_target)?;
        tunnel.local_host = host.trim().to_owned();
    }
    if let Some(port) = request.local_port {
        if port == 0 {
            return Err(AppError::BadRequest("local port cannot be zero".into()));
        }
        tunnel.local_port = port;
    }
    if let Some(port) = request.remote_port {
        if tunnel.kind == TunnelKind::Web {
            return Err(AppError::BadRequest(
                "web tunnels do not use a remote port".into(),
            ));
        }
        validate_remote_port(state, port)?;
        tunnel.remote_port = Some(port);
    }
    if let Some(kind) = request.kind
        && kind != tunnel.kind
    {
        return Err(AppError::BadRequest(
            "tunnel kind cannot be changed after creation".into(),
        ));
    }
    if let Some(scheme) = request.local_scheme {
        tunnel.local_scheme = scheme;
    }
    if let Some(hostname) = request.hostname {
        if tunnel.kind != TunnelKind::Web {
            return Err(AppError::BadRequest(
                "only web tunnels have hostnames".into(),
            ));
        }
        tunnel.hostname = Some(normalize_hostname(state, &hostname)?);
    }
    if let Some(mode) = request.access_mode {
        tunnel.access_mode = mode;
    }
    if let Some(cidrs) = request.allowed_cidrs {
        tunnel.allowed_cidrs = cidrs;
    }
    if let Some(enabled) = request.enabled {
        tunnel.enabled = enabled;
    }
    validate_tunnel(&tunnel)?;
    tunnel.updated_at = Utc::now();
    let cidrs =
        serde_json::to_string(&tunnel.allowed_cidrs).map_err(|e| AppError::Internal(e.into()))?;
    let result = sqlx::query(
        r#"UPDATE tunnels SET name = ?, local_host = ?, local_port = ?, local_scheme = ?,
        remote_port = ?, hostname = ?, access_mode = ?, allowed_cidrs = ?, enabled = ?,
        updated_at = ? WHERE id = ?"#,
    )
    .bind(&tunnel.name)
    .bind(&tunnel.local_host)
    .bind(i64::from(tunnel.local_port))
    .bind(scheme_str(tunnel.local_scheme))
    .bind(tunnel.remote_port.map(i64::from))
    .bind(&tunnel.hostname)
    .bind(access_mode_str(tunnel.access_mode))
    .bind(cidrs)
    .bind(tunnel.enabled)
    .bind(tunnel.updated_at.to_rfc3339())
    .bind(tunnel.id.to_string())
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => Ok(tunnel),
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => Err(
            AppError::Conflict("remote port is already allocated".into()),
        ),
        Err(error) => Err(error.into()),
    }
}

pub async fn delete(state: &SharedState, id: Uuid, owner: Option<Uuid>) -> Result<(), AppError> {
    let tunnel = get(&state.db, id).await?;
    if owner.is_some_and(|owner| owner != tunnel.agent_id) {
        return Err(AppError::NotFound);
    }
    sqlx::query("DELETE FROM tunnels WHERE id = ?")
        .bind(id.to_string())
        .execute(&state.db)
        .await?;
    Ok(())
}

pub fn source_allowed(tunnel: &Tunnel, address: IpAddr) -> bool {
    let address = match address {
        IpAddr::V6(value) => value
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(value)),
        value => value,
    };
    match tunnel.access_mode {
        AccessMode::Public => true,
        AccessMode::Allowlist => tunnel
            .allowed_cidrs
            .iter()
            .any(|network| network.contains(&address)),
    }
}

async fn allocate_port(state: &SharedState, kind: TunnelKind) -> Result<u16, AppError> {
    let rows =
        sqlx::query("SELECT remote_port FROM tunnels WHERE kind = ? AND remote_port IS NOT NULL")
            .bind(kind_str(kind))
            .fetch_all(&state.db)
            .await?;
    let used = rows
        .into_iter()
        .map(|row| row.get::<i64, _>("remote_port") as u16)
        .collect::<std::collections::HashSet<_>>();
    (state.config.port_start..=state.config.port_end)
        .find(|port| !used.contains(port))
        .ok_or_else(|| AppError::Conflict("public port pool is exhausted".into()))
}

fn validate_create(state: &SharedState, request: &CreateTunnelRequest) -> Result<(), AppError> {
    if request.name.trim().is_empty() || request.name.chars().count() > 80 {
        return Err(AppError::BadRequest(
            "name must contain 1 to 80 characters".into(),
        ));
    }
    if request.local_port == 0 {
        return Err(AppError::BadRequest("local port cannot be zero".into()));
    }
    validate_local_host(&request.local_host, request.allow_lan_target)?;
    if let Some(port) = request.remote_port {
        validate_remote_port(state, port)?;
    }
    validate_kind_scheme(request.kind, request.local_scheme)?;
    if request.kind == TunnelKind::Web {
        normalize_hostname(
            state,
            request.hostname.as_deref().unwrap_or(request.name.as_str()),
        )?;
    } else if request.hostname.is_some() {
        return Err(AppError::BadRequest(
            "only web tunnels may specify a hostname".into(),
        ));
    }
    if request.access_mode == AccessMode::Allowlist && request.allowed_cidrs.is_empty() {
        return Err(AppError::BadRequest(
            "allowlist mode requires at least one CIDR".into(),
        ));
    }
    Ok(())
}

fn validate_tunnel(tunnel: &Tunnel) -> Result<(), AppError> {
    if tunnel.name.is_empty() || tunnel.name.chars().count() > 80 {
        return Err(AppError::BadRequest(
            "name must contain 1 to 80 characters".into(),
        ));
    }
    if tunnel.access_mode == AccessMode::Allowlist && tunnel.allowed_cidrs.is_empty() {
        return Err(AppError::BadRequest(
            "allowlist mode requires at least one CIDR".into(),
        ));
    }
    validate_kind_scheme(tunnel.kind, tunnel.local_scheme)?;
    match tunnel.kind {
        TunnelKind::Tcp | TunnelKind::Udp if tunnel.remote_port.is_none() => {
            return Err(AppError::BadRequest(
                "port tunnel requires remote_port".into(),
            ));
        }
        TunnelKind::Web if tunnel.hostname.is_none() => {
            return Err(AppError::BadRequest("web tunnel requires hostname".into()));
        }
        _ => {}
    }
    Ok(())
}

fn validate_kind_scheme(kind: TunnelKind, scheme: LocalScheme) -> Result<(), AppError> {
    let valid = matches!(
        (kind, scheme),
        (TunnelKind::Tcp, LocalScheme::Tcp)
            | (TunnelKind::Udp, LocalScheme::Udp)
            | (TunnelKind::Web, LocalScheme::Http | LocalScheme::Https)
    );
    if valid {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "local scheme is incompatible with tunnel kind".into(),
        ))
    }
}

fn normalize_hostname(state: &SharedState, value: &str) -> Result<String, AppError> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let slug = if value.ends_with(&format!(".{}", state.config.web_base_domain)) {
        value
            .strip_suffix(&format!(".{}", state.config.web_base_domain))
            .unwrap_or(&value)
    } else {
        value.as_str()
    };
    if slug.is_empty()
        || slug.len() > 63
        || slug.starts_with('-')
        || slug.ends_with('-')
        || !slug.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
    {
        return Err(AppError::BadRequest(
            "hostname must be a DNS label containing letters, digits, or hyphens".into(),
        ));
    }
    Ok(format!("{slug}.{}", state.config.web_base_domain))
}

fn validate_local_host(host: &str, allow_lan: bool) -> Result<(), AppError> {
    let host = host.trim();
    if host.is_empty() || host.len() > 253 || host.contains(char::is_whitespace) {
        return Err(AppError::BadRequest("invalid local host".into()));
    }
    let is_loopback =
        host == "localhost" || IpAddr::from_str(host).is_ok_and(|address| address.is_loopback());
    if !is_loopback && !allow_lan {
        return Err(AppError::BadRequest(
            "non-loopback targets require allow_lan_target confirmation".into(),
        ));
    }
    Ok(())
}

fn validate_remote_port(state: &SharedState, port: u16) -> Result<(), AppError> {
    if !(state.config.port_start..=state.config.port_end).contains(&port) {
        return Err(AppError::BadRequest(format!(
            "remote port must be within {}..={}",
            state.config.port_start, state.config.port_end
        )));
    }
    Ok(())
}

fn row_to_tunnel(row: SqliteRow) -> Result<Tunnel, AppError> {
    let access_mode = match row.get::<String, _>("access_mode").as_str() {
        "allowlist" => AccessMode::Allowlist,
        "public" => AccessMode::Public,
        _ => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "invalid access mode in database"
            )));
        }
    };
    let enabled = row.get::<bool, _>("enabled");
    Ok(Tunnel {
        id: Uuid::parse_str(&row.get::<String, _>("id"))
            .map_err(|error| AppError::Internal(error.into()))?,
        agent_id: Uuid::parse_str(&row.get::<String, _>("agent_id"))
            .map_err(|error| AppError::Internal(error.into()))?,
        name: row.get("name"),
        local_host: row.get("local_host"),
        local_port: row.get::<i64, _>("local_port") as u16,
        kind: parse_kind(&row.get::<String, _>("kind"))?,
        local_scheme: parse_scheme(&row.get::<String, _>("local_scheme"))?,
        remote_port: row
            .get::<Option<i64>, _>("remote_port")
            .map(|port| port as u16),
        hostname: row.get("hostname"),
        access_mode,
        allowed_cidrs: serde_json::from_str(&row.get::<String, _>("allowed_cidrs"))
            .map_err(|error| AppError::Internal(error.into()))?,
        enabled,
        status: if enabled {
            TunnelStatus::Starting
        } else {
            TunnelStatus::Stopped
        },
        created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
            .map_err(|error| AppError::Internal(error.into()))?
            .with_timezone(&Utc),
        updated_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))
            .map_err(|error| AppError::Internal(error.into()))?
            .with_timezone(&Utc),
    })
}

fn access_mode_str(mode: AccessMode) -> &'static str {
    match mode {
        AccessMode::Allowlist => "allowlist",
        AccessMode::Public => "public",
    }
}

fn kind_str(kind: TunnelKind) -> &'static str {
    match kind {
        TunnelKind::Tcp => "tcp",
        TunnelKind::Udp => "udp",
        TunnelKind::Web => "web",
    }
}

fn scheme_str(scheme: LocalScheme) -> &'static str {
    match scheme {
        LocalScheme::Tcp => "tcp",
        LocalScheme::Udp => "udp",
        LocalScheme::Http => "http",
        LocalScheme::Https => "https",
    }
}

fn parse_kind(value: &str) -> Result<TunnelKind, AppError> {
    match value {
        "tcp" => Ok(TunnelKind::Tcp),
        "udp" => Ok(TunnelKind::Udp),
        "web" => Ok(TunnelKind::Web),
        _ => Err(AppError::Internal(anyhow::anyhow!("invalid tunnel kind"))),
    }
}

fn parse_scheme(value: &str) -> Result<LocalScheme, AppError> {
    match value {
        "tcp" => Ok(LocalScheme::Tcp),
        "udp" => Ok(LocalScheme::Udp),
        "http" => Ok(LocalScheme::Http),
        "https" => Ok(LocalScheme::Https),
        _ => Err(AppError::Internal(anyhow::anyhow!("invalid local scheme"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;

    fn tunnel(mode: AccessMode, cidrs: Vec<IpNet>) -> Tunnel {
        let now = Utc::now();
        Tunnel {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            name: "test".into(),
            local_host: "127.0.0.1".into(),
            local_port: 22,
            kind: TunnelKind::Tcp,
            local_scheme: LocalScheme::Tcp,
            remote_port: Some(20000),
            hostname: None,
            access_mode: mode,
            allowed_cidrs: cidrs,
            enabled: true,
            status: TunnelStatus::Online,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn cidr_allowlist_matches_source() {
        let value = tunnel(AccessMode::Allowlist, vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(source_allowed(&value, "10.20.30.40".parse().unwrap()));
        assert!(!source_allowed(&value, "192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn public_mode_accepts_any_source() {
        let value = tunnel(AccessMode::Public, vec![]);
        assert!(source_allowed(&value, "203.0.113.10".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_ipv6_matches_ipv4_allowlist() {
        let value = tunnel(
            AccessMode::Allowlist,
            vec!["203.0.113.0/24".parse().unwrap()],
        );
        assert!(source_allowed(
            &value,
            "::ffff:203.0.113.7".parse().unwrap()
        ));
    }
}
