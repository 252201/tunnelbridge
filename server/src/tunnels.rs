use std::{net::IpAddr, str::FromStr};

use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool, sqlite::SqliteRow};
use tunnelbridge_protocol::{
    AccessMode, CreateTunnelRequest, Tunnel, TunnelStatus, UpdateTunnelRequest,
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

pub async fn create(
    state: &SharedState,
    agent_id: Uuid,
    request: CreateTunnelRequest,
) -> Result<Tunnel, AppError> {
    validate_create(state, &request)?;
    let remote_port = match request.remote_port {
        Some(port) => {
            validate_remote_port(state, port)?;
            port
        }
        None => allocate_port(state).await?,
    };
    let now = Utc::now();
    let tunnel = Tunnel {
        id: Uuid::new_v4(),
        agent_id,
        name: request.name.trim().to_owned(),
        local_host: request.local_host.trim().to_owned(),
        local_port: request.local_port,
        remote_port,
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
        (id, agent_id, name, local_host, local_port, remote_port, access_mode, allowed_cidrs, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(tunnel.id.to_string())
    .bind(agent_id.to_string())
    .bind(&tunnel.name)
    .bind(&tunnel.local_host)
    .bind(i64::from(tunnel.local_port))
    .bind(i64::from(tunnel.remote_port))
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
            AppError::Conflict(format!("remote port {remote_port} is already allocated")),
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
        validate_remote_port(state, port)?;
        tunnel.remote_port = port;
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
        r#"UPDATE tunnels SET name = ?, local_host = ?, local_port = ?, remote_port = ?,
        access_mode = ?, allowed_cidrs = ?, enabled = ?, updated_at = ? WHERE id = ?"#,
    )
    .bind(&tunnel.name)
    .bind(&tunnel.local_host)
    .bind(i64::from(tunnel.local_port))
    .bind(i64::from(tunnel.remote_port))
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

async fn allocate_port(state: &SharedState) -> Result<u16, AppError> {
    let rows = sqlx::query("SELECT remote_port FROM tunnels")
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
    Ok(())
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
        remote_port: row.get::<i64, _>("remote_port") as u16,
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
            remote_port: 20000,
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
