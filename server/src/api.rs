use std::net::SocketAddr;

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query, State, WebSocketUpgrade},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
};
use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tokio::sync::mpsc;
use tunnelbridge_protocol::{
    ActiveConnection, AgentControlMessage, AuditEntry, CreateDeviceRequest, CreateTunnelRequest,
    Device, DeviceTokenResponse, LoginRequest, LoginResponse, MetricsSnapshot, PROTOCOL_VERSION,
    Tunnel, TunnelStatus, UpdateTunnelRequest,
};
use uuid::Uuid;

use crate::{
    auth::{
        clear_session_cookie, create_session, hash_password, hash_token, login_allowed,
        random_secret, remove_session, require_admin, require_device, session_cookie,
        verify_password,
    },
    error::AppError,
    gateway,
    state::{AgentPeer, SharedState},
    tunnels,
};

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/me", get(me))
        .route(
            "/api/v1/admin/devices",
            get(list_devices).post(create_device),
        )
        .route("/api/v1/admin/devices/{id}", delete(revoke_device))
        .route("/api/v1/admin/tunnels", get(admin_list_tunnels))
        .route(
            "/api/v1/admin/tunnels/{id}",
            patch(admin_update_tunnel).delete(admin_delete_tunnel),
        )
        .route("/api/v1/admin/connections", get(list_connections))
        .route("/api/v1/admin/audit", get(list_audit))
        .route("/api/v1/admin/metrics", get(admin_metrics))
        .route("/api/v1/admin/settings", get(admin_settings))
        .route("/api/v1/admin/password", patch(change_password))
        .route(
            "/api/v1/agent/tunnels",
            get(agent_list_tunnels).post(agent_create_tunnel),
        )
        .route(
            "/api/v1/agent/tunnels/{id}",
            patch(agent_update_tunnel).delete(agent_delete_tunnel),
        )
        .route("/api/v1/agent/control", get(agent_control))
        .route("/api/v1/agent/data/{connection_id}", get(agent_data))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn ready(State(state): State<SharedState>) -> Result<&'static str, AppError> {
    sqlx::query("SELECT 1").execute(&state.db).await?;
    Ok("ready")
}

async fn metrics(State(state): State<SharedState>) -> Json<MetricsSnapshot> {
    Json(state.metrics())
}

async fn login(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<Response, AppError> {
    let rate_key = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| gateway::parse_forwarded_ip(Some(value)))
        })
        .unwrap_or(peer.ip())
        .to_string();
    if !login_allowed(&state, &rate_key) {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"code":"rate_limited","message":"Try again in one minute"})),
        )
            .into_response());
    }
    let row = sqlx::query("SELECT username, password_hash FROM admins WHERE username = ?")
        .bind(&request.username)
        .fetch_optional(&state.db)
        .await?;
    let valid = row.as_ref().is_some_and(|row| {
        verify_password(
            row.get::<String, _>("password_hash").as_str(),
            &request.password,
        )
    });
    if !valid {
        audit(
            &state,
            "auth.login_failed",
            &request.username,
            "invalid credentials",
        )
        .await?;
        return Err(AppError::Unauthorized);
    }
    state.login_attempts.remove(&rate_key);
    let (session_id, csrf_token) = create_session(&state, request.username.clone());
    audit(
        &state,
        "auth.login",
        &request.username,
        "administrator signed in",
    )
    .await?;
    let mut response = Json(LoginResponse {
        username: request.username,
        csrf_token,
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&session_cookie(&state, &session_id))
            .map_err(|error| AppError::Internal(error.into()))?,
    );
    Ok(response)
}

async fn logout(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (username, _) = require_admin(&state, &headers, &Method::POST)?;
    remove_session(&state, &headers);
    audit(&state, "auth.logout", &username, "administrator signed out").await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_session_cookie(&state))
            .map_err(|error| AppError::Internal(error.into()))?,
    );
    Ok(response)
}

async fn me(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<LoginResponse>, AppError> {
    let (username, csrf_token) = require_admin(&state, &headers, &Method::GET)?;
    Ok(Json(LoginResponse {
        username,
        csrf_token,
    }))
}

async fn list_devices(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Device>>, AppError> {
    require_admin(&state, &headers, &Method::GET)?;
    let rows = sqlx::query(
        "SELECT id, name, revoked, last_seen_at, created_at FROM devices ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;
    let devices = rows
        .into_iter()
        .map(|row| {
            let id = Uuid::parse_str(&row.get::<String, _>("id"))
                .map_err(|error| AppError::Internal(error.into()))?;
            Ok(Device {
                id,
                name: row.get("name"),
                online: state.agents.contains_key(&id),
                revoked: row.get("revoked"),
                last_seen_at: parse_optional_time(row.get::<Option<String>, _>("last_seen_at"))?,
                created_at: parse_time(row.get("created_at"))?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(Json(devices))
}

async fn create_device(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<CreateDeviceRequest>,
) -> Result<(StatusCode, Json<DeviceTokenResponse>), AppError> {
    let (username, _) = require_admin(&state, &headers, &Method::POST)?;
    let name = request.name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(AppError::BadRequest(
            "device name must contain 1 to 80 characters".into(),
        ));
    }
    let id = Uuid::new_v4();
    let token = random_secret(32);
    let created_at = Utc::now();
    sqlx::query(
        "INSERT INTO devices (id, name, token_hash, revoked, created_at) VALUES (?, ?, ?, 0, ?)",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(hash_token(&token))
    .bind(created_at.to_rfc3339())
    .execute(&state.db)
    .await?;
    audit(
        &state,
        "device.create",
        &id.to_string(),
        &format!("created by {username}"),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(DeviceTokenResponse {
            id,
            name: name.into(),
            token,
            created_at,
        }),
    ))
}

async fn revoke_device(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let (username, _) = require_admin(&state, &headers, &Method::DELETE)?;
    let result = sqlx::query("UPDATE devices SET revoked = 1 WHERE id = ?")
        .bind(id.to_string())
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    if let Some((_, peer)) = state.agents.remove(&id) {
        peer.cancellation.cancel();
    }
    audit(
        &state,
        "device.revoke",
        &id.to_string(),
        &format!("revoked by {username}"),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_list_tunnels(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Tunnel>>, AppError> {
    require_admin(&state, &headers, &Method::GET)?;
    let tunnels = tunnels::list_all(&state.db).await?;
    Ok(Json(decorate_tunnels(&state, tunnels)))
}

async fn admin_update_tunnel(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<UpdateTunnelRequest>,
) -> Result<Json<Tunnel>, AppError> {
    let (username, _) = require_admin(&state, &headers, &Method::PATCH)?;
    let tunnel = tunnels::update(&state, id, None, request).await?;
    gateway::reconcile_listener(state.clone(), tunnel.clone()).await;
    gateway::sync_agent(&state, tunnel.agent_id).await;
    audit(
        &state,
        "tunnel.update",
        &id.to_string(),
        &format!("updated by {username}"),
    )
    .await?;
    Ok(Json(decorate_tunnel(&state, tunnel)))
}

async fn admin_delete_tunnel(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let (username, _) = require_admin(&state, &headers, &Method::DELETE)?;
    let tunnel = tunnels::get(&state.db, id).await?;
    tunnels::delete(&state, id, None).await?;
    gateway::stop_listener(&state, id);
    gateway::sync_agent(&state, tunnel.agent_id).await;
    audit(
        &state,
        "tunnel.delete",
        &id.to_string(),
        &format!("deleted by {username}"),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn agent_list_tunnels(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Tunnel>>, AppError> {
    let agent = require_device(&state, &headers).await?;
    let tunnels = tunnels::list_for_agent(&state.db, agent.id).await?;
    Ok(Json(decorate_tunnels(&state, tunnels)))
}

async fn agent_create_tunnel(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<CreateTunnelRequest>,
) -> Result<(StatusCode, Json<Tunnel>), AppError> {
    let agent = require_device(&state, &headers).await?;
    let tunnel = tunnels::create(&state, agent.id, request).await?;
    gateway::reconcile_listener(state.clone(), tunnel.clone()).await;
    gateway::sync_agent(&state, agent.id).await;
    audit(
        &state,
        "tunnel.create",
        &tunnel.id.to_string(),
        &format!("created by device {}", agent.name),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(decorate_tunnel(&state, tunnel))))
}

async fn agent_update_tunnel(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<UpdateTunnelRequest>,
) -> Result<Json<Tunnel>, AppError> {
    let agent = require_device(&state, &headers).await?;
    let tunnel = tunnels::update(&state, id, Some(agent.id), request).await?;
    gateway::reconcile_listener(state.clone(), tunnel.clone()).await;
    gateway::sync_agent(&state, agent.id).await;
    audit(
        &state,
        "tunnel.update",
        &id.to_string(),
        &format!("updated by device {}", agent.name),
    )
    .await?;
    Ok(Json(decorate_tunnel(&state, tunnel)))
}

async fn agent_delete_tunnel(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let agent = require_device(&state, &headers).await?;
    tunnels::delete(&state, id, Some(agent.id)).await?;
    gateway::stop_listener(&state, id);
    gateway::sync_agent(&state, agent.id).await;
    audit(
        &state,
        "tunnel.delete",
        &id.to_string(),
        &format!("deleted by device {}", agent.name),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_connections(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ActiveConnection>>, AppError> {
    require_admin(&state, &headers, &Method::GET)?;
    Ok(Json(
        state
            .active
            .iter()
            .map(|item| item.value().clone())
            .collect(),
    ))
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<u16>,
}

async fn list_audit(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>, AppError> {
    require_admin(&state, &headers, &Method::GET)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let rows = sqlx::query(
        "SELECT id, action, subject, detail, created_at FROM audit_log ORDER BY id DESC LIMIT ?",
    )
    .bind(i64::from(limit))
    .fetch_all(&state.db)
    .await?;
    let entries = rows
        .into_iter()
        .map(|row| {
            Ok(AuditEntry {
                id: row.get("id"),
                action: row.get("action"),
                subject: row.get("subject"),
                detail: row.get("detail"),
                created_at: parse_time(row.get("created_at"))?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(Json(entries))
}

async fn admin_metrics(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<MetricsSnapshot>, AppError> {
    require_admin(&state, &headers, &Method::GET)?;
    Ok(Json(state.metrics()))
}

#[derive(Serialize)]
struct ServerSettingsResponse {
    port_start: u16,
    port_end: u16,
    ticket_ttl_seconds: u64,
    connect_timeout_seconds: u64,
    idle_timeout_seconds: u64,
    audit_retention_days: i64,
}

async fn admin_settings(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<ServerSettingsResponse>, AppError> {
    require_admin(&state, &headers, &Method::GET)?;
    Ok(Json(ServerSettingsResponse {
        port_start: state.config.port_start,
        port_end: state.config.port_end,
        ticket_ttl_seconds: state.config.ticket_ttl.as_secs(),
        connect_timeout_seconds: state.config.connect_timeout.as_secs(),
        idle_timeout_seconds: state.config.idle_timeout.as_secs(),
        audit_retention_days: state.config.audit_retention_days,
    }))
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<Response, AppError> {
    let (username, _) = require_admin(&state, &headers, &Method::PATCH)?;
    if request.new_password.len() < 12 {
        return Err(AppError::BadRequest(
            "new password must contain at least 12 characters".into(),
        ));
    }
    let row = sqlx::query("SELECT password_hash FROM admins WHERE username = ?")
        .bind(&username)
        .fetch_one(&state.db)
        .await?;
    if !verify_password(
        &row.get::<String, _>("password_hash"),
        &request.current_password,
    ) {
        return Err(AppError::Unauthorized);
    }
    let password_hash = hash_password(&request.new_password)?;
    sqlx::query("UPDATE admins SET password_hash = ? WHERE username = ?")
        .bind(password_hash)
        .bind(&username)
        .execute(&state.db)
        .await?;
    audit(
        &state,
        "auth.password_change",
        &username,
        "administrator password changed",
    )
    .await?;
    state.sessions.clear();
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_session_cookie(&state))
            .map_err(|error| AppError::Internal(error.into()))?,
    );
    Ok(response)
}

async fn agent_control(
    State(state): State<SharedState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let agent = require_device(&state, &headers).await?;
    Ok(ws.on_upgrade(move |socket| run_control_socket(state, agent.id, agent.name, socket)))
}

async fn run_control_socket(
    state: SharedState,
    agent_id: Uuid,
    name: String,
    socket: axum::extract::ws::WebSocket,
) {
    let session_id = Uuid::new_v4();
    let disconnect = tokio_util::sync::CancellationToken::new();
    let (mut writer, mut reader) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel();
    state.agents.insert(
        agent_id,
        AgentPeer {
            session_id,
            sender: tx.clone(),
            cancellation: disconnect.clone(),
        },
    );
    let _ = sqlx::query("UPDATE devices SET last_seen_at = ? WHERE id = ?")
        .bind(Utc::now().to_rfc3339())
        .bind(agent_id.to_string())
        .execute(&state.db)
        .await;
    let _ = tx.send(AgentControlMessage::Welcome {
        protocol_version: PROTOCOL_VERSION,
        server_time: Utc::now(),
    });
    gateway::sync_agent(&state, agent_id).await;
    let writer_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            let Ok(json) = serde_json::to_string(&message) else {
                continue;
            };
            if writer
                .send(axum::extract::ws::Message::Text(json.into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    loop {
        let message = tokio::select! {
            _ = disconnect.cancelled() => break,
            message = reader.next() => message,
        };
        let Some(Ok(message)) = message else { break };
        match message {
            axum::extract::ws::Message::Text(text) => {
                match serde_json::from_str::<AgentControlMessage>(&text) {
                    Ok(AgentControlMessage::Ping { sent_at }) => {
                        let _ = tx.send(AgentControlMessage::Pong { sent_at });
                    }
                    Ok(AgentControlMessage::Hello {
                        protocol_version, ..
                    }) if protocol_version != PROTOCOL_VERSION => {
                        let _ = tx.send(AgentControlMessage::Error {
                            code: "protocol_mismatch".into(),
                            message: format!("server protocol is {PROTOCOL_VERSION}"),
                        });
                        break;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(agent_id = %agent_id, error = %error, "invalid control message")
                    }
                }
            }
            axum::extract::ws::Message::Close(_) => break,
            _ => {}
        }
    }
    writer_task.abort();
    if state
        .agents
        .get(&agent_id)
        .is_some_and(|peer| peer.session_id == session_id)
    {
        state.agents.remove(&agent_id);
    }
    tracing::info!(agent_id = %agent_id, agent_name = %name, "agent disconnected");
}

async fn agent_data(
    State(state): State<SharedState>,
    Path(connection_id): Path<Uuid>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let agent = require_device(&state, &headers).await?;
    let ticket = headers
        .get("x-tunnel-ticket")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let sender = gateway::claim_data_channel(&state, connection_id, agent.id, ticket)
        .ok_or(AppError::Unauthorized)?;
    Ok(ws.on_upgrade(move |socket| async move {
        let _ = sender.send(socket);
    }))
}

fn decorate_tunnels(state: &SharedState, values: Vec<Tunnel>) -> Vec<Tunnel> {
    values
        .into_iter()
        .map(|value| decorate_tunnel(state, value))
        .collect()
}

fn decorate_tunnel(state: &SharedState, mut tunnel: Tunnel) -> Tunnel {
    tunnel.status = if !tunnel.enabled {
        TunnelStatus::Stopped
    } else if !state.listeners.contains_key(&tunnel.id) {
        TunnelStatus::Error
    } else if !state.agents.contains_key(&tunnel.agent_id) {
        TunnelStatus::AgentOffline
    } else {
        TunnelStatus::Online
    };
    tunnel
}

async fn audit(
    state: &SharedState,
    action: &str,
    subject: &str,
    detail: &str,
) -> Result<(), AppError> {
    sqlx::query("INSERT INTO audit_log (action, subject, detail, created_at) VALUES (?, ?, ?, ?)")
        .bind(action)
        .bind(subject)
        .bind(detail)
        .bind(Utc::now().to_rfc3339())
        .execute(&state.db)
        .await?;
    Ok(())
}

pub async fn cleanup(state: SharedState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
    loop {
        interval.tick().await;
        state
            .sessions
            .retain(|_, session| session.expires_at > std::time::Instant::now());
        state
            .pending
            .retain(|_, pending| pending.expires_at > std::time::Instant::now());
        let cutoff = Utc::now() - chrono::Duration::days(state.config.audit_retention_days);
        let _ = sqlx::query("DELETE FROM audit_log WHERE created_at < ?")
            .bind(cutoff.to_rfc3339())
            .execute(&state.db)
            .await;
        let _ = sqlx::query("DELETE FROM connection_history WHERE closed_at < ?")
            .bind(cutoff.to_rfc3339())
            .execute(&state.db)
            .await;
    }
}

fn parse_time(value: String) -> Result<DateTime<Utc>, AppError> {
    Ok(DateTime::parse_from_rfc3339(&value)
        .map_err(|error| AppError::Internal(error.into()))?
        .with_timezone(&Utc))
}

fn parse_optional_time(value: Option<String>) -> Result<Option<DateTime<Utc>>, AppError> {
    value.map(parse_time).transpose()
}
