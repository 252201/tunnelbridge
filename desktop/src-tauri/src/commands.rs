use std::sync::Arc;

use reqwest::{Client, Method, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use tauri::{AppHandle, State};
use tauri_plugin_autostart::ManagerExt as AutostartManagerExt;
use tauri_plugin_updater::UpdaterExt;
use tunnelbridge_protocol::{
    AgentEnrollmentResponse, ApiError, CreateTunnelRequest, TransportMode, Tunnel,
    UpdateTunnelRequest,
};
use uuid::Uuid;

use crate::{
    agent,
    config::{
        AgentConfig, load_token, normalize_server_url, save_config, save_token,
        save_transport_certificate, save_transport_fingerprint,
    },
    runtime::{AppSnapshot, RuntimeState},
};

#[tauri::command]
pub async fn get_snapshot(state: State<'_, Arc<RuntimeState>>) -> Result<AppSnapshot, String> {
    Ok(state.snapshot().await)
}

#[tauri::command(rename_all = "camelCase")]
pub async fn configure_server(
    state: State<'_, Arc<RuntimeState>>,
    server_url: String,
    token: String,
    device_name: String,
) -> Result<(), String> {
    let server_url = normalize_server_url(&server_url).map_err(display_error)?;
    if token.trim().len() < 20 {
        return Err("设备令牌格式无效".into());
    }
    let name = device_name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err("设备名称需要包含 1 到 80 个字符".into());
    }
    let client = Client::new();
    let enrollment: AgentEnrollmentResponse = request(
        &client,
        &server_url,
        token.trim(),
        Method::GET,
        "/api/v1/agent/enrollment",
        Option::<&()>::None,
    )
    .await?;
    let existing_id = state
        .config
        .read()
        .await
        .as_ref()
        .map(|value| value.installation_id);
    let previous = state.config.read().await.clone();
    let config = AgentConfig {
        server_url,
        device_name: name.into(),
        installation_id: existing_id.unwrap_or_else(Uuid::new_v4),
        transport_mode: previous
            .as_ref()
            .map_or(TransportMode::Auto, |value| value.transport_mode),
        quic_port: enrollment.quic_port,
        kcp_port: enrollment.kcp_port,
    };
    save_token(config.installation_id, token.trim()).map_err(display_error)?;
    save_transport_fingerprint(config.installation_id, &enrollment.transport_fingerprint)
        .map_err(display_error)?;
    save_transport_certificate(
        config.installation_id,
        &enrollment.transport_certificate_der,
    )
    .map_err(display_error)?;
    save_config(&state.config_path(), &config).map_err(display_error)?;
    *state.config.write().await = Some(config);
    *state.tunnels.write().await = enrollment.tunnels;
    state.log("info", "服务器配置已验证并保存").await;
    agent::restart_agent(state.inner().clone());
    Ok(())
}

#[tauri::command]
pub async fn create_tunnel(
    state: State<'_, Arc<RuntimeState>>,
    request: CreateTunnelRequest,
) -> Result<Tunnel, String> {
    create_tunnel_inner(state.inner().clone(), request).await
}

async fn create_tunnel_inner(
    state: Arc<RuntimeState>,
    request_body: CreateTunnelRequest,
) -> Result<Tunnel, String> {
    let (config, token) = credentials(&state).await?;
    let tunnel = request(
        &Client::new(),
        &config.server_url,
        &token,
        Method::POST,
        "/api/v1/agent/tunnels",
        Some(&request_body),
    )
    .await?;
    refresh_tunnels(&state).await?;
    state.log("info", "已创建并同步新隧道").await;
    Ok(tunnel)
}

#[tauri::command]
pub async fn update_tunnel(
    state: State<'_, Arc<RuntimeState>>,
    id: Uuid,
    update: UpdateTunnelRequest,
) -> Result<Tunnel, String> {
    let (config, token) = credentials(&state).await?;
    let tunnel = request(
        &Client::new(),
        &config.server_url,
        &token,
        Method::PATCH,
        &format!("/api/v1/agent/tunnels/{id}"),
        Some(&update),
    )
    .await?;
    refresh_tunnels(&state).await?;
    Ok(tunnel)
}

#[tauri::command]
pub async fn delete_tunnel(state: State<'_, Arc<RuntimeState>>, id: Uuid) -> Result<(), String> {
    let (config, token) = credentials(&state).await?;
    request_empty(
        &Client::new(),
        &config.server_url,
        &token,
        Method::DELETE,
        &format!("/api/v1/agent/tunnels/{id}"),
        Option::<&()>::None,
    )
    .await?;
    refresh_tunnels(&state).await?;
    state.log("info", "隧道已删除，远程端口已释放").await;
    Ok(())
}

#[tauri::command]
pub async fn set_all_enabled(
    state: State<'_, Arc<RuntimeState>>,
    enabled: bool,
) -> Result<(), String> {
    set_all_enabled_inner(state.inner().clone(), enabled).await
}

#[tauri::command(rename_all = "camelCase")]
pub async fn set_transport_mode(
    state: State<'_, Arc<RuntimeState>>,
    mode: TransportMode,
) -> Result<(), String> {
    let mut config = state.config.read().await.clone().ok_or("尚未配置服务器")?;
    config.transport_mode = mode;
    save_config(&state.config_path(), &config).map_err(display_error)?;
    *state.config.write().await = Some(config);
    state
        .log("info", format!("承载策略已切换为 {mode:?}"))
        .await;
    agent::restart_agent(state.inner().clone());
    Ok(())
}

pub async fn set_all_enabled_inner(state: Arc<RuntimeState>, enabled: bool) -> Result<(), String> {
    let items = state.tunnels.read().await.clone();
    for tunnel in items {
        if tunnel.enabled != enabled {
            let (config, token) = credentials(&state).await?;
            let _: Tunnel = request(
                &Client::new(),
                &config.server_url,
                &token,
                Method::PATCH,
                &format!("/api/v1/agent/tunnels/{}", tunnel.id),
                Some(&UpdateTunnelRequest {
                    enabled: Some(enabled),
                    ..Default::default()
                }),
            )
            .await?;
        }
    }
    refresh_tunnels(&state).await?;
    Ok(())
}

#[tauri::command]
pub fn get_autostart(app: AppHandle) -> Result<bool, String> {
    app.autolaunch().is_enabled().map_err(display_error)
}

#[tauri::command]
pub fn set_autostart(app: AppHandle, enabled: bool) -> Result<bool, String> {
    if enabled {
        app.autolaunch().enable().map_err(display_error)?;
    } else {
        app.autolaunch().disable().map_err(display_error)?;
    }
    app.autolaunch().is_enabled().map_err(display_error)
}

#[tauri::command]
pub async fn check_for_updates(app: AppHandle) -> Result<String, String> {
    match app
        .updater()
        .map_err(display_error)?
        .check()
        .await
        .map_err(display_error)?
    {
        Some(update) => Ok(format!("UPDATE_AVAILABLE:{}", update.version)),
        None => Ok("当前已是最新版本".into()),
    }
}

#[tauri::command]
pub async fn install_update(app: AppHandle) -> Result<(), String> {
    if let Some(update) = app
        .updater()
        .map_err(display_error)?
        .check()
        .await
        .map_err(display_error)?
    {
        update
            .download_and_install(|_, _| {}, || {})
            .await
            .map_err(display_error)?;
    }
    Ok(())
}

async fn credentials(state: &RuntimeState) -> Result<(AgentConfig, String), String> {
    let config = state.config.read().await.clone().ok_or("尚未配置服务器")?;
    let token = load_token(config.installation_id).map_err(display_error)?;
    Ok((config, token))
}

async fn refresh_tunnels(state: &RuntimeState) -> Result<(), String> {
    let (config, token) = credentials(state).await?;
    let tunnels = request(
        &Client::new(),
        &config.server_url,
        &token,
        Method::GET,
        "/api/v1/agent/tunnels",
        Option::<&()>::None,
    )
    .await?;
    *state.tunnels.write().await = tunnels;
    Ok(())
}

async fn request<T, B>(
    client: &Client,
    server: &str,
    token: &str,
    method: Method,
    path: &str,
    body: Option<&B>,
) -> Result<T, String>
where
    T: DeserializeOwned,
    B: Serialize + ?Sized,
{
    let mut builder = client
        .request(method, format!("{server}{path}"))
        .bearer_auth(token);
    if let Some(body) = body {
        builder = builder.json(body);
    }
    let response = builder.send().await.map_err(display_error)?;
    if !response.status().is_success() {
        return Err(response_error(response).await);
    }
    response.json().await.map_err(display_error)
}

async fn request_empty<B>(
    client: &Client,
    server: &str,
    token: &str,
    method: Method,
    path: &str,
    body: Option<&B>,
) -> Result<(), String>
where
    B: Serialize + ?Sized,
{
    let mut builder = client
        .request(method, format!("{server}{path}"))
        .bearer_auth(token);
    if let Some(body) = body {
        builder = builder.json(body);
    }
    let response = builder.send().await.map_err(display_error)?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(response_error(response).await)
    }
}

async fn response_error(response: reqwest::Response) -> String {
    let status = response.status();
    match response.json::<ApiError>().await {
        Ok(error) => error.message,
        Err(_) if status == StatusCode::UNAUTHORIZED => "设备令牌无效或已撤销".into(),
        Err(_) => format!("服务器返回 {status}"),
    }
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
