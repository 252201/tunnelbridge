use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use http::HeaderValue;
use rand::Rng;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};
use tokio_util::sync::CancellationToken;
use tunnelbridge_protocol::{
    AgentControlMessage, DATA_FRAME_BYTES, DATA_FRAME_EOF, PROTOCOL_VERSION, Tunnel,
};
use url::Url;
use uuid::Uuid;

use crate::{
    config::{AgentConfig, load_token},
    runtime::{AgentStatus, RuntimeState},
};

pub fn restart_agent(state: Arc<RuntimeState>) {
    tauri::async_runtime::spawn(async move {
        let cancellation = CancellationToken::new();
        if let Some(previous) = state
            .cancellation
            .lock()
            .await
            .replace(cancellation.clone())
        {
            previous.cancel();
        }
        run_reconnecting(state, cancellation).await;
    });
}

async fn run_reconnecting(state: Arc<RuntimeState>, cancellation: CancellationToken) {
    let mut attempt = 0_u32;
    loop {
        if cancellation.is_cancelled() {
            return;
        }
        let Some(config) = state.config.read().await.clone() else {
            state
                .set_status(AgentStatus::Unconfigured, "尚未连接服务器")
                .await;
            return;
        };
        let token = match load_token(config.installation_id) {
            Ok(token) => token,
            Err(error) => {
                state
                    .set_status(AgentStatus::Error, "无法读取设备令牌")
                    .await;
                state.log("error", error.to_string()).await;
                return;
            }
        };
        state
            .set_status(AgentStatus::Connecting, "正在建立加密控制通道")
            .await;
        match run_control(state.clone(), &config, &token, cancellation.clone()).await {
            Ok(()) if cancellation.is_cancelled() => return,
            Ok(()) => state.log("warn", "控制通道已关闭").await,
            Err(error) => state.log("warn", format!("连接失败：{error:#}")).await,
        }
        state
            .set_status(AgentStatus::Offline, "连接中断，正在重试")
            .await;
        attempt = (attempt + 1).min(8);
        let base = 2_u64.pow(attempt).min(60);
        let jitter = rand::rng().random_range(0..=1_000_u64);
        tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_millis(base * 1_000 + jitter)) => {}
        }
    }
}

async fn run_control(
    state: Arc<RuntimeState>,
    config: &AgentConfig,
    token: &str,
    cancellation: CancellationToken,
) -> Result<()> {
    let url = websocket_url(&config.server_url, "/api/v1/agent/control")?;
    let mut request = url.as_str().into_client_request()?;
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    let (socket, _) = connect_async(request).await.context("连接中继服务器")?;
    let (mut writer, mut reader) = socket.split();
    send_control(
        &mut writer,
        &AgentControlMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            agent_id: config.installation_id,
            name: config.device_name.clone(),
        },
    )
    .await?;
    state
        .set_status(AgentStatus::Online, "控制通道已连接")
        .await;
    state.log("info", "已连接中继服务器").await;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => {
                let _ = writer.close().await;
                return Ok(());
            }
            _ = heartbeat.tick() => {
                send_control(&mut writer, &AgentControlMessage::Ping { sent_at: Utc::now() }).await?;
            }
            message = reader.next() => {
                let Some(message) = message else { return Ok(()) };
                match message? {
                    Message::Text(text) => {
                        match serde_json::from_str::<AgentControlMessage>(&text)? {
                            AgentControlMessage::Welcome { protocol_version, .. } => {
                                if protocol_version != PROTOCOL_VERSION {
                                    anyhow::bail!("协议版本不兼容：服务器 {protocol_version}，客户端 {PROTOCOL_VERSION}");
                                }
                            }
                            AgentControlMessage::ConfigSync { tunnels } => {
                                *state.tunnels.write().await = tunnels;
                            }
                            AgentControlMessage::OpenConnection { connection_id, tunnel, peer_addr, ticket, .. } => {
                                let state = state.clone();
                                let config = config.clone();
                                let token = token.to_owned();
                                tauri::async_runtime::spawn(async move {
                                    state.log("info", format!("{} 收到来自 {peer_addr} 的连接", tunnel.name)).await;
                                    {
                                        let mut metrics = state.metrics.write().await;
                                        metrics.active_connections += 1;
                                    }
                                    let result = open_data_channel_with_ticket(
                                        state.clone(), &config, &token, connection_id, tunnel, &ticket,
                                    ).await;
                                    {
                                        let mut metrics = state.metrics.write().await;
                                        metrics.active_connections = metrics.active_connections.saturating_sub(1);
                                        if result.is_err() { metrics.failed_connections += 1; }
                                    }
                                    if let Err(error) = result {
                                        state.log("error", format!("转发连接失败：{error:#}")).await;
                                    }
                                });
                            }
                            AgentControlMessage::Error { code, message } => {
                                state.log("error", format!("服务器错误 {code}：{message}")).await;
                            }
                            _ => {}
                        }
                    }
                    Message::Ping(payload) => writer.send(Message::Pong(payload)).await?,
                    Message::Close(_) => return Ok(()),
                    _ => {}
                }
            }
        }
    }
}

async fn send_control<S>(writer: &mut S, message: &AgentControlMessage) -> Result<()>
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    writer
        .send(Message::Text(serde_json::to_string(message)?.into()))
        .await?;
    Ok(())
}

async fn open_data_channel_with_ticket(
    state: Arc<RuntimeState>,
    config: &AgentConfig,
    token: &str,
    connection_id: Uuid,
    tunnel: Tunnel,
    ticket: &str,
) -> Result<()> {
    let local = TcpStream::connect((tunnel.local_host.as_str(), tunnel.local_port))
        .await
        .with_context(|| format!("连接本地目标 {}:{}", tunnel.local_host, tunnel.local_port))?;
    let url = websocket_url(
        &config.server_url,
        &format!("/api/v1/agent/data/{connection_id}"),
    )?;
    let mut request = url.as_str().into_client_request()?;
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    request
        .headers_mut()
        .insert("x-tunnel-ticket", HeaderValue::from_str(ticket)?);
    let (websocket, _) = connect_async(request).await.context("建立数据通道")?;
    bridge_local(state, local, websocket).await
}

async fn bridge_local(
    state: Arc<RuntimeState>,
    local: TcpStream,
    websocket: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
) -> Result<()> {
    let (mut local_read, mut local_write) = local.into_split();
    let (mut ws_write, mut ws_read) = websocket.split();
    let upstream_state = state.clone();
    let upstream = async move {
        let mut buffer = vec![0_u8; 32 * 1024];
        loop {
            let count =
                tokio::time::timeout(Duration::from_secs(600), local_read.read(&mut buffer))
                    .await
                    .context("连接空闲超时")??;
            if count == 0 {
                ws_write
                    .send(Message::Binary(vec![DATA_FRAME_EOF].into()))
                    .await?;
                break;
            }
            let mut frame = Vec::with_capacity(count + 1);
            frame.push(DATA_FRAME_BYTES);
            frame.extend_from_slice(&buffer[..count]);
            ws_write.send(Message::Binary(frame.into())).await?;
            upstream_state.metrics.write().await.bytes_up += count as u64;
        }
        anyhow::Ok(())
    };
    let downstream = async move {
        loop {
            let message = tokio::time::timeout(Duration::from_secs(600), ws_read.next())
                .await
                .context("连接空闲超时")?;
            let Some(message) = message else { break };
            match message? {
                Message::Binary(frame) if frame.first() == Some(&DATA_FRAME_BYTES) => {
                    local_write.write_all(&frame[1..]).await?;
                    state.metrics.write().await.bytes_down += (frame.len() - 1) as u64;
                }
                Message::Binary(frame) if frame.first() == Some(&DATA_FRAME_EOF) => {
                    local_write.shutdown().await?;
                    break;
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        anyhow::Ok(())
    };
    let (up, down) = tokio::join!(upstream, downstream);
    up?;
    down?;
    Ok(())
}

fn websocket_url(server_url: &str, path: &str) -> Result<Url> {
    let mut url = Url::parse(server_url)?;
    url.set_scheme(if url.scheme() == "https" { "wss" } else { "ws" })
        .map_err(|_| anyhow::anyhow!("无法转换 WebSocket 地址"))?;
    url.set_path(path);
    Ok(url)
}
