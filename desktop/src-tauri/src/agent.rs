use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use http::HeaderValue;
use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::mpsc,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};
use tokio_util::sync::CancellationToken;
use tunnelbridge_protocol::{
    ActiveTransport, AgentControlMessage, CARRIER_FRAME_DATA, CARRIER_FRAME_FIN,
    CARRIER_FRAME_RESET, CarrierCapabilities, PROTOCOL_VERSION, Tunnel, decode_carrier_frame,
    encode_carrier_frame,
};
use url::Url;
use uuid::Uuid;

use crate::{
    config::{AgentConfig, load_token, load_transport_certificate, load_transport_fingerprint},
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
        match run_carrier(state.clone(), &config, &token, cancellation.clone()).await {
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

#[derive(Debug)]
pub(crate) enum Outbound {
    Control(Box<AgentControlMessage>),
    Binary(Vec<u8>),
    Close,
}

impl Outbound {
    pub(crate) fn control(message: AgentControlMessage) -> Self {
        Self::Control(Box::new(message))
    }
}

pub(crate) type LocalStreams = Arc<DashMap<Uuid, mpsc::Sender<(u8, Vec<u8>)>>>;

pub(crate) const DIRECT_RECORD_CONTROL: u8 = 0;
pub(crate) const DIRECT_RECORD_BINARY: u8 = 1;
pub(crate) const MAX_DIRECT_RECORD: usize = 16 * 1024 * 1024;

async fn run_carrier(
    state: Arc<RuntimeState>,
    config: &AgentConfig,
    token: &str,
    cancellation: CancellationToken,
) -> Result<()> {
    match config.transport_mode {
        tunnelbridge_protocol::TransportMode::Quic => {
            run_quic_carrier(state, config, token, cancellation).await
        }
        tunnelbridge_protocol::TransportMode::Kcp => {
            crate::kcp::run(state, config, token, cancellation).await
        }
        tunnelbridge_protocol::TransportMode::Wss => {
            run_wss_carrier(state, config, token, cancellation).await
        }
        tunnelbridge_protocol::TransportMode::Auto => {
            match run_quic_carrier(state.clone(), config, token, cancellation.child_token()).await {
                Ok(()) if cancellation.is_cancelled() => Ok(()),
                Ok(()) => run_wss_carrier(state, config, token, cancellation).await,
                Err(error) => {
                    let reason = format!("QUIC 不可用：{error:#}");
                    state.log("warn", format!("{reason}，已回退 WSS")).await;
                    state
                        .set_transport(ActiveTransport::Wss, Some(reason))
                        .await;
                    run_wss_carrier(state, config, token, cancellation).await
                }
            }
        }
    }
}

async fn run_wss_carrier(
    state: Arc<RuntimeState>,
    config: &AgentConfig,
    token: &str,
    cancellation: CancellationToken,
) -> Result<()> {
    let url = websocket_url(&config.server_url, "/api/v2/agent/carrier")?;
    let mut request = url.as_str().into_client_request()?;
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    let (socket, _) = connect_async(request).await.context("连接中继服务器")?;
    let (mut writer, mut reader) = socket.split();
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Outbound>(256);
    let streams = Arc::new(DashMap::<Uuid, mpsc::Sender<(u8, Vec<u8>)>>::new());
    let writer_task = tauri::async_runtime::spawn(async move {
        while let Some(outbound) = outbound_rx.recv().await {
            let result = match outbound {
                Outbound::Control(message) => {
                    writer
                        .send(Message::Text(serde_json::to_string(&message)?.into()))
                        .await
                }
                Outbound::Binary(frame) => writer.send(Message::Binary(frame.into())).await,
                Outbound::Close => {
                    let _ = writer.close().await;
                    return anyhow::Ok(());
                }
            };
            result?;
        }
        anyhow::Ok(())
    });
    outbound_tx
        .send(Outbound::control(AgentControlMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            agent_id: config.installation_id,
            name: config.device_name.clone(),
            capabilities: CarrierCapabilities {
                transports: vec![ActiveTransport::Wss],
                tunnel_kinds: vec![
                    tunnelbridge_protocol::TunnelKind::Tcp,
                    tunnelbridge_protocol::TunnelKind::Udp,
                    tunnelbridge_protocol::TunnelKind::Web,
                ],
                ..CarrierCapabilities::default()
            },
            config_version: 0,
        }))
        .await?;
    state
        .set_status(AgentStatus::Online, "控制通道已连接")
        .await;
    state.log("info", "已连接中继服务器").await;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
    let mut quic_probe = tokio::time::interval(Duration::from_secs(300));
    quic_probe.tick().await;
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => {
                let _ = outbound_tx.send(Outbound::Close).await;
                writer_task.abort();
                return Ok(());
            }
            _ = heartbeat.tick() => {
                outbound_tx.send(Outbound::control(AgentControlMessage::Ping { sent_at: Utc::now() })).await?;
            }
            _ = quic_probe.tick(), if config.transport_mode == tunnelbridge_protocol::TransportMode::Auto => {
                let _ = outbound_tx.send(Outbound::Close).await;
                anyhow::bail!("定期重新探测 QUIC");
            }
            message = reader.next() => {
                let Some(message) = message else { return Ok(()) };
                match message? {
                    Message::Text(text) => {
                        match serde_json::from_str::<AgentControlMessage>(&text)? {
                            AgentControlMessage::Welcome { protocol_version, transport, .. } => {
                                if protocol_version != PROTOCOL_VERSION {
                                    anyhow::bail!("协议版本不兼容：服务器 {protocol_version}，客户端 {PROTOCOL_VERSION}");
                                }
                                state.set_transport(transport.unwrap_or(ActiveTransport::Wss), None).await;
                            }
                            AgentControlMessage::ConfigSync { tunnels } => {
                                *state.tunnels.write().await = tunnels;
                            }
                            AgentControlMessage::OpenConnection { connection_id, tunnel, peer_addr, peer_location, ticket, .. } => {
                                let state = state.clone();
                                let outbound = outbound_tx.clone();
                                let streams = streams.clone();
                                tauri::async_runtime::spawn(async move {
                                    state.log_with_location(
                                        "info",
                                        format!("{} 收到来自 {peer_addr} 的连接", tunnel.name),
                                        peer_location,
                                    ).await;
                                    {
                                        let mut metrics = state.metrics.write().await;
                                        metrics.active_connections += 1;
                                    }
                                    let result = open_multiplexed_stream(
                                        state.clone(), outbound, streams, connection_id, tunnel, ticket,
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
                            AgentControlMessage::OpenUdpSession { session_id, tunnel, peer_addr, peer_location, ticket, .. } => {
                                let state = state.clone();
                                let outbound = outbound_tx.clone();
                                let streams = streams.clone();
                                tauri::async_runtime::spawn(async move {
                                    state.log_with_location(
                                        "info",
                                        format!("{} 收到来自 {peer_addr} 的 UDP 会话", tunnel.name),
                                        peer_location,
                                    ).await;
                                    if let Err(error) = open_udp_session(
                                        state.clone(), outbound, streams, session_id, tunnel, ticket,
                                    ).await {
                                        state.log("error", format!("UDP 转发失败：{error:#}")).await;
                                    }
                                });
                            }
                            AgentControlMessage::Error { code, message } => {
                                state.log("error", format!("服务器错误 {code}：{message}")).await;
                            }
                            _ => {}
                        }
                    }
                    Message::Binary(frame) => {
                        if let Some((kind, id, payload)) = decode_carrier_frame(&frame)
                            && let Some(sender) = streams.get(&id)
                        {
                            let _ = sender.send((kind, payload.to_vec())).await;
                        }
                    }
                    Message::Ping(_) => {
                        outbound_tx.send(Outbound::control(AgentControlMessage::Pong { sent_at: Utc::now() })).await?;
                    }
                    Message::Close(_) => return Ok(()),
                    _ => {}
                }
            }
        }
    }
}

async fn run_quic_carrier(
    state: Arc<RuntimeState>,
    config: &AgentConfig,
    token: &str,
    cancellation: CancellationToken,
) -> Result<()> {
    let certificate_b64 = load_transport_certificate(config.installation_id)?;
    let certificate_der = STANDARD
        .decode(certificate_b64.trim())
        .context("解析固定的传输证书")?;
    let expected = load_transport_fingerprint(config.installation_id)?;
    let actual = hex::encode(Sha256::digest(&certificate_der));
    anyhow::ensure!(actual == expected, "传输证书指纹与注册记录不匹配");
    let certificate = rustls::pki_types::CertificateDer::from(certificate_der);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate)?;
    let rustls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let bind: std::net::SocketAddr = "0.0.0.0:0".parse()?;
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(client_config);
    let url = Url::parse(&config.server_url)?;
    let host = url.host_str().context("服务器地址缺少主机")?;
    let port = if config.quic_port == 0 {
        443
    } else {
        config.quic_port
    };
    let address = tokio::net::lookup_host((host, port))
        .await?
        .next()
        .context("无法解析服务器地址")?;
    let connection = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.connect(address, "tunnelbridge-transport")?,
    )
    .await
    .context("QUIC 连接超时")??;
    let (mut send, mut recv) = connection.open_bi().await?;
    let hello = AgentControlMessage::Hello {
        protocol_version: PROTOCOL_VERSION,
        agent_id: config.installation_id,
        name: config.device_name.clone(),
        capabilities: CarrierCapabilities {
            transports: vec![ActiveTransport::Quic, ActiveTransport::Wss],
            tunnel_kinds: vec![
                tunnelbridge_protocol::TunnelKind::Tcp,
                tunnelbridge_protocol::TunnelKind::Udp,
                tunnelbridge_protocol::TunnelKind::Web,
            ],
            ..CarrierCapabilities::default()
        },
        config_version: 0,
    };
    let auth = tunnelbridge_protocol::DirectCarrierAuth {
        token: token.to_owned(),
        hello,
    };
    write_direct_record(
        &mut send,
        DIRECT_RECORD_CONTROL,
        &serde_json::to_vec(&auth)?,
    )
    .await?;
    let streams = Arc::new(DashMap::<Uuid, mpsc::Sender<(u8, Vec<u8>)>>::new());
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Outbound>(256);
    let writer_connection = connection.clone();
    let writer_task = tauri::async_runtime::spawn(async move {
        while let Some(outbound) = outbound_rx.recv().await {
            match outbound {
                Outbound::Control(message) => {
                    write_direct_record(
                        &mut send,
                        DIRECT_RECORD_CONTROL,
                        &serde_json::to_vec(&message)?,
                    )
                    .await?;
                }
                Outbound::Binary(frame)
                    if frame.first() == Some(&tunnelbridge_protocol::CARRIER_FRAME_DATAGRAM) =>
                {
                    if writer_connection
                        .send_datagram(frame.clone().into())
                        .is_err()
                    {
                        write_direct_record(&mut send, DIRECT_RECORD_BINARY, &frame).await?;
                    }
                }
                Outbound::Binary(frame) => {
                    write_direct_record(&mut send, DIRECT_RECORD_BINARY, &frame).await?;
                }
                Outbound::Close => break,
            }
        }
        anyhow::Ok(())
    });
    state
        .set_status(AgentStatus::Online, "QUIC 承载已连接")
        .await;
    state.set_transport(ActiveTransport::Quic, None).await;
    state.log("info", "已通过 QUIC 连接中继服务器").await;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            _ = heartbeat.tick() => {
                outbound_tx.send(Outbound::control(AgentControlMessage::Ping { sent_at: Utc::now() })).await?;
            }
            record = read_direct_record(&mut recv) => {
                let (kind, payload) = record?;
                if kind == DIRECT_RECORD_BINARY {
                    route_local_frame(&streams, &payload).await;
                    continue;
                }
                let message: AgentControlMessage = serde_json::from_slice(&payload)?;
                dispatch_control_message(
                    state.clone(), outbound_tx.clone(), streams.clone(), message,
                ).await?;
            }
            datagram = connection.read_datagram() => {
                route_local_frame(&streams, &datagram?).await;
            }
        }
    }
    let _ = outbound_tx.send(Outbound::Close).await;
    writer_task.abort();
    connection.close(0_u32.into(), b"client closing");
    endpoint.wait_idle().await;
    Ok(())
}

pub(crate) async fn dispatch_control_message(
    state: Arc<RuntimeState>,
    outbound: mpsc::Sender<Outbound>,
    streams: LocalStreams,
    message: AgentControlMessage,
) -> Result<()> {
    match message {
        AgentControlMessage::Welcome {
            protocol_version,
            transport,
            ..
        } => {
            anyhow::ensure!(protocol_version == PROTOCOL_VERSION, "协议版本不兼容");
            state
                .set_transport(transport.unwrap_or(ActiveTransport::Quic), None)
                .await;
        }
        AgentControlMessage::ConfigSync { tunnels } => {
            *state.tunnels.write().await = tunnels;
        }
        AgentControlMessage::OpenConnection {
            connection_id,
            tunnel,
            peer_addr,
            peer_location,
            ticket,
            ..
        } => {
            let task_state = state.clone();
            let task_outbound = outbound.clone();
            let task_streams = streams.clone();
            tauri::async_runtime::spawn(async move {
                task_state
                    .log_with_location(
                        "info",
                        format!("{} 收到来自 {peer_addr} 的连接", tunnel.name),
                        peer_location,
                    )
                    .await;
                if let Err(error) = open_multiplexed_stream(
                    task_state.clone(),
                    task_outbound,
                    task_streams,
                    connection_id,
                    tunnel,
                    ticket,
                )
                .await
                {
                    task_state
                        .log("error", format!("转发连接失败：{error:#}"))
                        .await;
                }
            });
        }
        AgentControlMessage::OpenUdpSession {
            session_id,
            tunnel,
            peer_addr,
            peer_location,
            ticket,
            ..
        } => {
            let task_state = state.clone();
            let task_outbound = outbound.clone();
            let task_streams = streams.clone();
            tauri::async_runtime::spawn(async move {
                task_state
                    .log_with_location(
                        "info",
                        format!("{} 收到来自 {peer_addr} 的 UDP 会话", tunnel.name),
                        peer_location,
                    )
                    .await;
                if let Err(error) = open_udp_session(
                    task_state.clone(),
                    task_outbound,
                    task_streams,
                    session_id,
                    tunnel,
                    ticket,
                )
                .await
                {
                    task_state
                        .log("error", format!("UDP 转发失败：{error:#}"))
                        .await;
                }
            });
        }
        AgentControlMessage::Error { code, message } => {
            state
                .log("error", format!("服务器错误 {code}：{message}"))
                .await;
        }
        _ => {}
    }
    Ok(())
}

async fn route_local_frame(streams: &DashMap<Uuid, mpsc::Sender<(u8, Vec<u8>)>>, frame: &[u8]) {
    if let Some((kind, id, payload)) = decode_carrier_frame(frame)
        && let Some(sender) = streams.get(&id)
    {
        let _ = sender.send((kind, payload.to_vec())).await;
    }
}

pub(crate) async fn read_direct_record<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(u8, Vec<u8>)> {
    let kind = reader.read_u8().await?;
    let length = reader.read_u32().await? as usize;
    anyhow::ensure!(length <= MAX_DIRECT_RECORD, "承载记录过大");
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    Ok((kind, payload))
}

pub(crate) async fn write_direct_record<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    kind: u8,
    payload: &[u8],
) -> Result<()> {
    writer.write_u8(kind).await?;
    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn open_udp_session(
    state: Arc<RuntimeState>,
    outbound: mpsc::Sender<Outbound>,
    streams: LocalStreams,
    session_id: Uuid,
    tunnel: Tunnel,
    ticket: String,
) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    if let Err(error) = socket
        .connect((tunnel.local_host.as_str(), tunnel.local_port))
        .await
    {
        outbound
            .send(Outbound::control(AgentControlMessage::ConnectionAck {
                connection_id: session_id,
                accepted: false,
                error: Some(format!("连接本地 UDP 目标失败：{error}")),
                ticket: Some(ticket),
            }))
            .await?;
        return Err(error.into());
    }
    let socket = Arc::new(socket);
    let (stream_tx, mut stream_rx) = mpsc::channel::<(u8, Vec<u8>)>(64);
    streams.insert(session_id, stream_tx);
    outbound
        .send(Outbound::control(AgentControlMessage::ConnectionAck {
            connection_id: session_id,
            accepted: true,
            error: None,
            ticket: Some(ticket),
        }))
        .await?;
    let inbound_socket = socket.clone();
    let inbound = async {
        while let Some((kind, payload)) = stream_rx.recv().await {
            if kind == tunnelbridge_protocol::CARRIER_FRAME_DATAGRAM {
                inbound_socket.send(&payload).await?;
                state.metrics.write().await.bytes_down += payload.len() as u64;
            }
        }
        anyhow::Ok(())
    };
    let outbound_socket = socket;
    let outbound_sender = outbound;
    let outgoing = async {
        let mut buffer = vec![0_u8; tunnelbridge_protocol::MAX_UDP_DATAGRAM];
        loop {
            let count =
                tokio::time::timeout(Duration::from_secs(60), outbound_socket.recv(&mut buffer))
                    .await
                    .context("UDP 会话空闲超时")??;
            outbound_sender
                .send(Outbound::Binary(encode_carrier_frame(
                    tunnelbridge_protocol::CARRIER_FRAME_DATAGRAM,
                    session_id,
                    &buffer[..count],
                )))
                .await?;
            state.metrics.write().await.bytes_up += count as u64;
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    };
    tokio::select! {
        result = inbound => result?,
        result = outgoing => result?,
    }
    streams.remove(&session_id);
    Ok(())
}

async fn open_multiplexed_stream(
    state: Arc<RuntimeState>,
    outbound: mpsc::Sender<Outbound>,
    streams: LocalStreams,
    connection_id: Uuid,
    tunnel: Tunnel,
    ticket: String,
) -> Result<()> {
    let local = match TcpStream::connect((tunnel.local_host.as_str(), tunnel.local_port)).await {
        Ok(local) => local,
        Err(error) => {
            outbound
                .send(Outbound::control(AgentControlMessage::ConnectionAck {
                    connection_id,
                    accepted: false,
                    error: Some(format!("连接本地目标失败：{error}")),
                    ticket: Some(ticket),
                }))
                .await?;
            return Err(error).with_context(|| {
                format!("连接本地目标 {}:{}", tunnel.local_host, tunnel.local_port)
            });
        }
    };
    let (stream_tx, stream_rx) = mpsc::channel(64);
    streams.insert(connection_id, stream_tx);
    outbound
        .send(Outbound::control(AgentControlMessage::ConnectionAck {
            connection_id,
            accepted: true,
            error: None,
            ticket: Some(ticket),
        }))
        .await?;
    let result = if tunnel.kind == tunnelbridge_protocol::TunnelKind::Web
        && tunnel.local_scheme == tunnelbridge_protocol::LocalScheme::Https
    {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
        let server_name = rustls::pki_types::ServerName::try_from(tunnel.local_host.clone())
            .context("本地 HTTPS 主机名无法用于证书校验")?;
        let local = connector
            .connect(server_name, local)
            .await
            .context("本地 HTTPS 证书校验失败")?;
        bridge_local(state, connection_id, local, outbound.clone(), stream_rx).await
    } else {
        bridge_local(state, connection_id, local, outbound.clone(), stream_rx).await
    };
    streams.remove(&connection_id);
    result
}

async fn bridge_local<S>(
    state: Arc<RuntimeState>,
    connection_id: Uuid,
    local: S,
    outbound: mpsc::Sender<Outbound>,
    mut inbound: mpsc::Receiver<(u8, Vec<u8>)>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut local_read, mut local_write) = tokio::io::split(local);
    let upstream_state = state.clone();
    let upstream_outbound = outbound.clone();
    let upstream = async move {
        let mut buffer = vec![0_u8; 32 * 1024];
        loop {
            let count =
                tokio::time::timeout(Duration::from_secs(600), local_read.read(&mut buffer))
                    .await
                    .context("连接空闲超时")??;
            if count == 0 {
                upstream_outbound
                    .send(Outbound::Binary(encode_carrier_frame(
                        CARRIER_FRAME_FIN,
                        connection_id,
                        &[],
                    )))
                    .await?;
                break;
            }
            upstream_outbound
                .send(Outbound::Binary(encode_carrier_frame(
                    CARRIER_FRAME_DATA,
                    connection_id,
                    &buffer[..count],
                )))
                .await?;
            upstream_state.metrics.write().await.bytes_up += count as u64;
        }
        anyhow::Ok(())
    };
    let downstream = async move {
        loop {
            let message = tokio::time::timeout(Duration::from_secs(600), inbound.recv())
                .await
                .context("连接空闲超时")?;
            let Some(message) = message else { break };
            match message.0 {
                CARRIER_FRAME_DATA => {
                    local_write.write_all(&message.1).await?;
                    state.metrics.write().await.bytes_down += message.1.len() as u64;
                }
                CARRIER_FRAME_FIN => {
                    local_write.shutdown().await?;
                    break;
                }
                CARRIER_FRAME_RESET => anyhow::bail!("服务端重置了逻辑流"),
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
