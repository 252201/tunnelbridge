use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
};

use anyhow::Result;
use chrono::Utc;
use kcp_tokio::{KcpConfig, KcpListener};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;
use tunnelbridge_protocol::{
    ActiveTransport, AgentControlMessage, DirectCarrierAuth, PROTOCOL_VERSION,
};
use uuid::Uuid;

use crate::{
    auth::authenticate_device_token,
    gateway,
    state::{AgentPeer, SharedState},
    transport_identity,
};

const CONTROL: u8 = 0;
const BINARY: u8 = 1;
const MAX_RECORD: usize = 16 * 1024 * 1024;

pub async fn serve(state: SharedState) {
    if let Err(error) = serve_inner(state.clone()).await {
        tracing::error!(error = %error, "KCP carrier stopped");
        state.counters.failed.fetch_add(1, Ordering::Relaxed);
    }
}

async fn serve_inner(state: SharedState) -> Result<()> {
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![transport_identity::certificate()?],
            transport_identity::private_key()?,
        )?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let address: SocketAddr = ([0, 0, 0, 0], state.config.kcp_port).into();
    let config = KcpConfig::new().fast_mode().stream_mode(true);
    let mut listener = KcpListener::bind(address, config).await?;
    tracing::info!(address = %address, "KCP carrier ready");
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(stream) => {
                    if let Err(error) = run_stream(state, stream).await {
                        tracing::warn!(peer = %peer, error = %error, "KCP carrier connection failed");
                    }
                }
                Err(error) => {
                    tracing::warn!(peer = %peer, error = %error, "KCP TLS handshake failed")
                }
            }
        });
    }
}

async fn run_stream<S>(state: SharedState, stream: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (kind, payload) = read_record(&mut reader).await?;
    anyhow::ensure!(kind == CONTROL, "missing KCP carrier auth");
    let auth: DirectCarrierAuth = serde_json::from_slice(&payload)?;
    let identity = authenticate_device_token(&state, &auth.token)
        .await
        .map_err(|_| anyhow::anyhow!("invalid device token"))?;
    anyhow::ensure!(
        matches!(auth.hello, AgentControlMessage::Hello { protocol_version, .. } if protocol_version == PROTOCOL_VERSION),
        "protocol mismatch"
    );
    let session_id = Uuid::new_v4();
    let cancellation = tokio_util::sync::CancellationToken::new();
    let (control_tx, mut control_rx) = mpsc::unbounded_channel();
    let (binary_tx, mut binary_rx) = mpsc::channel::<Vec<u8>>(256);
    state.agents.insert(
        identity.id,
        AgentPeer {
            session_id,
            sender: control_tx.clone(),
            binary_sender: binary_tx,
            transport: ActiveTransport::Kcp,
            cancellation: cancellation.clone(),
        },
    );
    state.counters.kcp.fetch_add(1, Ordering::Relaxed);
    let _ = control_tx.send(AgentControlMessage::Welcome {
        protocol_version: PROTOCOL_VERSION,
        server_time: Utc::now(),
        capabilities: super::api::server_capabilities(),
        transport: Some(ActiveTransport::Kcp),
    });
    gateway::sync_agent(&state, identity.id).await;
    let writer_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                message = control_rx.recv() => {
                    let Some(message) = message else { break };
                    write_record(&mut writer, CONTROL, &serde_json::to_vec(&message)?).await?;
                }
                frame = binary_rx.recv() => {
                    let Some(frame) = frame else { break };
                    write_record(&mut writer, BINARY, &frame).await?;
                }
            }
        }
        anyhow::Ok(())
    });
    loop {
        let (kind, payload) = tokio::select! {
            _ = cancellation.cancelled() => break,
            record = read_record(&mut reader) => match record { Ok(value) => value, Err(_) => break },
        };
        if kind == BINARY {
            gateway::route_carrier_frame(&state, &payload).await;
            continue;
        }
        let Ok(message) = serde_json::from_slice::<AgentControlMessage>(&payload) else {
            continue;
        };
        match message {
            AgentControlMessage::Ping { sent_at } => {
                let _ = control_tx.send(AgentControlMessage::Pong { sent_at });
            }
            AgentControlMessage::ConnectionAck {
                connection_id,
                accepted,
                error,
                ticket,
            } => {
                gateway::acknowledge_connection(
                    &state,
                    connection_id,
                    identity.id,
                    ticket.as_deref(),
                    accepted,
                    error,
                );
            }
            _ => {}
        }
    }
    writer_task.abort();
    if state
        .agents
        .get(&identity.id)
        .is_some_and(|peer| peer.session_id == session_id)
    {
        state.agents.remove(&identity.id);
    }
    state.counters.kcp.fetch_sub(1, Ordering::Relaxed);
    Ok(())
}

async fn read_record<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(u8, Vec<u8>)> {
    let kind = reader.read_u8().await?;
    let length = reader.read_u32().await? as usize;
    anyhow::ensure!(length <= MAX_RECORD, "KCP carrier record too large");
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    Ok((kind, payload))
}

async fn write_record<W: AsyncWrite + Unpin>(
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
