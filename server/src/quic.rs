use std::{net::SocketAddr, sync::atomic::Ordering};

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};
use tunnelbridge_protocol::{
    ActiveTransport, AgentControlMessage, CARRIER_FRAME_DATAGRAM, DirectCarrierAuth,
    PROTOCOL_VERSION,
};
use uuid::Uuid;

use crate::{
    auth::authenticate_device_token,
    gateway,
    state::{AgentPeer, SharedState},
    transport_identity,
};

const RECORD_CONTROL: u8 = 0;
const RECORD_BINARY: u8 = 1;
const MAX_RECORD_SIZE: usize = 16 * 1024 * 1024;

pub async fn serve(state: SharedState) {
    if let Err(error) = serve_inner(state.clone()).await {
        tracing::error!(error = %error, "QUIC carrier stopped");
        state.counters.failed.fetch_add(1, Ordering::Relaxed);
    }
}

async fn serve_inner(state: SharedState) -> Result<()> {
    let mut config = quinn::ServerConfig::with_single_cert(
        vec![transport_identity::certificate()?],
        transport_identity::private_key()?,
    )?;
    let transport = std::sync::Arc::get_mut(&mut config.transport)
        .context("QUIC transport config is shared")?;
    transport.max_concurrent_bidi_streams(512_u32.into());
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    let address: SocketAddr = ([0, 0, 0, 0], state.config.quic_listen_port).into();
    let endpoint = quinn::Endpoint::server(config, address)?;
    tracing::info!(address = %address, "QUIC carrier ready");
    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = accept(state, incoming).await {
                tracing::warn!(error = %error, "QUIC carrier connection failed");
            }
        });
    }
    Ok(())
}

async fn accept(state: SharedState, incoming: quinn::Incoming) -> Result<()> {
    let connection = incoming.await?;
    let (mut send, mut recv) = connection.accept_bi().await?;
    let (record_type, payload) = read_record(&mut recv).await?;
    anyhow::ensure!(record_type == RECORD_CONTROL, "missing direct carrier auth");
    let auth: DirectCarrierAuth = serde_json::from_slice(&payload)?;
    let identity = authenticate_device_token(&state, &auth.token)
        .await
        .map_err(|_| anyhow::anyhow!("invalid device token"))?;
    match auth.hello {
        AgentControlMessage::Hello {
            protocol_version, ..
        } if protocol_version == PROTOCOL_VERSION => {}
        _ => anyhow::bail!("protocol mismatch"),
    }

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
            transport: ActiveTransport::Quic,
            cancellation: cancellation.clone(),
        },
    );
    state.counters.quic.fetch_add(1, Ordering::Relaxed);
    let _ = control_tx.send(AgentControlMessage::Welcome {
        protocol_version: PROTOCOL_VERSION,
        server_time: Utc::now(),
        capabilities: super::api::server_capabilities(),
        transport: Some(ActiveTransport::Quic),
    });
    gateway::sync_agent(&state, identity.id).await;

    let writer_connection = connection.clone();
    let writer = tokio::spawn(async move {
        loop {
            tokio::select! {
                control = control_rx.recv() => {
                    let Some(control) = control else { break };
                    write_record(&mut send, RECORD_CONTROL, &serde_json::to_vec(&control)?).await?;
                }
                binary = binary_rx.recv() => {
                    let Some(binary) = binary else { break };
                    if binary.first() == Some(&CARRIER_FRAME_DATAGRAM) {
                        if writer_connection.send_datagram(binary.clone().into()).is_err() {
                            write_record(&mut send, RECORD_BINARY, &binary).await?;
                        }
                    } else {
                        write_record(&mut send, RECORD_BINARY, &binary).await?;
                    }
                }
            }
        }
        anyhow::Ok(())
    });

    let datagram_state = state.clone();
    let datagram_connection = connection.clone();
    let datagrams = tokio::spawn(async move {
        while let Ok(frame) = datagram_connection.read_datagram().await {
            gateway::route_carrier_frame(&datagram_state, &frame).await;
        }
    });

    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            record = read_record(&mut recv) => {
                let Ok((record_type, payload)) = record else { break };
                if record_type == RECORD_BINARY {
                    gateway::route_carrier_frame(&state, &payload).await;
                    continue;
                }
                let Ok(message) = serde_json::from_slice::<AgentControlMessage>(&payload) else { continue };
                match message {
                    AgentControlMessage::Ping { sent_at } => {
                        let _ = control_tx.send(AgentControlMessage::Pong { sent_at });
                    }
                    AgentControlMessage::ConnectionAck { connection_id, accepted, error, ticket } => {
                        gateway::acknowledge_connection(
                            &state, connection_id, identity.id, ticket.as_deref(), accepted, error,
                        );
                    }
                    _ => {}
                }
            }
        }
    }
    writer.abort();
    datagrams.abort();
    if state
        .agents
        .get(&identity.id)
        .is_some_and(|peer| peer.session_id == session_id)
    {
        state.agents.remove(&identity.id);
    }
    state.counters.quic.fetch_sub(1, Ordering::Relaxed);
    connection.close(0_u32.into(), b"carrier closed");
    Ok(())
}

async fn read_record<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<(u8, Vec<u8>)> {
    let kind = reader.read_u8().await?;
    let length = reader.read_u32().await? as usize;
    anyhow::ensure!(length <= MAX_RECORD_SIZE, "carrier record too large");
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    Ok((kind, payload))
}

async fn write_record<W: AsyncWriteExt + Unpin>(
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
