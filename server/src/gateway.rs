use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::Context;
use chrono::Utc;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;
use tunnelbridge_protocol::{
    ActiveConnection, AgentControlMessage, CARRIER_FRAME_DATA, CARRIER_FRAME_FIN,
    CARRIER_FRAME_RESET, Tunnel, TunnelKind, encode_carrier_frame,
};
use uuid::Uuid;

use crate::{
    auth::{hash_token, random_secret},
    state::{InboundCarrierFrame, PendingConnection, SharedState},
    tunnels,
};

pub async fn restore_listeners(state: &SharedState) -> anyhow::Result<()> {
    for tunnel in tunnels::list_all(&state.db)
        .await
        .map_err(|e| anyhow::anyhow!(e))?
    {
        if tunnel.enabled && tunnel.kind != TunnelKind::Web {
            start_listener(state.clone(), tunnel).await;
        }
    }
    Ok(())
}

pub async fn reconcile_listener(state: SharedState, tunnel: Tunnel) {
    stop_listener(&state, tunnel.id);
    if tunnel.enabled && tunnel.kind != TunnelKind::Web {
        tokio::time::sleep(Duration::from_millis(25)).await;
        start_listener(state, tunnel).await;
    }
}

pub fn stop_listener(state: &SharedState, tunnel_id: Uuid) {
    if let Some((_, token)) = state.listeners.remove(&tunnel_id) {
        token.cancel();
    }
}

pub async fn sync_agent(state: &SharedState, agent_id: Uuid) {
    let Ok(items) = tunnels::list_for_agent(&state.db, agent_id).await else {
        return;
    };
    if let Some(peer) = state.agents.get(&agent_id) {
        let _ = peer
            .sender
            .send(AgentControlMessage::ConfigSync { tunnels: items });
    }
}

async fn start_listener(state: SharedState, tunnel: Tunnel) {
    if tunnel.kind != TunnelKind::Tcp {
        start_udp_listener(state, tunnel).await;
        return;
    }
    let cancellation = CancellationToken::new();
    state.listeners.insert(tunnel.id, cancellation.clone());
    tokio::spawn(async move {
        let Some(remote_port) = tunnel.remote_port else {
            return;
        };
        let listener = match bind_dual_stack(remote_port) {
            Ok(listener) => listener,
            Err(error) => {
                tracing::error!(tunnel_id = %tunnel.id, port = remote_port, error = %error, "failed to bind tunnel listener");
                state.listeners.remove(&tunnel.id);
                state
                    .counters
                    .failed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
        };
        tracing::info!(tunnel_id = %tunnel.id, port = remote_port, "tunnel listener online");
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        let state = state.clone();
                        let tunnel = tunnel.clone();
                        tokio::spawn(async move {
                            if let Err(error) = accept_public_connection(state, tunnel, stream, peer).await {
                                tracing::warn!(error = %error, "public connection failed");
                            }
                        });
                    }
                    Err(error) => tracing::warn!(error = %error, "accept failed"),
                }
            }
        }
        tracing::info!(tunnel_id = %tunnel.id, "tunnel listener stopped");
    });
}

fn bind_dual_stack(port: u16) -> std::io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::from(([0_u16; 8], port)).into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

async fn accept_public_connection(
    state: SharedState,
    tunnel: Tunnel,
    tcp: TcpStream,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    if !tunnels::source_allowed(&tunnel, peer.ip()) {
        state
            .counters
            .rejected
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        anyhow::bail!("source {} is not allowed", peer.ip());
    }
    let agent = state
        .agents
        .get(&tunnel.agent_id)
        .map(|entry| entry.clone());
    let Some(agent) = agent else {
        state
            .counters
            .failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        anyhow::bail!("agent is offline");
    };
    let peer_location = state.geoip.lookup(peer.ip()).await;
    let connection_id = Uuid::new_v4();
    let ticket = random_secret(32);
    let (ack_tx, ack_rx) = oneshot::channel();
    let (frame_tx, frame_rx) = mpsc::channel(64);
    state.streams.insert(connection_id, frame_tx);
    state.pending.insert(
        connection_id,
        PendingConnection {
            agent_id: tunnel.agent_id,
            ticket_hash: hash_token(&ticket),
            expires_at: Instant::now() + state.config.ticket_ttl,
            ack_tx,
        },
    );
    let expires_at = Utc::now()
        + chrono::Duration::from_std(state.config.ticket_ttl)
            .unwrap_or(chrono::Duration::seconds(15));
    agent
        .sender
        .send(AgentControlMessage::OpenConnection {
            connection_id,
            tunnel: tunnel.clone(),
            peer_addr: peer.to_string(),
            peer_location: peer_location.clone(),
            ticket,
            expires_at,
        })
        .context("send open connection to agent")?;
    match tokio::time::timeout(state.config.connect_timeout, ack_rx).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => {
            state.pending.remove(&connection_id);
            state.streams.remove(&connection_id);
            anyhow::bail!("agent rejected connection: {error}");
        }
        _ => {
            state.pending.remove(&connection_id);
            state.streams.remove(&connection_id);
            state
                .counters
                .failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            anyhow::bail!("agent multiplexed stream timed out");
        }
    }
    let active = ActiveConnection {
        id: connection_id,
        tunnel_id: tunnel.id,
        peer_addr: peer.to_string(),
        peer_location,
        opened_at: Utc::now(),
        bytes_up: 0,
        bytes_down: 0,
        tunnel_kind: tunnel.kind,
        transport: Some(agent.transport),
    };
    state.active.insert(connection_id, active);
    let result = bridge(
        state.clone(),
        connection_id,
        tcp,
        agent.binary_sender.clone(),
        frame_rx,
    )
    .await;
    state.streams.remove(&connection_id);
    if let Some((_, summary)) = state.active.remove(&connection_id)
        && let Err(error) = sqlx::query(
            r#"INSERT INTO connection_history
            (id, tunnel_id, peer_addr, opened_at, closed_at, bytes_up, bytes_down)
            VALUES (?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(summary.id.to_string())
        .bind(summary.tunnel_id.to_string())
        .bind(summary.peer_addr)
        .bind(summary.opened_at.to_rfc3339())
        .bind(Utc::now().to_rfc3339())
        .bind(summary.bytes_up as i64)
        .bind(summary.bytes_down as i64)
        .execute(&state.db)
        .await
    {
        tracing::warn!(connection_id = %connection_id, error = %error, "failed to persist connection summary");
    }
    result
}

pub fn acknowledge_connection(
    state: &SharedState,
    connection_id: Uuid,
    agent_id: Uuid,
    ticket: Option<&str>,
    accepted: bool,
    error: Option<String>,
) -> bool {
    {
        let Some(pending) = state.pending.get(&connection_id) else {
            return false;
        };
        if pending.agent_id != agent_id
            || pending.expires_at <= Instant::now()
            || ticket.is_none_or(|ticket| pending.ticket_hash != hash_token(ticket))
        {
            return false;
        }
    }
    let Some((_, pending)) = state.pending.remove(&connection_id) else {
        return false;
    };
    let _ = pending.ack_tx.send(if accepted {
        Ok(())
    } else {
        Err(error.unwrap_or_else(|| "local target rejected connection".into()))
    });
    true
}

pub async fn route_carrier_frame(state: &SharedState, frame: &[u8]) {
    let Some((kind, id, payload)) = tunnelbridge_protocol::decode_carrier_frame(frame) else {
        return;
    };
    if let Some(sender) = state.streams.get(&id) {
        let _ = sender
            .send(InboundCarrierFrame {
                kind,
                payload: payload.to_vec(),
            })
            .await;
    }
}

async fn bridge<S>(
    state: SharedState,
    connection_id: Uuid,
    tcp: S,
    carrier: mpsc::Sender<Vec<u8>>,
    mut inbound: mpsc::Receiver<InboundCarrierFrame>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp);
    let upstream_carrier = carrier.clone();
    let upstream = async {
        let mut buffer = vec![0_u8; 32 * 1024];
        loop {
            let count = tokio::time::timeout(state.config.idle_timeout, tcp_read.read(&mut buffer))
                .await
                .context("connection idle timeout")??;
            if count == 0 {
                upstream_carrier
                    .send(encode_carrier_frame(CARRIER_FRAME_FIN, connection_id, &[]))
                    .await?;
                break;
            }
            upstream_carrier
                .send(encode_carrier_frame(
                    CARRIER_FRAME_DATA,
                    connection_id,
                    &buffer[..count],
                ))
                .await?;
            state.counters.add_down(count as u64);
            if let Some(mut active) = state.active.get_mut(&connection_id) {
                active.bytes_down += count as u64;
            }
        }
        anyhow::Ok(())
    };
    let downstream = async {
        loop {
            let message = tokio::time::timeout(state.config.idle_timeout, inbound.recv())
                .await
                .context("connection idle timeout")?;
            let Some(message) = message else { break };
            match message.kind {
                CARRIER_FRAME_DATA => {
                    tcp_write.write_all(&message.payload).await?;
                    state.counters.add_up(message.payload.len() as u64);
                    if let Some(mut active) = state.active.get_mut(&connection_id) {
                        active.bytes_up += message.payload.len() as u64;
                    }
                }
                CARRIER_FRAME_FIN => {
                    tcp_write.shutdown().await?;
                    break;
                }
                CARRIER_FRAME_RESET => anyhow::bail!("agent reset stream"),
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

pub async fn open_virtual_stream(
    state: SharedState,
    tunnel: Tunnel,
    peer: SocketAddr,
) -> anyhow::Result<tokio::io::DuplexStream> {
    if !tunnels::source_allowed(&tunnel, peer.ip()) {
        state
            .counters
            .rejected
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        anyhow::bail!("source {} is not allowed", peer.ip());
    }
    let agent = state
        .agents
        .get(&tunnel.agent_id)
        .map(|entry| entry.clone())
        .context("agent is offline")?;
    let connection_id = Uuid::new_v4();
    let ticket = random_secret(32);
    let (ack_tx, ack_rx) = oneshot::channel();
    let (frame_tx, frame_rx) = mpsc::channel(64);
    state.streams.insert(connection_id, frame_tx);
    state.pending.insert(
        connection_id,
        PendingConnection {
            agent_id: tunnel.agent_id,
            ticket_hash: hash_token(&ticket),
            expires_at: Instant::now() + state.config.ticket_ttl,
            ack_tx,
        },
    );
    let peer_location = state.geoip.lookup(peer.ip()).await;
    agent.sender.send(AgentControlMessage::OpenConnection {
        connection_id,
        tunnel: tunnel.clone(),
        peer_addr: peer.to_string(),
        peer_location: peer_location.clone(),
        ticket,
        expires_at: Utc::now()
            + chrono::Duration::from_std(state.config.ticket_ttl)
                .unwrap_or(chrono::Duration::seconds(15)),
    })?;
    match tokio::time::timeout(state.config.connect_timeout, ack_rx).await {
        Ok(Ok(Ok(()))) => {}
        result => {
            state.pending.remove(&connection_id);
            state.streams.remove(&connection_id);
            match result {
                Ok(Ok(Err(error))) => anyhow::bail!(error),
                _ => anyhow::bail!("web stream acknowledgement timed out"),
            }
        }
    }
    state.active.insert(
        connection_id,
        ActiveConnection {
            id: connection_id,
            tunnel_id: tunnel.id,
            peer_addr: peer.to_string(),
            peer_location,
            opened_at: Utc::now(),
            bytes_up: 0,
            bytes_down: 0,
            tunnel_kind: tunnel.kind,
            transport: Some(agent.transport),
        },
    );
    let (application, bridge_stream) = tokio::io::duplex(128 * 1024);
    let bridge_state = state.clone();
    tokio::spawn(async move {
        let result = bridge(
            bridge_state.clone(),
            connection_id,
            bridge_stream,
            agent.binary_sender.clone(),
            frame_rx,
        )
        .await;
        bridge_state.streams.remove(&connection_id);
        bridge_state.active.remove(&connection_id);
        if let Err(error) = result {
            tracing::debug!(connection_id = %connection_id, error = %error, "web stream closed");
        }
    });
    Ok(application)
}

async fn start_udp_listener(state: SharedState, tunnel: Tunnel) {
    crate::udp::start_listener(state, tunnel).await;
}

pub fn parse_forwarded_ip(value: Option<&str>) -> Option<IpAddr> {
    value?.split(',').next()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_ip_uses_first_hop() {
        assert_eq!(
            parse_forwarded_ip(Some("203.0.113.9, 10.0.0.2")),
            Some("203.0.113.9".parse().unwrap())
        );
    }
}
