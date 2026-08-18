use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Instant,
};

use anyhow::Context;
use chrono::Utc;
use tokio::{net::UdpSocket, sync::mpsc};
use tunnelbridge_protocol::{
    AgentControlMessage, CARRIER_FRAME_DATAGRAM, MAX_UDP_DATAGRAM, Tunnel, encode_carrier_frame,
};
use uuid::Uuid;

use crate::{
    auth::{hash_token, random_secret},
    state::{InboundCarrierFrame, PendingConnection, SharedState},
    tunnels,
};

struct Session {
    id: Uuid,
    last_seen: Instant,
}

pub async fn start_listener(state: SharedState, tunnel: Tunnel) {
    let cancellation = tokio_util::sync::CancellationToken::new();
    state.listeners.insert(tunnel.id, cancellation.clone());
    tokio::spawn(async move {
        let Some(port) = tunnel.remote_port else {
            return;
        };
        let socket = match UdpSocket::bind(("0.0.0.0", port)).await {
            Ok(socket) => Arc::new(socket),
            Err(error) => {
                tracing::error!(tunnel_id = %tunnel.id, port, error = %error, "failed to bind UDP tunnel");
                state.listeners.remove(&tunnel.id);
                state.counters.failed.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let mut sessions = HashMap::<SocketAddr, Session>::new();
        let mut buffer = vec![0_u8; MAX_UDP_DATAGRAM];
        let mut cleanup = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = cleanup.tick() => {
                    let now = Instant::now();
                    sessions.retain(|_, session| {
                        let keep = now.duration_since(session.last_seen) < state.config.udp_session_timeout;
                        if !keep {
                            state.streams.remove(&session.id);
                            state.active.remove(&session.id);
                            state.counters.active_udp.fetch_sub(1, Ordering::Relaxed);
                        }
                        keep
                    });
                }
                received = socket.recv_from(&mut buffer) => {
                    let Ok((count, peer)) = received else { continue };
                    if !tunnels::source_allowed(&tunnel, peer.ip()) {
                        state.counters.rejected.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let session_id = if let Some(session) = sessions.get_mut(&peer) {
                        session.last_seen = Instant::now();
                        session.id
                    } else {
                        match open_session(&state, &tunnel, peer, socket.clone()).await {
                            Ok(id) => {
                                sessions.insert(peer, Session { id, last_seen: Instant::now() });
                                id
                            }
                            Err(error) => {
                                tracing::warn!(tunnel_id = %tunnel.id, peer = %peer, error = %error, "failed to open UDP session");
                                state.counters.failed.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        }
                    };
                    let Some(agent) = state.agents.get(&tunnel.agent_id).map(|agent| agent.clone()) else { continue };
                    if agent.binary_sender.send(encode_carrier_frame(
                        CARRIER_FRAME_DATAGRAM,
                        session_id,
                        &buffer[..count],
                    )).await.is_err() {
                        sessions.remove(&peer);
                    } else {
                        state.counters.add_down(count as u64);
                    }
                }
            }
        }
        for session in sessions.values() {
            state.streams.remove(&session.id);
            state.active.remove(&session.id);
        }
        tracing::info!(tunnel_id = %tunnel.id, "UDP tunnel listener stopped");
    });
}

async fn open_session(
    state: &SharedState,
    tunnel: &Tunnel,
    peer: SocketAddr,
    socket: Arc<UdpSocket>,
) -> anyhow::Result<Uuid> {
    let agent = state
        .agents
        .get(&tunnel.agent_id)
        .map(|agent| agent.clone())
        .context("agent is offline")?;
    let id = Uuid::new_v4();
    let ticket = random_secret(32);
    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    let (frame_tx, mut frame_rx) = mpsc::channel::<InboundCarrierFrame>(64);
    state.streams.insert(id, frame_tx);
    state.pending.insert(
        id,
        PendingConnection {
            agent_id: tunnel.agent_id,
            ticket_hash: hash_token(&ticket),
            expires_at: Instant::now() + state.config.ticket_ttl,
            ack_tx,
        },
    );
    agent.sender.send(AgentControlMessage::OpenUdpSession {
        session_id: id,
        tunnel: tunnel.clone(),
        peer_addr: peer.to_string(),
        peer_location: state.geoip.lookup(peer.ip()).await,
        ticket,
        expires_at: Utc::now()
            + chrono::Duration::from_std(state.config.ticket_ttl)
                .unwrap_or(chrono::Duration::seconds(15)),
    })?;
    match tokio::time::timeout(state.config.connect_timeout, ack_rx).await {
        Ok(Ok(Ok(()))) => {}
        result => {
            state.pending.remove(&id);
            state.streams.remove(&id);
            match result {
                Ok(Ok(Err(error))) => anyhow::bail!(error),
                _ => anyhow::bail!("UDP session acknowledgement timed out"),
            }
        }
    }
    state.counters.active_udp.fetch_add(1, Ordering::Relaxed);
    state.active.insert(
        id,
        tunnelbridge_protocol::ActiveConnection {
            id,
            tunnel_id: tunnel.id,
            peer_addr: peer.to_string(),
            peer_location: state.geoip.lookup(peer.ip()).await,
            opened_at: Utc::now(),
            bytes_up: 0,
            bytes_down: 0,
            tunnel_kind: tunnel.kind,
            transport: Some(agent.transport),
        },
    );
    let response_state = state.clone();
    tokio::spawn(async move {
        while let Some(frame) = frame_rx.recv().await {
            if frame.kind == CARRIER_FRAME_DATAGRAM {
                if socket.send_to(&frame.payload, peer).await.is_err() {
                    break;
                }
                response_state.counters.add_up(frame.payload.len() as u64);
            }
        }
    });
    Ok(id)
}
