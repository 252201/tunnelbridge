use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::Context;
use axum::extract::ws::{Message, WebSocket};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use tokio_util::sync::CancellationToken;
use tunnelbridge_protocol::{
    ActiveConnection, AgentControlMessage, DATA_FRAME_BYTES, DATA_FRAME_EOF, Tunnel,
};
use uuid::Uuid;

use crate::{
    auth::{hash_token, random_secret},
    state::{PendingConnection, SharedState},
    tunnels,
};

pub async fn restore_listeners(state: &SharedState) -> anyhow::Result<()> {
    for tunnel in tunnels::list_all(&state.db)
        .await
        .map_err(|e| anyhow::anyhow!(e))?
    {
        if tunnel.enabled {
            start_listener(state.clone(), tunnel).await;
        }
    }
    Ok(())
}

pub async fn reconcile_listener(state: SharedState, tunnel: Tunnel) {
    stop_listener(&state, tunnel.id);
    if tunnel.enabled {
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
    let cancellation = CancellationToken::new();
    state.listeners.insert(tunnel.id, cancellation.clone());
    tokio::spawn(async move {
        let listener = match bind_dual_stack(tunnel.remote_port) {
            Ok(listener) => listener,
            Err(error) => {
                tracing::error!(tunnel_id = %tunnel.id, port = tunnel.remote_port, error = %error, "failed to bind tunnel listener");
                state.listeners.remove(&tunnel.id);
                state
                    .counters
                    .failed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
        };
        tracing::info!(tunnel_id = %tunnel.id, port = tunnel.remote_port, "tunnel listener online");
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
    let connection_id = Uuid::new_v4();
    let ticket = random_secret(32);
    let (socket_tx, socket_rx) = oneshot::channel();
    state.pending.insert(
        connection_id,
        PendingConnection {
            agent_id: tunnel.agent_id,
            ticket_hash: hash_token(&ticket),
            expires_at: Instant::now() + state.config.ticket_ttl,
            socket_tx,
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
            ticket,
            expires_at,
        })
        .context("send open connection to agent")?;
    let websocket = match tokio::time::timeout(state.config.connect_timeout, socket_rx).await {
        Ok(Ok(socket)) => socket,
        _ => {
            state.pending.remove(&connection_id);
            state
                .counters
                .failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            anyhow::bail!("agent data channel timed out");
        }
    };
    let active = ActiveConnection {
        id: connection_id,
        tunnel_id: tunnel.id,
        peer_addr: peer.to_string(),
        opened_at: Utc::now(),
        bytes_up: 0,
        bytes_down: 0,
    };
    state.active.insert(connection_id, active);
    let result = bridge(state.clone(), connection_id, tcp, websocket).await;
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

pub fn claim_data_channel(
    state: &SharedState,
    connection_id: Uuid,
    agent_id: Uuid,
    ticket: &str,
) -> Option<oneshot::Sender<WebSocket>> {
    {
        let pending = state.pending.get(&connection_id)?;
        if pending.agent_id != agent_id
            || pending.expires_at <= Instant::now()
            || pending.ticket_hash != hash_token(ticket)
        {
            return None;
        }
    }
    let pending = state.pending.remove(&connection_id)?.1;
    Some(pending.socket_tx)
}

async fn bridge(
    state: SharedState,
    connection_id: Uuid,
    tcp: TcpStream,
    websocket: WebSocket,
) -> anyhow::Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let (mut ws_write, mut ws_read) = websocket.split();
    let upstream = async {
        let mut buffer = vec![0_u8; 32 * 1024];
        loop {
            let count = tokio::time::timeout(state.config.idle_timeout, tcp_read.read(&mut buffer))
                .await
                .context("connection idle timeout")??;
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
            state.counters.add_down(count as u64);
            if let Some(mut active) = state.active.get_mut(&connection_id) {
                active.bytes_down += count as u64;
            }
        }
        anyhow::Ok(())
    };
    let downstream = async {
        loop {
            let message = tokio::time::timeout(state.config.idle_timeout, ws_read.next())
                .await
                .context("connection idle timeout")?;
            let Some(message) = message else { break };
            match message? {
                Message::Binary(frame) if frame.first() == Some(&DATA_FRAME_BYTES) => {
                    tcp_write.write_all(&frame[1..]).await?;
                    state.counters.add_up((frame.len() - 1) as u64);
                    if let Some(mut active) = state.active.get_mut(&connection_id) {
                        active.bytes_up += (frame.len() - 1) as u64;
                    }
                }
                Message::Binary(frame) if frame.first() == Some(&DATA_FRAME_EOF) => {
                    tcp_write.shutdown().await?;
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
