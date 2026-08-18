use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use axum::extract::ws::WebSocket;
use dashmap::DashMap;
use sqlx::SqlitePool;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tunnelbridge_protocol::{ActiveConnection, AgentControlMessage, MetricsSnapshot};
use uuid::Uuid;

use crate::{config::Config, geoip::GeoIpResolver};

pub type SharedState = Arc<AppState>;

pub struct AppState {
    pub config: Config,
    pub db: SqlitePool,
    pub sessions: DashMap<String, AdminSession>,
    pub login_attempts: DashMap<String, LoginWindow>,
    pub agents: DashMap<Uuid, AgentPeer>,
    pub pending: DashMap<Uuid, PendingConnection>,
    pub listeners: DashMap<Uuid, CancellationToken>,
    pub active: DashMap<Uuid, ActiveConnection>,
    pub counters: Counters,
    pub geoip: GeoIpResolver,
}

impl AppState {
    pub fn new(config: Config, db: SqlitePool) -> SharedState {
        let geoip = GeoIpResolver::new(config.geoip_url.clone());
        Arc::new(Self {
            config,
            db,
            sessions: DashMap::new(),
            login_attempts: DashMap::new(),
            agents: DashMap::new(),
            pending: DashMap::new(),
            listeners: DashMap::new(),
            active: DashMap::new(),
            counters: Counters::default(),
            geoip,
        })
    }

    pub fn metrics(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            online_agents: self.agents.len() as u64,
            active_connections: self.active.len() as u64,
            bytes_up: self.counters.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.counters.bytes_down.load(Ordering::Relaxed),
            rejected_connections: self.counters.rejected.load(Ordering::Relaxed),
            failed_connections: self.counters.failed.load(Ordering::Relaxed),
        }
    }
}

pub struct AdminSession {
    pub username: String,
    pub csrf_token: String,
    pub expires_at: Instant,
}

pub struct LoginWindow {
    pub started_at: Instant,
    pub attempts: u8,
}

pub struct PendingConnection {
    pub agent_id: Uuid,
    pub ticket_hash: String,
    pub expires_at: Instant,
    pub socket_tx: oneshot::Sender<WebSocket>,
}

#[derive(Clone)]
pub struct AgentPeer {
    pub session_id: Uuid,
    pub sender: mpsc::UnboundedSender<AgentControlMessage>,
    pub cancellation: CancellationToken,
}

#[derive(Default)]
pub struct Counters {
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub rejected: AtomicU64,
    pub failed: AtomicU64,
}

impl Counters {
    pub fn add_up(&self, value: u64) {
        self.bytes_up.fetch_add(value, Ordering::Relaxed);
    }

    pub fn add_down(&self, value: u64) {
        self.bytes_down.fetch_add(value, Ordering::Relaxed);
    }
}

pub fn session_expiry(ttl: Duration) -> Instant {
    Instant::now() + ttl
}
