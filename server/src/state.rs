use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use sqlx::SqlitePool;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tunnelbridge_protocol::{
    ActiveConnection, ActiveTransport, AgentControlMessage, MetricsSnapshot,
};
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
    pub streams: DashMap<Uuid, mpsc::Sender<InboundCarrierFrame>>,
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
            streams: DashMap::new(),
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
            carrier_sessions: self.agents.len() as u64,
            active_udp_sessions: self.counters.active_udp.load(Ordering::Relaxed),
            http_requests: self.counters.http_requests.load(Ordering::Relaxed),
            quic_connections: self.counters.quic.load(Ordering::Relaxed),
            kcp_connections: self.counters.kcp.load(Ordering::Relaxed),
            wss_connections: self.counters.wss.load(Ordering::Relaxed),
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
    pub ack_tx: oneshot::Sender<Result<(), String>>,
}

#[derive(Debug)]
pub struct InboundCarrierFrame {
    pub kind: u8,
    pub payload: Vec<u8>,
}

#[derive(Clone)]
pub struct AgentPeer {
    pub session_id: Uuid,
    pub sender: mpsc::UnboundedSender<AgentControlMessage>,
    pub binary_sender: mpsc::Sender<Vec<u8>>,
    pub transport: ActiveTransport,
    pub cancellation: CancellationToken,
}

#[derive(Default)]
pub struct Counters {
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub rejected: AtomicU64,
    pub failed: AtomicU64,
    pub active_udp: AtomicU64,
    pub http_requests: AtomicU64,
    pub quic: AtomicU64,
    pub kcp: AtomicU64,
    pub wss: AtomicU64,
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
