use std::{collections::VecDeque, path::PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tunnelbridge_protocol::{ActiveTransport, GeoLocation, MetricsSnapshot, TransportMode, Tunnel};

use crate::config::AgentConfig;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Unconfigured,
    Connecting,
    Online,
    Offline,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEntry {
    pub at: DateTime<Utc>,
    pub level: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_location: Option<GeoLocation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppSnapshot {
    pub configured: bool,
    pub server_url: Option<String>,
    pub status: AgentStatus,
    pub status_message: String,
    pub tunnels: Vec<Tunnel>,
    pub metrics: MetricsSnapshot,
    pub events: Vec<EventEntry>,
    pub active_transport: Option<ActiveTransport>,
    pub transport_fallback_reason: Option<String>,
    pub transport_mode: Option<TransportMode>,
}

pub struct RuntimeState {
    data_dir: PathBuf,
    app: AppHandle,
    pub config: RwLock<Option<AgentConfig>>,
    pub status: RwLock<(AgentStatus, String)>,
    pub tunnels: RwLock<Vec<Tunnel>>,
    pub metrics: RwLock<MetricsSnapshot>,
    pub events: RwLock<VecDeque<EventEntry>>,
    pub cancellation: Mutex<Option<CancellationToken>>,
    pub transport: RwLock<(Option<ActiveTransport>, Option<String>)>,
}

impl RuntimeState {
    pub fn new(data_dir: PathBuf, app: AppHandle) -> Self {
        Self {
            data_dir,
            app,
            config: RwLock::new(None),
            status: RwLock::new((AgentStatus::Unconfigured, "尚未连接服务器".into())),
            tunnels: RwLock::new(Vec::new()),
            metrics: RwLock::new(MetricsSnapshot::default()),
            events: RwLock::new(VecDeque::new()),
            cancellation: Mutex::new(None),
            transport: RwLock::new((None, None)),
        }
    }

    pub fn config_path(&self) -> PathBuf {
        self.data_dir.join("config.json")
    }

    pub async fn set_status(&self, status: AgentStatus, message: impl Into<String>) {
        let message = message.into();
        *self.status.write().await = (status, message.clone());
        if let Some(tray) = self.app.tray_by_id("main") {
            let symbol = tray_status_symbol(status);
            let _ = tray.set_title(Some(symbol));
            let _ = tray.set_tooltip(Some(format!("TunnelBridge — {message}")));
        }
    }

    pub async fn log(&self, level: &str, message: impl Into<String>) {
        self.log_with_location(level, message, None).await;
    }

    pub async fn set_transport(&self, transport: ActiveTransport, fallback_reason: Option<String>) {
        *self.transport.write().await = (Some(transport), fallback_reason);
    }

    pub async fn log_with_location(
        &self,
        level: &str,
        message: impl Into<String>,
        peer_location: Option<GeoLocation>,
    ) {
        let mut entries = self.events.write().await;
        entries.push_front(EventEntry {
            at: Utc::now(),
            level: level.into(),
            message: message.into(),
            peer_location,
        });
        entries.truncate(200);
    }

    pub async fn snapshot(&self) -> AppSnapshot {
        let config = self.config.read().await.clone();
        let (status, status_message) = self.status.read().await.clone();
        let (active_transport, transport_fallback_reason) = self.transport.read().await.clone();
        AppSnapshot {
            configured: config.is_some(),
            server_url: config.as_ref().map(|value| value.server_url.clone()),
            transport_mode: config.as_ref().map(|value| value.transport_mode),
            status,
            status_message,
            tunnels: self.tunnels.read().await.clone(),
            metrics: self.metrics.read().await.clone(),
            events: self.events.read().await.iter().cloned().collect(),
            active_transport,
            transport_fallback_reason,
        }
    }
}

fn tray_status_symbol(status: AgentStatus) -> &'static str {
    match status {
        AgentStatus::Online => "🟢",
        AgentStatus::Connecting => "🟡",
        AgentStatus::Offline | AgentStatus::Error => "🔴",
        AgentStatus::Unconfigured => "⚪",
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentStatus, tray_status_symbol};

    #[test]
    fn tray_status_uses_colored_state_dots() {
        assert_eq!(tray_status_symbol(AgentStatus::Online), "🟢");
        assert_eq!(tray_status_symbol(AgentStatus::Connecting), "🟡");
        assert_eq!(tray_status_symbol(AgentStatus::Offline), "🔴");
        assert_eq!(tray_status_symbol(AgentStatus::Error), "🔴");
        assert_eq!(tray_status_symbol(AgentStatus::Unconfigured), "⚪");
    }
}
