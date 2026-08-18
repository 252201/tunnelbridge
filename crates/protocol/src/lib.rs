use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 1;
pub const DATA_FRAME_BYTES: u8 = 0;
pub const DATA_FRAME_EOF: u8 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    Allowlist,
    Public,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelStatus {
    Stopped,
    Starting,
    Online,
    AgentOffline,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tunnel {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub name: String,
    pub local_host: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub access_mode: AccessMode,
    pub allowed_cidrs: Vec<IpNet>,
    pub enabled: bool,
    pub status: TunnelStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeoLocation {
    pub country_code: String,
    pub country_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTunnelRequest {
    pub name: String,
    pub local_host: String,
    pub local_port: u16,
    pub remote_port: Option<u16>,
    pub access_mode: AccessMode,
    #[serde(default)]
    pub allowed_cidrs: Vec<IpNet>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allow_lan_target: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateTunnelRequest {
    pub name: Option<String>,
    pub local_host: Option<String>,
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub access_mode: Option<AccessMode>,
    pub allowed_cidrs: Option<Vec<IpNet>>,
    pub enabled: Option<bool>,
    #[serde(default)]
    pub allow_lan_target: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum AgentControlMessage {
    Hello {
        protocol_version: u16,
        agent_id: Uuid,
        name: String,
    },
    Welcome {
        protocol_version: u16,
        server_time: DateTime<Utc>,
    },
    Ping {
        sent_at: DateTime<Utc>,
    },
    Pong {
        sent_at: DateTime<Utc>,
    },
    ConfigSync {
        tunnels: Vec<Tunnel>,
    },
    OpenConnection {
        connection_id: Uuid,
        tunnel: Tunnel,
        peer_addr: String,
        #[serde(default)]
        peer_location: Option<GeoLocation>,
        ticket: String,
        expires_at: DateTime<Utc>,
    },
    ConnectionAck {
        connection_id: Uuid,
        accepted: bool,
        error: Option<String>,
    },
    Traffic {
        connection_id: Uuid,
        bytes_up: u64,
        bytes_down: u64,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub username: String,
    pub csrf_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDeviceRequest {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTokenResponse {
    pub id: Uuid,
    pub name: String,
    pub token: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub name: String,
    pub online: bool,
    pub revoked: bool,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub action: String,
    pub subject: String,
    pub detail: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveConnection {
    pub id: Uuid,
    pub tunnel_id: Uuid,
    pub peer_addr: String,
    #[serde(default)]
    pub peer_location: Option<GeoLocation>,
    pub opened_at: DateTime<Utc>,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsSnapshot {
    pub online_agents: u64,
    pub active_connections: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub rejected_connections: u64,
    pub failed_connections: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_message_round_trips() {
        let message = AgentControlMessage::Ping {
            sent_at: Utc::now(),
        };
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains("ping"));
        let _: AgentControlMessage = serde_json::from_str(&json).unwrap();
    }
}
