use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 2;
pub const DATA_FRAME_BYTES: u8 = 0;
pub const DATA_FRAME_EOF: u8 = 1;
pub const CARRIER_FRAME_DATA: u8 = 2;
pub const CARRIER_FRAME_FIN: u8 = 3;
pub const CARRIER_FRAME_RESET: u8 = 4;
pub const CARRIER_FRAME_DATAGRAM: u8 = 5;
pub const MAX_UDP_DATAGRAM: usize = 65_507;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TunnelKind {
    #[default]
    Tcp,
    Udp,
    Web,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LocalScheme {
    #[default]
    Tcp,
    Udp,
    Http,
    Https,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    #[default]
    Auto,
    Quic,
    Kcp,
    Wss,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActiveTransport {
    Quic,
    Kcp,
    Wss,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CarrierCapabilities {
    pub transports: Vec<ActiveTransport>,
    pub tunnel_kinds: Vec<TunnelKind>,
    pub max_streams: u32,
    pub max_datagram_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectCarrierAuth {
    pub token: String,
    pub hello: AgentControlMessage,
}

impl Default for CarrierCapabilities {
    fn default() -> Self {
        Self {
            transports: vec![ActiveTransport::Wss],
            tunnel_kinds: vec![TunnelKind::Tcp],
            max_streams: 256,
            max_datagram_size: MAX_UDP_DATAGRAM as u32,
        }
    }
}

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
    #[serde(default)]
    pub kind: TunnelKind,
    #[serde(default)]
    pub local_scheme: LocalScheme,
    pub remote_port: Option<u16>,
    pub hostname: Option<String>,
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
    #[serde(default)]
    pub kind: TunnelKind,
    #[serde(default)]
    pub local_scheme: LocalScheme,
    pub remote_port: Option<u16>,
    #[serde(default)]
    pub hostname: Option<String>,
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
    pub kind: Option<TunnelKind>,
    pub local_scheme: Option<LocalScheme>,
    pub remote_port: Option<u16>,
    pub hostname: Option<String>,
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
        #[serde(default)]
        capabilities: CarrierCapabilities,
        #[serde(default)]
        config_version: u64,
    },
    Welcome {
        protocol_version: u16,
        server_time: DateTime<Utc>,
        #[serde(default)]
        capabilities: CarrierCapabilities,
        #[serde(default)]
        transport: Option<ActiveTransport>,
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
    OpenUdpSession {
        session_id: Uuid,
        tunnel: Tunnel,
        peer_addr: String,
        #[serde(default)]
        peer_location: Option<GeoLocation>,
        ticket: String,
        expires_at: DateTime<Utc>,
    },
    CloseUdpSession {
        session_id: Uuid,
        reason: String,
    },
    ConnectionAck {
        connection_id: Uuid,
        accepted: bool,
        error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ticket: Option<String>,
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
pub struct AgentEnrollmentResponse {
    pub tunnels: Vec<Tunnel>,
    pub transport_fingerprint: String,
    pub transport_certificate_der: String,
    pub quic_port: u16,
    pub kcp_port: u16,
    pub capabilities: CarrierCapabilities,
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
    #[serde(default)]
    pub tunnel_kind: TunnelKind,
    #[serde(default)]
    pub transport: Option<ActiveTransport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsSnapshot {
    pub online_agents: u64,
    pub active_connections: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub rejected_connections: u64,
    pub failed_connections: u64,
    #[serde(default)]
    pub carrier_sessions: u64,
    #[serde(default)]
    pub active_udp_sessions: u64,
    #[serde(default)]
    pub http_requests: u64,
    #[serde(default)]
    pub quic_connections: u64,
    #[serde(default)]
    pub kcp_connections: u64,
    #[serde(default)]
    pub wss_connections: u64,
}

/// Encodes a multiplexed binary carrier frame as:
/// kind (1 byte), stream/session UUID (16 bytes), payload (remaining bytes).
pub fn encode_carrier_frame(kind: u8, id: Uuid, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(17 + payload.len());
    frame.push(kind);
    frame.extend_from_slice(id.as_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn decode_carrier_frame(frame: &[u8]) -> Option<(u8, Uuid, &[u8])> {
    if frame.len() < 17 {
        return None;
    }
    let id = Uuid::from_slice(&frame[1..17]).ok()?;
    Some((frame[0], id, &frame[17..]))
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

    #[test]
    fn multiplexed_frame_round_trips_binary_payload() {
        let id = Uuid::new_v4();
        let payload = [0, 1, 2, 0, 255];
        let encoded = encode_carrier_frame(CARRIER_FRAME_DATA, id, &payload);
        let (kind, decoded_id, decoded_payload) = decode_carrier_frame(&encoded).unwrap();
        assert_eq!(kind, CARRIER_FRAME_DATA);
        assert_eq!(decoded_id, id);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn malformed_multiplexed_frame_is_rejected() {
        assert!(decode_carrier_frame(&[CARRIER_FRAME_DATA; 16]).is_none());
    }
}
