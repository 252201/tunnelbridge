export type AccessMode = "allowlist" | "public";
export type TunnelStatus = "stopped" | "starting" | "online" | "agent_offline" | "error";
export type TunnelKind = "tcp" | "udp" | "web";
export type LocalScheme = "tcp" | "udp" | "http" | "https";
export type TransportMode = "auto" | "quic" | "kcp" | "wss";
export type ActiveTransport = "quic" | "kcp" | "wss";

export interface Tunnel {
  id: string;
  agent_id: string;
  name: string;
  local_host: string;
  local_port: number;
  kind: TunnelKind;
  local_scheme: LocalScheme;
  remote_port: number | null;
  hostname: string | null;
  access_mode: AccessMode;
  allowed_cidrs: string[];
  enabled: boolean;
  status: TunnelStatus;
  created_at: string;
  updated_at: string;
}

export interface CreateTunnelRequest {
  name: string;
  local_host: string;
  local_port: number;
  kind: TunnelKind;
  local_scheme: LocalScheme;
  remote_port?: number;
  hostname?: string;
  access_mode: AccessMode;
  allowed_cidrs: string[];
  enabled: boolean;
  allow_lan_target: boolean;
}

export interface UpdateTunnelRequest {
  name?: string;
  local_host?: string;
  local_port?: number;
  kind?: TunnelKind;
  local_scheme?: LocalScheme;
  remote_port?: number;
  hostname?: string;
  access_mode?: AccessMode;
  allowed_cidrs?: string[];
  enabled?: boolean;
  allow_lan_target?: boolean;
}

export interface Device {
  id: string;
  name: string;
  online: boolean;
  revoked: boolean;
  last_seen_at: string | null;
  created_at: string;
}

export interface DeviceTokenResponse {
  id: string;
  name: string;
  token: string;
  created_at: string;
}

export interface GeoLocation {
  country_code: string;
  country_name: string;
}

export interface ActiveConnection {
  id: string;
  tunnel_id: string;
  peer_addr: string;
  peer_location?: GeoLocation | null;
  opened_at: string;
  bytes_up: number;
  bytes_down: number;
  tunnel_kind: TunnelKind;
  transport?: ActiveTransport | null;
}

export interface AuditEntry {
  id: number;
  action: string;
  subject: string;
  detail: string;
  created_at: string;
}

export interface MetricsSnapshot {
  online_agents: number;
  active_connections: number;
  bytes_up: number;
  bytes_down: number;
  rejected_connections: number;
  failed_connections: number;
  carrier_sessions: number;
  active_udp_sessions: number;
  http_requests: number;
  quic_connections: number;
  kcp_connections: number;
  wss_connections: number;
}

export interface ApiError {
  code: string;
  message: string;
}
