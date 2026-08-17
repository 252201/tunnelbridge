export type AccessMode = "allowlist" | "public";
export type TunnelStatus = "stopped" | "starting" | "online" | "agent_offline" | "error";

export interface Tunnel {
  id: string;
  agent_id: string;
  name: string;
  local_host: string;
  local_port: number;
  remote_port: number;
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
  remote_port?: number;
  access_mode: AccessMode;
  allowed_cidrs: string[];
  enabled: boolean;
  allow_lan_target: boolean;
}

export interface UpdateTunnelRequest {
  name?: string;
  local_host?: string;
  local_port?: number;
  remote_port?: number;
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

export interface ActiveConnection {
  id: string;
  tunnel_id: string;
  peer_addr: string;
  opened_at: string;
  bytes_up: number;
  bytes_down: number;
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
}

export interface ApiError {
  code: string;
  message: string;
}
