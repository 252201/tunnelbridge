import { FormEvent, useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { AccessMode, ActiveTransport, CreateTunnelRequest, GeoLocation, LocalScheme, MetricsSnapshot, Tunnel, TunnelKind, TransportMode } from "@tunnelbridge/api-types";
import ipaddr from "ipaddr.js";
import {
  Activity, ArrowDownToLine, ArrowUpFromLine, Cable, Check, ChevronRight,
  CircleDot, Copy, Gauge, KeyRound, Network, Plus, Power, RefreshCw,
  Server, Settings, ShieldCheck, Trash2, X,
} from "lucide-react";

type View = "overview" | "tunnels" | "activity" | "settings";
type AgentStatus = "unconfigured" | "connecting" | "online" | "offline" | "error";

interface EventEntry { at: string; level: "info" | "warn" | "error"; message: string; peer_location?: GeoLocation | null }
interface AppSnapshot {
  configured: boolean;
  server_url: string | null;
  status: AgentStatus;
  status_message: string;
  tunnels: Tunnel[];
  metrics: MetricsSnapshot;
  events: EventEntry[];
  active_transport: ActiveTransport | null;
  transport_fallback_reason: string | null;
  transport_mode: TransportMode | null;
}

const emptyMetrics: MetricsSnapshot = {
  online_agents: 0, active_connections: 0, bytes_up: 0, bytes_down: 0,
  rejected_connections: 0, failed_connections: 0,
  carrier_sessions: 0, active_udp_sessions: 0, http_requests: 0,
  quic_connections: 0, kcp_connections: 0, wss_connections: 0,
};

const defaultSnapshot: AppSnapshot = {
  configured: false, server_url: null, status: "unconfigured",
  status_message: "尚未连接服务器", tunnels: [], metrics: emptyMetrics, events: [],
  active_transport: null, transport_fallback_reason: null,
  transport_mode: null,
};
let updateCheckStarted = false;

function isTauri() {
  return "__TAURI_INTERNALS__" in window;
}

async function command<T>(name: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri()) throw new Error("请在 TunnelBridge 桌面应用中执行此操作");
  return invoke<T>(name, args);
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`;
  return `${(value / 1024 ** 3).toFixed(2)} GB`;
}

function publicEndpoint(tunnel: Tunnel) {
  return tunnel.kind === "web" ? `https://${tunnel.hostname}` : `${tunnel.kind.toUpperCase()} :${tunnel.remote_port}`;
}

function countryFlag(code: string) {
  const normalized = code.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(normalized)) return "🌐";
  return [...normalized].map((letter) => String.fromCodePoint(letter.charCodeAt(0) + 127397)).join("");
}

function countryLabel(location: GeoLocation) {
  try {
    return new Intl.DisplayNames(["zh-CN"], { type: "region" }).of(location.country_code) ?? location.country_name;
  } catch {
    return location.country_name;
  }
}

function CountryBadge({ location }: { location?: GeoLocation | null }) {
  if (!location) return <span className="source-location unknown" title="暂时无法解析来源国家"><span aria-hidden="true">🌐</span><span>未知来源</span></span>;
  return <span className="source-location" title={`${location.country_name} · ${location.country_code}`}><span aria-hidden="true">{countryFlag(location.country_code)}</span><span>{countryLabel(location)}</span></span>;
}

function statusLabel(status: AgentStatus) {
  return ({ unconfigured: "未配置", connecting: "正在连接", online: "已连接", offline: "连接中断", error: "需要处理" })[status];
}

function App() {
  const [view, setView] = useState<View>("overview");
  const [snapshot, setSnapshot] = useState(defaultSnapshot);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [showConnect, setShowConnect] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!isTauri()) {
      setSnapshot({ ...defaultSnapshot, status: "offline", status_message: "浏览器预览模式" });
      setLoading(false);
      return;
    }
    try {
      setSnapshot(await command<AppSnapshot>("get_snapshot"));
    } catch (error) {
      setNotice(String(error));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(refresh, 4000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    if (!loading && !snapshot.configured) setShowConnect(true);
  }, [loading, snapshot.configured]);

  useEffect(() => {
    if (!isTauri() || updateCheckStarted) return;
    updateCheckStarted = true;
    command<string>("check_for_updates")
      .then(async (result) => {
        if (!result.startsWith("UPDATE_AVAILABLE:")) return;
        const version = result.slice("UPDATE_AVAILABLE:".length);
        if (window.confirm(`TunnelBridge ${version} 已发布，是否下载并安装？`)) {
          await command("install_update");
          setNotice("更新已安装，请重新启动 TunnelBridge");
        }
      })
      .catch(() => undefined);
  }, []);

  const onlineCount = snapshot.tunnels.filter((tunnel) => tunnel.status === "online").length;
  const address = snapshot.server_url?.replace(/^https?:\/\//, "") ?? "未绑定节点";

  async function toggleTunnel(tunnel: Tunnel) {
    try {
      await command("update_tunnel", { id: tunnel.id, update: { enabled: !tunnel.enabled } });
      await refresh();
    } catch (error) { setNotice(String(error)); }
  }

  async function removeTunnel(tunnel: Tunnel) {
    if (!window.confirm(`删除隧道“${tunnel.name}”？公网端点 ${publicEndpoint(tunnel)} 将被释放。`)) return;
    try {
      await command("delete_tunnel", { id: tunnel.id });
      await refresh();
    } catch (error) { setNotice(String(error)); }
  }

  return (
    <div className="app-shell">
      <aside className="rail">
        <div className="brand-mark" aria-label="TunnelBridge"><span /><span /></div>
        <nav aria-label="主导航">
          <NavButton active={view === "overview"} label="总览" icon={<Gauge />} onClick={() => setView("overview")} />
          <NavButton active={view === "tunnels"} label="隧道" icon={<Cable />} onClick={() => setView("tunnels")} />
          <NavButton active={view === "activity"} label="活动" icon={<Activity />} onClick={() => setView("activity")} />
        </nav>
        <div className="rail-bottom">
          <NavButton active={view === "settings"} label="设置" icon={<Settings />} onClick={() => setView("settings")} />
        </div>
      </aside>

      <main>
        <header className="topbar">
          <div className="eyebrow"><span className={`signal ${snapshot.status}`} /> RELAY / {address}</div>
          <div className="top-actions">
            <button className="icon-button" onClick={refresh} aria-label="刷新"><RefreshCw /></button>
            <button className="primary small" onClick={() => setShowCreate(true)} disabled={!snapshot.configured}><Plus /> 新建隧道</button>
          </div>
        </header>

        <section className="workspace">
          {view === "overview" && (
            <Overview snapshot={snapshot} onlineCount={onlineCount} onOpenTunnels={() => setView("tunnels")} />
          )}
          {view === "tunnels" && (
            <TunnelView tunnels={snapshot.tunnels} onCreate={() => setShowCreate(true)} onToggle={toggleTunnel} onDelete={removeTunnel} />
          )}
          {view === "activity" && <ActivityView snapshot={snapshot} />}
          {view === "settings" && <SettingsView snapshot={snapshot} onReconnect={() => setShowConnect(true)} onNotice={setNotice} />}
        </section>
      </main>

      {showCreate && <TunnelEditor onClose={() => setShowCreate(false)} onSaved={async () => { setShowCreate(false); await refresh(); }} onNotice={setNotice} />}
      {showConnect && <ConnectPanel configured={snapshot.configured} serverUrl={snapshot.server_url ?? ""} onClose={() => snapshot.configured && setShowConnect(false)} onConnected={async () => { setShowConnect(false); await refresh(); }} onNotice={setNotice} />}
      {notice && <div className="toast" role="alert"><span>{notice}</span><button onClick={() => setNotice(null)} aria-label="关闭"><X /></button></div>}
    </div>
  );
}

function NavButton({ active, label, icon, onClick }: { active: boolean; label: string; icon: React.ReactNode; onClick: () => void }) {
  return <button className={`nav-button ${active ? "active" : ""}`} onClick={onClick}>{icon}<span>{label}</span></button>;
}

function Overview({ snapshot, onlineCount, onOpenTunnels }: { snapshot: AppSnapshot; onlineCount: number; onOpenTunnels: () => void }) {
  const latest = snapshot.events.slice(0, 5);
  return <div className="view enter">
    <div className="hero-grid">
      <div>
        <p className="section-index">01 / CONTROL PLANE</p>
        <h1>把本地服务，<br /><em>安全地接入公网。</em></h1>
        <p className="hero-copy">所有连接都由这台 Mac 主动发起。无需开放路由器端口，隧道内容不会被 TunnelBridge 记录。</p>
      </div>
      <div className={`connection-orbit ${snapshot.status}`}>
        <div className="orbit-ring one" /><div className="orbit-ring two" />
        <div className="orbit-core"><Network /><strong>{statusLabel(snapshot.status)}</strong><span>{snapshot.status_message}</span></div>
      </div>
    </div>

    <div className="stat-row">
      <Metric label="在线隧道" value={`${onlineCount} / ${snapshot.tunnels.length}`} note="TCP endpoints" />
      <Metric label="当前连接" value={String(snapshot.metrics.active_connections)} note="Live sessions" />
      <Metric label="累计下行" value={formatBytes(snapshot.metrics.bytes_down)} note="Relay → Local" />
      <Metric label="累计上行" value={formatBytes(snapshot.metrics.bytes_up)} note="Local → Relay" />
    </div>

    <div className="overview-bottom">
      <div className="panel route-panel">
        <div className="panel-head"><div><p className="section-index">ACTIVE ROUTES</p><h2>隧道路径</h2></div><button className="text-button" onClick={onOpenTunnels}>管理全部 <ChevronRight /></button></div>
        {snapshot.tunnels.length === 0 ? <EmptyCompact /> : snapshot.tunnels.slice(0, 4).map((tunnel) => <TunnelRow tunnel={tunnel} key={tunnel.id} compact />)}
      </div>
      <div className="panel security-panel">
        <ShieldCheck />
        <p className="section-index">SECURITY POSTURE</p>
        <h2>默认拒绝，按需放行</h2>
        <p>新映射必须配置来源 CIDR。设备凭据保存在 macOS 钥匙串，数据票据仅可消费一次。</p>
        <div className="security-score"><span>保护状态</span><strong>严格</strong></div>
      </div>
    </div>
  </div>;
}

function Metric({ label, value, note }: { label: string; value: string; note: string }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong><code>{note}</code></div>;
}

function TunnelView({ tunnels, onCreate, onToggle, onDelete }: { tunnels: Tunnel[]; onCreate: () => void; onToggle: (t: Tunnel) => void; onDelete: (t: Tunnel) => void }) {
  return <div className="view enter">
    <div className="view-heading"><div><p className="section-index">02 / TCP TUNNELS</p><h1>隧道</h1><p>每个公网端口对应一个仅由本机访问的服务。</p></div><button className="primary" onClick={onCreate}><Plus /> 创建映射</button></div>
    <div className="tunnel-table panel">
      <div className="table-head"><span>状态 / 名称</span><span>本地目标</span><span>公网端点</span><span>访问策略</span><span /></div>
      {tunnels.length === 0 ? <div className="large-empty"><Cable /><h2>尚无隧道</h2><p>创建第一条 TCP 映射，把 SSH、数据库或本地开发服务接入公网。</p><button className="secondary" onClick={onCreate}><Plus /> 创建第一条</button></div> : tunnels.map((tunnel) => <TunnelRow key={tunnel.id} tunnel={tunnel} onToggle={onToggle} onDelete={onDelete} />)}
    </div>
  </div>;
}

function TunnelRow({ tunnel, compact, onToggle, onDelete }: { tunnel: Tunnel; compact?: boolean; onToggle?: (t: Tunnel) => void; onDelete?: (t: Tunnel) => void }) {
  const stateLabel = ({ online: "运行中", stopped: "已停止", starting: "启动中", agent_offline: "设备离线", error: "端口异常" })[tunnel.status];
  return <div className={`tunnel-row ${compact ? "compact" : ""}`}>
    <div className="tunnel-name"><span className={`tunnel-dot ${tunnel.status}`} /><div><strong>{tunnel.name}</strong><small>{stateLabel}</small></div></div>
    <code>{tunnel.local_host}:{tunnel.local_port}</code>
    <code className="public-port">{publicEndpoint(tunnel)}<Copy size={13} /></code>
    {!compact && <span className={`policy ${tunnel.access_mode}`}>{tunnel.access_mode === "allowlist" ? `${tunnel.allowed_cidrs.length} 条白名单` : "公开访问"}</span>}
    {!compact && <div className="row-actions"><button className={`switch ${tunnel.enabled ? "on" : ""}`} role="switch" aria-checked={tunnel.enabled} onClick={() => onToggle?.(tunnel)}><span /></button><button className="ghost-danger" onClick={() => onDelete?.(tunnel)} aria-label={`删除 ${tunnel.name}`}><Trash2 /></button></div>}
  </div>;
}

function ActivityView({ snapshot }: { snapshot: AppSnapshot }) {
  return <div className="view enter">
    <div className="view-heading"><div><p className="section-index">03 / LIVE SIGNAL</p><h1>活动</h1><p>仅记录连接状态和传输计数，不记录隧道载荷。</p></div></div>
    <div className="activity-layout">
      <div className="panel traffic-board"><div className="traffic-direction"><ArrowDownToLine /><span>下行流量</span><strong>{formatBytes(snapshot.metrics.bytes_down)}</strong></div><div className="traffic-line"><i /><i /><i /><i /><i /><i /><i /></div><div className="traffic-direction"><ArrowUpFromLine /><span>上行流量</span><strong>{formatBytes(snapshot.metrics.bytes_up)}</strong></div></div>
      <div className="panel event-panel"><div className="panel-head"><div><p className="section-index">LOCAL EVENT LOG</p><h2>最近事件</h2></div></div><EventList events={snapshot.events} /></div>
    </div>
  </div>;
}

function EventList({ events }: { events: EventEntry[] }) {
  if (!events.length) return <div className="event-empty">等待连接事件…</div>;
  return <div className="event-list">{events.map((event, index) => <div className="event" key={`${event.at}-${index}`}><time>{new Date(event.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time><span className={event.level} /><p className="event-copy"><span>{event.message}</span>{event.peer_location !== undefined && <CountryBadge location={event.peer_location} />}</p></div>)}</div>;
}

function SettingsView({ snapshot, onReconnect, onNotice }: { snapshot: AppSnapshot; onReconnect: () => void; onNotice: (m: string) => void }) {
  const [autostart, setAutostart] = useState(false);
  useEffect(() => { if (isTauri()) command<boolean>("get_autostart").then(setAutostart).catch(() => undefined); }, []);
  async function toggleAutostart() {
    try { const enabled = await command<boolean>("set_autostart", { enabled: !autostart }); setAutostart(enabled); }
    catch (error) { onNotice(String(error)); }
  }
  async function checkUpdate() {
    try {
      const result = await command<string>("check_for_updates");
      if (result.startsWith("UPDATE_AVAILABLE:")) {
        const version = result.slice("UPDATE_AVAILABLE:".length);
        if (window.confirm(`发现 TunnelBridge ${version}，现在下载并安装？`)) {
          await command("install_update");
          onNotice("更新已安装，请重新启动 TunnelBridge");
        }
      } else onNotice(result);
    } catch (error) { onNotice(String(error)); }
  }
  async function changeTransport(mode: TransportMode) {
    try { await command("set_transport_mode", { mode }); onNotice(`承载策略已切换为 ${mode.toUpperCase()}`); }
    catch (error) { onNotice(String(error)); }
  }
  return <div className="view enter"><div className="view-heading"><div><p className="section-index">04 / SYSTEM</p><h1>设置</h1><p>管理中继节点、后台行为和应用更新。</p></div></div>
    <div className="settings-grid">
      <div className="panel settings-card"><Server /><div><h2>中继服务器</h2><p>{snapshot.server_url ?? "尚未配置"}</p><small>设备令牌已存入 macOS 钥匙串，不会显示在界面中。</small></div><button className="secondary" onClick={onReconnect}>{snapshot.configured ? "重新配置" : "连接"}</button></div>
      <div className="panel settings-card"><Network /><div><h2>承载协议</h2><p>当前：{snapshot.active_transport?.toUpperCase() ?? "未连接"}</p><small>{snapshot.transport_fallback_reason ?? "自动模式优先 QUIC，失败后回退 WSS；KCP 需手动选择。"}</small></div><select value={snapshot.transport_mode ?? "auto"} onChange={(e)=>void changeTransport(e.target.value as TransportMode)}><option value="auto">自动</option><option value="quic">QUIC</option><option value="kcp">KCP</option><option value="wss">WSS</option></select></div>
      <div className="panel settings-card"><Power /><div><h2>登录时启动</h2><p>开机后在菜单栏运行 TunnelBridge</p><small>默认关闭，隧道只会在应用运行时保持连接。</small></div><button className={`switch ${autostart ? "on" : ""}`} role="switch" aria-checked={autostart} onClick={toggleAutostart}><span /></button></div>
      <div className="panel settings-card"><RefreshCw /><div><h2>应用更新</h2><p>TunnelBridge 0.2.1</p><small>更新包经过独立签名与 Apple 公证。</small></div><button className="secondary" onClick={checkUpdate}>检查更新</button></div>
    </div>
  </div>;
}

function ConnectPanel({ configured, serverUrl, onClose, onConnected, onNotice }: { configured: boolean; serverUrl: string; onClose: () => void; onConnected: () => void; onNotice: (m: string) => void }) {
  const [server, setServer] = useState(serverUrl || "https://");
  const [token, setToken] = useState("");
  const [name, setName] = useState("My Mac");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true);
    try { await command("configure_server", { serverUrl: server, token, deviceName: name }); await onConnected(); }
    catch (error) { onNotice(String(error)); } finally { setBusy(false); }
  }
  return <div className="modal-backdrop"><form className="connect-card" onSubmit={submit}>
    {configured && <button type="button" className="modal-close" onClick={onClose}><X /></button>}
    <div className="connect-glyph"><span /><KeyRound /></div><p className="section-index">DEVICE ENROLLMENT</p><h1>连接你的中继节点</h1><p>在服务端管理后台创建一个设备令牌，然后粘贴到这里。令牌只会保存到 macOS 钥匙串。</p>
    <label>服务器地址<input value={server} onChange={(e) => setServer(e.target.value)} placeholder="https://relay.example.com" required /></label>
    <label>设备名称<input value={name} onChange={(e) => setName(e.target.value)} placeholder="My MacBook" required maxLength={80} /></label>
    <label>设备令牌<input type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder="粘贴一次性展示的令牌" required /></label>
    <button className="primary connect-submit" disabled={busy}>{busy ? <RefreshCw className="spin" /> : <Check />} {busy ? "正在验证" : "验证并连接"}</button>
    <small className="privacy-note"><ShieldCheck /> 连接将使用 TLS 加密；不会关闭证书验证。</small>
  </form></div>;
}

function TunnelEditor({ onClose, onSaved, onNotice }: { onClose: () => void; onSaved: () => void; onNotice: (m: string) => void }) {
  const [name, setName] = useState(""); const [host, setHost] = useState("127.0.0.1");
  const [localPort, setLocalPort] = useState("22"); const [remotePort, setRemotePort] = useState("");
  const [kind, setKind] = useState<TunnelKind>("tcp"); const [localScheme, setLocalScheme] = useState<LocalScheme>("tcp");
  const [hostname, setHostname] = useState("");
  const [mode, setMode] = useState<AccessMode>("allowlist"); const [cidrs, setCidrs] = useState("");
  const [lanConfirmed, setLanConfirmed] = useState(false); const [publicConfirmed, setPublicConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const isLoopback = ["localhost", "127.0.0.1", "::1"].includes(host.trim());
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (mode === "public" && !publicConfirmed) { onNotice("公开访问需要先确认风险"); return; }
    if (!isLoopback && !lanConfirmed) { onNotice("局域网目标需要先确认访问范围"); return; }
    const allowedCidrs = cidrs.split(/[\n,]/).map((v) => v.trim()).filter(Boolean);
    if (mode === "allowlist") {
      const invalid = allowedCidrs.find((cidr) => { try { ipaddr.parseCIDR(cidr); return false; } catch { return true; } });
      if (invalid) { onNotice(`CIDR 格式无效：${invalid}`); return; }
    }
    const request: CreateTunnelRequest = { name, local_host: host, local_port: Number(localPort), kind, local_scheme: localScheme, remote_port: kind !== "web" && remotePort ? Number(remotePort) : undefined, hostname: kind === "web" ? hostname : undefined, access_mode: mode, allowed_cidrs: allowedCidrs, enabled: true, allow_lan_target: !isLoopback && lanConfirmed };
    setBusy(true); try { await command("create_tunnel", { request }); await onSaved(); } catch (error) { onNotice(String(error)); } finally { setBusy(false); }
  }
  return <div className="drawer-backdrop"><form className="drawer" onSubmit={submit}><div className="drawer-head"><div><p className="section-index">NEW MULTI-PROTOCOL ROUTE</p><h1>创建隧道</h1></div><button type="button" className="modal-close" onClick={onClose}><X /></button></div>
    <div className="form-grid"><label className="wide">代理类型<select value={kind} onChange={(e) => { const next=e.target.value as TunnelKind; setKind(next); setLocalScheme(next === "tcp" ? "tcp" : next === "udp" ? "udp" : "http"); setLocalPort(next === "web" ? "3000" : next === "udp" ? "53" : "22"); }}><option value="tcp">TCP</option><option value="udp">UDP</option><option value="web">HTTP / HTTPS</option></select></label><label className="wide">名称<input value={name} onChange={(e) => setName(e.target.value)} placeholder={kind === "web" ? "本地 Web 应用" : "生产环境 SSH"} required maxLength={80} /></label><label>本地地址<input value={host} onChange={(e) => setHost(e.target.value)} required /></label><label>本地端口<input type="number" min="1" max="65535" value={localPort} onChange={(e) => setLocalPort(e.target.value)} required /></label>{kind === "web" ? <><label>本地协议<select value={localScheme} onChange={(e)=>setLocalScheme(e.target.value as LocalScheme)}><option value="http">HTTP</option><option value="https">HTTPS（严格校验证书）</option></select></label><label>公网子域名<input value={hostname} onChange={(e)=>setHostname(e.target.value.toLowerCase())} placeholder="myapp" pattern="[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?" required /></label></> : <label className="wide">远程端口 <small>留空自动分配</small><input type="number" min="1" max="65535" value={remotePort} onChange={(e) => setRemotePort(e.target.value)} placeholder="自动" /></label>}</div>
    {!isLoopback && <label className="confirm"><input type="checkbox" checked={lanConfirmed} onChange={(e) => setLanConfirmed(e.target.checked)} /><span><strong>允许访问局域网目标</strong>客户端将能连接到这台 Mac 可访问的远程主机。</span></label>}
    <fieldset><legend>公网访问策略</legend><button type="button" className={`mode-card ${mode === "allowlist" ? "selected" : ""}`} onClick={() => setMode("allowlist")}><ShieldCheck /><span><strong>IP 白名单</strong><small>仅允许指定来源网络</small></span></button><button type="button" className={`mode-card danger ${mode === "public" ? "selected" : ""}`} onClick={() => setMode("public")}><Network /><span><strong>公开访问</strong><small>允许任意来源建立连接</small></span></button></fieldset>
    {mode === "allowlist" ? <label>允许的 CIDR<textarea value={cidrs} onChange={(e) => setCidrs(e.target.value)} placeholder={"203.0.113.8/32\n2001:db8::/48"} required /></label> : <label className="confirm danger"><input type="checkbox" checked={publicConfirmed} onChange={(e) => setPublicConfirmed(e.target.checked)} /><span><strong>我了解公开暴露的风险</strong>目标服务必须配置可靠的身份认证。</span></label>}
    <div className="drawer-footer"><button type="button" className="secondary" onClick={onClose}>取消</button><button className="primary" disabled={busy}>{busy ? "正在创建…" : "创建并启动"}</button></div>
  </form></div>;
}

function EmptyCompact() { return <div className="empty-compact"><CircleDot /><span>尚未创建隧道</span></div>; }

export default App;
