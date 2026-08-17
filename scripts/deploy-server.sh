#!/usr/bin/env bash
# Interactive TunnelBridge server deployment for a Linux VPS.
#
# The script deliberately keeps Cloudflare credentials and SSH private keys on
# the operator's machine. It only sends deployment files and commands through
# the encrypted SSH session.

set -Eeuo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly IMAGE_REPOSITORY="ghcr.io/252201/tunnelbridge-server"
readonly DEFAULT_VERSION="v0.1.1"
readonly DEFAULT_SSH_PORT="22"
readonly DEFAULT_SSH_USER="ubuntu"
readonly DEFAULT_PORT_START="20000"
readonly DEFAULT_PORT_END="20100"
readonly REMOTE_ROOT="/opt/tunnelbridge"
readonly SERVER_CONTAINER="tunnelbridge-server"
readonly CADDY_CONTAINER="tunnelbridge-caddy"
readonly CADDY_NETWORK="tunnelbridge"
readonly SERVER_LOCAL_PORT="18080"
readonly API_BASE="https://api.cloudflare.com/client/v4"

DRY_RUN=0
TMP_DIR=""
KNOWN_HOSTS=""
CF_TOKEN=""
ADMIN_PASSWORD=""
ADMIN_PASSWORD_IS_NEW=0
REMOTE_DB_EXISTS=""
WEB_MODE=""
NGINX_CONF_PATH=""
NGINX_BACKUP_PATH=""

log() {
  printf '[TunnelBridge] %s\n' "$*"
}

warn() {
  printf '[TunnelBridge] 警告：%s\n' "$*" >&2
}

die() {
  printf '[TunnelBridge] 错误：%s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
用法：
  ./scripts/deploy-server.sh
  ./scripts/deploy-server.sh --dry-run
  ./scripts/deploy-server.sh --help

脚本会交互询问 VPS SSH、Cloudflare API Token、域名、版本和端口范围，
然后部署 GHCR Server 镜像、持久化 SQLite、HTTPS 反向代理和健康检查。

环境变量（可选，用于减少重复输入）：
  TB_VPS_IP             VPS IPv4 地址
  TB_SSH_PORT           SSH 端口，默认 22
  TB_SSH_USER           SSH 用户，默认 ubuntu
  TB_SSH_KEY            SSH 私钥路径
  CLOUDFLARE_API_TOKEN  Cloudflare API Token
  TB_DOMAIN             公网域名
  TB_VERSION            镜像标签，默认 v0.1.1
  TB_PORT_START         TCP 端口池起始值，默认 20000
  TB_PORT_END           TCP 端口池结束值，默认 20100
  TB_ACME_EMAIL         Let's Encrypt 联系邮箱（可选）
  TB_ADMIN_PASSWORD     首次管理员密码（建议仅交互输入）
EOF
}

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    # TMP_DIR is created by this script and never points at user data.
    rm -rf "$TMP_DIR"
  fi
}

on_error() {
  local code=$?
  printf '[TunnelBridge] 部署中止（退出码 %s）。现有服务未被脚本主动停止。\n' "$code" >&2
  exit "$code"
}

trap cleanup EXIT
trap on_error ERR

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "缺少命令 $1。请先安装后重试。"
}

prompt_value() {
  local label="$1"
  local default_value="${2-}"
  local value=""

  if [[ -n "$default_value" ]]; then
    printf '%s [%s]：' "$label" "$default_value" >&2
  else
    printf '%s：' "$label" >&2
  fi
  if ! IFS= read -r value; then
    value=""
  fi
  if [[ -z "$value" ]]; then
    value="$default_value"
  fi
  printf '%s' "$value"
}

prompt_secret() {
  local label="$1"
  local value=""
  printf '%s：' "$label" >&2
  if ! IFS= read -r -s value; then
    value=""
  fi
  printf '\n' >&2
  printf '%s' "$value"
}

confirm() {
  local label="$1"
  local answer=""
  printf '%s [y/N]：' "$label"
  if ! IFS= read -r answer; then
    return 1
  fi
  case "$answer" in
    y|Y|yes|YES|Yes) return 0 ;;
    *) return 1 ;;
  esac
}

is_integer() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

validate_inputs() {
  is_integer "$SSH_PORT" || die "SSH 端口必须是数字。"
  (( SSH_PORT >= 1 && SSH_PORT <= 65535 )) || die "SSH 端口范围无效。"
  is_integer "$PORT_START" || die "端口池起始值必须是数字。"
  is_integer "$PORT_END" || die "端口池结束值必须是数字。"
  (( PORT_START >= 1 && PORT_START <= 65535 )) || die "端口池起始值无效。"
  (( PORT_END >= 1 && PORT_END <= 65535 )) || die "端口池结束值无效。"
  (( PORT_START <= PORT_END )) || die "端口池起始值不能大于结束值。"
  [[ "$VPS_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "当前脚本要求 VPS_IP 为 IPv4 地址。"
  local octet
  IFS=. read -r -a octets <<< "$VPS_IP"
  for octet in "${octets[@]}"; do
    (( octet >= 0 && octet <= 255 )) || die "VPS_IP 不是有效 IPv4 地址。"
  done
  [[ "$DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] || die "域名格式无效，请使用完整域名，例如 tunnelbridge.example.com。"
  [[ "$VPS_USER" =~ ^[A-Za-z_][A-Za-z0-9._-]*$ ]] || die "SSH 用户名格式无效。"
  [[ "$VERSION" =~ ^v?[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "版本标签格式无效。"
  [[ -z "$ACME_EMAIL" || "$ACME_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "ACME 邮箱格式无效。"
  if [[ -n "$CF_TOKEN" ]]; then
    [[ "$CF_TOKEN" != *$'\n'* && "$CF_TOKEN" != *$'\r'* ]] || die "Cloudflare API Token 不能包含换行。"
  fi
  if [[ -n "$ADMIN_PASSWORD" ]]; then
    [[ "$ADMIN_PASSWORD" != *$'\n'* && "$ADMIN_PASSWORD" != *$'\r'* ]] || die "管理员密码不能包含换行。"
    (( ${#ADMIN_PASSWORD} >= 12 )) || die "管理员密码至少需要 12 个字符。"
  fi
}

choose_json_backend() {
  if command -v jq >/dev/null 2>&1; then
    JSON_BACKEND="jq"
  elif command -v python3 >/dev/null 2>&1; then
    JSON_BACKEND="python3"
  else
    die "需要 jq 或 python3 解析 Cloudflare API 响应。"
  fi
}

json_field() {
  local json="$1"
  local path="$2"
  if [[ "$JSON_BACKEND" == "jq" ]]; then
    printf '%s' "$json" | jq -r "$path"
  else
    printf '%s' "$json" | python3 -c '
import json, sys
value = json.load(sys.stdin)
path = sys.argv[1].lstrip(".").split(".")
for part in path:
    if not part:
        continue
    if isinstance(value, list):
        value = value[int(part)]
    else:
        value = value.get(part)
    if value is None:
        break
if isinstance(value, bool):
    print("true" if value else "false")
elif value is None:
    print("")
elif isinstance(value, (dict, list)):
    print(json.dumps(value, separators=(",", ":")))
else:
    print(value)
' "$path"
  fi
}

json_errors() {
  local json="$1"
  if [[ "$JSON_BACKEND" == "jq" ]]; then
    printf '%s' "$json" | jq -r '[.errors[]?.message] | join("; ")'
  else
    printf '%s' "$json" | python3 -c 'import json,sys; print("; ".join(e.get("message", "") for e in json.load(sys.stdin).get("errors", [])))'
  fi
}

json_string() {
  local value="$1"
  if [[ "$JSON_BACKEND" == "jq" ]]; then
    printf '%s' "$value" | jq -Rs .
  else
    printf '%s' "$value" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'
  fi
}

cf_api() {
  curl --fail --silent --show-error --retry 3 --connect-timeout 10 \
    -H "Authorization: Bearer $CF_TOKEN" \
    -H 'Content-Type: application/json' "$@"
}

find_zone() {
  local zones_json="$1"
  if [[ "$JSON_BACKEND" == "jq" ]]; then
    printf '%s' "$zones_json" | jq -r --arg domain "$DOMAIN" '
      [ .result[] | .name as $name | select($domain == $name or ($domain | endswith("." + $name))) ]
      | sort_by(.name | length)
      | if length == 0 then "" else .[-1] | [.id, .name] | @tsv end
    '
  else
    printf '%s' "$zones_json" | python3 -c '
import json,sys
domain=sys.argv[1]
zones=json.load(sys.stdin).get("result", [])
matches=[z for z in zones if domain == z.get("name") or domain.endswith("." + z.get("name", ""))]
if matches:
    z=sorted(matches, key=lambda x: len(x.get("name", "")))[-1]
    print(f"{z.get('id','')}\t{z.get('name','')}")
' "$DOMAIN"
  fi
}

record_lines() {
  local records_json="$1"
  if [[ "$JSON_BACKEND" == "jq" ]]; then
    printf '%s' "$records_json" | jq -r '.result[]? | [.id, .type, .name, .content, (.proxied // false)] | @tsv'
  else
    printf '%s' "$records_json" | python3 -c '
import json,sys
for r in json.load(sys.stdin).get("result", []):
    print("\t".join(str(r.get(k, "")) for k in ("id","type","name","content")) + "\t" + str(r.get("proxied", False)).lower())
'
  fi
}

shell_quote() {
  # Bash's %q produces one shell word that is safe to embed in the remote
  # bash script, including newlines and single quotes in a Caddy/HTTP config.
  printf '%q' "$1"
}

run_remote() {
  ssh -o BatchMode=yes -o ConnectTimeout=12 -o ServerAliveInterval=15 \
    -o ServerAliveCountMax=3 -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile="$KNOWN_HOSTS" -p "$SSH_PORT" -i "$SSH_KEY" \
    "$VPS_USER@$VPS_IP" "$@"
}

run_remote_script() {
  local script="$1"
  printf '%s\n' "$script" | ssh -o BatchMode=yes -o ConnectTimeout=12 \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS" \
    -p "$SSH_PORT" -i "$SSH_KEY" "$VPS_USER@$VPS_IP" 'bash -s'
}

prompt_inputs() {
  local default_key="${TB_SSH_KEY:-$HOME/.ssh/id_ed25519}"
  VPS_IP="${TB_VPS_IP:-$(prompt_value 'VPS IPv4 地址' '')}"
  SSH_PORT="${TB_SSH_PORT:-$(prompt_value 'SSH 端口' "$DEFAULT_SSH_PORT")}"
  VPS_USER="${TB_SSH_USER:-$(prompt_value 'SSH 用户' "$DEFAULT_SSH_USER")}"
  SSH_KEY="${TB_SSH_KEY:-$(prompt_value 'SSH 私钥路径' "$default_key")}"
  CF_TOKEN="${CLOUDFLARE_API_TOKEN:-$(prompt_secret 'Cloudflare API Token')}"
  DOMAIN="${TB_DOMAIN:-$(prompt_value '公网域名（例如 tunnelbridge.example.com）' '')}"
  VERSION="${TB_VERSION:-$(prompt_value 'Server 镜像标签' "$DEFAULT_VERSION")}"
  PORT_START="${TB_PORT_START:-$(prompt_value 'TCP 端口池起始值' "$DEFAULT_PORT_START")}"
  PORT_END="${TB_PORT_END:-$(prompt_value 'TCP 端口池结束值' "$DEFAULT_PORT_END")}"
  ACME_EMAIL="${TB_ACME_EMAIL:-$(prompt_value 'ACME 邮箱（可留空）' '')}"

  if [[ -n "${TB_ADMIN_PASSWORD:-}" ]]; then
    ADMIN_PASSWORD="$TB_ADMIN_PASSWORD"
    ADMIN_PASSWORD_IS_NEW=1
  else
    ADMIN_PASSWORD="$(prompt_secret '管理员密码（留空自动生成）')"
    if [[ -z "$ADMIN_PASSWORD" ]]; then
      ADMIN_PASSWORD="$(openssl rand -hex 24)"
    fi
    ADMIN_PASSWORD_IS_NEW=1
  fi
}

print_plan() {
  cat <<EOF

部署计划：
  VPS              ${VPS_USER}@${VPS_IP}:${SSH_PORT}
  公网域名         ${DOMAIN}
  Server 镜像      ${IMAGE_REPOSITORY}:${VERSION}
  TCP 端口池       ${PORT_START}-${PORT_END}
  HTTPS 代理       自动检测 Nginx；若无则启动 Caddy
  Cloudflare 代理  关闭（任意 TCP 端口不能走橙云代理）
  数据目录         ${REMOTE_ROOT}/data

EOF
}

configure_cloudflare_dns() {
  log "读取 Cloudflare Zone。"
  local zones_json
  zones_json="$(cf_api "$API_BASE/zones?per_page=100&status=active")" || die "无法访问 Cloudflare API。"
  [[ "$(json_field "$zones_json" '.success')" == "true" ]] || die "Cloudflare Zone 查询失败：$(json_errors "$zones_json")"

  local zone_match
  zone_match="$(find_zone "$zones_json")"
  [[ -n "$zone_match" ]] || die "找不到 $DOMAIN 对应的 Cloudflare Zone。"
  IFS=$'\t' read -r ZONE_ID ZONE_NAME <<< "$zone_match"
  log "使用 Zone ${ZONE_NAME}。"

  local records_json record_count=0 record_id="" record_type="" record_content=""
  records_json="$(cf_api "$API_BASE/zones/$ZONE_ID/dns_records?name=$DOMAIN")"
  [[ "$(json_field "$records_json" '.success')" == "true" ]] || die "DNS 记录查询失败：$(json_errors "$records_json")"
  while IFS=$'\t' read -r id type name content proxied; do
    [[ -z "${id:-}" ]] && continue
    record_count=$((record_count + 1))
    record_id="$id"
    record_type="$type"
    record_content="$content"
  done <<< "$(record_lines "$records_json")"

  (( record_count <= 1 )) || die "$DOMAIN 存在多条 DNS 记录，脚本不会自动覆盖。"
  if [[ "$record_count" -eq 1 && "$record_type" != "A" ]]; then
    die "$DOMAIN 已存在 $record_type 记录，脚本只会安全管理 A 记录。"
  fi

  local payload response action
  payload="{\"type\":\"A\",\"name\":\"$DOMAIN\",\"content\":\"$VPS_IP\",\"ttl\":120,\"proxied\":false}"
  if [[ "$record_count" -eq 1 ]]; then
    response="$(cf_api -X PUT "$API_BASE/zones/$ZONE_ID/dns_records/$record_id" --data-raw "$payload")"
    action="更新"
  else
    response="$(cf_api -X POST "$API_BASE/zones/$ZONE_ID/dns_records" --data-raw "$payload")"
    action="创建"
  fi
  [[ "$(json_field "$response" '.success')" == "true" ]] || die "Cloudflare DNS ${action}失败：$(json_errors "$response")"
  log "Cloudflare DNS 已${action}：${DOMAIN} -> ${VPS_IP}（DNS-only）。"
}

detect_remote() {
  log "检查 SSH、Docker 和现有 Web 服务。"
  run_remote 'command -v docker >/dev/null && sudo -n true && sudo -n docker info >/dev/null' \
    || die "SSH 或 Docker 检查失败；请确认 SSH 私钥、用户和免密码 sudo。"

  WEB_MODE="$(run_remote 'if command -v nginx >/dev/null 2>&1 && sudo -n nginx -t >/dev/null 2>&1; then echo nginx; else echo caddy; fi')"
  REMOTE_DB_EXISTS="$(run_remote "if sudo -n test -f ${REMOTE_ROOT}/data/tunnelbridge.db; then echo yes; else echo no; fi")"
  if [[ "$REMOTE_DB_EXISTS" == "yes" ]]; then
    if [[ "$ADMIN_PASSWORD_IS_NEW" -eq 1 ]]; then
      warn "检测到已有 SQLite 数据库，管理员密码保持不变；本次输入的密码不会写入服务器。"
    fi
    ADMIN_PASSWORD=""
    ADMIN_PASSWORD_IS_NEW=0
  fi
  local ports_in_use
  ports_in_use="$(run_remote 'ss -ltn 2>/dev/null | awk "NR > 1 {print \$4}" | grep -E "(:80|:443)$" || true')"
  local existing_server existing_caddy
  existing_server="$(run_remote "sudo -n docker ps -a --filter name=^/${SERVER_CONTAINER}\$ --format '{{.Names}}' || true")"
  existing_caddy="$(run_remote "sudo -n docker ps -a --filter name=^/${CADDY_CONTAINER}\$ --format '{{.Names}}' || true")"
  if [[ "$WEB_MODE" == "nginx" && -n "$existing_server" ]]; then
    :
  elif [[ "$WEB_MODE" == "nginx" ]]; then
    local local_port_in_use
    local_port_in_use="$(run_remote "ss -ltn 2>/dev/null | awk \"NR > 1 {print \\\$4}\" | grep -E ':${SERVER_LOCAL_PORT}\$' || true")"
    [[ -z "$local_port_in_use" ]] || die "本机端口 ${SERVER_LOCAL_PORT} 已被其他服务占用；脚本不会停止现有服务。"
  fi
  if [[ "$WEB_MODE" == "caddy" && -n "$ports_in_use" && -z "$existing_caddy" ]]; then
    die "VPS 没有可用的 Nginx，且 80/443 已被占用；脚本不会停止现有服务。"
  fi

  if [[ -n "$existing_server" ]]; then
    confirm "发现已有 $SERVER_CONTAINER 容器，确认重建容器（数据目录保留）吗？" \
      || die "已取消，未修改现有容器。"
    OVERWRITE_SERVER=1
  else
    OVERWRITE_SERVER=0
  fi
  if [[ "$WEB_MODE" == "caddy" && -n "$existing_caddy" ]]; then
    confirm "发现已有 $CADDY_CONTAINER 容器，确认重建吗？" \
      || die "已取消，未修改现有 Caddy 容器。"
    OVERWRITE_CADDY=1
  else
    OVERWRITE_CADDY=0
  fi

  log "使用 $WEB_MODE HTTPS 入口。"
}

deploy_server_container() {
  local image="${IMAGE_REPOSITORY}:${VERSION}"
  local bootstrap_line=""
  if [[ "$ADMIN_PASSWORD_IS_NEW" -eq 1 ]]; then
    bootstrap_line="TB_ADMIN_PASSWORD=$ADMIN_PASSWORD"
  fi

  local env_lines
  env_lines=$(cat <<EOF
TB_LISTEN_ADDR=0.0.0.0:8080
TB_DATABASE_URL=sqlite:///app/data/tunnelbridge.db?mode=rwc
TB_ADMIN_DIST=/app/admin
${bootstrap_line}
TB_SECURE_COOKIES=true
TB_PORT_START=${PORT_START}
TB_PORT_END=${PORT_END}
TB_AUDIT_RETENTION_DAYS=30
RUST_LOG=tunnelbridge_server=info
EOF
)

  local quoted_env=""
  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    quoted_env+=" $(shell_quote "$line")"
  done <<< "$env_lines"

  local network_args=""
  local health_command="sudo docker inspect --format '{{.State.Health.Status}}' ${SERVER_CONTAINER} | grep -q '^healthy$'"
  if [[ "$WEB_MODE" == "caddy" ]]; then
    network_args="--network ${CADDY_NETWORK}"
  else
    network_args="-p 127.0.0.1:${SERVER_LOCAL_PORT}:8080"
  fi

  local script
  script=$(cat <<EOF
set -eu
sudo install -d -m 0750 ${REMOTE_ROOT}
sudo install -d -o 10001 -g 10001 -m 0750 ${REMOTE_ROOT}/data
printf '%s\\n'${quoted_env} | sudo tee ${REMOTE_ROOT}/.env >/dev/null
sudo chmod 0600 ${REMOTE_ROOT}/.env
sudo docker pull ${image}
if [ "${OVERWRITE_SERVER}" = 1 ]; then sudo docker rm -f ${SERVER_CONTAINER} >/dev/null; fi
if [ "${WEB_MODE}" = caddy ]; then sudo docker network inspect ${CADDY_NETWORK} >/dev/null 2>&1 || sudo docker network create ${CADDY_NETWORK} >/dev/null; fi
sudo docker run -d --name ${SERVER_CONTAINER} --restart unless-stopped ${network_args} -p ${PORT_START}-${PORT_END}:${PORT_START}-${PORT_END} -v ${REMOTE_ROOT}/data:/app/data --env-file ${REMOTE_ROOT}/.env ${image} >/dev/null
ready=0
for i in \$(seq 1 45); do
  if ${health_command}; then ready=1; break; fi
  sleep 2
done
if [ "\$ready" -ne 1 ]; then sudo docker logs --tail 100 ${SERVER_CONTAINER} >&2; exit 1; fi
EOF
)
  run_remote_script "$script" || die "Server 容器启动失败。"

  if [[ "$ADMIN_PASSWORD_IS_NEW" -eq 1 ]]; then
    log "首次管理员初始化完成，移除 bootstrap 密码并重建容器。"
    local clear_script
    clear_script=$(cat <<EOF
set -eu
sudo sed -i '/^TB_ADMIN_PASSWORD=/d' ${REMOTE_ROOT}/.env
sudo docker rm -f ${SERVER_CONTAINER} >/dev/null
sudo docker run -d --name ${SERVER_CONTAINER} --restart unless-stopped ${network_args} -p ${PORT_START}-${PORT_END}:${PORT_START}-${PORT_END} -v ${REMOTE_ROOT}/data:/app/data --env-file ${REMOTE_ROOT}/.env ${image} >/dev/null
ready=0
for i in \$(seq 1 45); do
  if ${health_command}; then ready=1; break; fi
  sleep 2
done
if [ "\$ready" -ne 1 ]; then sudo docker logs --tail 100 ${SERVER_CONTAINER} >&2; exit 1; fi
if sudo docker inspect ${SERVER_CONTAINER} --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -q '^TB_ADMIN_PASSWORD='; then
  echo 'bootstrap password remains in container environment' >&2
  exit 1
fi
EOF
)
    run_remote_script "$clear_script" || die "移除 bootstrap 密码后重启失败。"
  fi
  log "Server 容器已就绪。"
}

select_nginx_config_path() {
  NGINX_CONF_PATH="$(run_remote 'if sudo -n nginx -T 2>/dev/null | grep -Fq "/www/server/panel/vhost/nginx/*.conf"; then echo /www/server/panel/vhost/nginx/tunnelbridge.conf; elif sudo -n nginx -T 2>/dev/null | grep -Fq "/etc/nginx/conf.d/*.conf"; then echo /etc/nginx/conf.d/tunnelbridge.conf; else echo /etc/nginx/conf.d/tunnelbridge.conf; fi')"
}

ensure_certbot() {
  log "检查 certbot。"
  run_remote_script 'set -eu
if command -v certbot >/dev/null 2>&1; then
  exit 0
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "未找到 certbot，且当前 VPS 没有 apt-get；请先手动安装 certbot。" >&2
  exit 1
fi
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y certbot
command -v certbot >/dev/null 2>&1'
}

install_nginx_config() {
  local config="$1"
  local config_quoted
  config_quoted="$(shell_quote "$config")"
  local script
  script=$(cat <<EOF
set -eu
sudo install -d -m 0755 \$(dirname ${NGINX_CONF_PATH})
printf '%s' ${config_quoted} | sudo tee ${NGINX_CONF_PATH} >/dev/null
if ! sudo nginx -t; then
  echo 'nginx -t failed; current running configuration was not reloaded' >&2
  exit 1
fi
if command -v systemctl >/dev/null 2>&1 && sudo systemctl reload nginx >/dev/null 2>&1; then
  :
else
  sudo nginx -s reload
fi
EOF
)
  run_remote_script "$script"
}

configure_nginx() {
  ensure_certbot || die "无法准备 certbot。"
  select_nginx_config_path
  NGINX_BACKUP_PATH="${REMOTE_ROOT}/backups/nginx.$(date +%Y%m%d%H%M%S).conf"
  log "使用 Nginx 配置文件 ${NGINX_CONF_PATH}。"
  local backup_script
  backup_script=$(cat <<EOF
set -eu
sudo install -d -m 0750 ${REMOTE_ROOT}/backups
if [ -f ${NGINX_CONF_PATH} ]; then sudo cp -a ${NGINX_CONF_PATH} ${NGINX_BACKUP_PATH}; fi
EOF
)
  run_remote_script "$backup_script"

  local http_config
  http_config=$(cat <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/tunnelbridge-acme;
        default_type text/plain;
        try_files \$uri =404;
    }

    location / {
        proxy_pass http://127.0.0.1:${SERVER_LOCAL_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }
}
EOF
)
  install_nginx_config "$http_config" || die "Nginx HTTP 配置失败。备份位于 ${NGINX_BACKUP_PATH}。"

  local email_args="--register-unsafely-without-email --no-eff-email"
  if [[ -n "$ACME_EMAIL" ]]; then
    email_args="--email $(shell_quote "$ACME_EMAIL") --no-eff-email"
  fi
  local cert_script
  cert_script=$(cat <<EOF
set -eu
sudo install -d -m 0755 /var/www/tunnelbridge-acme
sudo certbot certonly --webroot -w /var/www/tunnelbridge-acme -d ${DOMAIN} --non-interactive --agree-tos --keep-until-expiring ${email_args}
sudo test -s /etc/letsencrypt/live/${DOMAIN}/fullchain.pem
sudo test -s /etc/letsencrypt/live/${DOMAIN}/privkey.pem
EOF
)
  run_remote_script "$cert_script" || die "Let’s Encrypt 证书申请失败。HTTP ACME 配置已保留，备份位于 ${NGINX_BACKUP_PATH}。"

  local https_config
  https_config=$(cat <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/tunnelbridge-acme;
        default_type text/plain;
        try_files \$uri =404;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:TBSSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:${SERVER_LOCAL_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }
}
EOF
)
  install_nginx_config "$https_config" || die "Nginx HTTPS 配置失败。备份位于 ${NGINX_BACKUP_PATH}。"
  log "Nginx HTTPS 已就绪。"
}

configure_caddy() {
  local email_line=""
  if [[ -n "$ACME_EMAIL" ]]; then
    email_line="    email ${ACME_EMAIL}"
  fi
  local global_options=""
  if [[ -n "$email_line" ]]; then
    global_options="$(printf '{\n%s\n}\n\n' "$email_line")"
  fi
  local caddyfile
  caddyfile=$(cat <<EOF
${global_options}
${DOMAIN} {
    encode zstd gzip
    reverse_proxy ${SERVER_CONTAINER}:8080
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "same-origin"
        X-Frame-Options "DENY"
        Content-Security-Policy "default-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self' wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
    }
}
EOF
)
  local quoted_caddyfile
  quoted_caddyfile="$(shell_quote "$caddyfile")"
  local script
  script=$(cat <<EOF
set -eu
sudo install -d -m 0750 ${REMOTE_ROOT}/caddy-data ${REMOTE_ROOT}/caddy-config
printf '%s' ${quoted_caddyfile} | sudo tee ${REMOTE_ROOT}/Caddyfile >/dev/null
sudo chmod 0640 ${REMOTE_ROOT}/Caddyfile
sudo docker pull caddy:2.10-alpine
if [ "${OVERWRITE_CADDY}" = 1 ]; then sudo docker rm -f ${CADDY_CONTAINER} >/dev/null; fi
sudo docker run -d --name ${CADDY_CONTAINER} --restart unless-stopped --network ${CADDY_NETWORK} -p 80:80 -p 443:443 -v ${REMOTE_ROOT}/Caddyfile:/etc/caddy/Caddyfile:ro -v ${REMOTE_ROOT}/caddy-data:/data -v ${REMOTE_ROOT}/caddy-config:/config caddy:2.10-alpine >/dev/null
sleep 3
sudo docker ps --filter name=^/${CADDY_CONTAINER}\$ --format '{{.Status}}' | grep -q '^Up'
EOF
)
  run_remote_script "$script" || die "Caddy 启动失败。"
  log "Caddy HTTPS 已启动，等待证书签发。"
}

verify_deployment() {
  local base_url="https://${DOMAIN}"
  log "验证 HTTPS 和 Server 就绪接口。"
  local code="" https_ready=0
  for _ in $(seq 1 30); do
    if code="$(curl --fail --silent --show-error --connect-timeout 10 \
      --resolve "${DOMAIN}:443:${VPS_IP}" -o /dev/null -w '%{http_code}' \
      "${base_url}/readyz")" && [[ "$code" == "200" ]]; then
      https_ready=1
      break
    fi
    sleep 2
  done
  [[ "$https_ready" -eq 1 ]] || die "无法从本机访问 ${base_url}/readyz（最后 HTTP 状态：${code:-无响应}）。请检查 VPS 安全组、DNS 和证书签发。"

  if [[ "$ADMIN_PASSWORD_IS_NEW" -eq 1 ]]; then
    local body login_code password_json
    password_json="$(json_string "$ADMIN_PASSWORD")"
    body="{\"username\":\"admin\",\"password\":${password_json}}"
    login_code="$(curl --fail --silent --show-error --connect-timeout 10 \
      --resolve "${DOMAIN}:443:${VPS_IP}" -H 'Content-Type: application/json' \
      --data-raw "$body" -o /dev/null -w '%{http_code}' \
      "${base_url}/api/v1/auth/login")" || die "管理员登录接口验证失败。"
    [[ "$login_code" == "200" ]] || die "管理员登录返回 HTTP ${login_code}。"
  fi

  if command -v nc >/dev/null 2>&1; then
    if ! nc -z -w 3 "$VPS_IP" "$PORT_START" >/dev/null 2>&1; then
      warn "TCP 起始端口 $PORT_START 从当前网络不可达；请检查云安全组。"
    fi
    if ! nc -z -w 3 "$VPS_IP" "$PORT_END" >/dev/null 2>&1; then
      warn "TCP 结束端口 $PORT_END 从当前网络不可达；请检查云安全组。"
    fi
  fi

  cat <<EOF

部署完成：
  管理后台：${base_url}/
  客户端服务器地址：${base_url}
  GHCR 镜像：${IMAGE_REPOSITORY}:${VERSION}
  TCP 映射端口池：${PORT_START}-${PORT_END}
EOF
  if [[ "$ADMIN_PASSWORD_IS_NEW" -eq 1 ]]; then
    cat <<EOF
  管理员用户名：admin
  初始管理员密码：${ADMIN_PASSWORD}

请登录后立即修改初始密码。脚本不会把该密码写入 Git 仓库。
EOF
  else
    cat <<'EOF'
  数据库已存在，管理员密码保持不变；脚本没有重置它。
EOF
  fi
  cat <<EOF

创建隧道后，HTTP 本地服务的公网地址形如：
  http://${DOMAIN}:<远程端口>

Cloudflare DNS 记录保持 DNS-only，因为橙云代理不能转发 20000–20100 的任意 TCP 端口。
EOF
}

main() {
  case "${1:-}" in
    --help|-h)
      usage
      return 0
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
    "") ;;
    *) die "未知参数：$1。使用 --help 查看用法。" ;;
  esac

  require_cmd curl
  require_cmd ssh
  require_cmd openssl
  require_cmd ssh-keygen
  choose_json_backend
  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tunnelbridge-deploy.XXXXXX")"
  KNOWN_HOSTS="${TMP_DIR}/known_hosts"

  cat <<'EOF'
TunnelBridge Server 交互式部署
-------------------------------
脚本不会停止未知服务；80/443 若被占用，会优先复用现有 Nginx。
Cloudflare 仅用于 DNS，Token 和 SSH 私钥不会上传到 VPS。
EOF
  prompt_inputs
  validate_inputs
  print_plan

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "dry-run：未调用 Cloudflare API，未连接 VPS，未写入任何远程文件。"
    return 0
  fi
  [[ -f "$SSH_KEY" ]] || die "找不到 SSH 私钥：$SSH_KEY"
  [[ -n "$CF_TOKEN" ]] || die "Cloudflare API Token 不能为空。"

  detect_remote
  configure_cloudflare_dns
  deploy_server_container
  if [[ "$WEB_MODE" == "nginx" ]]; then
    configure_nginx
  else
    configure_caddy
  fi
  verify_deployment
}

main "$@"
