#!/usr/bin/env bash
set -euo pipefail

# =========================
# Paths / constants
# =========================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILES_DIR="${SCRIPT_DIR}/files"

ENV_FILE="/etc/voip-install.env"
LOG_FILE="/var/log/voip-install.log"

STATE_DIR="/var/lib/voip-install"
USERS_FILE="${STATE_DIR}/users.csv"

CRED_FILE="/root/voip_credentials.txt"

# Modes
DRY_RUN=0
RECONFIGURE=0
RESET_USERS=0

# CLI overrides: KEY=VALUE
declare -a OVERRIDES=()

# Runtime detected
PUBLIC_IP=""

# =========================
# Logging
# =========================
log() {
  printf '[%s] %s\n' "$(date -Is)" "$*"
}

die() {
  log "ERROR: $*"
  exit 1
}

setup_logging() {
  # In dry-run we must not create/modify files.
  if [[ "$DRY_RUN" -eq 1 ]]; then
    return 0
  fi
  mkdir -p "$(dirname "$LOG_FILE")"
  touch "$LOG_FILE"
  chmod 600 "$LOG_FILE"
  exec > >(tee -a "$LOG_FILE") 2>&1
}

# =========================
# Helpers
# =========================
run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] $*"
    return 0
  fi
  "$@"
}

run_bash() {
  # Run a string via bash -lc
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] bash -lc $1"
    return 0
  fi
  bash -lc "$1"
}

file_install() {
  # file_install <src> <dst> <mode>
  local src="$1"
  local dst="$2"
  local mode="$3"

  [[ -f "$src" ]] || die "Missing file: $src"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] install -D -m ${mode} ${src} ${dst}"
    return 0
  fi

  install -D -m "$mode" "$src" "$dst"
}

write_file() {
  # write_file <dst> <mode> <owner:group>  (content from stdin)
  local dst="$1"
  local mode="$2"
  local owner_group="$3"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] write ${dst} (mode ${mode}, owner ${owner_group})"
    return 0
  fi

  install -D -m "$mode" /dev/stdin "$dst"
  chown "$owner_group" "$dst"
}

trim() {
  # trim <string>
  local s="${1:-}"
  # shellcheck disable=SC2001
  echo "$s" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

is_number() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

is_ipv4() {
  local ip="${1:-}"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

# =========================
# Args / usage
# =========================
usage() {
  cat <<'EOF'
Usage:
  sudo ./install.sh [--dry-run] [--reconfigure] [--reset-users] [--set KEY=VALUE]...

Modes:
  --dry-run        Show plan only, change nothing
  --reconfigure    Regenerate configs, keep existing users/passwords
  --reset-users    Regenerate users/passwords (overwrites state users.csv)

Overrides:
  --set KEY=VALUE  Override variables (allowed keys listed in README)

Examples:
  sudo ./install.sh
  sudo ./install.sh --dry-run
  sudo ./install.sh --reconfigure
  sudo ./install.sh --reset-users
  sudo ./install.sh --set SIP_PORT=5062 --set RTP_PORT_START=12000 --set RTP_PORT_END=13000
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --reconfigure)
        RECONFIGURE=1
        shift
        ;;
      --reset-users)
        RESET_USERS=1
        shift
        ;;
      --set)
        [[ $# -ge 2 ]] || die "--set requires KEY=VALUE"
        OVERRIDES+=("$2")
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1 (use --help)"
        ;;
    esac
  done

  if [[ "$RECONFIGURE" -eq 1 && "$RESET_USERS" -eq 1 ]]; then
    die "Choose only one: --reconfigure OR --reset-users"
  fi
}

# =========================
# Required functions (as requested)
# =========================
check_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Run as root (use sudo)."
  fi
}

load_env() {
  # Defaults
  SIP_USERS_BASE="${SIP_USERS_BASE:-1001}"
  SIP_USERS_COUNT="${SIP_USERS_COUNT:-12}"

  SIP_PASSWORD_MODE="${SIP_PASSWORD_MODE:-random}"   # random|preset
  SIP_PASSWORD_PRESET="${SIP_PASSWORD_PRESET:-MyStrongPass-{ext}}"

  SIP_PORT="${SIP_PORT:-5060}"
  RTP_PORT_START="${RTP_PORT_START:-10000}"
  RTP_PORT_END="${RTP_PORT_END:-20000}"

  LOCAL_NET="${LOCAL_NET:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"
  TIMEZONE="${TIMEZONE:-Europe/Moscow}"

  ALLOW_SSH_FROM="${ALLOW_SSH_FROM:-}"

  # Load /etc/voip-install.env if present
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
  fi

  # Apply CLI overrides safely (only allow known keys)
  for kv in "${OVERRIDES[@]}"; do
    [[ "$kv" == *=* ]] || die "Bad --set value: $kv (expected KEY=VALUE)"
    key="${kv%%=*}"
    val="${kv#*=}"

    case "$key" in
      SIP_USERS_BASE|SIP_USERS_COUNT|SIP_PASSWORD_MODE|SIP_PASSWORD_PRESET|SIP_PORT|RTP_PORT_START|RTP_PORT_END|LOCAL_NET|TIMEZONE|ALLOW_SSH_FROM)
        printf -v "$key" '%s' "$val"
        ;;
      *)
        die "Unknown/forbidden key for --set: $key"
        ;;
    esac
  done

  validate_env
}

validate_env() {
  is_number "$SIP_USERS_BASE" || die "SIP_USERS_BASE must be a number"
  is_number "$SIP_USERS_COUNT" || die "SIP_USERS_COUNT must be a number"
  [[ "$SIP_USERS_COUNT" -ge 1 ]] || die "SIP_USERS_COUNT must be >= 1"

  [[ "$SIP_PASSWORD_MODE" == "random" || "$SIP_PASSWORD_MODE" == "preset" ]] || die "SIP_PASSWORD_MODE must be random|preset"

  is_number "$SIP_PORT" || die "SIP_PORT must be a number"
  is_number "$RTP_PORT_START" || die "RTP_PORT_START must be a number"
  is_number "$RTP_PORT_END" || die "RTP_PORT_END must be a number"
  [[ "$RTP_PORT_START" -lt "$RTP_PORT_END" ]] || die "RTP_PORT_START must be < RTP_PORT_END"

  [[ -n "$(trim "$TIMEZONE")" ]] || die "TIMEZONE must be non-empty"
}

detect_public_ip() {
  # Requires curl (installed in install_packages)
  local ip=""

  if command -v curl >/dev/null 2>&1; then
    ip="$(curl -fsS -4 --max-time 5 https://api.ipify.org || true)"
  fi
  if is_ipv4 "$ip"; then
    PUBLIC_IP="$ip"
    return 0
  fi

  # Fallback: best effort (may return interface IP)
  ip="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)"
  if is_ipv4 "$ip"; then
    PUBLIC_IP="$ip"
    return 0
  fi

  PUBLIC_IP="127.0.0.1"
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive

  local apt_opts=(
    -y
    -o Dpkg::Options::=--force-confdef
    -o Dpkg::Options::=--force-confold
  )

  run apt-get update -y

  # "Обновляет систему" (без интерактива и без слома конфигов)
  run apt-get "${apt_opts[@]}" upgrade

  run apt-get "${apt_opts[@]}" install --no-install-recommends \
    asterisk \
    fail2ban \
    nftables \
    curl \
    ca-certificates \
    openssl
}

configure_asterisk() {
  # Base configs from repo
  file_install "${FILES_DIR}/asterisk/pjsip.conf"      "/etc/asterisk/pjsip.conf"      "0644"
  file_install "${FILES_DIR}/asterisk/extensions.conf" "/etc/asterisk/extensions.conf" "0644"
  file_install "${FILES_DIR}/asterisk/logger.conf"     "/etc/asterisk/logger.conf"     "0644"

  # Generate dynamic configs
  generate_pjsip
  generate_dialplan

  # RTP port range
  write_file "/etc/asterisk/rtp.conf" "0640" "root:asterisk" <<EOF
; Autogenerated by voip-install ($(date -Is))
[general]
rtpstart=${RTP_PORT_START}
rtpend=${RTP_PORT_END}
EOF

  # Permissions for asterisk configs
  if [[ "$DRY_RUN" -eq 0 ]]; then
    chown root:asterisk /etc/asterisk/pjsip.conf \
      /etc/asterisk/pjsip_transport.conf \
      /etc/asterisk/pjsip_endpoints.conf \
      /etc/asterisk/extensions.conf \
      /etc/asterisk/extensions_internal.conf \
      /etc/asterisk/logger.conf \
      /etc/asterisk/rtp.conf 2>/dev/null || true

    chmod 0640 /etc/asterisk/pjsip.conf \
      /etc/asterisk/pjsip_transport.conf \
      /etc/asterisk/pjsip_endpoints.conf \
      /etc/asterisk/extensions.conf \
      /etc/asterisk/extensions_internal.conf \
      /etc/asterisk/logger.conf \
      /etc/asterisk/rtp.conf 2>/dev/null || true
  else
    log "[dry-run] chown/chmod asterisk configs"
  fi
}

generate_users_state_if_needed() {
  # State dir
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] ensure state dir ${STATE_DIR}"
  else
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
  fi

  if [[ "$RESET_USERS" -eq 1 ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      log "[dry-run] reset users: remove ${USERS_FILE}"
    else
      rm -f "$USERS_FILE"
    fi
  fi

  if [[ -s "$USERS_FILE" ]]; then
    log "Users state exists: ${USERS_FILE} (passwords preserved)"
    return 0
  fi

  log "Generating users state: ${USERS_FILE} (${SIP_USERS_COUNT} users from ${SIP_USERS_BASE})"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] would generate CSV ext,password"
    return 0
  fi

  : > "$USERS_FILE"
  chmod 600 "$USERS_FILE"

  for ((i=0; i<SIP_USERS_COUNT; i++)); do
    ext=$((SIP_USERS_BASE + i))

    if [[ "$SIP_PASSWORD_MODE" == "preset" ]]; then
      # Pattern supports {ext}
      pass="${SIP_PASSWORD_PRESET//\{ext\}/$ext}"
    else
      pass="$(openssl rand -hex 8)"
    fi

    printf '%s,%s\n' "$ext" "$pass" >> "$USERS_FILE"
  done
}

generate_pjsip() {
  generate_users_state_if_needed

  # Transport (NAT-aware)
  write_file "/etc/asterisk/pjsip_transport.conf" "0640" "root:asterisk" <<EOF
; Autogenerated by voip-install ($(date -Is))
[transport-udp]
type=transport
protocol=udp
bind=0.0.0.0:${SIP_PORT}
external_signaling_address=${PUBLIC_IP}
external_signaling_port=${SIP_PORT}
external_media_address=${PUBLIC_IP}
$(for n in $(echo "$LOCAL_NET" | tr ',' ' '); do n="$(trim "$n")"; [[ -n "$n" ]] && echo "local_net=${n}"; done)
allow_reload=yes
EOF

  # Endpoints/auth/aor
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] would generate /etc/asterisk/pjsip_endpoints.conf from ${USERS_FILE}"
    return 0
  fi

  {
    echo "; Autogenerated by voip-install ($(date -Is))"
    echo
    echo "[endpoint-basic](!)"
    echo "type=endpoint"
    echo "transport=transport-udp"
    echo "context=internal"
    echo "disallow=all"
    echo "allow=ulaw,alaw"
    echo "direct_media=no"
    echo "rtp_symmetric=yes"
    echo "force_rport=yes"
    echo "rewrite_contact=yes"
    echo "dtmf_mode=rfc4733"
    echo
    echo "[aor-basic](!)"
    echo "type=aor"
    echo "max_contacts=1"
    echo "remove_existing=yes"
    echo "qualify_frequency=60"
    echo
    echo "[auth-basic](!)"
    echo "type=auth"
    echo "auth_type=userpass"
    echo

    while IFS=',' read -r ext pass; do
      ext="$(trim "$ext")"
      pass="$(trim "$pass")"
      [[ -z "$ext" ]] && continue

      echo "[${ext}](endpoint-basic)"
      echo "auth=${ext}"
      echo "aors=${ext}"
      echo "callerid=${ext} <${ext}>"
      echo
      echo "[${ext}](auth-basic)"
      echo "username=${ext}"
      echo "password=${pass}"
      echo
      echo "[${ext}](aor-basic)"
      echo
    done < "$USERS_FILE"
  } > /etc/asterisk/pjsip_endpoints.conf
}

generate_dialplan() {
  generate_users_state_if_needed

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] would generate /etc/asterisk/extensions_internal.conf from ${USERS_FILE}"
    return 0
  fi

  {
    echo "; Autogenerated by voip-install ($(date -Is))"
    echo
    echo "[internal]"
    while IFS=',' read -r ext _pass; do
      ext="$(trim "$ext")"
      [[ -z "$ext" ]] && continue
      echo "exten => ${ext},1,NoOp(Internal call to ${ext})"
      echo " same => n,Dial(PJSIP/${ext},20)"
      echo " same => n,Hangup()"
      echo
    done < "$USERS_FILE"
  } > /etc/asterisk/extensions_internal.conf
}

configure_firewall() {
  local tpl="${FILES_DIR}/firewall/nftables.conf.template"
  [[ -f "$tpl" ]] || die "Missing template: $tpl"

  local ssh_rule=""
  if [[ -n "$(trim "$ALLOW_SSH_FROM")" ]]; then
    ssh_rule="tcp dport 22 ip saddr ${ALLOW_SSH_FROM} accept"
  else
    ssh_rule="tcp dport 22 accept"
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] render /etc/nftables.conf from template"
  else
    sed \
      -e "s/__SIP_PORT__/${SIP_PORT}/g" \
      -e "s/__RTP_START__/${RTP_PORT_START}/g" \
      -e "s/__RTP_END__/${RTP_PORT_END}/g" \
      -e "s|__SSH_RULE__|${ssh_rule}|g" \
      "$tpl" > /etc/nftables.conf
    chmod 0644 /etc/nftables.conf
  fi

  run systemctl enable --now nftables
  run systemctl restart nftables
}

configure_fail2ban() {
  file_install "${FILES_DIR}/fail2ban/filter.d/asterisk-pjsip.conf" \
    "/etc/fail2ban/filter.d/asterisk-pjsip.conf" "0644"

  local tpl="${FILES_DIR}/fail2ban/jail.d/asterisk-pjsip.conf.template"
  [[ -f "$tpl" ]] || die "Missing template: $tpl"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] render /etc/fail2ban/jail.d/asterisk-pjsip.conf from template"
  else
    sed -e "s/__SIP_PORT__/${SIP_PORT}/g" "$tpl" > /etc/fail2ban/jail.d/asterisk-pjsip.conf
    chmod 0644 /etc/fail2ban/jail.d/asterisk-pjsip.conf
  fi

  run systemctl enable --now fail2ban
  run systemctl restart fail2ban
}

start_services() {
  run systemctl enable --now asterisk
  run systemctl restart asterisk
}

health_check() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] health-check: asterisk -rx \"core show uptime\" / \"pjsip show endpoints\""
    return 0
  fi

  # Wait for asterisk
  for _ in $(seq 1 30); do
    if asterisk -rx "core show uptime" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  asterisk -rx "core show uptime" >/dev/null 2>&1 || die "Asterisk CLI not responding"

  log "Asterisk uptime:"
  asterisk -rx "core show uptime" || true

  log "PJSIP endpoints:"
  asterisk -rx "pjsip show endpoints" || true
}

write_credentials() {
  generate_users_state_if_needed

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] write ${CRED_FILE}"
    return 0
  fi

  {
    echo "Server: ${PUBLIC_IP}"
    echo "SIP: ${PUBLIC_IP}:${SIP_PORT} (UDP)"
    echo "RTP: ${RTP_PORT_START}-${RTP_PORT_END} (UDP)"
    echo "Transport: UDP"
    echo "Codecs: ulaw, alaw"
    echo
    echo "Users (ext<TAB>password):"
    while IFS=',' read -r ext pass; do
      ext="$(trim "$ext")"
      pass="$(trim "$pass")"
      [[ -z "$ext" ]] && continue
      printf "%s\t%s\n" "$ext" "$pass"
    done < "$USERS_FILE"
    echo
    echo "Bootstrap log: ${LOG_FILE}"
    echo "Asterisk log: /var/log/asterisk/messages"
  } > "$CRED_FILE"

  chmod 600 "$CRED_FILE"
}

# =========================
# Plan / main
# =========================
show_plan() {
  cat <<EOF
Plan:
- OS: Debian 12
- Packages: asterisk, fail2ban, nftables, curl, ca-certificates, openssl
- Config:
  /etc/asterisk/pjsip.conf
  /etc/asterisk/pjsip_transport.conf
  /etc/asterisk/pjsip_endpoints.conf
  /etc/asterisk/extensions.conf
  /etc/asterisk/extensions_internal.conf
  /etc/asterisk/logger.conf
  /etc/asterisk/rtp.conf
  /etc/nftables.conf
  /etc/fail2ban/filter.d/asterisk-pjsip.conf
  /etc/fail2ban/jail.d/asterisk-pjsip.conf
- State:
  ${USERS_FILE}  (passwords preserved unless --reset-users)
- Output:
  ${CRED_FILE}
  ${LOG_FILE}

Variables:
  SIP_USERS_BASE=${SIP_USERS_BASE}
  SIP_USERS_COUNT=${SIP_USERS_COUNT}
  SIP_PASSWORD_MODE=${SIP_PASSWORD_MODE}
  SIP_PORT=${SIP_PORT}
  RTP_PORT_START=${RTP_PORT_START}
  RTP_PORT_END=${RTP_PORT_END}
  LOCAL_NET=${LOCAL_NET}
  TIMEZONE=${TIMEZONE}
  ALLOW_SSH_FROM=${ALLOW_SSH_FROM}
EOF
}

main() {
  parse_args "$@"
  check_root

  # load env BEFORE logging redirection (dry-run must not touch files)
  load_env

  setup_logging

  log "=== voip-install started ==="
  if [[ "$DRY_RUN" -eq 1 ]]; then
    show_plan
    log "=== voip-install dry-run finished ==="
    exit 0
  fi

  # Timezone (best-effort)
  if command -v timedatectl >/dev/null 2>&1; then
    run timedatectl set-timezone "$TIMEZONE" || true
  fi

  install_packages
  detect_public_ip
  log "PUBLIC_IP=${PUBLIC_IP}"

  # Always (re)configure (idempotent). Passwords preserved unless --reset-users.
  configure_firewall
  configure_fail2ban
  configure_asterisk
  start_services
  health_check
  write_credentials

  log "Credentials: ${CRED_FILE}"
  log "=== voip-install finished ==="
}

main "$@"

