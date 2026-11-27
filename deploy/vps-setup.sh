#!/usr/bin/env bash
# Vernam (VRNM) v2.2.0 Testnet — ROOT VPS PROVISIONING SCRIPT
#
# NOTE: This is a root server provisioning script for Ubuntu/Debian VPS hosts
# (installs system packages, builds /usr/local/bin/vrnm, creates the `vernam`
# system user, installs a hardened systemd service, and configures UFW).
# It is NOT a desktop/client installer — for user-space CLI installation without
# sudo, inspect and run `deploy/install.sh` instead.
#
# Inspect-first usage (do NOT pipe unverified remote scripts to sudo bash):
#   git clone https://github.com/gpt4omni/vernam.git
#   cd vernam
#   less deploy/vps-setup.sh
#   sudo bash deploy/vps-setup.sh
#
# Optional environment overrides:
#   VRNM_REPO_URL  (default: https://github.com/gpt4omni/vernam.git)
#   VRNM_BRANCH    (default: main)
#   VRNM_SRC_DIR   (default: /opt/vernam)
#   VRNM_DATA_DIR  (default: /var/lib/vernam)
#   VRNM_BIND      (default: 0.0.0.0:8080)
#   VRNM_USER      (default: vernam)

set -euo pipefail

VRNM_REPO_URL="${VRNM_REPO_URL:-https://github.com/gpt4omni/vernam.git}"
VRNM_BRANCH="${VRNM_BRANCH:-main}"
VRNM_SRC_DIR="${VRNM_SRC_DIR:-/opt/vernam}"
VRNM_DATA_DIR="${VRNM_DATA_DIR:-/var/lib/vernam}"
VRNM_BIND="${VRNM_BIND:-0.0.0.0:8080}"
VRNM_USER="${VRNM_USER:-vernam}"
VRNM_BIN="/usr/local/bin/vrnm"
VRNM_SERVICE="vernam-testnet.service"
VRNM_PORT="${VRNM_BIND##*:}"

log()  { printf '\033[1;32m[vernam]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[vernam]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[vernam]\033[0m %s\n' "$*" >&2; exit 1; }

validate_config() {
    if [[ ! "${VRNM_BIND}" =~ ^[0-9A-Za-z.\[\]:-]+:[0-9]{1,5}$ ]]; then
        err "Invalid VRNM_BIND='${VRNM_BIND}': must match host:port (e.g., 0.0.0.0:8080 or [::]:8080)."
    fi
    if [[ ! "${VRNM_PORT}" =~ ^[0-9]{1,5}$ ]] || (( 10#${VRNM_PORT} < 1 || 10#${VRNM_PORT} > 65535 )); then
        err "Invalid port '${VRNM_PORT}' in VRNM_BIND='${VRNM_BIND}': must be 1..65535."
    fi
    if [[ ! "${VRNM_USER}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
        err "Invalid VRNM_USER='${VRNM_USER}': must be a valid POSIX system username."
    fi
    if [[ ! "${VRNM_DATA_DIR}" =~ ^/[0-9A-Za-z._/-]+$ ]] || [[ "${VRNM_DATA_DIR}" == *".."* ]]; then
        err "Invalid VRNM_DATA_DIR='${VRNM_DATA_DIR}': must be an absolute path without '..' or metacharacters."
    fi
}

run_root() {
    if [[ "${EUID}" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

require_privileges() {
    if [[ "${EUID}" -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
        err "Please run as root or install sudo."
    fi
}

install_system_packages() {
    if ! command -v apt-get >/dev/null 2>&1; then
        warn "apt-get not found; assuming build-essential, curl, and git are already installed."
        return
    fi

    local missing=()
    command -v cc   >/dev/null 2>&1 || missing+=(build-essential)
    command -v curl >/dev/null 2>&1 || missing+=(curl)
    command -v git  >/dev/null 2>&1 || missing+=(git)

    if (( ${#missing[@]} > 0 )); then
        log "Installing system packages: ${missing[*]} ca-certificates"
        run_root env DEBIAN_FRONTEND=noninteractive apt-get update -qq
        run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
            "${missing[@]}" ca-certificates
    else
        log "System build dependencies already present."
    fi
}

ensure_rust() {
    # Load existing rustup environment if present
    if [[ -f "${HOME}/.cargo/env" ]]; then
        # shellcheck disable=SC1091
        source "${HOME}/.cargo/env"
    elif [[ -f "/root/.cargo/env" ]] && [[ "${EUID}" -eq 0 ]]; then
        # shellcheck disable=SC1091
        source "/root/.cargo/env"
    fi

    if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
        warn "Rust / Cargo toolchain not found. This script does NOT execute unverified remote curl|sh installers."
        cat >&2 <<'EOF'

Please install Rust >= 1.85 (edition 2024) manually first — e.g. via your OS
package manager (`apt install rustc cargo` if >= 1.85) or a verified rustup
installer from https://rustup.rs — then re-run:

  sudo bash deploy/vps-setup.sh
EOF
        exit 1
    fi

    # Edition 2024 requires Rust >= 1.85
    local rustc_ver major_ver minor_ver
    rustc_ver="$(rustc --version | awk '{print $2}')"
    major_ver="$(printf '%s' "${rustc_ver}" | cut -d. -f1)"
    minor_ver="$(printf '%s' "${rustc_ver}" | cut -d. -f2)"
    if [[ "${major_ver}" =~ ^[0-9]+$ ]] && [[ "${minor_ver}" =~ ^[0-9]+$ ]]; then
        if (( major_ver < 1 || (major_ver == 1 && minor_ver < 85) )); then
            if command -v rustup >/dev/null 2>&1; then
                log "Updating Rust (${rustc_ver} < 1.85 required for edition 2024)..."
                rustup update stable
                rustup default stable
            else
                err "Rust ${rustc_ver} is too old for edition 2024 (requires >= 1.85). Please upgrade Rust."
            fi
        fi
    fi

    log "Using $(rustc --version) / $(cargo --version)"
}

resolve_source_dir() {
    local candidate=""

    # 1. Check current working directory
    if [[ -f "${PWD}/Cargo.toml" ]] && grep -q 'name = "vernam-rs"' "${PWD}/Cargo.toml" 2>/dev/null; then
        candidate="${PWD}"
    fi

    # 2. Check directory containing this script
    if [[ -z "${candidate}" ]] && [[ -n "${BASH_SOURCE[0]:-}" ]] && [[ -f "${BASH_SOURCE[0]}" ]]; then
        local script_dir parent_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        parent_dir="$(cd "${script_dir}/.." && pwd)"
        if [[ -f "${parent_dir}/Cargo.toml" ]] && grep -q 'name = "vernam-rs"' "${parent_dir}/Cargo.toml" 2>/dev/null; then
            candidate="${parent_dir}"
        fi
    fi

    if [[ -n "${candidate}" ]]; then
        log "Detected local Vernam repository at ${candidate}"
        BUILD_DIR="${candidate}"
        return
    fi

    # 3. Clone or update from GitHub
    if [[ -d "${VRNM_SRC_DIR}/.git" ]]; then
        log "Updating existing repository in ${VRNM_SRC_DIR}..."
        if [[ "${EUID}" -ne 0 ]]; then
            run_root chown -R "$(id -u):$(id -g)" "${VRNM_SRC_DIR}"
        fi
        git -C "${VRNM_SRC_DIR}" fetch --depth 1 origin "${VRNM_BRANCH}"
        git -C "${VRNM_SRC_DIR}" checkout -B "${VRNM_BRANCH}" "origin/${VRNM_BRANCH}"
    else
        log "Cloning ${VRNM_REPO_URL} (branch: ${VRNM_BRANCH}) into ${VRNM_SRC_DIR}..."
        run_root mkdir -p "${VRNM_SRC_DIR}"
        if [[ "${EUID}" -ne 0 ]]; then
            run_root chown "$(id -u):$(id -g)" "${VRNM_SRC_DIR}"
        fi
        git clone --depth 1 --branch "${VRNM_BRANCH}" "${VRNM_REPO_URL}" "${VRNM_SRC_DIR}"
    fi

    if [[ -f "${VRNM_SRC_DIR}/Cargo.toml" ]]; then
        BUILD_DIR="${VRNM_SRC_DIR}"
    elif [[ -f "${VRNM_SRC_DIR}/vernam-rs/Cargo.toml" ]]; then
        BUILD_DIR="${VRNM_SRC_DIR}/vernam-rs"
    else
        err "Could not locate Cargo.toml inside ${VRNM_SRC_DIR}"
    fi
}

build_and_install_binary() {
    log "Building Vernam release binary (zero external crates)..."
    (
        cd "${BUILD_DIR}"
        cargo build --release --offline
    )

    local built_bin=""
    if [[ -x "${BUILD_DIR}/target/release/vernam-rs" ]]; then
        built_bin="${BUILD_DIR}/target/release/vernam-rs"
    elif [[ -x "${BUILD_DIR}/target/release/vrnm" ]]; then
        built_bin="${BUILD_DIR}/target/release/vrnm"
    else
        err "Release binary not found in ${BUILD_DIR}/target/release/"
    fi

    log "Installing ${VRNM_BIN}..."
    run_root install -D -m 0755 "${built_bin}" "${VRNM_BIN}"
    run_root ln -sfn "${VRNM_BIN}" /usr/local/bin/vernam-rs
}

configure_user_and_dirs() {
    if ! id -u "${VRNM_USER}" >/dev/null 2>&1; then
        log "Creating system user '${VRNM_USER}'..."
        run_root useradd --system \
            --home-dir "${VRNM_DATA_DIR}" \
            --shell /usr/sbin/nologin \
            --no-create-home \
            "${VRNM_USER}"
    else
        log "System user '${VRNM_USER}' already exists."
    fi

    log "Ensuring data directory ${VRNM_DATA_DIR} (mode 0700)..."
    run_root mkdir -p "${VRNM_DATA_DIR}"
    run_root chown "${VRNM_USER}:${VRNM_USER}" "${VRNM_DATA_DIR}"
    run_root chmod 0700 "${VRNM_DATA_DIR}"
}

install_systemd_service() {
    local unit_dest="/etc/systemd/system/${VRNM_SERVICE}"
    local unit_src="${BUILD_DIR}/deploy/${VRNM_SERVICE}"

    log "Installing systemd unit ${unit_dest}..."
    if [[ -f "${unit_src}" ]]; then
        run_root install -m 0644 "${unit_src}" "${unit_dest}"
    else
        run_root tee "${unit_dest}" >/dev/null <<EOF
[Unit]
Description=Vernam (VRNM) Information-Theoretically Secure Testnet Node
Documentation=https://github.com/gpt4omni/vernam
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${VRNM_USER}
Group=${VRNM_USER}
WorkingDirectory=${VRNM_DATA_DIR}
StateDirectory=vernam
StateDirectoryMode=0700
Environment=VRNM_BIND=${VRNM_BIND}
Environment=VRNM_DATA_DIR=${VRNM_DATA_DIR}
ExecStart=${VRNM_BIN} testnet --bind ${VRNM_BIND}
Restart=on-failure
RestartSec=3
TimeoutStopSec=15
LimitNOFILE=65536
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF
    fi

    # Apply validated VRNM_USER, VRNM_DATA_DIR, and VRNM_BIND consistently to the installed unit.
    run_root sed -i \
        -e "s|^User=.*|User=${VRNM_USER}|" \
        -e "s|^Group=.*|Group=${VRNM_USER}|" \
        -e "s|^WorkingDirectory=.*|WorkingDirectory=${VRNM_DATA_DIR}|" \
        -e "s|^Environment=VRNM_DATA_DIR=.*|Environment=VRNM_DATA_DIR=${VRNM_DATA_DIR}|" \
        -e "s|^Environment=VRNM_BIND=.*|Environment=VRNM_BIND=${VRNM_BIND}|" \
        -e "s|--bind [^ ]*|--bind ${VRNM_BIND}|" \
        "${unit_dest}"

    run_root systemctl daemon-reload
    run_root systemctl enable "${VRNM_SERVICE}"
    run_root systemctl restart "${VRNM_SERVICE}"
}

configure_firewall() {
    if command -v ufw >/dev/null 2>&1; then
        if run_root ufw status 2>/dev/null | grep -qi "Status: active"; then
            log "UFW is active; allowing TCP port ${VRNM_PORT}..."
            run_root ufw allow "${VRNM_PORT}/tcp" comment "Vernam Testnet" >/dev/null
        else
            log "UFW installed but inactive; skipping firewall rule."
        fi
    fi
}

wait_for_health() {
    local health_url="http://127.0.0.1:${VRNM_PORT}/health"
    log "Waiting for node health check at ${health_url}..."

    local i
    for (( i = 1; i <= 30; i++ )); do
        if curl -fsS --max-time 2 "${health_url}" >/dev/null 2>&1; then
            log "Vernam Testnet is healthy and accepting requests!"
            return
        fi
        sleep 1
    done

    warn "Health check timed out after 30s. Recent service logs:"
    run_root journalctl -u "${VRNM_SERVICE}" -n 30 --no-pager || true
    err "Vernam Testnet failed to pass health check at ${health_url}"
}

detect_public_ip() {
    local ip=""
    ip="$(curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null || true)"
    if [[ -z "${ip}" ]]; then
        ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    fi
    printf '%s' "${ip:-<YOUR_VPS_IP>}"
}

print_summary() {
    local public_ip node_url
    public_ip="$(detect_public_ip)"
    node_url="http://${public_ip}:${VRNM_PORT}"

    cat <<EOF

====================================================================
  Vernam (VRNM) v2.2.0 Testnet Node is LIVE!
====================================================================

  Dashboard URL : ${node_url}
  Health Check  : ${node_url}/health
  Data Dir      : ${VRNM_DATA_DIR} (mode 0700, owner ${VRNM_USER})
  Systemd Unit  : ${VRNM_SERVICE}

  Service management:
    sudo systemctl status ${VRNM_SERVICE}
    sudo journalctl -fu ${VRNM_SERVICE}

  Try your Vernam CLI wallet against this node:
    export VRNM_NODE="${node_url}"
    vrnm wallet create --name alice
    vrnm wallet faucet --name alice --node "\$VRNM_NODE"
    vrnm wallet balance --name alice --node "\$VRNM_NODE"
    vrnm wallet send --from alice --to bob --amount 10 --node "\$VRNM_NODE"
    vrnm wallet send-private --from alice --to bob --amount 5 --node "\$VRNM_NODE"
    vrnm wallet status --node "\$VRNM_NODE"

  SECURITY NOTE:
    - Front :${VRNM_PORT} with HTTPS (see deploy/Caddyfile) before handling real auth keys.
    - NEVER restore an old snapshot/backup of burned OTP WAL pad files!
====================================================================
EOF
}

main() {
    validate_config
    require_privileges
    install_system_packages
    ensure_rust
    resolve_source_dir
    build_and_install_binary
    configure_user_and_dirs
    install_systemd_service
    configure_firewall
    wait_for_health
    print_summary
}

main "$@"
