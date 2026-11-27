#!/usr/bin/env bash
# Vernam (VRNM) v1.2 — Zero-Dependency One-Line Installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/gpt4omni/vernam/main/deploy/install.sh | bash
#
# Optional environment overrides:
#   VRNM_REPO_URL     (default: https://github.com/gpt4omni/vernam.git)
#   VRNM_BRANCH       (default: main)
#   VRNM_SRC_DIR      (default: ~/.local/src/vernam)
#   VRNM_INSTALL_DIR  (default: ~/.local/bin)

set -euo pipefail

VRNM_REPO_URL="${VRNM_REPO_URL:-https://github.com/gpt4omni/vernam.git}"
VRNM_BRANCH="${VRNM_BRANCH:-main}"
VRNM_SRC_DIR="${VRNM_SRC_DIR:-${HOME}/.local/src/vernam}"
VRNM_INSTALL_DIR="${VRNM_INSTALL_DIR:-${HOME}/.local/bin}"
VRNM_TESTNET_SEED="88.216.62.115:8080"
VRNM_TESTNET_URL="http://${VRNM_TESTNET_SEED}"

log()  { printf '\033[1;32m[vernam]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[vernam]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[vernam]\033[0m %s\n' "$*" >&2; exit 1; }

check_rust() {
    if [[ -f "${HOME}/.cargo/env" ]]; then
        # shellcheck disable=SC1091
        source "${HOME}/.cargo/env"
    fi

    if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
        warn "Rust / Cargo toolchain not found in PATH."
        cat >&2 <<'EOF'

Install Rust (edition 2024 requires Rust >= 1.85) with rustup:

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source "$HOME/.cargo/env"

Then re-run this installer:

  curl -fsSL https://raw.githubusercontent.com/gpt4omni/vernam/main/deploy/install.sh | bash
EOF
        exit 1
    fi

    local rustc_ver major_ver minor_ver
    rustc_ver="$(rustc --version | awk '{print $2}')"
    major_ver="$(printf '%s' "${rustc_ver}" | cut -d. -f1)"
    minor_ver="$(printf '%s' "${rustc_ver}" | cut -d. -f2)"

    if [[ "${major_ver}" =~ ^[0-9]+$ ]] && [[ "${minor_ver}" =~ ^[0-9]+$ ]]; then
        if (( major_ver < 1 || (major_ver == 1 && minor_ver < 85) )); then
            err "Rust ${rustc_ver} detected, but Vernam (edition 2024) requires Rust >= 1.85. Run: rustup update stable"
        fi
    fi

    log "Toolchain verified: $(rustc --version) | $(cargo --version)"
}

resolve_source() {
    # 1. Reuse current working directory if already inside a Vernam checkout.
    if [[ -f "${PWD}/Cargo.toml" ]] && grep -q 'name = "vernam-rs"' "${PWD}/Cargo.toml" 2>/dev/null; then
        BUILD_DIR="${PWD}"
        log "Using local Vernam repository at ${BUILD_DIR}"
        return
    fi

    # 2. Reuse parent directory when invoked directly from deploy/install.sh.
    if [[ -n "${BASH_SOURCE[0]:-}" ]] && [[ -f "${BASH_SOURCE[0]}" ]]; then
        local script_dir parent_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        parent_dir="$(cd "${script_dir}/.." && pwd)"
        if [[ -f "${parent_dir}/Cargo.toml" ]] && grep -q 'name = "vernam-rs"' "${parent_dir}/Cargo.toml" 2>/dev/null; then
            BUILD_DIR="${parent_dir}"
            log "Using local Vernam repository at ${BUILD_DIR}"
            return
        fi
    fi

    # 3. Clone or update from GitHub.
    if ! command -v git >/dev/null 2>&1; then
        err "'git' is required to clone ${VRNM_REPO_URL}. Please install git and retry."
    fi

    if [[ -d "${VRNM_SRC_DIR}/.git" ]]; then
        log "Updating existing checkout in ${VRNM_SRC_DIR}..."
        git -C "${VRNM_SRC_DIR}" fetch --depth 1 origin "${VRNM_BRANCH}"
        git -C "${VRNM_SRC_DIR}" checkout -B "${VRNM_BRANCH}" "origin/${VRNM_BRANCH}"
    else
        log "Cloning ${VRNM_REPO_URL} (branch: ${VRNM_BRANCH}) into ${VRNM_SRC_DIR}..."
        mkdir -p "$(dirname "${VRNM_SRC_DIR}")"
        git clone --depth 1 --branch "${VRNM_BRANCH}" "${VRNM_REPO_URL}" "${VRNM_SRC_DIR}"
    fi

    if [[ -f "${VRNM_SRC_DIR}/Cargo.toml" ]]; then
        BUILD_DIR="${VRNM_SRC_DIR}"
    elif [[ -f "${VRNM_SRC_DIR}/vernam-rs/Cargo.toml" ]]; then
        BUILD_DIR="${VRNM_SRC_DIR}/vernam-rs"
    else
        err "Could not find Cargo.toml inside ${VRNM_SRC_DIR}"
    fi
}

build_and_install() {
    log "Building zero-dependency release binary (cargo build --release --offline)..."
    (
        cd "${BUILD_DIR}"
        if ! cargo build --release --offline; then
            warn "Offline build fallback: retrying with cargo build --release (0 external crates)..."
            cargo build --release
        fi
    )

    local built_bin=""
    if [[ -x "${BUILD_DIR}/target/release/vernam-rs" ]]; then
        built_bin="${BUILD_DIR}/target/release/vernam-rs"
    elif [[ -x "${BUILD_DIR}/target/release/vrnm" ]]; then
        built_bin="${BUILD_DIR}/target/release/vrnm"
    else
        err "Release binary not found in ${BUILD_DIR}/target/release/"
    fi

    mkdir -p "${VRNM_INSTALL_DIR}"
    cp -f "${built_bin}" "${VRNM_INSTALL_DIR}/vrnm"
    chmod 0755 "${VRNM_INSTALL_DIR}/vrnm"
    log "Installed vrnm -> ${VRNM_INSTALL_DIR}/vrnm"
}

print_quickstart() {
    local path_note=""
    case ":${PATH}:" in
        *":${VRNM_INSTALL_DIR}:"*) ;;
        *)
            path_note="
NOTE: ${VRNM_INSTALL_DIR} is not currently in your PATH. Add it with:
  export PATH=\"${VRNM_INSTALL_DIR}:\$PATH\"
"
            ;;
    esac

    cat <<EOF
${path_note}
========================================================================
  Vernam (VRNM) v1.2 installed successfully!
  Zero external crates | Pure Information-Theoretic Security
  Live Testnet Explorer : ${VRNM_TESTNET_URL}/
========================================================================

Quick-Start Commands:

  1. Connect to the live public testnet & create a crash-safe wallet:
     export VRNM_NODE="${VRNM_TESTNET_URL}"
     vrnm wallet create --name alice --node "\$VRNM_NODE"
     vrnm wallet faucet --name alice --node "\$VRNM_NODE"
     vrnm wallet balance --name alice --node "\$VRNM_NODE"

  2. Send a blinded Shielded IT-MPC transfer (amount & recipient hidden):
     vrnm wallet create --name bob --node "\$VRNM_NODE"
     vrnm wallet send-private --from alice --to bob --amount 25 --node "\$VRNM_NODE"

  3. Join the decentralized P2P validator mesh (auto-discovers peers):
     vrnm node --bind 0.0.0.0:8080 --advertise <YOUR_PUBLIC_IP>:8080 --seed ${VRNM_TESTNET_SEED}

  4. Run a verified Beacon-Paired Proof-of-Pad (PoP) audit or live miner:
     vrnm pop-mine
     vrnm miner --cores 1 --node "\$VRNM_NODE"

  5. Explore local standalone testnet, v1.0 zero-admin demo & benchmarks:
     vrnm testnet --bind 127.0.0.1:8080
     vrnm v1-demo
     vrnm bench
     vrnm help
EOF
}

main() {
    check_rust
    resolve_source
    build_and_install
    print_quickstart
}

main "$@"
