#!/usr/bin/env bash
# =============================================================================
# install.sh — Stage 1 Installation Script (Linux/macOS)
# =============================================================================
#
# Supports:
#   • Debian / Ubuntu (apt)
#   • RHEL / Fedora / Rocky / AlmaLinux (dnf / yum)
#   • Alpine Linux (apk)
#
# What this script does:
#   1. Detects the host OS/package manager.
#   2. Installs system dependencies (libpcap, build tools).
#   3. Installs the Rust toolchain via rustup (if not already present).
#   4. Compiles Stage 1 in release mode.
#   5. Installs the binary to /usr/local/bin/ddos_stage1.
#   6. Writes a systemd service unit (Linux only) to allow boot-time autostart.
#
# Usage:
#   sudo bash scripts/install.sh [--interface br0] [--victim-ip 10.0.0.3]
#
# Options:
#   --interface  <IFACE>   Default capture interface written into the service unit
#   --victim-ip  <IP>      Default victim IP written into the service unit
#   --no-service           Skip systemd unit installation
#
# Notes:
#   • Must be run as root (or with sudo) because pcap and systemd require it.
#   • The Rust toolchain is installed into ~/.cargo for the current user.
#     If running as root via sudo, the toolchain lands in /root/.cargo.
#   • Use `sudo setcap cap_net_raw+ep /usr/local/bin/ddos_stage1` after install
#     to run the binary WITHOUT root in production.
# =============================================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Defaults ──────────────────────────────────────────────────────────────────
INTERFACE="br0"
VICTIM_IP=""
INSTALL_SERVICE=true
BINARY_NAME="ddos_stage1"
INSTALL_DIR="/usr/local/bin"
SERVICE_DIR="/etc/systemd/system"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")/stage1"

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface)  INTERFACE="$2"; shift 2 ;;
        --victim-ip)  VICTIM_IP="$2"; shift 2 ;;
        --no-service) INSTALL_SERVICE=false; shift ;;
        --help|-h)
            grep '^#' "$0" | head -40 | sed 's/^# \?//'
            exit 0 ;;
        *) error "Unknown argument: $1" ;;
    esac
done

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root. Try: sudo bash $0"
fi

echo ""
info "═══════════════════════════════════════════════════════"
info "  Adaptive DDoS Pre-Filter — Stage 1 Installer        "
info "═══════════════════════════════════════════════════════"
echo ""

# =============================================================================
# STEP 1 — Detect OS and package manager
# =============================================================================
info "Detecting operating system..."

PKG_MANAGER=""
OS_NAME=""

if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt"
    OS_NAME="Debian/Ubuntu"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    OS_NAME="RHEL/Fedora"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    OS_NAME="RHEL/CentOS (legacy)"
elif command -v apk &>/dev/null; then
    PKG_MANAGER="apk"
    OS_NAME="Alpine Linux"
else
    error "Unsupported OS: could not find apt, dnf, yum, or apk."
fi

success "Detected OS: $OS_NAME (package manager: $PKG_MANAGER)"

# =============================================================================
# STEP 2 — Install system dependencies
# =============================================================================
info "Installing system dependencies..."

install_deps_apt() {
    apt-get update -qq
    # libpcap-dev  : headers and static lib for pcap crate
    # build-essential : gcc, make, linker
    # pkg-config   : lets Cargo find libpcap via pkg-config
    apt-get install -y --no-install-recommends \
        libpcap-dev \
        build-essential \
        pkg-config \
        curl
}

install_deps_dnf() {
    # libpcap-devel provides the headers and .so needed to compile the pcap crate
    dnf install -y \
        libpcap-devel \
        gcc \
        pkg-config \
        curl
}

install_deps_yum() {
    yum install -y \
        libpcap-devel \
        gcc \
        pkgconfig \
        curl
}

install_deps_apk() {
    # Alpine uses musl libc; libpcap-dev provides headers
    apk add --no-cache \
        libpcap-dev \
        build-base \
        pkgconfig \
        curl \
        bash
}

case "$PKG_MANAGER" in
    apt) install_deps_apt ;;
    dnf) install_deps_dnf ;;
    yum) install_deps_yum ;;
    apk) install_deps_apk ;;
esac

success "System dependencies installed."

# =============================================================================
# STEP 3 — Install Rust toolchain via rustup
# =============================================================================
info "Checking for Rust toolchain..."

if command -v cargo &>/dev/null && command -v rustc &>/dev/null; then
    RUST_VER=$(rustc --version)
    success "Rust already installed: $RUST_VER"
else
    info "Rust not found. Installing via rustup..."
    # -y  : non-interactive, accept defaults
    # --no-modify-path : do not modify PATH in shell profiles (we source manually)
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --no-modify-path --default-toolchain stable

    # Source the Cargo environment for the rest of this script.
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
    success "Rust toolchain installed: $(rustc --version)"
fi

# Ensure the stable toolchain is the active one.
rustup default stable &>/dev/null || true

# =============================================================================
# STEP 4 — Compile Stage 1 in release mode
# =============================================================================
info "Building Stage 1 (release mode — this may take a few minutes on first build)..."

if [[ ! -d "$PROJECT_DIR" ]]; then
    error "Stage 1 source directory not found at: $PROJECT_DIR"
fi

cd "$PROJECT_DIR"

# RUSTFLAGS: target-cpu=native enables CPU-specific optimisations (AVX2, etc.)
# on the gateway host. Remove this flag if building for distribution to other
# machines (use target-cpu=x86-64-v2 or omit entirely).
RUSTFLAGS="-C target-cpu=native" cargo build --release 2>&1

success "Build complete: target/release/$BINARY_NAME"

# =============================================================================
# STEP 5 — Install the binary
# =============================================================================
info "Installing binary to $INSTALL_DIR/$BINARY_NAME..."
install -m 755 "target/release/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
success "Binary installed: $INSTALL_DIR/$BINARY_NAME"

# Grant CAP_NET_RAW so the binary can capture packets without running as root.
if command -v setcap &>/dev/null; then
    setcap cap_net_raw+ep "$INSTALL_DIR/$BINARY_NAME"
    success "CAP_NET_RAW capability granted — binary can run without sudo."
else
    warn "setcap not found. You will need to run $BINARY_NAME as root."
fi

# =============================================================================
# STEP 6 — Install systemd service unit (optional, Linux only)
# =============================================================================
if $INSTALL_SERVICE && command -v systemctl &>/dev/null; then
    info "Installing systemd service unit..."

    # Build the ExecStart command line.
    EXEC_START="$INSTALL_DIR/$BINARY_NAME --interface $INTERFACE"
    if [[ -n "$VICTIM_IP" ]]; then
        EXEC_START+=" --victim-ip $VICTIM_IP"
    else
        warn "No --victim-ip specified. Service will run without a BPF filter (dev mode)."
        EXEC_START+=" --no-filter"
    fi

    cat > "$SERVICE_DIR/ddos-stage1.service" << EOF
# =============================================================================
# ddos-stage1.service — systemd unit for the DDoS mitigation Stage 1 daemon
# Generated by install.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# =============================================================================

[Unit]
Description=Adaptive DDoS Pre-Filter Stage 1 (Rust)
Documentation=https://github.com/your-repo/ddos-reduction
# Start after the network bridge (br0) is fully up.
After=network-online.target
Wants=network-online.target

[Service]
Type=simple

# The binary has CAP_NET_RAW set via setcap, so it does not need to run as root.
# If setcap failed during install, change User=root.
User=root
Group=root

ExecStart=$EXEC_START

# Restart automatically if the process crashes (not if stopped manually).
Restart=on-failure
RestartSec=5s

# Log level. Change to debug for verbose per-window output.
Environment="RUST_LOG=info"

# Hard limits to protect the host if something goes wrong.
# MemoryMax=256M caps RSS; LimitNOFILE increases the open-file limit for pcap.
MemoryMax=256M
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    success "Systemd service installed: ddos-stage1.service"
    info ""
    info "To enable at boot and start now:"
    info "    systemctl enable --now ddos-stage1"
    info ""
    info "To check logs:"
    info "    journalctl -u ddos-stage1 -f"
else
    if $INSTALL_SERVICE; then
        warn "systemctl not found; skipping service installation (Alpine OpenRC or non-systemd system)."
    fi
fi

# =============================================================================
# Done
# =============================================================================
echo ""
success "════════════════════════════════════════════"
success " Stage 1 installation complete!            "
success "════════════════════════════════════════════"
echo ""
info "Quick start:"
info "  sudo $BINARY_NAME --interface $INTERFACE --victim-ip <YOUR_VICTIM_IP>"
echo ""
