#!/usr/bin/env bash
# =============================================================================
# install.sh — Stage 1 & 2 Installation Script (Linux/macOS)
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
#   sudo bash scripts/install.sh [--interface ens19] [--victim-ips 10.0.0.3,10.0.0.4] [--victim-subnet 10.0.0.0/24]
#
# Options:
#   --interface  <IFACE>     Default capture interface written into the service unit
#   --victim-ips <IPs>       Default list of victim IPs (comma-separated, alias: --victim-ip)
#   --victim-subnet <SUBNET> Default victim subnet CIDR (e.g. 10.0.0.0/24)
#   --no-service             Skip systemd unit installation
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
VICTIM_IPS=""
VICTIM_SUBNET=""
INSTALL_SERVICE=true
BINARY_NAME="ddos_stage1"
INSTALL_DIR="/usr/local/bin"
SERVICE_DIR="/etc/systemd/system"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")/stage1"

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface)               INTERFACE="$2"; shift 2 ;;
        --victim-ip|--victim-ips)  VICTIM_IPS="$2"; shift 2 ;;
        --victim-subnet)           VICTIM_SUBNET="$2"; shift 2 ;;
        --no-service)              INSTALL_SERVICE=false; shift ;;
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
info "  Adaptive DDoS Mitigation — Stage 1 & 2 Installer     "
info "═══════════════════════════════════════════════════════"
echo ""

# ── Interactive prompts ───────────────────────────────────────────────────────
if [[ -t 0 ]]; then
    # Resolve current target default for the prompt
    CURRENT_TARGET=""
    if [[ -n "$VICTIM_IPS" ]]; then
        CURRENT_TARGET="$VICTIM_IPS"
    elif [[ -n "$VICTIM_SUBNET" ]]; then
        CURRENT_TARGET="$VICTIM_SUBNET"
    fi

    echo -ne "${YELLOW}[INPUT]${NC} Enter the network interface to monitor [default: ${INTERFACE}]: "
    read -r input_iface
    if [[ -n "$input_iface" ]]; then
        INTERFACE="$input_iface"
    fi

    echo -ne "${YELLOW}[INPUT]${NC} Enter the victim IP(s) or subnet (e.g. 10.0.0.3 or 10.0.0.0/24) [default: ${CURRENT_TARGET:-none}]: "
    read -r input_target
    if [[ -n "$input_target" ]]; then
        if [[ "$input_target" == "none" ]]; then
            VICTIM_IPS=""
            VICTIM_SUBNET=""
        elif [[ "$input_target" == *"/"* ]]; then
            VICTIM_SUBNET="$input_target"
            VICTIM_IPS=""
        else
            VICTIM_IPS="$input_target"
            VICTIM_SUBNET=""
        fi
    fi
    echo ""
fi

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
    # python3, python3-pip, python3-venv, ipset : for Stage 2
    apt-get install -y --no-install-recommends \
        libpcap-dev \
        build-essential \
        pkg-config \
        curl \
        python3 \
        python3-pip \
        python3-venv \
        ipset
}

install_deps_dnf() {
    # libpcap-devel provides the headers and .so needed to compile the pcap crate
    dnf install -y \
        libpcap-devel \
        gcc \
        pkg-config \
        curl \
        python3 \
        python3-pip \
        ipset
}

install_deps_yum() {
    yum install -y \
        libpcap-devel \
        gcc \
        pkgconfig \
        curl \
        python3 \
        python3-pip \
        ipset
}

install_deps_apk() {
    # Alpine uses musl libc; libpcap-dev provides headers
    # py3-* packages avoid compilation of heavy libraries
    apk add --no-cache \
        libpcap-dev \
        build-base \
        pkgconfig \
        curl \
        bash \
        python3 \
        py3-pip \
        ipset \
        py3-pandas \
        py3-numpy \
        py3-scikit-learn \
        py3-joblib
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
# STEP 5.5 — Setup Stage 2 Python Virtual Environment
# =============================================================================
info "Setting up Stage 2 Python virtual environment..."
STAGE2_DIR="$(dirname "$PROJECT_DIR")/stage2"
if [[ -d "$STAGE2_DIR" ]]; then
    if ! command -v python3 &>/dev/null; then
        error "python3 is not installed."
    fi
    info "Creating virtual environment at $STAGE2_DIR/venv..."
    if [[ "$PKG_MANAGER" == "apk" ]]; then
        python3 -m venv --clear --system-site-packages "$STAGE2_DIR/venv"
    else
        python3 -m venv --clear "$STAGE2_DIR/venv"
    fi
    
    info "Installing dependencies from requirements.txt..."
    "$STAGE2_DIR/venv/bin/pip" install --upgrade pip
    "$STAGE2_DIR/venv/bin/pip" install -r "$STAGE2_DIR/requirements.txt"
    
    info "Setting up administrative database and user..."
    "$STAGE2_DIR/venv/bin/python" "$STAGE2_DIR/setup_admin.py"
    
    success "Stage 2 Python environment setup complete."
else
    warn "Stage 2 directory not found at $STAGE2_DIR. Skipping."
fi

# =============================================================================
# STEP 6 — Install systemd service units (optional, Linux only)
# =============================================================================
if $INSTALL_SERVICE && command -v systemctl &>/dev/null; then
    info "Installing systemd service units..."

    # Build the ExecStart command line.
    EXEC_START="\"$INSTALL_DIR/$BINARY_NAME\" --interface $INTERFACE"
    if [[ -n "$VICTIM_IPS" ]]; then
        EXEC_START+=" --victim-ips $VICTIM_IPS"
    elif [[ -n "$VICTIM_SUBNET" ]]; then
        EXEC_START+=" --victim-subnet $VICTIM_SUBNET"
    else
        warn "No --victim-ips or --victim-subnet specified. Service will run without a BPF filter (dev mode)."
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
# Start after network is up and Stage 2 classification engine is running
After=network-online.target ddos-stage2.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$EXEC_START
Restart=on-failure
RestartSec=5s
Environment="RUST_LOG=info"
MemoryMax=256M
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    if [[ -d "$STAGE2_DIR" ]]; then
        cat > "$SERVICE_DIR/ddos-stage2.service" << EOF
# =============================================================================
# ddos-stage2.service — systemd unit for the DDoS mitigation Stage 2 daemon
# Generated by install.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# =============================================================================

[Unit]
Description=Adaptive DDoS Mitigation Stage 2 Classifier (Python)
After=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory="$STAGE2_DIR"
ExecStart=/bin/bash -c 'source "$STAGE2_DIR/venv/bin/activate" && exec python3 stage2.py'
Restart=on-failure
RestartSec=5s
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
EOF
        success "Systemd service file created for Stage 2."
    fi

    systemctl daemon-reload
    success "Systemd services installed: ddos-stage1.service, ddos-stage2.service"
    info ""
    info "To enable at boot and start now:"
    info "    systemctl enable --now ddos-stage2"
    info "    systemctl enable --now ddos-stage1"
    info ""
    info "To check logs:"
    info "    journalctl -u ddos-stage2 -f"
    info "    journalctl -u ddos-stage1 -f"
else
    if $INSTALL_SERVICE; then
        warn "systemctl not found; skipping service installation (Alpine OpenRC or non-systemd system)."
    fi
fi

# =============================================================================
# Done
# =============================================================================
info "========================================================================"
info "   CRITICAL ACTION REQUIRED: MACHINE LEARNING MODEL TRAINING"
info "========================================================================"
info "The Random Forest classifier must be trained on network traffic baselines"
info "before starting the detection services."
info ""
info "Step 1: Generate Training Data (Capture on your gateway interface):"
info ""
info "  a) Capture NORMAL peacetime baseline traffic (Label 0) for ~5 minutes (until warm-up completes):"
info "     sudo ddos_stage1 --interface \$INTERFACE --victim-ips <VICTIM_IPS> --train-csv stage1/training_data.csv --train-label 0"
info ""
info "  b) Capture FLASH CROWD (legitimate high-volume) traffic (Label 1) for ~5 minutes (until warm-up completes):"
info "     sudo ddos_stage1 --interface \$INTERFACE --victim-ips <VICTIM_IPS> --train-csv stage1/training_data.csv --train-label 1"
info ""
info "  c) Capture DDoS attack traffic (Label 2) for ~5 minutes (until warm-up completes):"
info "     sudo ddos_stage1 --interface \$INTERFACE --victim-ips <VICTIM_IPS> --train-csv stage1/training_data.csv --train-label 2"
info ""
info "Step 2: Train the Random Forest Classifier Model:"
info "  Run the training script (this cleans transient rows, balances classes,"
info "  and saves the model inside the stage2 directory):"
info "     stage2/venv/bin/python stage2/train.py"
info ""
info "Step 3: Launch System Daemons:"
info "  Once trained, start and enable the systemd services:"
info "     sudo systemctl enable --now ddos-stage2"
info "     sudo systemctl enable --now ddos-stage1"
info "========================================================================"
echo ""
