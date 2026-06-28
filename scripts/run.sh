#!/usr/bin/env bash
# =============================================================================
# run.sh — Adaptive DDoS Mitigation Gateway Manual Runner
# =============================================================================
#
# PURPOSE:
#   Launches both Stage 1 (Rust Capture/Filter) and Stage 2 (Python ML/Mitigation)
#   in the foreground/background, orchestrating their startup sequence,
#   handling logging, and ensuring clean teardown on Ctrl+C.
#
# USAGE:
#   sudo ./run.sh --interface ens19 --victim-ip 10.0.0.3
#
# OPTIONS:
#   -i, --interface <IFACE>  Network interface to capture on (default: ens19)
#   -v, --victim-ip <IP>     Victim IP for BPF filtering (default: 10.0.0.3)
#   -k, --multiplier <VAL>   Anomaly multiplier threshold (default: 2.0)
#   -h, --help               Show this help message
# =============================================================================

set -euo pipefail

# ── Colour Helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[SYSTEM-INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[SYSTEM-OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[SYSTEM-WARN]${NC}  $*"; }
error()   { echo -e "${RED}[SYSTEM-ERROR]${NC} $*" >&2; exit 1; }

# ── Defaults ──────────────────────────────────────────────────────────────────
INTERFACE="ens19"
VICTIM_IP="10.0.0.3"
K_MULTIPLIER="2.0"
SOCKET_PATH="/tmp/ddos_stage1.sock"

# Get the directory of this runner script
RUN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$RUN_DIR")"

# ── Parse Arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--interface)
            INTERFACE="$2"
            shift 2
            ;;
        -v|--victim-ip)
            VICTIM_IP="$2"
            shift 2
            ;;
        -k|--multiplier)
            K_MULTIPLIER="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: sudo $0 [options]"
            echo ""
            echo "Options:"
            echo "  -i, --interface <IFACE>  Capture interface (default: $INTERFACE)"
            echo "  -v, --victim-ip <IP>     BPF target victim IP (default: $VICTIM_IP)"
            echo "  -k, --multiplier <VAL>   Anomaly threshold multiplier (default: $K_MULTIPLIER)"
            echo "  -h, --help               Show this help message"
            exit 0
            ;;
        *)
            error "Unknown argument: $1. Use --help for usage information."
            ;;
    esac
done

# ── Root Privilege Check ──────────────────────────────────────────────────────
# Both pcap raw sockets (Stage 1) and ipset kernel updates (Stage 2) require root
if [[ $EUID -ne 0 ]]; then
    error "This script orchestrates low-level network captures and kernel ipsets. It must be run with sudo."
fi

# ── Dependency & Path Resolving ───────────────────────────────────────────────
STAGE1_BIN=""
if [[ -f "$PROJECT_ROOT/stage1/target/release/ddos_stage1" ]]; then
    STAGE1_BIN="$PROJECT_ROOT/stage1/target/release/ddos_stage1"
elif [[ -f "$PROJECT_ROOT/stage1/target/debug/ddos_stage1" ]]; then
    STAGE1_BIN="$PROJECT_ROOT/stage1/target/debug/ddos_stage1"
    warn "Release binary not found. Using DEBUG build of Stage 1 (slower performance)."
elif command -v ddos_stage1 &>/dev/null; then
    STAGE1_BIN="$(command -v ddos_stage1)"
else
    error "Could not find ddos_stage1 binary. Run installation/build first."
fi

STAGE2_VENV_PYTHON="$PROJECT_ROOT/stage2/venv/bin/python3"
STAGE2_SCRIPT="$PROJECT_ROOT/stage2/stage2.py"
STAGE2_MODEL="$PROJECT_ROOT/stage2/ddos_rf_model.joblib"

if [[ ! -f "$STAGE2_VENV_PYTHON" ]]; then
    error "Stage 2 python virtual environment not found at $STAGE2_VENV_PYTHON. Run installation first."
fi

if [[ ! -f "$STAGE2_SCRIPT" ]]; then
    error "Stage 2 python script not found at $STAGE2_SCRIPT."
fi

if [[ ! -f "$STAGE2_MODEL" ]]; then
    error "Model file not found at $STAGE2_MODEL. Please train the model first by running:\n    $PROJECT_ROOT/stage2/venv/bin/python3 $PROJECT_ROOT/stage2/train.py"
fi

# ── Environment Preparation ───────────────────────────────────────────────────
info "Orchestrating Adaptive DDoS Mitigation Gateway..."
info "Config: Interface=$INTERFACE | Target Victim=$VICTIM_IP | k-threshold=$K_MULTIPLIER"

# Ensure socket is not lingering from a crashed previous run
if [[ -S "$SOCKET_PATH" || -f "$SOCKET_PATH" ]]; then
    info "Cleaning up leftover Unix Socket at $SOCKET_PATH..."
    rm -f "$SOCKET_PATH"
fi

# ── Process Cleanup Orchestration ─────────────────────────────────────────────
# Track background PIDs to kill on exit
STAGE2_PID=""
STAGE1_PID=""

cleanup() {
    echo ""
    info "Teardown signal received. Cleaning up processes..."
    
    if [[ -n "$STAGE1_PID" ]]; then
        info "Stopping Stage 1 (Rust Filter, PID $STAGE1_PID)..."
        kill "$STAGE1_PID" 2>/dev/null || true
    fi
    
    if [[ -n "$STAGE2_PID" ]]; then
        info "Stopping Stage 2 (Python Classifier, PID $STAGE2_PID)..."
        kill "$STAGE2_PID" 2>/dev/null || true
    fi
    
    # Wait for processes to exit
    wait 2>/dev/null || true
    
    if [[ -S "$SOCKET_PATH" || -f "$SOCKET_PATH" ]]; then
        info "Cleaning up IPC socket file..."
        rm -f "$SOCKET_PATH"
    fi
    
    success "Teardown complete. Gateway offline."
}

# Catch SIGINT (Ctrl+C), SIGTERM, and SIGHUP
trap cleanup EXIT SIGINT SIGTERM SIGHUP

# ── Launch Stage 2 (ML/Mitigation Engine) ──────────────────────────────────────
info "Starting Stage 2 Python Daemon..."
# Change working directory to stage2 so it can load the joblib model correctly
cd "$PROJECT_ROOT/stage2"
"$STAGE2_VENV_PYTHON" "$STAGE2_SCRIPT" &
STAGE2_PID=$!

# Wait for the Unix Domain Socket to appear
info "Waiting for Stage 2 socket listening path to initialize..."
SOCKET_TIMEOUT=10
SOCKET_COUNTER=0
while [[ ! -S "$SOCKET_PATH" ]]; do
    sleep 0.2
    SOCKET_COUNTER=$((SOCKET_COUNTER + 1))
    if [[ $SOCKET_COUNTER -ge $((SOCKET_TIMEOUT * 5)) ]]; then
        error "Stage 2 failed to create Unix socket at $SOCKET_PATH after ${SOCKET_TIMEOUT}s. Check stage2 logs."
    fi
done
success "Stage 2 socket is open and listening."

# ── Launch Stage 1 (Rust Capture & Feature Extraction Engine) ─────────────────
info "Starting Stage 1 Rust Pre-Filter (forwarding output to terminal)..."
cd "$PROJECT_ROOT/stage1"

# We run Stage 1 in the background as well, then wait on it. This allows bash's
# trap to catch Ctrl+C instantly instead of being blocked by the Rust binary's execution thread.
RUST_LOG=debug "$STAGE1_BIN" \
    --interface "$INTERFACE" \
    --victim-ip "$VICTIM_IP" \
    --k "$K_MULTIPLIER" \
    --socket "$SOCKET_PATH" &
STAGE1_PID=$!

# Wait on Stage 1 (will run indefinitely until Ctrl+C/SIGINT)
wait "$STAGE1_PID"
