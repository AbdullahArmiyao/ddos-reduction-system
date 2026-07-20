#!/usr/bin/env bash
# =============================================================================
# update.sh — Stage 1 & 2 Update Script
# =============================================================================
#
# Updates an existing Stage 1 & 2 installation to the latest code in the project
# directory. Does NOT download anything from the internet (except optionally
# updating the Rust toolchain itself).
#
# What this script does:
#   1. Stops the running ddos-stage1 & ddos-stage2 systemd services (if active).
#   2. Optionally updates the Rust toolchain to the latest stable release.
#   3. Rebuilds Stage 1 in release mode.
#   4. Updates Stage 2 Python dependencies inside virtual environment.
#   5. Replaces the installed binary atomically (no downtime window on the fs).
#   6. Reapplies CAP_NET_RAW capability to the new binary.
#   7. Restarts the systemd services.
#
# Usage:
#   sudo bash scripts/update.sh [--no-toolchain-update] [--no-service-restart]
#
# Options:
#   --no-toolchain-update   Skip `rustup update` (use existing compiler)
#   --no-service-restart    Do not restart the systemd service after update
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Defaults ──────────────────────────────────────────────────────────────────
UPDATE_TOOLCHAIN=true
RESTART_SERVICE=true
BINARY_NAME="ddos_stage1"
INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="ddos-stage1"
SERVICE2_NAME="ddos-stage2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")/stage1"
STAGE2_DIR="$(dirname "$SCRIPT_DIR")/stage2"

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-toolchain-update) UPDATE_TOOLCHAIN=false; shift ;;
        --no-service-restart)  RESTART_SERVICE=false; shift ;;
        --help|-h)
            grep '^#' "$0" | head -30 | sed 's/^# \?//'
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
info "  Adaptive DDoS Mitigation — Stage 1 & 2 Updater       "
info "═══════════════════════════════════════════════════════"
echo ""

# =============================================================================
# STEP 1 — Stop the running services (if systemd is available and services exist)
# =============================================================================
SERVICE1_WAS_ACTIVE=false
SERVICE2_WAS_ACTIVE=false

if command -v systemctl &>/dev/null; then
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Stopping $SERVICE_NAME service before update..."
        systemctl stop "$SERVICE_NAME"
        SERVICE1_WAS_ACTIVE=true
        success "$SERVICE_NAME stopped."
    fi
    if systemctl is-active --quiet "$SERVICE2_NAME" 2>/dev/null; then
        info "Stopping $SERVICE2_NAME service before update..."
        systemctl stop "$SERVICE2_NAME"
        SERVICE2_WAS_ACTIVE=true
        success "$SERVICE2_NAME stopped."
    fi
else
    warn "systemctl not found; skipping service stop."
fi

# =============================================================================
# STEP 2 — Update the Rust toolchain (optional)
# =============================================================================
if $UPDATE_TOOLCHAIN; then
    info "Updating Rust toolchain..."
    # Source the cargo env in case we're running in a minimal shell.
    # shellcheck source=/dev/null
    [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"

    if command -v rustup &>/dev/null; then
        rustup update stable 2>&1
        success "Rust toolchain updated: $(rustc --version)"
    else
        warn "rustup not found. Skipping toolchain update (using existing compiler)."
    fi
else
    info "Toolchain update skipped (--no-toolchain-update)."
fi

# =============================================================================
# STEP 3 — Rebuild Stage 1
# =============================================================================
info "Rebuilding Stage 1 in release mode..."

if [[ ! -d "$PROJECT_DIR" ]]; then
    error "Stage 1 source directory not found at: $PROJECT_DIR"
fi

# Source cargo env again in case we are in a fresh root shell.
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"

cd "$PROJECT_DIR"
RUSTFLAGS="-C target-cpu=native" cargo build --release 2>&1
success "Build complete."

# =============================================================================
# STEP 3.5 — Update Stage 2 Python dependencies
# =============================================================================
if [[ -d "$STAGE2_DIR" ]]; then
    info "Updating Stage 2 Python dependencies..."
    if [[ -d "$STAGE2_DIR/venv" ]]; then
        # Check if the python interpreter path is valid/executable
        if ! "$STAGE2_DIR/venv/bin/python" -c "import sys" &>/dev/null; then
            warn "Virtual environment is broken, moved, or invalid. Re-creating..."
            python3 -m venv --clear "$STAGE2_DIR/venv"
        fi
        
        "$STAGE2_DIR/venv/bin/pip" install --upgrade pip
        "$STAGE2_DIR/venv/bin/pip" install -r "$STAGE2_DIR/requirements.txt"
        
        info "Updating/migrating administrative database..."
        "$STAGE2_DIR/venv/bin/python" "$STAGE2_DIR/setup_admin.py"
        
        success "Stage 2 dependencies updated."
    else
        warn "Stage 2 virtual environment not found. Skip pip update."
    fi
fi

# =============================================================================
# STEP 4 — Atomic binary replacement
# =============================================================================
info "Replacing binary at $INSTALL_DIR/$BINARY_NAME..."

# Copy to a temp file first, then atomically move it over the old binary.
# This avoids a race window where the binary is partially written.
TMP_BINARY="$(mktemp --tmpdir="$INSTALL_DIR" "$BINARY_NAME.XXXXXX")"
install -m 755 "target/release/$BINARY_NAME" "$TMP_BINARY"
mv -f "$TMP_BINARY" "$INSTALL_DIR/$BINARY_NAME"
success "Binary updated: $INSTALL_DIR/$BINARY_NAME"

# =============================================================================
# STEP 5 — Reapply CAP_NET_RAW capability
# =============================================================================
if command -v setcap &>/dev/null; then
    # The setcap capability is stored in the inode extended attributes.
    # Replacing the binary clears them — we must reapply after every update.
    setcap cap_net_raw+ep "$INSTALL_DIR/$BINARY_NAME"
    success "CAP_NET_RAW reapplied."
else
    warn "setcap not found. Run the binary as root."
fi

# =============================================================================
# STEP 6 — Restart the services (optional)
# =============================================================================
if $RESTART_SERVICE; then
    if $SERVICE2_WAS_ACTIVE; then
        info "Restarting $SERVICE2_NAME..."
        systemctl start "$SERVICE2_NAME"
        sleep 0.5
    fi
    if $SERVICE1_WAS_ACTIVE; then
        info "Restarting $SERVICE_NAME..."
        systemctl start "$SERVICE_NAME"
        sleep 0.5
    fi

    # Verify status
    if command -v systemctl &>/dev/null; then
        if $SERVICE1_WAS_ACTIVE && ! systemctl is-active --quiet "$SERVICE_NAME"; then
            warn "$SERVICE_NAME failed to start. Check: journalctl -u $SERVICE_NAME -n 20"
        fi
        if $SERVICE2_WAS_ACTIVE && ! systemctl is-active --quiet "$SERVICE2_NAME"; then
            warn "$SERVICE2_NAME failed to start. Check: journalctl -u $SERVICE2_NAME -n 20"
        fi
    fi
fi

echo ""
success "════════════════════════════════════════════"
success " Stage 1 & 2 update complete!              "
success "════════════════════════════════════════════"
echo ""
