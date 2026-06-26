#!/usr/bin/env bash
# =============================================================================
# update.sh — Stage 1 Update Script
# =============================================================================
#
# Updates an existing Stage 1 installation to the latest code in the project
# directory. Does NOT download anything from the internet (except optionally
# updating the Rust toolchain itself).
#
# What this script does:
#   1. Stops the running ddos-stage1 systemd service (if active).
#   2. Optionally updates the Rust toolchain to the latest stable release.
#   3. Rebuilds Stage 1 in release mode.
#   4. Replaces the installed binary atomically (no downtime window on the fs).
#   5. Reapplies CAP_NET_RAW capability to the new binary.
#   6. Restarts the systemd service.
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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")/stage1"

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
info "  Adaptive DDoS Pre-Filter — Stage 1 Updater          "
info "═══════════════════════════════════════════════════════"
echo ""

# =============================================================================
# STEP 1 — Stop the running service (if systemd is available and service exists)
# =============================================================================
SERVICE_WAS_ACTIVE=false

if command -v systemctl &>/dev/null; then
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Stopping $SERVICE_NAME service before update..."
        systemctl stop "$SERVICE_NAME"
        SERVICE_WAS_ACTIVE=true
        success "$SERVICE_NAME stopped."
    else
        info "Service $SERVICE_NAME is not currently running."
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
# STEP 6 — Restart the service (optional)
# =============================================================================
if $RESTART_SERVICE && $SERVICE_WAS_ACTIVE; then
    info "Restarting $SERVICE_NAME..."
    systemctl start "$SERVICE_NAME"
    sleep 1
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        success "$SERVICE_NAME is running."
    else
        warn "$SERVICE_NAME failed to start. Check: journalctl -u $SERVICE_NAME -n 20"
    fi
elif $RESTART_SERVICE && command -v systemctl &>/dev/null; then
    info "Service was not running before update; not starting it automatically."
    info "To start: systemctl start $SERVICE_NAME"
fi

echo ""
success "════════════════════════════════════════════"
success " Stage 1 update complete!                  "
success "════════════════════════════════════════════"
echo ""
