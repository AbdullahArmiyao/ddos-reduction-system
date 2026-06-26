#!/usr/bin/env bash
# =============================================================================
# uninstall.sh — Stage 1 Uninstall Script
# =============================================================================
#
# Completely removes Stage 1 from the system:
#   1. Stops and disables the systemd service unit.
#   2. Removes the systemd unit file.
#   3. Removes the installed binary.
#   4. Optionally removes compiled build artefacts (target/ directory).
#   5. Optionally removes the Rust toolchain (rustup self uninstall).
#   6. Removes the IPC socket file if it exists.
#
# The project source files (stage1/src/) are NOT deleted — only installed
# system files are removed. Use --remove-build to also wipe target/.
#
# Usage:
#   sudo bash scripts/uninstall.sh [OPTIONS]
#
# Options:
#   --remove-build      Also delete the stage1/target/ build cache
#   --remove-rust       Also uninstall the Rust toolchain via rustup
#   --yes               Skip the confirmation prompt (non-interactive)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Defaults ──────────────────────────────────────────────────────────────────
REMOVE_BUILD=false
REMOVE_RUST=false
CONFIRM=true
BINARY_NAME="ddos_stage1"
INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="ddos-stage1"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SOCKET_FILE="/tmp/ddos_stage1.sock"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(dirname "$SCRIPT_DIR")/stage1/target"

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --remove-build) REMOVE_BUILD=true; shift ;;
        --remove-rust)  REMOVE_RUST=true; shift ;;
        --yes)          CONFIRM=false; shift ;;
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
info "  Adaptive DDoS Pre-Filter — Stage 1 Uninstaller      "
info "═══════════════════════════════════════════════════════"
echo ""

# ── Confirmation prompt ───────────────────────────────────────────────────────
if $CONFIRM; then
    warn "This will remove Stage 1 from your system."
    warn "The following will be deleted:"
    warn "  • $INSTALL_DIR/$BINARY_NAME"
    warn "  • $SERVICE_FILE (if present)"
    warn "  • $SOCKET_FILE (if present)"
    $REMOVE_BUILD && warn "  • $BUILD_DIR (build cache)"
    $REMOVE_RUST  && warn "  • Rust toolchain (~/.cargo and ~/.rustup)"
    echo ""
    read -r -p "Are you sure? (yes/no): " ANSWER
    [[ "$ANSWER" != "yes" ]] && { info "Uninstall cancelled."; exit 0; }
fi

# =============================================================================
# STEP 1 — Stop and disable the systemd service
# =============================================================================
if command -v systemctl &>/dev/null; then
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Stopping $SERVICE_NAME..."
        systemctl stop "$SERVICE_NAME"
        success "$SERVICE_NAME stopped."
    fi

    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Disabling $SERVICE_NAME..."
        systemctl disable "$SERVICE_NAME"
        success "$SERVICE_NAME disabled."
    fi
else
    info "systemctl not found; skipping service stop."
fi

# =============================================================================
# STEP 2 — Remove the systemd unit file
# =============================================================================
if [[ -f "$SERVICE_FILE" ]]; then
    info "Removing systemd unit file: $SERVICE_FILE"
    rm -f "$SERVICE_FILE"
    # Reload systemd so it forgets about the removed unit.
    command -v systemctl &>/dev/null && systemctl daemon-reload
    success "Unit file removed."
else
    info "No systemd unit file found at $SERVICE_FILE (skipping)."
fi

# =============================================================================
# STEP 3 — Remove the binary
# =============================================================================
if [[ -f "$INSTALL_DIR/$BINARY_NAME" ]]; then
    info "Removing binary: $INSTALL_DIR/$BINARY_NAME"
    # Clear the setcap capability before deleting, to be clean.
    command -v setcap &>/dev/null && setcap -r "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
    rm -f "$INSTALL_DIR/$BINARY_NAME"
    success "Binary removed."
else
    warn "Binary not found at $INSTALL_DIR/$BINARY_NAME (already removed?)."
fi

# =============================================================================
# STEP 4 — Remove the IPC socket file (if a previous run left it behind)
# =============================================================================
if [[ -S "$SOCKET_FILE" ]] || [[ -f "$SOCKET_FILE" ]]; then
    info "Removing IPC socket: $SOCKET_FILE"
    rm -f "$SOCKET_FILE"
    success "Socket file removed."
fi

# =============================================================================
# STEP 5 — Remove build artefacts (optional)
# =============================================================================
if $REMOVE_BUILD; then
    if [[ -d "$BUILD_DIR" ]]; then
        info "Removing build cache: $BUILD_DIR"
        rm -rf "$BUILD_DIR"
        success "Build cache removed."
    else
        info "No build cache found at $BUILD_DIR."
    fi
else
    info "Build cache kept (use --remove-build to delete $BUILD_DIR)."
fi

# =============================================================================
# STEP 6 — Remove Rust toolchain (optional, DESTRUCTIVE)
# =============================================================================
if $REMOVE_RUST; then
    warn "Removing Rust toolchain (rustup self uninstall)..."
    if command -v rustup &>/dev/null; then
        [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
        rustup self uninstall -y
        success "Rust toolchain removed."
    else
        warn "rustup not found; toolchain may have already been removed."
    fi
else
    info "Rust toolchain kept (use --remove-rust to also uninstall rustup)."
fi

echo ""
success "════════════════════════════════════════════"
success " Stage 1 has been uninstalled successfully "
success "════════════════════════════════════════════"
echo ""
info "Source files in stage1/src/ have NOT been deleted."
info "Re-install at any time with: sudo bash scripts/install.sh"
echo ""
