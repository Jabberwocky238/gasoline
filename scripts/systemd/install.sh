#!/usr/bin/env bash
# Gasoline systemd installer.
#
# Usage:
#   sudo ./install.sh operator install     # install operator
#   sudo ./install.sh operator uninstall   # remove operator unit + binary
#   sudo ./install.sh client   install     # install client
#   sudo ./install.sh client   uninstall   # remove client unit + binary
#
# Override via env: DOWNLOAD_URL, PREFIX, CONFIG_DIR, LOG_DIR.

set -euo pipefail

DOWNLOAD_URL="${DOWNLOAD_URL:-https://github.com/jabberwocky238/gasoline/releases/latest/download/gasoline-linux-amd64}"
PREFIX="${PREFIX:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/gasoline}"
LOG_DIR="${LOG_DIR:-/var/log/gasoline}"
UNIT_DIR="/etc/systemd/system"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

usage() {
    sed -n '2,10p' "$0" | sed 's/^# \?//'
    exit "${1:-1}"
}

fetch_binary() {
    if [[ -x "$PREFIX/gasoline" ]]; then
        echo "binary already present at $PREFIX/gasoline (skipping)"
        return
    fi
    if [[ -f "$REPO_ROOT/bin/gasoline-linux-amd64" ]]; then
        install -m 0755 "$REPO_ROOT/bin/gasoline-linux-amd64" "$PREFIX/gasoline"
        echo "installed binary from $REPO_ROOT/bin/"
    else
        echo "downloading $DOWNLOAD_URL"
        curl -fsSL -o "$PREFIX/gasoline" "$DOWNLOAD_URL"
        chmod 0755 "$PREFIX/gasoline"
    fi
}

do_install() {
    local role="$1"
    fetch_binary
    install -d -m 0755 "$CONFIG_DIR" "$CONFIG_DIR/vni.d" "$LOG_DIR"

    local src="$REPO_ROOT/scripts/config.sample-$role.yaml"
    local dst="$CONFIG_DIR/$role.yaml"
    [[ -f "$src" && ! -f "$dst" ]] && install -m 0640 "$src" "$dst"
    install -m 0644 "$SCRIPT_DIR/gasoline-$role.service" "$UNIT_DIR/"
    systemctl daemon-reload
    echo "installed. enable with: systemctl enable --now gasoline-$role"
}

do_uninstall() {
    local role="$1"
    systemctl disable --now "gasoline-$role" 2>/dev/null || true
    rm -f "$UNIT_DIR/gasoline-$role.service"
    systemctl daemon-reload
    # Remove binary only when no gasoline unit remains.
    if ! ls "$UNIT_DIR"/gasoline-*.service >/dev/null 2>&1; then
        rm -f "$PREFIX/gasoline"
    fi
    echo "removed gasoline-$role. configs kept at $CONFIG_DIR"
}

[[ $# -eq 2 ]] || usage
role="$1"
action="$2"
case "$role"   in operator|client)   ;; *) usage ;; esac
case "$action" in install|uninstall) ;; *) usage ;; esac

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

if [[ "$action" == "install" ]]; then do_install "$role"; else do_uninstall "$role"; fi
