#!/bin/bash
set -e

BINARY_NAME="shared-ip"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/shared-ip"

echo "=== Shared-IP Uninstaller ==="

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: Must be run as root"
    exit 1
fi

echo "[1/3] Stopping and removing service..."
"$INSTALL_DIR/$BINARY_NAME" service uninstall 2>/dev/null || true

echo "[2/3] Removing binary..."
rm -f "$INSTALL_DIR/$BINARY_NAME"

echo "[3/3] Removing config..."
read -p "Remove config directory $CONFIG_DIR? [y/N]: " answer
if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
    rm -rf "$CONFIG_DIR"
    echo "  Config removed."
else
    echo "  Config preserved at $CONFIG_DIR"
fi

echo ""
echo "=== Uninstalled ==="
