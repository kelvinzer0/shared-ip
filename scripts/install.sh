#!/bin/bash
set -e

BINARY_NAME="shared-ip"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/shared-ip"

echo "=== Shared-IP Installer ==="

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Check Go installation
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Install Go first:"
    echo "  https://golang.org/doc/install"
    exit 1
fi

echo "[1/4] Building..."
cd "$(dirname "$0")/.."
go build -ldflags="-s -w" -o "$BINARY_NAME" .
echo "  Built: $BINARY_NAME"

echo "[2/4] Installing binary to $INSTALL_DIR..."
cp "$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
chmod +x "$INSTALL_DIR/$BINARY_NAME"
echo "  Installed: $INSTALL_DIR/$BINARY_NAME"

echo "[3/4] Creating config directory..."
mkdir -p "$CONFIG_DIR"
echo "  Config: $CONFIG_DIR/config.json"

echo "[4/4] Installing service..."
"$INSTALL_DIR/$BINARY_NAME" service install

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Usage:"
echo "  $BINARY_NAME add domain.com --port=443 --localipv4=192.168.1.10"
echo "  $BINARY_NAME add domain.com --port=80 --localipv4=192.168.1.10"
echo "  $BINARY_NAME list"
echo ""
echo "Service:"
echo "  service $BINARY_NAME start"
echo "  service $BINARY_NAME status"
echo ""
echo "DNS: Point A/AAAA record to this VPS public IP."
