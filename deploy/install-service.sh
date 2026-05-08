#!/usr/bin/env bash
set -euo pipefail

# CamScan systemd service installer
# Run with: sudo ./install-service.sh [username]

# I8: Accept username as argument; default to $SUDO_USER or current user
CAMSCAN_USER="${1:-${SUDO_USER:-$(whoami)}}"

BINARY_SRC="$(dirname "$0")/../camscan"
BINARY_DST="/usr/local/bin/camscan"
SERVICE_SRC="$(dirname "$0")/camscan.service"
ENV_EXAMPLE="$(dirname "$0")/camscan.env.example"
ENV_DST="/etc/camscan/camscan.env"

echo "🔧 Installing CamScan service (user: $CAMSCAN_USER)..."

# 1. Build binary if not present
if [ ! -f "$BINARY_SRC" ]; then
    echo "  Building binary..."
    cd "$(dirname "$0")/.."
    go build -ldflags "-X github.com/xalgord/camscan/cmd.version=$(git describe --tags --always 2>/dev/null || echo dev)" -o camscan .
    cd - >/dev/null
fi

# 2. Copy binary
echo "  → Copying binary to $BINARY_DST"
cp "$BINARY_SRC" "$BINARY_DST"
chmod 755 "$BINARY_DST"

# 3. Create env config directory
if [ ! -f "$ENV_DST" ]; then
    echo "  → Creating /etc/camscan/ with env template"
    mkdir -p /etc/camscan
    cp "$ENV_EXAMPLE" "$ENV_DST"
    chmod 600 "$ENV_DST"
    echo "  ⚠  Edit $ENV_DST with your actual API keys!"
else
    echo "  → $ENV_DST already exists, skipping"
fi

# 4. Create log directory
mkdir -p /var/log/camscan
chown "$CAMSCAN_USER:$CAMSCAN_USER" /var/log/camscan

# 5. Patch systemd unit with actual user
sed "s/User=camscan/User=$CAMSCAN_USER/;s/Group=camscan/Group=$CAMSCAN_USER/" \
    "$SERVICE_SRC" > /etc/systemd/system/camscan.service
systemctl daemon-reload

echo ""
echo "✅ CamScan service installed!"
echo ""
echo "Next steps:"
echo "  1. Edit your API keys:  sudo nano /etc/camscan/camscan.env"
echo "  2. Set scan parameters: CAMSCAN_ARGS in /etc/camscan/camscan.env"
echo "  3. Start the service:   sudo systemctl start camscan"
echo "  4. Enable on boot:      sudo systemctl enable camscan"
echo "  5. Check logs:          journalctl -u camscan -f"
