#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

LOG_LEVEL="info"
INSTALL_DIR="/opt/aegisray"
BINARY_NAME="aegisray-mesh"
CONFIG_FILE="$INSTALL_DIR/config.yaml"
SERVICE_FILE="/etc/systemd/system/aegisray.service"

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# 1. Check Root
if [ "$EUID" -ne 0 ]; then
  error "Please run as root"
fi

# 2. Detect Network Interface
DEFAULT_IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
log "Detected default interface: $DEFAULT_IFACE"

# 3. Setup Directories
log "Creating installation directory at $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR/certs"
mkdir -p "$INSTALL_DIR/logs"

# 4. Build or Copy Binary
if [ -f "./bin/$BINARY_NAME" ]; then
    log "Found binary in ./bin/, copying..."
    cp "./bin/$BINARY_NAME" "$INSTALL_DIR/"
elif [ -f "./$BINARY_NAME" ]; then
    log "Found binary in current directory, copying..."
    cp "./$BINARY_NAME" "$INSTALL_DIR/"
elif command -v go &> /dev/null; then
    log "Binary not found, building with Go..."
    # Ensure we are in a repo? Assumes script is run from repo root
    if [ -f "go.mod" ]; then
        make build
        cp "./bin/$BINARY_NAME" "$INSTALL_DIR/"
    else
        error "go.mod not found. Are you running this from the AegisRay repository root?"
    fi
else
    error "AegisRay binary not found and Go is not installed. Please build 'bin/$BINARY_NAME' first."
fi

chmod +x "$INSTALL_DIR/$BINARY_NAME"

# 5. Configure System (IP Forwarding)
log "Enabling IP Forwarding..."
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-aegisray.conf
sysctl -p /etc/sysctl.d/99-aegisray.conf

# 6. Configure Firewall (Masquerading)
# Note: This is ephemeral. A robust script would modify ufw or nftables rules persistently.
# We will use iptables-persistent checks or just add command to rc.local/systemd for minimal dep requirement
log "Configuring NAT/Masquerading..."
if ! iptables -t nat -C POSTROUTING -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -o "$DEFAULT_IFACE" -j MASQUERADE
    log "Added iptables rule."
else
    log "iptables rule already exists."
fi

# 7. Generate Configuration
NODE_NAME="proxy-$(hostname)-$(date +%s)"
log "Generating config file at $CONFIG_FILE..."
cat > "$CONFIG_FILE" <<EOF
# AegisRay Proxy Configuration
node_name: "$NODE_NAME"
mesh_ip: "100.64.0.1" # Fixed IP for Server/Exit Node

# Network
listen_port: 51820
api_port: 8081  # Avoid conflict with port 8080
network_name: "aegis-mesh"
network_cidr: "100.64.0.0/16"

# Role: Exit Node / Proxy
exit_node: true
mesh_routing: true
enable_tun: true

# Security
use_tls: true
cert_file: "$INSTALL_DIR/certs/node.crt"
key_file: "$INSTALL_DIR/certs/node.key"
stealth_mode: true
stealth_domains:
  - "cloudflare.com"
  - "google.com"

# Discovery
auto_discovery: true
# static_peers:
#   - "another-node:51820" 
EOF

# 8. Create Systemd Service
log "Creating systemd service..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=AegisRay Mesh VPN Node
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$BINARY_NAME -config=$CONFIG_FILE
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# 9. Start Service
log "Reloading systemd and starting AegisRay..."
systemctl daemon-reload
systemctl enable aegisray
systemctl restart aegisray

success "AegisRay Proxy deployed successfully!"
echo -e "
Configuration: $CONFIG_FILE
Service Status: systemctl status aegisray
Logs: journalctl -u aegisray -f
"
