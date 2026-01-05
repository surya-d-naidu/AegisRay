# 🚀 Deployment Guide

This guide covers how to deploy AegisRay in various environments.

## 📦 1. Docker Deployment (Recommended)

Docker is the easiest way to run AegisRay without worrying about system dependencies.

### Prerequisites
*   Docker & Docker Compose installed.
*   `cap_add: NET_ADMIN` capability (for TUN interface).

### Docker Compose
Create a `docker-compose.yml`:
```yaml
version: '3.8'
services:
  aegis-node:
    image: aegisray/mesh:latest
    container_name: aegis-node
    cap_add:
      - NET_ADMIN      # Required for VPN Interface
      - SYS_MODULE     # Optional, for kernel mods
    volumes:
      - ./config.yaml:/app/configs/mesh.yaml
    ports:
      - "51820:51820/udp" # P2P Port
      - "51820:51820/tcp" # Fallback/Signal Port
    restart: always
```

### Run
```bash
docker compose up -d
```

---

## 🐧 2. Linux Systemd Service

For permanent installation on a Linux server/VPS.

### Build
```bash
make build
sudo cp bin/aegisray-mesh /usr/local/bin/
sudo mkdir -p /etc/aegisray
sudo cp configs/mesh.yaml /etc/aegisray/config.yaml
```

### Create Service File
Create `/etc/systemd/system/aegisray.service`:
```ini
[Unit]
Description=AegisRay Mesh VPN
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/aegisray-mesh -config=/etc/aegisray/config.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

# Capabilities for network administration
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

### Enable & Start
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aegisray
sudo systemctl status aegisray
```

---

## 📱 3. Tuning & Optimization

For high-throughput nodes (1Gbps+), consider these kernel tweaks:

### `/etc/sysctl.conf`
```bash
# Allow IP forwarding (Critical for Routers/Exit Nodes)
net.ipv4.ip_forward = 1

# Increase buffer sizes for high-speed UDP
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
```
Apply with `sysctl -p`.

## 🛡️ Firewall Rules

Ensure your external firewall (AWS Security Group, UFW, iptables) allows:
*   **UDP 51820**: Incoming P2P connections.
*   **TCP 51820**: (Optional) For TLS/gRPC fallback.
