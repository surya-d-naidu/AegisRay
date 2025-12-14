# Getting Started with AegisRay

Welcome to AegisRay! This guide will help you set up your first P2P mesh VPN network in under 10 minutes.

## 🎯 What You'll Build

By the end of this guide, you'll have:
- A working AegisRay mesh network with multiple nodes
- Secure P2P connections with SNI masquerading
- Real-time monitoring and management interfaces
- Understanding of the core concepts

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux, macOS, or Windows
- **Memory**: 512MB RAM minimum, 1GB recommended
- **Network**: Internet connection with outbound access to ports 443, 80, 8443
- **Architecture**: x86_64 or ARM64

### Required Software
- **Docker & Docker Compose** (recommended) OR
- **Go 1.21+** (for building from source)
- **curl** (for API testing)

## 🚀 Quick Start (5 Minutes)

### Option 1: Docker Deployment (Recommended)

1. **Clone the Repository**
```bash
git clone https://github.com/surya-d-naidu/AegisRay.git
cd AegisRay
```

2. **Start the Mesh Network**
```bash
# Start a complete 3-node mesh network
docker-compose -f simulations/docker-compose.yml up -d

# Verify all services are running
docker-compose -f simulations/docker-compose.yml ps
```

3. **Check Network Status**
```bash
# View mesh network status
curl -s http://localhost:8080/status | jq .

# View connected peers
curl -s http://localhost:8080/peers | jq .
```

4. **Access Web Dashboard**
Open [http://localhost:3000](http://localhost:3000) to view the mesh network dashboard.

### Option 2: Manual Node Setup

1. **Download Pre-built Binaries**
```bash
# Linux x86_64
wget https://github.com/surya-d-naidu/AegisRay/releases/latest/download/aegisray-linux-amd64.tar.gz
tar -xzf aegisray-linux-amd64.tar.gz

# macOS
wget https://github.com/surya-d-naidu/AegisRay/releases/latest/download/aegisray-darwin-amd64.tar.gz
tar -xzf aegisray-darwin-amd64.tar.gz
```

2. **Create Configuration**
```bash
# Create config directory
mkdir -p ~/.config/aegisray

# Generate default configuration
./aegisray-mesh --generate-config > ~/.config/aegisray/node.yaml
```

3. **Start Your First Node**
```bash
# Start mesh node
sudo ./aegisray-mesh -config ~/.config/aegisray/node.yaml
```

## 🏗️ Understanding the Architecture

### Mesh Network Topology

AegisRay creates a **peer-to-peer mesh network** where nodes connect directly:

```
┌─────────────────── AegisRay Mesh Network ───────────────────┐
│                                                             │
│  📱 Client Node A ←──→ 🌍 Exit Node US ←──→ 📱 Client Node B │
│       ↑                      ↓                      ↑       │
│       │                      │                      │       │
│       └────→ 🌍 Exit Node EU ←─────────────────────┘       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Key Benefits:**
- **No Central Point of Failure**: Nodes connect directly to each other
- **Automatic Failover**: Traffic routes around failed nodes
- **Geographic Distribution**: Exit nodes in multiple regions
- **Load Balancing**: Traffic distributed across available paths

### Node Types

**1. Client Nodes** 📱
- Connect to the mesh network
- Route traffic through exit nodes
- Ideal for laptops, phones, IoT devices

**2. Exit Nodes** 🌍
- Provide internet access to mesh clients
- Act as VPN gateways
- Can be deployed in multiple regions

**3. Coordinator Nodes** 🎯 (Optional)
- Help with initial peer discovery
- Not required for mesh operation
- Used for bootstrapping large networks

## 📖 Basic Operations

### Viewing Network Status

```bash
# Check if node is healthy
curl http://localhost:8080/health

# Get detailed network status
curl http://localhost:8080/status

# List all connected peers
curl http://localhost:8080/peers
```

### Managing Peers

```bash
# Add a static peer
curl -X POST http://localhost:8080/api/peers \
  -H "Content-Type: application/json" \
  -d '{"address": "peer.example.com:443"}'

# Remove a peer
curl -X DELETE http://localhost:8080/api/peers/PEER_ID
```

### Configuration Management

```bash
# Reload configuration
curl -X POST http://localhost:8080/api/config/reload

# Update log level
curl -X PUT http://localhost:8080/api/config \
  -H "Content-Type: application/json" \
  -d '{"log_level": "debug"}'
```

## 🔧 Configuration Basics

### Essential Configuration Options

```yaml
# ~/.config/aegisray/node.yaml

# Node Identity
node_name: "my-aegisray-node"
listen_port: 443

# Network Settings
network_name: "my-mesh"
network_cidr: "100.64.0.0/16"

# Peer Discovery
static_peers:
  - "exit1.example.com:443"
  - "exit2.example.com:443"
auto_discovery: true

# Security
use_tls: true
stealth_mode: true
stealth_domains:
  - "cloudflare.com"
  - "fastly.com"

# Performance
enable_tun: true
mtu: 1420
```

### Environment Variables

```bash
# Node configuration
export AEGISRAY_NODE_NAME="mobile-client"
export AEGISRAY_MESH_IP="100.64.1.42"
export AEGISRAY_NETWORK_NAME="corporate-mesh"

# Connection settings
export AEGISRAY_LISTEN_PORT="443"
export AEGISRAY_LOG_LEVEL="info"

# Stealth settings
export AEGISRAY_STEALTH_MODE="true"
export AEGISRAY_SNI_DOMAIN="googleapis.com"
```

## 🛠️ Verification Steps

### 1. Health Check
```bash
curl -f http://localhost:8080/health
# Expected: {"status":"healthy","node_id":"...","timestamp":"..."}
```

### 2. Peer Connectivity
```bash
curl -s http://localhost:8080/peers | jq '.peers | length'
# Expected: Number > 0 (indicating connected peers)
```

### 3. Network Interface
```bash
# Check TUN interface (Linux/macOS)
ip addr show aegis0

# Check routes
ip route | grep 100.64.0.0
```

### 4. Traffic Test
```bash
# Test mesh connectivity (from client node)
ping 100.64.0.1  # Ping exit node mesh IP

# Test internet access through mesh
curl --interface aegis0 http://httpbin.org/ip
```

## 🔍 Monitoring & Debugging

### Log Files
```bash
# View live logs
tail -f /var/log/aegisray.log

# Search for errors
grep -i error /var/log/aegisray.log

# Filter by component
grep "p2p_discovery" /var/log/aegisray.log
```

### Performance Metrics
```bash
# Network statistics
curl -s http://localhost:8080/api/stats | jq .

# Peer latencies
curl -s http://localhost:8080/api/peers | jq '.peers[] | {id: .id, latency: .latency}'

# Traffic statistics
curl -s http://localhost:8080/api/traffic | jq .
```

### Debugging Common Issues

**No Peers Connecting**
```bash
# Check static peer configuration
curl -s http://localhost:8080/status | jq '.p2p_discovery.static_peers'

# Verify network connectivity
telnet exit1.example.com 443

# Check firewall rules
sudo iptables -L -n | grep 443
```

**TUN Interface Issues**
```bash
# Check interface status
ip link show aegis0

# Verify permissions (Linux)
ls -l /dev/net/tun

# Check kernel modules (Linux)
lsmod | grep tun
```

## 📱 Mobile Client Setup

### Android APK Installation
```bash
# Download latest APK
wget https://github.com/surya-d-naidu/AegisRay/releases/latest/download/aegisray-android.apk

# Install via ADB
adb install aegisray-android.apk
```

### iOS Configuration
```bash
# Generate mobile configuration
./aegisray-mesh --generate-mobile-config > aegisray-mobile.json

# Import into iOS app via QR code or file
```

## ⭐ Next Steps

Now that you have AegisRay running:

1. **📖 Learn More**: Read the [Architecture Overview](architecture.md)
2. **🔧 Advanced Config**: Explore [Configuration Reference](configuration.md)  
3. **🏭 Production Setup**: Follow [Production Deployment](deployment/production.md)
4. **📱 Mobile Integration**: Set up [Mobile Apps](integrations/mobile.md)
5. **🛡️ Security Hardening**: Review [Security Model](security.md)

## 🆘 Need Help?

- **Documentation**: Browse the complete [docs](README.md)
- **Issues**: Report problems on [GitHub Issues](https://github.com/surya-d-naidu/AegisRay/issues)
- **Community**: Join discussions at [discuss.aegisray.dev](https://discuss.aegisray.dev)
- **Support**: Commercial support available at [support@aegisray.dev](mailto:support@aegisray.dev)

---

**Congratulations! 🎉** You now have a working AegisRay mesh VPN network. The mesh will automatically discover peers, establish secure connections, and provide encrypted internet access.
