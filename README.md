# AegisRay

<div align="center">

**Ultra-Stealth VPN Tunnel with SNI Masquerading & TLS Encryption**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![gRPC](https://img.shields.io/badge/Protocol-gRPC-green?style=flat&logo=grpc)](https://grpc.io/)
[![Docker](https://img.shields.io/badge/Deploy-Docker-blue?style=flat&logo=docker)](https://docker.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat)](LICENSE)

</div>

## 🛡️ Overview

AegisRay is a sophisticated **mesh VPN network** designed to bypass restrictive firewalls and deep packet inspection (DPI) systems. Unlike traditional hub-and-spoke VPNs, AegisRay creates a **peer-to-peer mesh network** where nodes connect directly to each other, similar to Tailscale but with advanced stealth capabilities.

### ✨ Key Features

#### 🕸️ **Mesh Network Architecture**
- **Peer-to-Peer Connections**: Direct connections between nodes without central servers
- **Automatic Peer Discovery**: Finds and connects to other nodes automatically
- **NAT Traversal**: Breakthrough firewalls and NATs using STUN/TURN and hole punching
- **Load Balancing**: Distribute traffic across multiple mesh paths
- **Self-Healing**: Automatically routes around failed nodes

#### 🥷 **Advanced Stealth Features**
- **SNI Masquerading**: Disguises mesh traffic as connections to popular websites (CloudFlare, Google, etc.)
- **Traffic Camouflage**: All mesh communication looks like legitimate HTTPS browsing
- **Port Flexibility**: Uses standard ports (443, 80) to blend with normal web traffic
- **Metadata Obfuscation**: Hides VPN signatures from deep packet inspection

#### 🔒 **Security & Performance**
- **End-to-End Encryption**: Military-grade encryption for all mesh data
- **Perfect Forward Secrecy**: Dynamic key rotation and session isolation
- **Zero Trust Architecture**: Each connection is individually authenticated and encrypted
- **High Performance**: Optimized protocols with minimal latency overhead

#### 🚀 **Enterprise Ready**
- **Docker Integration**: Easy deployment with Docker Compose
- **Multi-Mode Support**: Client nodes, exit nodes, and coordinators
- **Auto-Reconnection**: Robust connection recovery and failover
- **Cross-Platform**: Linux, Windows, macOS, iOS, Android support

## 🏗️ Mesh Network Architecture

### Traditional VPN vs AegisRay Mesh

**Traditional Hub-and-Spoke VPN:**
```
Client A ──► VPN Server ◄── Client B
Client C ──► VPN Server ◄── Client D
     (Single point of failure)
```

**AegisRay Mesh Network:**
```
    Exit Node ◄──────────────┐
        │                    │
        │    ┌─────────────────────┐
        ▼    │                     │
   📱Mobile ◄┼─► 💻Laptop ◄───► 🖥️Desktop
        │    │     │              │
        │    │     │         🖧 Server
        │    │     │              │
        └────┼─────┼──► 📟IoT ◄────┘
             │     │
        🏢 Office ◄┘
        
   (Self-healing P2P mesh with multiple paths)
```

### Stealth Layer Architecture
```
┌─────────────────────────────────────────────┐
│            Internet Traffic                  │
│  ┌─────────────────────────────────────┐   │
│  │        Fake HTTPS Traffic            │   │
│  │  SNI: cloudflare.com                │   │
│  │  Port: 443 (HTTPS)                  │   │
│  │  Headers: Normal browser headers     │   │
│  │                                     │   │
│  │  ┌─────────────────────────────┐   │   │
│  │  │     Encrypted Mesh Data      │   │   │
│  │  │   ┌─────────────────────┐   │   │   │
│  │  │   │   VPN Tunnel Data    │   │   │   │
│  │  │   └─────────────────────┘   │   │   │
│  │  └─────────────────────────────┘   │   │
│  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

### 🔧 Core Components

#### �️ **Mesh Network Layer**
- **Mesh Node**: Core P2P networking with peer discovery and routing
- **NAT Traversal**: STUN/TURN client with UDP hole punching
- **Coordinator**: Peer discovery and mesh coordination service
- **Route Manager**: Intelligent routing and load balancing

#### 🥷 **Stealth Layer** 
- **SNI Faker**: Dynamic fake SNI generation for traffic masquerading
- **Certificate Manager**: Automatic TLS certificate generation and rotation
- **Traffic Camouflage**: Makes VPN traffic look like normal HTTPS browsing
- **DPI Evasion**: Advanced techniques to bypass deep packet inspection

#### 🔐 **Security Layer**
- **Crypto Engine**: RSA/AES hybrid encryption with perfect forward secrecy
- **Key Management**: Automatic key rotation and peer authentication
- **Zero Trust**: Every connection independently authenticated and encrypted

#### 🌐 **Network Layer**
- **TUN Interface**: Layer 3 VPN with full IP routing
- **Mesh Routing**: Intelligent multi-path routing across the mesh
- **Exit Nodes**: Internet gateway nodes for mesh clients

## 🚀 Quick Start

### Prerequisites

- Go 1.21+ or Docker
- Root privileges (for TUN interface)
- Linux/macOS/Windows

### 🕸️ Option 1: Mesh Network (Recommended)

#### 1. Clone & Build
```bash
git clone https://github.com/surya-d-naidu/AegisRay.git
cd AegisRay
make setup
make build
```

#### 2. Deploy Exit Node (VPS)
```bash
# Deploy complete mesh infrastructure
docker-compose -f docker-compose.mesh.yml up -d

# Or deploy single exit node
sudo ./bin/aegisray-mesh -config=configs/mesh-exit-node.yaml -exit-node
```

#### 3. Join Mesh Network (Client)
```bash
# Copy and edit mesh config
cp configs/mesh.example.yaml configs/mesh.yaml
# Edit: Set coordinators to your exit node IPs

# Join the mesh
sudo ./bin/aegisray-mesh -config=configs/mesh.yaml
```

#### 4. Mobile/Desktop Clients
```bash
# Mobile-optimized config
sudo ./bin/aegisray-mesh -config=configs/mesh-mobile.yaml

# Desktop config with more features
sudo ./bin/aegisray-mesh -config=configs/mesh.yaml
```

### 🏢 Option 2: Traditional VPN (Legacy)

#### 1. Deploy Server (VPS)
```bash
# Quick VPS deployment
./deploy.sh

# Or manual deployment
docker-compose -f docker-compose.prod.yml up -d
```

#### 2. Configure Client
Edit `configs/client.yaml`:
```yaml
server:
  host: "YOUR_VPS_IP"           # Replace with your VPS IP
  port: 443                    # Standard HTTPS port
  fake_sni: "cloudflare.com"   # Disguise as CloudFlare
  use_tls: true

tunnel:
  interface_name: "aegis0"
  local_ip: "10.8.0.2/24"
  dns_servers:
    - "8.8.8.8"
    - "1.1.1.1"
```

#### 3. Start Client
```bash
sudo ./bin/aegisray-client -config=configs/client.yaml
```

## 📋 Deployment Modes

### 🏢 Production Mode
- Standard deployment for general use
- Port 8443 (gRPC) + 80/1080 (proxies)
- Balanced performance and stealth

```bash
docker-compose -f docker-compose.prod.yml up -d
```

### 🥷 Ultra-Stealth Mode
- Maximum stealth for restrictive environments
- Only uses port 443 (HTTPS)
- Minimal logging and optimized evasion

```bash
docker-compose -f docker-compose.stealth.yml up -d
./bin/aegisray-client -config=configs/client-stealth.yaml
```

### 👨‍💻 Development Mode
- Local testing and development
- Full logging and debugging

```bash
docker-compose -f docker-compose.client.yml up -d
```

## ⚙️ Configuration

### Server Configuration (`configs/server.yaml`)

```yaml
server:
  host: "0.0.0.0"
  port: 8443
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
  log_level: "debug"
  max_clients: 100
  use_tls: true
  auto_cert: true

network:
  interface_name: "aegis-server"
  dns_servers:
    - "8.8.8.8"
    - "1.1.1.1"
  allowed_ips:
    - "10.8.0.0/24"
```

### Client Configuration (`configs/client.yaml`)

```yaml
server:
  host: "your-vps-ip"
  port: 443
  fake_sni: "cloudflare.com"
  use_tls: true
  log_level: "info"

tunnel:
  interface_name: "aegis0"
  local_ip: "10.8.0.2/24"
  dns_servers:
    - "8.8.8.8"
    - "1.1.1.1"
  routes:
    - "0.0.0.0/0"  # Route all traffic

client:
  id: "client-001"
  reconnect_interval: 5
  heartbeat_interval: 30
```

## 🔨 Build Commands

```bash
# Install dependencies
make deps

# Generate protobuf files
make proto

# Build both client and server
make build

# Build specific components
make server
make client

# Run components
make run-server
make run-client

# Clean build artifacts
make clean
```

## 🐳 Docker Usage

### Server Deployment

```bash
# Production server
docker-compose -f docker-compose.prod.yml up -d

# Ultra-stealth server (port 443 only)
docker-compose -f docker-compose.stealth.yml up -d

# Check status
docker-compose ps
docker-compose logs aegisray-server
```

### Client Usage

```bash
# Run client in container
docker-compose -f docker-compose.client.yml up -d

# Or run locally
sudo ./bin/aegisray-client -config=configs/client.yaml
```

## 🛡️ Security Features

### 🔐 Encryption
- **RSA-4096**: Key exchange
- **AES-256-GCM**: Data encryption
- **TLS 1.3**: Transport security
- **Perfect Forward Secrecy**: Session keys

### 🎭 Stealth Techniques
- **SNI Masquerading**: Fake certificate names
- **Traffic Camouflage**: Looks like HTTPS browsing
- **Port Disguise**: Uses standard web ports
- **Metadata Obfuscation**: Hidden tunnel signatures

### 🔒 Certificate Management
- Automatic certificate generation
- Self-signed or Let's Encrypt support
- Dynamic SNI certificate switching
- Certificate pinning protection

## 📊 Monitoring & Debugging

### Health Checks

```bash
# Server health
curl -k https://YOUR_VPS_IP:8443/health

# Docker health
docker-compose ps
```

### Logs

```bash
# Server logs
docker-compose logs -f aegisray-server

# Client logs
tail -f /var/log/aegisray-client.log
```

### Performance Metrics

```bash
# Network interface stats
ip -s link show aegis0

# Connection status
ss -tulpn | grep 8443
```

## 🔧 Troubleshooting

### Common Issues

#### 🚫 TUN Interface Permission Denied
```bash
# Ensure running as root
sudo ./bin/aegisray-client -config=configs/client.yaml

# Check TUN module
sudo modprobe tun
```

#### 🌐 Connection Refused
```bash
# Check firewall
sudo ufw status
sudo ufw allow 443/tcp

# Check server status
docker-compose ps
docker-compose logs aegisray-server
```

#### 🔐 TLS Certificate Errors
```bash
# Regenerate certificates
rm -rf certs/
make build
```

#### 📡 DNS Resolution Issues
```bash
# Update DNS servers in config
dns_servers:
  - "8.8.8.8"
  - "1.1.1.1"
```

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=debug

# Run with verbose output
./bin/aegisray-client -config=configs/client.yaml -v
```

## 🚀 Advanced Usage

### Custom SNI Profiles

Create custom SNI masquerading profiles:

```yaml
sni_profiles:
  cloudflare:
    - "cloudflare.com"
    - "cdn.cloudflare.com"
    - "api.cloudflare.com"
  google:
    - "google.com"
    - "googleapis.com"
    - "gstatic.com"
```

### Load Balancing

Deploy multiple servers with load balancing:

```yaml
servers:
  - host: "vps1.example.com"
    weight: 1
  - host: "vps2.example.com"
    weight: 2
```

### Traffic Routing

Configure selective routing:

```yaml
routes:
  bypass:
    - "192.168.0.0/16"
    - "10.0.0.0/8"
  tunnel:
    - "0.0.0.0/0"
```

## 🤝 Contributing

We welcome contributions! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone repository
git clone https://github.com/surya-d-naidu/AegisRay.git
cd AegisRay

# Setup development environment
make setup
make proto
make build

# Run tests
go test ./...
```

### Code Structure

```
├── cmd/                    # Main applications
│   ├── client/            # Client application
│   └── server/            # Server application
├── internal/              # Internal packages
│   ├── certs/            # Certificate management
│   ├── config/           # Configuration handling
│   ├── crypto/           # Encryption utilities
│   ├── network/          # Network interfaces
│   ├── p2p/              # P2P networking
│   ├── proxy/            # Proxy servers
│   └── sni/              # SNI masquerading
├── proto/                 # Protocol buffers
├── configs/               # Configuration files
└── docker/                # Docker configurations
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Issues**: [GitHub Issues](https://github.com/surya-d-naidu/AegisRay.git/issues)
- **Discussions**: [GitHub Discussions](https://github.com/surya-d-naidu/AegisRay.git/discussions)

## ⚠️ Disclaimer

AegisRay is designed for legitimate privacy and security purposes. Users are responsible for complying with local laws and regulations. The developers assume no liability for misuse of this software.

---

<div align="center">

**Made with ❤️ for internet freedom**

[⭐ Star this repo](https://github.com/surya-d-naidu/AegisRay.git) • [🐛 Report Bug](https://github.com/surya-d-naidu/AegisRay.git/issues) • [💡 Request Feature](https://github.com/surya-d-naidu/AegisRay.git/issues)

</div>
