# AegisRay

<div align="center">

**Ultra-Stealth VPN Tunnel with SNI Masquerading & TLS Encryption**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![gRPC](https://img.shields.io/badge/Protocol-gRPC-green?style=flat&logo=grpc)](https://grpc.io/)
[![Docker](https://img.shields.io/badge/Deploy-Docker-blue?style=flat&logo=docker)](https://docker.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat)](LICENSE)

</div>

## 🛡️ Overview

AegisRay is a sophisticated VPN tunnel solution designed to bypass restrictive firewalls and deep packet inspection (DPI) systems. It disguises VPN traffic as legitimate HTTPS traffic using advanced SNI (Server Name Indication) masquerading techniques.

### ✨ Key Features

- **🕵️ SNI Masquerading**: Disguises tunnel traffic as connections to popular websites (CloudFlare, Google, etc.)
- **🔒 End-to-End Encryption**: Military-grade encryption for all tunnel data
- **🌐 TLS Camouflage**: Uses port 443 (HTTPS) to appear as legitimate web traffic
- **🚀 High Performance**: Optimized gRPC-based protocol for minimal latency
- **🐳 Docker Ready**: Easy deployment with Docker Compose
- **📊 Multi-Mode Support**: Normal, production, and ultra-stealth configurations
- **🔄 Auto-Reconnection**: Robust connection recovery mechanisms
- **📡 Multiple Protocols**: HTTP and SOCKS proxy support

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client App    │───▶│  AegisRay VPN   │───▶│  Target Server  │
│                 │    │    Tunnel       │    │                 │
│  (Your Device)  │    │ (VPS/Cloud)     │    │  (Internet)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │  Fake SNI:      │
                       │  cloudflare.com │
                       │  google.com     │
                       │  microsoft.com  │
                       └─────────────────┘
```

### 🔧 Core Components

- **🖥️ Server**: gRPC tunnel server with TLS termination
- **📱 Client**: TUN interface client with traffic encryption
- **🔑 Certificate Manager**: Automatic TLS certificate generation
- **🎭 SNI Faker**: Dynamic fake SNI generation
- **🔐 Crypto Engine**: RSA/AES hybrid encryption
- **🌐 Proxy Services**: HTTP/SOCKS proxy servers

## 🚀 Quick Start

### Prerequisites

- Go 1.21+
- Docker & Docker Compose
- Root privileges (for TUN interface)
- A VPS with public IP

### 1. Clone & Build

```bash
git clone https://github.com/surya-d-naidu/AegisRay.git
cd AegisRay
make setup
make build
```

### 2. Deploy Server (VPS)

```bash
# Quick VPS deployment
./deploy.sh

# Or manual Docker deployment
docker-compose -f docker-compose.prod.yml up -d
```

### 3. Configure Client

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

### 4. Start Client

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
