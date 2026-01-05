# 🛡️ AegisRay: Ultra-Stealth Mesh VPN
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Security](https://img.shields.io/badge/Security-Strict-success?style=flat&logo=googlesheets)](/internal/crypto)
[![Network](https://img.shields.io/badge/Topology-Mesh-blueviolet?style=flat&logo=pypy)](/internal/mesh)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**AegisRay** is a production-grade, cryptographically secure P2P mesh VPN designed to operate in hostile network environments. It leverages multi-hop routing and SNI masquerading to traverse deep packet inspection (DPI) firewalls while maintaining absolute zero-trust privacy between peers.

---

## 🚀 Why AegisRay?

*   **👻 Invisible to DPI**: Traffic disguises itself as standard HTTPS web browsing (e.g., to `cloudflare.com` or `google.com`) using SNI Masquerading.
*   **🕸️ True Decentralization**: No central coordination server. Steps are fully autonomous using Distributed Hash Table (DHT) principles and gossip protocols.
*   **🔒 Military-Grade Crypto**:
    *   **Identity**: RSA-2048 identity keys bound to SHA-256 Node IDs.
    *   **Transport**: AES-256-GCM session keys, rotated automatically every hour.
    *   **Integrity**: RSA signatures on every Route Advertisement and Handshake.

---

## 📚 Documentation
For deep dives into specific topics, check out our detailed documentation:

- **[📖 Configuration Guide](docs/configuration.md)**: Templates for Peering, Gateways, and Exit Nodes.
- **[🏗️ System Architecture](docs/architecture.md)**: How MeshNode, Router, and P2P layers interact.
- **[🔐 Security Model](docs/security.md)**: Cryptographic audits, Handshake flows, and Threat models.
- **[🚀 Deployment & Tuning](docs/deployment.md)**: Docker, Systemd, and Kernel optimizations.

---

## 🏛️ Architecture

### 1. The Mesh (Layer 2.5)
AegisRay creates a virtual overlay network.
*   **Self-Healing**: Nodes monitor peer latency and packet loss. If a direct link fails, the mesh automatically re-routes traffic through healthy neighbors.
*   **NAT Traversal**: Built-in RFC 5389 STUN client and multi-burst UDP hole punching allow connections to pierce through strict corporate/residential NATs.

### 2. The Router (Layer 3)
*   **Split Horizon**: Routing logic explicitly prevents loops by filtering route advertisements based on their source.
*   **Transitive Routing**: `Node A <-> Node B <-> Node C`. If A cannot reach C directly, B acts as a transparent, encrypted relay.

---

## 🛠️ Quick Start

### Prerequisites
*   **Docker** (Recommended for testing)
*   **Go 1.21+** (For building from source)
*   **Linux** (Kernel 5.6+ with WireGuard modules for TUN support)

### 🧪 Run the Simulation
Verify the mesh logic in a safe, isolated container environment:

```bash
# 1. Clone the repo
git clone https://github.com/surya-d-naidu/AegisRay.git
cd AegisRay

# 2. Start a 2-node mesh cluster
docker compose -f docker-compose.test.yml up --build

# 3. Watch the magic in logs
```

### 📦 Production Build
```bash
# Build the binary
make build

# Run with a template config
sudo ./bin/aegisray-mesh -config=configs/templates/basic-peer.yaml
```

---

## 📋 Project Roadmap

**Current Status**: 🟢 **Release Candidate 1.0**

### 📱 Client Development
- [ ] **Mobile SDK**: Port core Mesh logic to `gomobile` (Android/iOS bindings).
- [ ] **Desktop GUI**: Electron or Gio UI for Windows/Mac/Linux.
- [ ] **Systray Agent**: Lightweight background daemon for status monitoring.

### 🧠 Core Networking
- [ ] **Multipath Routing**: Allow using multiple paths simultaneously for higher throughput.
- [ ] **Traffic Obfuscation V2**: Implement stronger padding to resist entropy analysis (e.g., mimic DTLS 1.3).
- [ ] **IPv6 Support**: Full IPv6 mesh overlay and transport.

### 🔐 Cryptography & Security
- [ ] **Post-Quantum KEM**: Replace RSA Handshake with Kyber/Dilithium algorithms.
- [ ] **Hardware Token Support**: Store Identity Keys on YubiKeys (PKCS#11).
- [ ] **Audit Logging**: Tamper-evident local audit logs for regulated environments.

### ☁️ Infrastructure / DevOps
- [ ] **Kubernetes Operator**: Custom Resource Definition (CRD) for auto-meshing K8s pods.
- [ ] **Terraform Provider**: Automate cloud gateway provisioning on AWS/GCP/DigitalOcean.

---

## 🛡️ Security Audit

AegisRay follows a **Zero-Trust** model.
1.  **Join Request**: A new node sends a signed request.
2.  **Verification**: The receiving peer verifies the signature against the public key `ID`.
3.  **Key Exchange**: An ephemeral AES session key is generated, encrypted with the target's RSA Public Key, and sent back.
4.  **Session-Lock**: All subsequent data packets use this unique AES key.

---

## 🤝 Contributing
Contributions are welcome! Please check out the `internal` directory to understand the core logic before submitting PRs.

## 📄 License
This project is licensed under the **MIT License**.

---
*Maintained with ❤️ by the AegisRay Team at [https://github.com/surya-d-naidu/AegisRay](https://github.com/surya-d-naidu/AegisRay)*
