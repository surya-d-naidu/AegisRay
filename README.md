# 🛡️ AegisRay: Ultra-Stealth Mesh VPN
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Security](https://img.shields.io/badge/Security-Strict-success?style=flat&logo=googlesheets)](/internal/crypto)
[![Network](https://img.shields.io/badge/Topology-Mesh-blueviolet?style=flat&logo=pypy)](/internal/mesh)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**AegisRay** is a security-focused P2P mesh VPN for hostile network environments. It uses mutual TLS, signed peer authorization, multi-hop routing, and SNI masquerading on TLS handshakes to reduce fingerprinting while maintaining zero-trust peer admission.

---

## 🚀 Why AegisRay?

*   **👻 Stealth-Oriented Transport**: TLS handshakes can use SNI masquerading so peer connections resemble ordinary HTTPS setup to allowed domains such as `cloudflare.com` or `google.com`.
*   **🕸️ True Decentralization**: No central coordination server. Steps are fully autonomous using Distributed Hash Table (DHT) principles and gossip protocols.
*   **🔒 Modern Crypto**:
    *   **Identity**: Ed25519 identity keys bound to SHA-256-derived Node IDs.
    *   **Transport Authentication**: Self-signed Ed25519 TLS certificates bound to the same identity key.
    *   **Session Keys**: X25519 key agreement with XChaCha20-Poly1305 peer encryption.

---

## 📚 Documentation
For deep dives into specific topics, check out our detailed documentation:

- **[📖 Configuration Guide](docs/configuration.md)**: Templates for Peering, Gateways, and Exit Nodes.
- **[🏗️ System Architecture](docs/architecture.md)**: How MeshNode, Router, and P2P layers interact.
- **[🔐 Security Model](docs/security.md)**: Cryptographic audits, Handshake flows, and Threat models.
- **[🗝️ Trust Operations](docs/trust.md)**: Generate trust roots, sign peer bundles, and manage admission.
- **[✅ Validation Guide](docs/validation.md)**: Runtime checks for smoke validation and production sign-off.
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
*   **Go 1.24+** (For building from source)
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

# Run with a template config after adding trust_root_public_key_file and authorized_peers_file
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
1.  **Admission**: A node must present a TLS certificate whose Ed25519 public key matches its claimed mesh identity.
2.  **Authorization**: The peer must also appear in an operator-provided trust bundle or explicit authorized key list.
3.  **Key Exchange**: Peers derive per-peer session keys using X25519.
4.  **Session-Lock**: Data packets are encrypted per peer, and route advertisements are signed.

---

## 🤝 Contributing
Contributions are welcome! Please check out the `internal` directory to understand the core logic before submitting PRs.

## 📄 License
This project is licensed under the **MIT License**.

---
*Maintained with ❤️ by the AegisRay Team at [https://github.com/surya-d-naidu/AegisRay](https://github.com/surya-d-naidu/AegisRay)*
