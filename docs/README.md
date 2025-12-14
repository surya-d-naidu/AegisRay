# AegisRay Documentation

Welcome to the comprehensive documentation for AegisRay, a peer-to-peer mesh VPN with advanced stealth capabilities and DPI evasion features.

## 📚 Documentation Structure

### Getting Started
- **[Getting Started Guide](getting-started.md)** - Get AegisRay running in 10 minutes
- **[Architecture Overview](architecture.md)** - System design and components
- **[Configuration Reference](configuration.md)** - Complete configuration options

### Core Documentation  
- **[API Reference](api-reference.md)** - REST API and gRPC documentation
- **[Security Model](security.md)** - Encryption, authentication, and stealth features
- **[Production Deployment](deployment/production.md)** - Enterprise deployment guide

### Integration Guides
- **[Mobile Integration](integrations/mobile.md)** - Flutter mobile app development
- **[Docker Deployment](deployment/docker.md)** - Containerized deployment
- **[Kubernetes](deployment/kubernetes.md)** - Kubernetes orchestration

### Advanced Topics
- **[Certificate Management](advanced/certificates.md)** - PKI and certificate lifecycle
- **[Network Segmentation](advanced/segmentation.md)** - Multi-tenant deployments
- **[Custom Protocols](advanced/protocols.md)** - Extending AegisRay protocols
- **[Plugin Development](advanced/plugins.md)** - Developing custom plugins

### Administration
- **[Monitoring & Logging](admin/monitoring.md)** - Observability and debugging
- **[Backup & Recovery](admin/backup.md)** - Data protection strategies  
- **[Troubleshooting](admin/troubleshooting.md)** - Common issues and solutions
- **[Performance Tuning](admin/performance.md)** - Optimization guidelines

## 🎯 Quick Navigation

### 🚀 For New Users
Start with the [Getting Started Guide](getting-started.md) to have AegisRay running quickly.

### 🏗️ For System Administrators  
Review the [Architecture Overview](architecture.md) and [Production Deployment](deployment/production.md) guides.

### 👨‍💻 For Developers
Explore the [API Reference](api-reference.md) and [Mobile Integration](integrations/mobile.md) for development.

### 🔧 For Advanced Users
Check out [Security Model](security.md) and [Configuration Reference](configuration.md) for customization.

## 📋 Feature Overview

### 🌐 P2P Mesh Networking
- **Decentralized Architecture**: No central points of failure
- **Automatic Peer Discovery**: Gossip protocol for scalable discovery
- **Multi-Path Routing**: Intelligent route selection and load balancing
- **NAT Traversal**: STUN/TURN support for firewall penetration

### 🔒 Advanced Security
- **Multi-Layer Encryption**: TLS 1.3 + ChaCha20-Poly1305
- **Perfect Forward Secrecy**: Automatic key rotation
- **SNI Masquerading**: Hide VPN traffic as HTTPS
- **Certificate-Based Authentication**: Mutual TLS authentication

### 🎭 Stealth Capabilities
- **DPI Evasion**: Deep packet inspection bypass
- **Domain Fronting**: Traffic appears to go to CDNs
- **Traffic Obfuscation**: Padding and timing randomization
- **Protocol Mimicry**: Blend with legitimate web traffic

### ⚡ High Performance
- **Zero-Copy Networking**: Optimized packet processing
- **Adaptive QoS**: Automatic quality-of-service management
- **Connection Pooling**: Efficient resource utilization
- **Mobile Optimized**: Battery and bandwidth efficient

### 📱 Cross-Platform Support
- **Desktop**: Windows, macOS, Linux
- **Mobile**: iOS and Android (Flutter SDK)
- **Server**: Docker, Kubernetes, systemd
- **Embedded**: ARM and MIPS support

## � Documentation Conventions

### Configuration Examples
Configuration examples use YAML format:
```yaml
node_name: "example-node"
network:
  cidr: "100.64.0.0/16"
  stealth_mode: true
```

### API Examples  
API examples show curl commands and responses:
```bash
curl -X GET http://localhost:8080/api/status
# Response: {"status":"healthy","peers":3}
```

### Code Examples
Code samples include multiple languages where applicable:
```go
// Go example
client := aegisray.NewClient("localhost:8080")
status, err := client.GetStatus()
```

```dart
// Flutter/Dart example
final aegisRay = AegisRayService();
await aegisRay.connect(staticPeers: ['exit1.example.com:443']);
```

## 🚀 Quick Start Commands

```bash
# Docker deployment (fastest)
git clone https://github.com/surya-d-naidu/AegisRay.git
cd AegisRay
docker-compose -f simulations/docker-compose.yml up -d

# Check status
curl http://localhost:8080/health

# View connected peers
curl http://localhost:8080/peers
```

## 🆘 Getting Help

- **GitHub Issues**: [Report bugs and request features](https://github.com/surya-d-naidu/AegisRay/issues)
- **Discussions**: [Community discussions](https://github.com/surya-d-naidu/AegisRay/discussions)
- **Documentation**: [Improve documentation](https://github.com/surya-d-naidu/AegisRay/tree/main/docs)
- **Security**: [Report security issues](mailto:security@aegisray.dev)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](../CONTRIBUTING.md) for details on:
- Code contributions and pull requests
- Documentation improvements
- Bug reports and feature requests
- Security vulnerability reporting

## 📄 License

AegisRay is open source software licensed under the [MIT License](../LICENSE).

This documentation is licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/).

---

**Version**: 1.0.0 | **Last Updated**: January 2024 | **Project**: [AegisRay](https://github.com/surya-d-naidu/AegisRay)

---

## 💡 Key Concepts

Before diving into the documentation, familiarize yourself with these core concepts:

**Mesh Network**: A decentralized network where each node can connect to multiple other nodes, creating redundant pathways for data transmission.

**SNI Masquerading**: A stealth technique that makes VPN traffic appear as legitimate HTTPS connections to popular websites.

**P2P Discovery**: Automatic peer discovery mechanism that allows nodes to find and connect to each other without central coordination.

**Exit Nodes**: Special mesh nodes that provide internet access to the mesh network, similar to Tor exit relays.

**NAT Traversal**: Techniques for establishing direct connections between nodes behind firewalls and NAT devices.

---

## 🔗 External Resources

- **GitHub Repository**: [github.com/surya-d-naidu/AegisRay](https://github.com/surya-d-naidu/AegisRay)
- **Docker Images**: [hub.docker.com/r/aegisray/*](https://hub.docker.com/u/aegisray)
- **Protocol Buffers**: [buf.build/aegisray/protocols](https://buf.build/aegisray/protocols)
- **Community Forum**: [discuss.aegisray.dev](https://discuss.aegisray.dev)

---

*Last updated: December 14, 2025*
