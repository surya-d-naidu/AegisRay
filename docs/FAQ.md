# ❓ AegisRay Frequently Asked Questions (FAQ)

Common questions and answers about the AegisRay P2P Mesh VPN system.

## 📚 General Questions

### What is AegisRay?
AegisRay is a peer-to-peer mesh VPN solution designed for maximum stealth and performance. Unlike traditional VPNs that rely on centralized servers, AegisRay creates a decentralized mesh network where nodes connect directly to each other, similar to Tailscale but with advanced stealth capabilities including SNI masquerading and DPI bypass.

### How is AegisRay different from other VPN solutions?

| Feature | AegisRay | Traditional VPN | Tailscale |
|---------|----------|----------------|-----------|
| Architecture | P2P Mesh | Hub-and-spoke | P2P Mesh |
| Stealth Features | ✅ SNI Masquerading, DPI Bypass | ❌ Easily detected | ⚠️ Limited stealth |
| Central Servers | ❌ Fully decentralized | ✅ Required | ✅ Coordination server |
| Performance | ✅ Direct peer connections | ⚠️ Through central server | ✅ Direct connections |
| Censorship Resistance | ✅ High | ❌ Low | ⚠️ Medium |

### Is AegisRay legal to use?
AegisRay is legal privacy and security software. However, users are responsible for complying with local laws and regulations. The stealth features are designed for legitimate privacy protection, not to enable illegal activities.

### What platforms does AegisRay support?
- **Server/Desktop**: Linux, macOS, Windows
- **Mobile**: Android and iOS (via Flutter SDK)
- **Containers**: Docker, Kubernetes
- **Cloud**: AWS, GCP, Azure, DigitalOcean

---

## 🔧 Technical Questions

### How does the mesh networking work?
AegisRay creates a mesh topology where each node can communicate directly with every other node:

1. **Peer Discovery**: Nodes find each other using STUN/TURN servers and bootstrap peers
2. **NAT Traversal**: Automatic firewall penetration using hole punching techniques
3. **Route Advertisement**: Nodes share routing information using a gossip protocol
4. **Traffic Routing**: Intelligent path selection based on latency, bandwidth, and reliability

### What is SNI masquerading?
SNI (Server Name Indication) masquerading disguises VPN traffic as connections to popular websites:

```
Normal VPN:  Client → [VPN Headers] → Server
             ↑ Easily detected by DPI systems

AegisRay:    Client → [HTTPS to github.com] → [Nested tunnel] → Server
             ↑ Appears as normal web browsing
```

The technique works by:
- Setting SNI field to legitimate domains (e.g., `cdn.cloudflare.com`)
- Using valid certificates for those domains
- Tunneling mesh traffic inside the TLS connection
- Mimicking normal browser connection patterns

### How does DPI bypass work?
Deep Packet Inspection (DPI) bypass uses multiple techniques:

1. **Protocol Obfuscation**: Traffic looks like HTTPS web browsing
2. **Timing Randomization**: Varies packet intervals to break analysis patterns
3. **Packet Size Variation**: Random padding to avoid fingerprinting
4. **Connection Patterns**: Mimics browser behavior (keep-alive, HTTP/2, etc.)

### What encryption does AegisRay use?
AegisRay uses a multi-layered encryption approach:
- **Application Layer**: ChaCha20-Poly1305 AEAD encryption (256-bit keys)
- **Transport Layer**: TLS 1.3 with perfect forward secrecy
- **Key Exchange**: Curve25519 ECDH with Ed25519 authentication
- **Key Rotation**: Automatic 24-hour key rotation cycle

---

## 🚀 Setup & Configuration

### How do I get started with AegisRay?

#### Quick Start (Docker - Recommended):
```bash
git clone https://github.com/surya-d-naidu/AegisRay.git
cd AegisRay
docker-compose -f docker-compose.prod.yml up -d
```

#### Manual Installation:
```bash
# Build from source
make setup && make build

# Generate certificates  
make certs

# Start server node
./bin/server --config configs/server.yaml

# Start client node (separate terminal)
./bin/client --config configs/client.yaml
```

### What ports does AegisRay use?
- **443/tcp**: Primary mesh communication (configurable)
- **8080/tcp**: HTTP API for monitoring (optional)
- **9090/tcp**: gRPC API for SDK integration (optional)
- **Various UDP**: Outbound only for STUN servers (19302, 3478, etc.)

### How do I configure AegisRay for maximum stealth?
Use the stealth configuration template:

```yaml
# Enhanced stealth settings
tls:
  enabled: true
  sni_domains:
    - "cdn.cloudflare.com"
    - "assets.github.com"
    - "fonts.googleapis.com"

stealth:
  domain_fronting: true
  traffic_obfuscation: true
  timing_randomization: true
  packet_padding: true

# Use standard HTTPS port
listen_address: "0.0.0.0:443"
```

### How do I set up a multi-node mesh network?

1. **Deploy Exit Node (VPS)**:
   ```bash
   # Configure as exit node
   mesh:
     exit_node: true
     allowed_ips: ["0.0.0.0/0"]
   ```

2. **Deploy Relay Nodes**:
   ```yaml
   # Relay node configuration
   p2p:
     bootstrap_peers:
       - "exit-node.example.com:443"
   mesh:
     exit_node: false
     route_advertisement: true
   ```

3. **Connect Client Nodes**:
   ```yaml
   # Client configuration
   p2p:
     bootstrap_peers:
       - "exit-node.example.com:443"
       - "relay-1.example.com:443"
   ```

---

## 🔒 Security Questions

### Is AegisRay secure?
Yes, AegisRay implements multiple security layers:
- **Quantum-resistant encryption**: ChaCha20-Poly1305 and Ed25519
- **Perfect forward secrecy**: Ephemeral keys for each session
- **Zero trust architecture**: No central authority required
- **Comprehensive audit logging**: All activities are logged and signed

### How does AegisRay protect against traffic analysis?
- **SNI masquerading**: Traffic appears as connections to popular sites
- **Timing obfuscation**: Randomized packet intervals
- **Size obfuscation**: Random padding and fragmentation
- **Pattern breaking**: Mimics legitimate browser traffic

### Can AegisRay be detected by firewalls/DPI systems?
AegisRay is designed to be extremely difficult to detect:
- Uses standard HTTPS port (443)
- Presents valid TLS certificates for masqueraded domains
- Traffic patterns match normal web browsing
- No distinctive protocol signatures

However, no system is 100% undetectable. Advanced state-level DPI with machine learning might eventually detect patterns.

### What happens if a node is compromised?
AegisRay's mesh architecture limits compromise impact:
- **Network isolation**: Compromised nodes can be automatically excluded
- **Perfect forward secrecy**: Past communications remain secure
- **Key rotation**: Automatic key changes limit exposure window
- **Certificate revocation**: Compromised certificates can be revoked
- **Audit trails**: All activities are logged for forensic analysis

---

## 🐛 Troubleshooting

### AegisRay won't start - what should I check?

1. **Check logs**:
   ```bash
   # Docker logs
   docker logs aegisray-server
   
   # System logs
   journalctl -u aegisray -f
   
   # Application logs
   tail -f /var/log/aegisray/server.log
   ```

2. **Verify configuration**:
   ```bash
   # Test config syntax
   ./bin/server --config configs/server.yaml --check-config
   ```

3. **Check permissions**:
   ```bash
   # TUN interface requires privileges
   sudo setcap cap_net_admin+ep ./bin/server
   
   # Or run as root
   sudo ./bin/server --config configs/server.yaml
   ```

4. **Verify ports**:
   ```bash
   # Check if port is available
   netstat -tlnp | grep :443
   
   # Test connectivity
   telnet server-address 443
   ```

### No peers are connecting - how do I debug?

1. **Check network connectivity**:
   ```bash
   # Test basic connectivity
   ping peer-address
   telnet peer-address 443
   
   # Check STUN server connectivity
   stunclient stun.l.google.com 19302
   ```

2. **Verify certificates**:
   ```bash
   # Check certificate validity
   openssl x509 -in certs/server.crt -text -noout
   
   # Test TLS connection
   openssl s_client -connect server:443 -servername example.com
   ```

3. **Check configuration**:
   ```bash
   # Verify bootstrap peers are reachable
   curl -k https://bootstrap-peer:443
   
   # Check mesh status
   curl http://localhost:8080/status | jq .peers
   ```

### Performance is slow - how can I optimize?

1. **Check system resources**:
   ```bash
   # CPU and memory usage
   top -p $(pgrep aegisray)
   
   # Network usage
   iftop -i aegis0
   
   # Disk I/O
   iotop -p $(pgrep aegisray)
   ```

2. **Optimize configuration**:
   ```yaml
   # Performance tuning
   mesh:
     connection_pool_size: 100
     read_buffer_size: 65536
     write_buffer_size: 65536
   
   # Disable compression on fast networks
   compression:
     enabled: false
   ```

3. **System tuning**:
   ```bash
   # Increase network buffers
   echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
   echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
   sysctl -p
   
   # Increase file descriptor limits
   ulimit -n 65536
   ```

### TUN interface not working

1. **Check TUN support**:
   ```bash
   # Verify TUN module is loaded
   lsmod | grep tun
   
   # Load TUN module if needed
   sudo modprobe tun
   
   # Check /dev/net/tun exists
   ls -la /dev/net/tun
   ```

2. **Check permissions**:
   ```bash
   # Add user to required groups (Ubuntu/Debian)
   sudo usermod -a -G netdev $USER
   
   # Or run with capabilities
   sudo setcap cap_net_admin+ep ./bin/server
   ```

3. **Docker considerations**:
   ```yaml
   # Docker compose with TUN support
   services:
     aegisray:
       privileged: true
       cap_add:
         - NET_ADMIN
       devices:
         - /dev/net/tun
   ```

---

## 🔧 Advanced Configuration

### How do I set up exit nodes in different countries?

1. **Deploy servers in target countries**:
   ```yaml
   # Exit node configuration
   mesh:
     exit_node: true
     allowed_ips: ["0.0.0.0/0"]
     metadata:
       country: "US"
       city: "New York"
       provider: "AWS"
   ```

2. **Configure geographic routing**:
   ```yaml
   # Client-side routing preferences
   routing:
     exit_node_selection: "geographic"
     preferred_countries: ["US", "CA", "UK"]
     avoid_countries: ["CN", "RU"]
   ```

### How do I integrate AegisRay with existing infrastructure?

1. **Corporate network integration**:
   ```yaml
   # Route corporate subnets through mesh
   routes:
     - destination: "192.168.0.0/16"
       gateway: "mesh"
     - destination: "10.0.0.0/8" 
       gateway: "mesh"
   ```

2. **Load balancer integration**:
   ```yaml
   # HAProxy configuration
   backend aegisray_mesh
     balance roundrobin
     option tcp-check
     server mesh1 10.0.1.10:443 check
     server mesh2 10.0.1.11:443 check
   ```

### How do I monitor AegisRay in production?

1. **Prometheus metrics**:
   ```yaml
   # prometheus.yml
   scrape_configs:
     - job_name: 'aegisray'
       static_configs:
         - targets: ['node1:8080', 'node2:8080']
       metrics_path: '/metrics'
   ```

2. **Health checks**:
   ```bash
   # Simple health check script
   #!/bin/bash
   if ! curl -f http://localhost:8080/health; then
     echo "AegisRay unhealthy"
     systemctl restart aegisray
   fi
   ```

3. **Log monitoring**:
   ```yaml
   # Filebeat configuration
   filebeat.inputs:
   - type: log
     paths:
       - /var/log/aegisray/*.log
     fields:
       service: aegisray
   ```

---

## 📱 Mobile & SDK Questions

### How do I use AegisRay on mobile devices?

AegisRay provides a Flutter SDK for mobile integration:

1. **Add dependency**:
   ```yaml
   # pubspec.yaml
   dependencies:
     aegisray_flutter: ^1.0.0
   ```

2. **Initialize client**:
   ```dart
   final client = await AegisRayClient.create(
     nodeAddress: 'mesh.example.com',
     httpPort: 8080,
     grpcPort: 9090,
   );
   
   await client.connect();
   await client.joinNetwork('mobile-client-001', '0.0.0.0:0');
   ```

### Can I build custom applications with AegisRay?

Yes! AegisRay provides SDKs for integration:

1. **Go SDK** (native):
   ```go
   client, err := aegisray.NewClient(&aegisray.Config{
       NodeAddress: "mesh.example.com",
       HTTPPort:    8080,
       GRPCPort:    9090,
   })
   ```

2. **REST API** (any language):
   ```bash
   # Get network status
   curl http://localhost:8080/status
   
   # Add peer
   curl -X POST http://localhost:8080/api/peers \
        -d '{"address": "peer.example.com:443"}'
   ```

3. **gRPC API** (many languages):
   ```python
   # Python example
   import grpc
   from proto import mesh_pb2_grpc, mesh_pb2
   
   channel = grpc.insecure_channel('localhost:9090')
   stub = mesh_pb2_grpc.MeshServiceStub(channel)
   
   response = stub.DiscoverPeers(mesh_pb2.DiscoverPeersRequest())
   ```

---

## 🌐 Network Questions

### What is the mesh IP address range?
By default, AegisRay uses the `10.100.0.0/16` range for the mesh network. This provides:
- **65,534 possible nodes** in the mesh
- **Non-overlapping** with most corporate networks
- **RFC 1918 private space** (not routed on internet)

You can customize this range in the configuration:
```yaml
mesh_ip: "172.16.0.1/12"  # Use different private range
```

### How does routing work in the mesh?
AegisRay uses an intelligent routing system:

1. **Direct connections**: Peers connect directly when possible
2. **Relay routing**: Multi-hop routing through intermediate nodes
3. **Load balancing**: Traffic distributed across multiple paths
4. **Exit node selection**: Automatic selection of best exit node

### Can I use AegisRay for site-to-site connections?
Yes! Configure AegisRay for site-to-site VPN:

```yaml
# Site A configuration
routes:
  - destination: "192.168.2.0/24"  # Site B network
    gateway: "mesh"
    advertise: true

# Site B configuration  
routes:
  - destination: "192.168.1.0/24"  # Site A network
    gateway: "mesh"
    advertise: true
```

---

## 💰 Licensing & Commercial Use

### What is the license for AegisRay?
AegisRay is released under the MIT License, which allows:
- **Commercial use**: Use in commercial products and services
- **Modification**: Modify the source code as needed
- **Distribution**: Distribute original or modified versions
- **Private use**: Use privately without sharing changes

### Can I use AegisRay in my company?
Yes! The MIT license allows commercial use. Many companies use AegisRay for:
- **Remote access VPN**: Secure employee connectivity
- **Site-to-site connections**: Connecting office locations
- **Cloud networking**: Secure cloud infrastructure
- **IoT connectivity**: Secure device communications

### Do I need to contribute changes back?
No, the MIT license doesn't require you to contribute changes back, but we encourage contributions to help improve AegisRay for everyone.

---

## 🆘 Getting Help

### Where can I get support?
- **GitHub Issues**: [Report bugs or request features](https://github.com/surya-d-naidu/AegisRay/issues)
- **Discussions**: [Community discussions and questions](https://github.com/surya-d-naidu/AegisRay/discussions)
- **Documentation**: [Complete technical documentation](docs/)
- **Examples**: [Code examples and tutorials](examples/)

### How do I report security issues?
For security vulnerabilities, please email: security@aegisray.dev
- Use GPG encryption if possible (key available on GitHub)
- Include detailed reproduction steps
- We aim to respond within 24 hours

### How can I contribute to AegisRay?
We welcome contributions!

1. **Code contributions**: Bug fixes, features, optimizations
2. **Documentation**: Tutorials, guides, API docs
3. **Testing**: Platform testing, performance benchmarks
4. **Translation**: Internationalization support
5. **Community**: Helping other users, writing blog posts

---

## 📈 Roadmap & Future Features

### What's planned for future releases?
- **WebRTC integration**: Browser-based mesh nodes
- **Quantum-resistant crypto**: Post-quantum cryptography
- **Enhanced mobile support**: Native iOS/Android apps
- **GUI management interface**: Web-based configuration
- **Enterprise features**: LDAP integration, advanced monitoring
- **Performance optimizations**: Multi-threading, hardware acceleration

### When will [specific feature] be available?
Check our [roadmap](ROADMAP.md) for planned features and timelines. Feature requests and contributions are welcome!

### Is there a commercial version?
AegisRay is open source and free. For enterprise support, custom development, or consulting services, contact us through GitHub discussions.

---

**Still have questions? Check our [GitHub Discussions](https://github.com/surya-d-naidu/AegisRay/discussions) or [open an issue](https://github.com/surya-d-naidu/AegisRay/issues)!**
