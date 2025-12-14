# AegisRay Architecture Overview

This document provides a comprehensive overview of the AegisRay P2P mesh VPN architecture, including system components, data flow, and design decisions.

## 📋 Table of Contents

- [System Architecture](#system-architecture)
- [Core Components](#core-components)
- [Network Topology](#network-topology)
- [Data Flow](#data-flow)
- [Security Model](#security-model)
- [Protocol Details](#protocol-details)
- [Performance Characteristics](#performance-characteristics)

## 🏗️ System Architecture

AegisRay is built as a **distributed peer-to-peer mesh VPN** with no central points of failure. The architecture consists of several key layers:

```
┌─────────────────────── AegisRay Architecture ───────────────────────┐
│                                                                     │
│  ┌─── Application Layer ───┐  ┌─── Management Layer ───┐            │
│  │  • Flutter Mobile App   │  │  • HTTP REST API       │            │
│  │  • Desktop Client       │  │  • Web Dashboard       │            │
│  │  • CLI Tools            │  │  • Monitoring          │            │
│  └─────────────────────────┘  └─────────────────────────┘            │
│                                                                     │
│  ┌─────────────────── P2P Mesh Network Layer ──────────────────────┐ │
│  │                                                                 │ │
│  │  ┌─── Mesh Router ───┐  ┌── P2P Discovery ──┐  ┌── Packet ───┐ │ │
│  │  │  • Route Mgmt     │  │  • Gossip Proto   │  │  Forwarder  │ │ │
│  │  │  • Path Finding   │  │  • Peer Bootstrap │  │  • TUN Mgmt │ │ │
│  │  │  • Load Balance   │  │  • NAT Traversal  │  │  • Traffic  │ │ │
│  │  └───────────────────┘  └───────────────────┘  └─────────────┘ │ │
│  │                                                                 │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌─────────────── Network Transport Layer ───────────────────┐      │
│  │                                                           │      │
│  │  ┌─ gRPC/TLS ─┐  ┌─ SNI Masq ─┐  ┌─ Connection ─┐       │      │
│  │  │ • Auth     │  │ • DPI Evas │  │ • TCP/UDP   │       │      │
│  │  │ • Compress │  │ • Domain   │  │ • QUIC      │       │      │
│  │  │ • Encrypt  │  │   Fronting │  │ • Failover  │       │      │
│  │  └────────────┘  └────────────┘  └─────────────┘       │      │
│  └─────────────────────────────────────────────────────────┘      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Design Principles

**1. Decentralization** 🌐
- No central coordinators required for mesh operation
- Peer discovery through gossip protocol
- Fault tolerance through redundant paths

**2. Security by Default** 🔒
- End-to-end encryption for all traffic
- Perfect Forward Secrecy (PFS)
- SNI masquerading for stealth operations

**3. Performance** ⚡
- Multi-path routing for load balancing
- Adaptive quality-of-service (QoS)
- Zero-copy packet processing where possible

**4. Simplicity** 🎯
- Single binary deployment
- Configuration-driven setup
- RESTful API for integration

## 🧩 Core Components

### 1. Mesh Node (`internal/mesh/node.go`)

The heart of AegisRay, managing mesh network participation.

```go
type MeshNode struct {
    NodeID        string
    MeshIP        net.IP           // Assigned mesh IP (e.g., 100.64.1.42)
    ListenAddr    string           // Public listen address
    
    // Core Services
    P2PDiscovery  *P2PDiscovery    // Peer discovery service
    Router        *MeshRouter      // Routing engine
    Forwarder     *PacketForwarder // Packet forwarding
    TunInterface  *TunInterface    // Network interface
    HTTPServer    *HTTPServer      // Management API
    
    // Connection Management  
    peers         map[string]*Peer // Active peer connections
    peerLock      sync.RWMutex     // Thread safety
}
```

**Responsibilities:**
- Coordinate all mesh services
- Manage peer lifecycle
- Handle graceful shutdown
- Provide unified configuration

### 2. P2P Discovery (`internal/mesh/p2p_discovery.go`)

Implements distributed peer discovery using gossip protocol.

```go
type P2PDiscovery struct {
    node           *MeshNode
    staticPeers    []string        // Bootstrap peers
    knownPeers     map[string]*PeerInfo
    gossipInterval time.Duration   // Peer advertisement frequency
    
    // NAT Traversal
    stunServers    []string        // STUN servers for NAT discovery
    turnServers    []string        // TURN relays for tough NATs
}
```

**Key Features:**
- **Gossip Protocol**: Peers share knowledge about other peers
- **Bootstrap Process**: Static peers help new nodes join
- **NAT Traversal**: STUN/TURN for firewall penetration
- **Adaptive Discovery**: Frequency adjusts based on network stability

**Discovery Process:**
```
1. New Node Joins    2. Bootstrap Connect    3. Gossip Exchange    4. Peer Connect
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  📱 New Node    │ │  🎯 Bootstrap   │ │  🗣️ Gossip      │ │  🤝 Direct      │
│                 │ │                 │ │                 │ │                 │
│ "I want to join │→│ "Here are 5     │→│ "I know 10      │→│ "Let's connect  │
│  the mesh!"     │ │  other peers"   │ │  more peers"    │ │  directly"      │
└─────────────────┘ └─────────────────┘ └─────────────────┘ └─────────────────┘
```

### 3. Mesh Router (`internal/mesh/router.go`)

Handles intelligent routing and path selection across the mesh.

```go
type MeshRouter struct {
    node        *MeshNode
    routeTable  map[string]*Route    // Destination -> Route mapping
    pathMetrics map[string]*Metrics  // Path performance data
    
    // Route Advertisement
    advInterval time.Duration        // How often to advertise routes
    advTicker   *time.Ticker        // Advertisement scheduler
}

type Route struct {
    Destination string      // Target mesh IP or subnet
    NextHop     string      // Next peer in path
    Cost        int         // Route cost metric
    Latency     time.Duration // Average latency
    Bandwidth   uint64      // Available bandwidth
    Reliability float64     // Success rate (0.0-1.0)
}
```

**Routing Algorithm:**
- **Distance Vector**: Similar to RIP but with modern enhancements
- **Multi-Metric**: Considers latency, bandwidth, and reliability
- **Load Balancing**: Distributes traffic across equivalent paths
- **Congestion Avoidance**: Adapts to network conditions

### 4. Packet Forwarder (`internal/mesh/packet_forwarder.go`)

Responsible for intercepting and routing IP traffic through the mesh.

```go
type PacketForwarder struct {
    node        *MeshNode
    tunIface    *TunInterface       // Network interface
    meshService tunnel.MeshServiceClient // gRPC client
    
    // Traffic Statistics
    stats       *TrafficStats
    statsLock   sync.RWMutex
}

type TrafficStats struct {
    PacketsSent     uint64
    PacketsReceived uint64
    BytesSent       uint64
    BytesReceived   uint64
    PacketsDropped  uint64
}
```

**Packet Processing Pipeline:**
```
┌── Incoming Packet ──┐    ┌─── Route Lookup ───┐    ┌─── Forward ────┐
│                     │    │                    │    │                │
│  📦 IP Packet       │ →  │  🔍 Find best      │ →  │  📡 Send via   │
│  Src: 192.168.1.10  │    │     path to dest   │    │     gRPC       │
│  Dst: 8.8.8.8       │    │     (Google DNS)   │    │                │
└─────────────────────┘    └────────────────────┘    └────────────────┘
```

### 5. TUN Interface Manager (`internal/mesh/tun_interface.go`)

Creates and manages the virtual network interface for the mesh.

```go
type TunInterface struct {
    name       string           // Interface name (e.g., "aegis0")
    device     *water.Interface // TUN device handle
    meshIP     net.IP          // Assigned mesh IP
    mtu        int             // Maximum transmission unit
    routes     []Route         // Interface routes
}
```

**Interface Configuration:**
```bash
# Example TUN interface setup
Interface: aegis0
IP Address: 100.64.1.42/16
MTU: 1420
Routes:
  - 100.64.0.0/16 dev aegis0    # Mesh network routes
  - 0.0.0.0/0 dev aegis0        # Default route (if exit node)
```

### 6. HTTP API Server (`internal/mesh/http_server.go`)

Provides RESTful API for monitoring and management.

```go
type HTTPServer struct {
    node       *MeshNode
    server     *http.Server
    router     *mux.Router    // HTTP request router
}

// API Endpoints
type APIEndpoints struct {
    Health     string  // GET  /health
    Status     string  // GET  /status  
    Peers      string  // GET  /peers
    AddPeer    string  // POST /api/peers
    RemovePeer string  // DELETE /api/peers/{id}
    Config     string  // GET/PUT /api/config
    Stats      string  // GET /api/stats
}
```

## 🌐 Network Topology

### Mesh Formation Process

**Phase 1: Bootstrap** ⚡
```
New Node (A)          Static Peer (B)
     │                        │
     │ ───── Connect ────────→ │
     │ ←──── Accept ────────── │
     │                        │
     │ ──── Handshake ──────→ │  
     │ ←── Certificate ────── │
     │                        │  
     │ ──── Join Request ───→ │
     │ ←── Peer List ──────── │
```

**Phase 2: Gossip** 🗣️
```
Node A                Node B                Node C
  │                     │                     │
  │ ── "I know C" ───→  │                     │
  │ ←─ "I know D" ────  │                     │
  │                     │ ─── "I know A" ──→ │
  │                     │ ←── "I know E" ──  │
  │                     │                     │
  │ ──────────── Direct Connect ────────────→ │
```

**Phase 3: Convergence** ⚖️
```
     Final Mesh Topology
        
    A ←─────→ B ←─────→ C
    │         │         │
    │         │         │
    ↓         ↓         ↓
    D ←─────→ E ←─────→ F
    
• All nodes know about all other nodes
• Multiple paths exist between any two nodes  
• Network is resilient to node failures
```

### Node Types & Roles

**Client Nodes** 📱
- Connect to mesh for internet access
- Typically behind NAT (homes, offices, mobile)
- Use exit nodes for external connectivity

**Exit Nodes** 🌍  
- Provide internet gateway for mesh clients
- Usually have public IP addresses
- Act as VPN exit points in different regions

**Relay Nodes** 🔄
- Forward traffic between other nodes
- Help with NAT traversal and connectivity
- Don't necessarily provide internet access

**Coordinator Nodes** 🎯 (Optional)
- Help bootstrap large networks
- Provide seed peer lists
- Not required for mesh operation

## 🔄 Data Flow

### Client Internet Access

```
┌─── Client App ───┐    ┌─── AegisRay ───┐    ┌─── Mesh ───┐    ┌─── Internet ───┐
│                  │    │                │    │             │    │                │
│  curl google.com │ →  │  TUN Interface │ →  │ Route via   │ →  │  google.com    │
│                  │    │  (aegis0)      │    │ Exit Node   │    │  responds      │
│                  │ ←  │                │ ←  │             │ ←  │                │
└──────────────────┘    └────────────────┘    └─────────────┘    └────────────────┘
```

**Detailed Flow:**

1. **Application Request**: App makes HTTP request to google.com
2. **OS Routing**: OS routes via TUN interface (aegis0) 
3. **Packet Capture**: AegisRay captures packet on TUN interface
4. **Route Decision**: Mesh router selects best exit node path
5. **Mesh Forwarding**: Packet forwarded through mesh to exit node
6. **Internet Access**: Exit node forwards to actual google.com
7. **Response Path**: Reply follows reverse path back to client

### Mesh-to-Mesh Communication

```
┌─ Node A (Client) ─┐    ┌─ Node B (Relay) ─┐    ┌─ Node C (Exit) ─┐
│                   │    │                  │    │                 │
│  Send to 8.8.8.8  │ →  │  Forward packet  │ →  │  Route to       │
│  via mesh         │    │  based on route  │    │  internet       │
│                   │ ←  │  table           │ ←  │  gateway        │
└───────────────────┘    └──────────────────┘    └─────────────────┘
```

### gRPC Service Communication

AegisRay uses gRPC for inter-node communication:

```protobuf
// proto/tunnel/tunnel.proto
service MeshService {
    rpc ForwardPacket(PacketRequest) returns (PacketResponse);
    rpc AdvertiseRoute(RouteAdvertisement) returns (Empty);
    rpc DiscoverPeers(PeerDiscoveryRequest) returns (PeerDiscoveryResponse);
    rpc Handshake(HandshakeRequest) returns (HandshakeResponse);
}
```

## 🔒 Security Model

### Encryption Layers

**Layer 1: TLS Transport** 🚛
- TLS 1.3 for all peer-to-peer connections
- Certificate-based authentication
- Perfect Forward Secrecy (PFS)

**Layer 2: Application Encryption** 🔐
- ChaCha20-Poly1305 for packet encryption
- Separate keys per peer connection
- Key rotation based on data volume/time

**Layer 3: SNI Masquerading** 🎭
- Hides real destination from DPI systems
- Mimics connections to legitimate domains
- Configurable domain fronting

### Certificate Management

```go
// internal/certs/certs.go
type CertManager struct {
    caCert     *x509.Certificate    // Root CA certificate
    caKey      *rsa.PrivateKey     // CA private key
    nodeCert   *x509.Certificate   // Node certificate
    nodeKey    *rsa.PrivateKey     // Node private key
}
```

**Certificate Hierarchy:**
```
┌─── Root CA ───┐
│  AegisRay CA  │ (Self-signed, long-lived)
└───────────────┘
        │ signs
        ↓
┌─── Node Cert ──┐
│   node-12345   │ (Client cert, medium-lived)
└────────────────┘
        │ presents
        ↓
┌─── Peer Auth ──┐
│   TLS Handshake│ (Per-connection, ephemeral)
└────────────────┘
```

### Traffic Analysis Resistance

**Timing Obfuscation** ⏰
- Random padding on packets
- Configurable delay jitter
- Traffic shaping patterns

**Volume Obfuscation** 📊  
- Dummy traffic generation
- Packet size normalization
- Burst pattern randomization

**Domain Fronting** 🎭
```yaml
# Configuration example
stealth:
  enabled: true
  domains:
    - "cloudflare.com"     # CDN with many services
    - "fastly.com"         # Popular CDN
    - "googleapis.com"     # Google APIs
  rotation_interval: "1h"  # Change domain every hour
```

## 📡 Protocol Details

### Peer Discovery Protocol

Uses a gossip-based approach for scalable peer discovery:

```
DISCOVER_PEERS Message:
┌─────────────────────┐
│ Type: DISCOVER      │
│ Node ID: abc123     │  
│ Known Peers: [      │
│   {id: def456,      │
│    addr: 1.2.3.4}   │
│   {id: ghi789,      │
│    addr: 5.6.7.8}   │
│ ]                   │
│ Timestamp: 12345    │
│ Signature: xyz...   │
└─────────────────────┘
```

### Route Advertisement

Nodes periodically advertise reachable destinations:

```
ROUTE_ADVERTISEMENT Message:
┌─────────────────────┐
│ Type: ROUTE_ADV     │
│ From: Node abc123   │
│ Routes: [           │
│   {dest: 0.0.0.0/0, │ ← "I can reach internet"
│    cost: 100,       │
│    bandwidth: 50M}  │
│   {dest: 10.0.0.0/8,│ ← "I can reach corporate"  
│    cost: 50}        │
│ ]                   │
│ TTL: 300s          │
└─────────────────────┘
```

### Packet Forwarding

Encapsulates IP packets for mesh transport:

```
PACKET_FORWARD Message:
┌─────────────────────┐
│ Type: PACKET        │
│ From: abc123        │
│ To: def456          │
│ Payload: [          │
│   Original IP Pkt   │ ← User's actual packet
│   Encrypted         │
│ ]                   │
│ Sequence: 12345     │
│ Checksum: xyz...    │
└─────────────────────┘
```

## ⚡ Performance Characteristics

### Latency Analysis

**Mesh Overhead Components:**
- Encryption/Decryption: ~0.1ms (ChaCha20)
- Route Lookup: ~0.01ms (hash table)
- gRPC Serialization: ~0.05ms
- Network Transit: Variable (depends on path)

**Total Typical Overhead: ~0.2ms**

### Throughput Optimization

**Zero-Copy Path** (Linux):
```go
// Optimized packet forwarding
func (pf *PacketForwarder) forwardFast(packet []byte) {
    // Skip copying for same-node routing  
    if isLocalDestination(packet) {
        injectIntoTun(packet) // Direct TUN injection
        return
    }
    
    // Minimize allocations for remote forwarding
    sendViaGRPC(packet) // Uses packet buffer pool
}
```

**Batch Processing**:
- Process multiple packets per syscall
- Vectorized encryption operations  
- Concurrent gRPC streams per peer

### Scalability Metrics

| Metric | Single Node | 10-Node Mesh | 100-Node Mesh |
|--------|------------|---------------|----------------|
| **Memory Usage** | 50MB | 75MB | 200MB |
| **CPU (idle)** | 1% | 2% | 5% |
| **CPU (active)** | 10% | 15% | 30% |
| **Connections** | 3-5 peers | 5-8 peers | 8-12 peers |
| **Routing Table** | 10 routes | 50 routes | 500 routes |

**Design Limits:**
- **Max Peers per Node**: 50 (configurable)
- **Max Mesh Size**: 1000 nodes (theoretical)
- **Route Table Size**: 10,000 entries
- **Packet Buffer Pool**: 10,000 packets

## 🔮 Advanced Features

### Quality of Service (QoS)

```go
// Traffic prioritization
type QoSPolicy struct {
    HighPriority   []string // DNS, SSH, real-time protocols
    MediumPriority []string // HTTP, HTTPS
    LowPriority    []string // BitTorrent, bulk transfers
    
    BandwidthLimits map[string]uint64 // Per-protocol limits
}
```

### Network Segmentation

```yaml
# Multi-tenant configuration
networks:
  - name: "corporate"
    cidr: "100.64.0.0/16"
    access_control: "strict"
    
  - name: "guest" 
    cidr: "100.65.0.0/16"
    access_control: "internet_only"
    
  - name: "iot"
    cidr: "100.66.0.0/16" 
    access_control: "local_only"
```

### Adaptive Routing

```go
// Route selection considers multiple factors
type PathMetrics struct {
    Latency     time.Duration // RTT measurement
    Bandwidth   uint64        // Available throughput  
    Reliability float64       // Success rate (0.0-1.0)
    Cost        int           // Hop count or monetary cost
    Congestion  float64       // Current load (0.0-1.0)
}

func (r *MeshRouter) selectBestPath(dest string) *Route {
    candidates := r.getRoutesTo(dest)
    
    // Weighted scoring algorithm
    for _, route := range candidates {
        score := calculateRouteScore(route.Metrics)
        if score > bestScore {
            bestRoute = route
            bestScore = score
        }
    }
    
    return bestRoute
}
```

---

This architecture provides a robust foundation for secure, scalable P2P mesh networking while maintaining simplicity and performance. The modular design allows for easy extension and customization based on specific deployment needs.
