# 🏗️ AegisRay Architecture

AegisRay is designed as a decentralized, self-organizing mesh network. It operates primarily at Layer 3 (IP) with a custom P2P overlay at Layer 2.5 (Mesh).

## 🧩 System Components

### 1. MeshNode (`internal/mesh/node.go`)
The central coordinator of the system.
*   **Responsibilities**:
    *   Identity Management (Start/Stop, key loading).
    *   Service Lifecycle (Orchestrates Sub-modules).
    *   gRPC Server (Handles incoming Peer communication).
    *   Traffic Dispatch (Routes packets between TUN interface and Mesh).

### 2. MeshRouter (`internal/mesh/router.go`)
Implements the routing logic for the mesh.
*   **Routing Algorithm**: Distance-vector style routing with enhancements.
    *   **Metric**: Hop count.
    *   **Loop Prevention**: **Split Horizon**. A node never advertises a route back to the peer it learned it from.
    *   **Transitive Routing**: Supports forwarding. If A connects to B, and B to C, A learns the path to C via B.
*   **Route Advertisement**:
    *   Periodic broadcasts (every 30s) of the routing table to connected peers.
    *   **Authenticated**: Advertisements are signed to prevent injection.

### 3. P2P Discovery (`internal/mesh/p2p_discovery.go`)
Manages peer finding and lifecycle.
*   **Discovery Mechanisms**:
    *   **Static**: Connects to hardcoded peers in config.
    *   **Gossip**: Asks connected peers for *their* peer lists (`DiscoverPeers` RPC).
    *   **Passive**: Learns about peers from incoming Join Requests.
*   **Health Checks**:
    *   Sends periodic Heartbeats (every 10s).
    *   Updates `LastSeen` timestamps.
    *   Triggers "Stale" state after 5 minutes of silence.

### 4. NAT Traversal (`internal/mesh/nat_traversal.go`)
Ensures connectivity across hostile network boundaries.
*   **STUN**: Resolves own Public IP/Port using Google/Cloudflare STUN servers.
*   **Techniques**:
    *   **Direct**: Tries connecting to the public IP directly.
    *   **UDP Hole Punching**: Sends simultaneous packet bursts ("AEGIS_HOLE_PUNCH") to open pinholes in stateful firewalls.
    *   **Relay (TURN)**: (Placeholder) Fallback mechanism for symmetric NATs.

### 5. Crypto Manager (`internal/crypto/encryption.go`)
Handles all security operations.
*   **Algorithms**:
    *   **Identity**: RSA-2048.
    *   **Signatures**: RSA-SHA256 (PKCS#1 v1.5).
    *   **Symmetric**: AES-256-GCM.
*   **Session Management**:
    *   Maintains a `map[peerID]cipher.AEAD`.
    *   Ensures isolation; compromising one session key does not affect others.

---

## 🔄 Packet Flow

### Outbound Traffic (Local -> Mesh)
1.  **TUN Interface**: Reads IP packet from OS kernel.
2.  **Lookup**: `MeshNode` checks Routing Table for destination IP.
3.  **Encryption**: `EncryptionManager` encrypts payload using the Next-Hop Peer's Session Key.
4.  **Encap**: Wraps encrypted payload in a `MeshPacket` (ProtoBuf).
5.  **Transport**: Sends via gRPC `StreamPackets` to the peer.

### Inbound Traffic (Mesh -> Local)
1.  **Receive**: `MeshNode` receives `MeshPacket` via gRPC.
2.  **Decryption**: Uses Sender's Session Key to decrypt payload.
3.  **Validation**: Checks if packet is destined for *this* node.
    *   *If Yes*: Write to **TUN Interface**.
    *   *If No*: Pass to **MeshRouter** for forwarding.

### Forwarding (Mesh -> Mesh)
1.  **Router**: Decrements TTL. Discards if TTL=0.
2.  **Next Hop**: Looks up new Next-Hop for the destination.
3.  **Re-Encryption**: (Note: Current implementation is hop-by-hop) Packet is re-encrypted for the next hop.
4.  **Send**: Forwards to the next peer.
