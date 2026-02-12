# AegisRay Technical Specification

## 1. System Overview
AegisRay is a peer-to-peer mesh VPN designed for stealth and censorship resistance. It operates by creating a virtual overlay network where every node acts as both a client and a router.

## 2. Protocol Design

### 2.1 Node Identity
- **Crypto**: RSA-2048 for long-term identity.
- **Node ID**: SHA-256 hash of the RSA public key (first 16 bytes encoded as hex).
- **Verification**: All handshake messages are signed with the RSA private key.

### 2.2 Handshake Protocol (Zero-Trust)
1.  **Join Request**: Initiator sends `JoinRequest` containing:
    - NodeID, Public Key, Mesh IP, Timestamp.
    - `Signature`: Sign(NodeID + MeshIP + NetworkName + Timestamp).
2.  **Verification**: Receiver verifies the signature against the provided Public Key and checks that NodeID matches `Hash(PublicKey)`.
3.  **Response**: Receiver sends `JoinResponse` with:
    - Assigned IP (if applicable), Peer List.
    - `Signature` of the response.
4.  **Key Exchange**:
    - Initiator generates a random 32-byte AES-256 session key.
    - Encrypts key with Receiver's RSA Public Key.
    - Signs the encrypted blob.

- **MeshPacket**:
    - `SourceID` (string)
    - `DestID` (string)
    - `PacketType` (Data, Control, Heartbeat, KeyExchange)
    - `Payload` (Encrypted bytes for Data packets)
    - `Metadata` (Optional routing info)

### 2.4 Transport
- **gRPC**: Used for control plane (Join, Discovery, Heartbeat) and currently for data plane encapsulation.
- **Stealth**: Uses SNI Masquerading (fake TLS ServerName) to look like harmless HTTPS to `google.com` or `cloudflare.com` during connection establishment.

## 3. Architecture Components

### 3.1 Mesh Node (`internal/mesh/node.go`)
The central coordinator that manages:
- **Peers**: Map of connected nodes.
- **Router**: Logic to forward packets to the correct peer.
- **Encryption**: Manages keys and crypto operations.
- **TUN Interface**: Reads/Writes IP packets from the OS.

### 3.2 P2P Discovery (`internal/mesh/p2p_discovery.go`)
- Maintains connections to peers.
- Handles "Gossip" peer discovery (asking peers for their peers).
- Manages static peer connections.
- Handles reconnection and health checks.

### 3.3 Packet Forwarder (`internal/mesh/packet_forwarder.go`)
- Bridges the TUN interface and the Mesh network.
- Parses IP headers to determine destination Mesh IP.

## 4. Security Considerations
- **Key Rotation**: Session keys are rotated every hour.
- **Replay Protection**: Timestamps in handshakes (needs strict clock sync or window).
- **Forward Secrecy**: Yes, due to frequent session key rotation (though RSA transport of keys is vulnerable if RSA key is compromised retrospectively; Diffie-Hellman would be better).

## 5. Future Improvements
- **Transport**: Switch to UDP/QUIC for better performance (TCP-over-TCP is problematic).
- **Crypto**: Upgrade to Ed25519 for identity and X25519 for key exchange (smaller, faster, safer).
- **Routing**: Implement a real routing protocol (e.g., localized Babel or similar) instead of static/gossip routing.
