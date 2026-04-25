# AegisRay Technical Specification

## 1. System Overview

AegisRay is a peer-to-peer mesh VPN focused on zero-trust admission, encrypted multi-hop transport, and stealth-oriented session establishment.

The current design uses:

- gRPC for peer RPCs
- mutual TLS with self-signed Ed25519 certificates bound to node identity
- signed peer admission policy
- X25519 for peer session agreement
- XChaCha20-Poly1305 for per-peer payload encryption
- SNI masquerading on outbound TLS handshakes as part of the stealth layer

## 2. Protocol Design

### 2.1 Node Identity

- **Identity Key**: Ed25519
- **Node ID**: first 16 bytes of `SHA-256(public_key)` encoded as hex
- **Transport Binding**: the TLS certificate public key must match the node identity public key

### 2.2 Admission Model

Production nodes fail closed unless one of these authorization sources is configured:

- `trust_root_public_key_file` plus `authorized_peers_file`
- `authorized_peer_keys`

`allow_unauthenticated_peers: true` is supported only for isolated test/lab environments.

### 2.3 Handshake Flow

1. **Join Request**
   The initiator sends `JoinRequest` over gRPC with node identity, mesh IP, network name, timestamp, and connection metadata.
2. **Transport Verification**
   The responder validates the presented TLS certificate and checks that it matches the claimed node identity.
3. **Authorization**
   The responder checks the peer against the configured trust policy.
4. **Join Response**
   The responder returns peer and network information, signed with its Ed25519 identity key.
5. **Per-Peer Key Exchange**
   Peers exchange signed X25519 ephemeral keys and derive a shared session key.

### 2.4 gRPC Surface

The active gRPC RPCs are:

- `JoinNetwork`
- `LeaveNetwork`
- `Heartbeat`
- `DiscoverPeers`
- `RequestIntroduction`
- `SendPacket`
- `AdvertiseRoutes`
- `RequestRoutes`
- `InitiateHolePunch`
- `ExchangeConnectionInfo`

### 2.5 Data Plane

- **Active Path**: `SendPacket`
- **Packet Envelope**:
  - `SourceID`
  - `DestID`
  - `PacketType`
  - `Payload`
  - `Metadata`

The router decrements TTL, tracks path metadata, and forwards packets to the next hop using gRPC.

### 2.6 Stealth Layer

When `use_tls: true` and `stealth_mode: true` are enabled:

- outbound peer dials use TLS
- the TLS `ServerName` is chosen from `stealth_domains`
- the handshake therefore resembles a common HTTPS destination such as `cloudflare.com` or `google.com`

This is a stealth layer for connection setup, not a guarantee of invisibility. Traffic timing, packet size, destination patterns, and operational mistakes can still reveal the tunnel.

## 3. Architecture Components

### 3.1 Mesh Node

`internal/mesh/node.go`

Responsibilities:

- load identity and trust policy
- start gRPC, HTTP, routing, discovery, NAT traversal, and TUN services
- enforce peer authorization
- process control and data packets

### 3.2 P2P Discovery

`internal/mesh/p2p_discovery.go`

Responsibilities:

- connect to static peers
- discover peers via gossip
- pin TLS transport identities
- maintain heartbeats and reconnection state
- apply SNI masquerading on outbound TLS dials

### 3.3 Mesh Router

`internal/mesh/router.go`

Responsibilities:

- maintain routes
- apply split-horizon route advertisement logic
- forward packets between peers
- verify signed route advertisements

### 3.4 Crypto Manager

`internal/crypto/encryption.go`

Responsibilities:

- Ed25519 signing and verification
- X25519 shared-secret derivation
- XChaCha20-Poly1305 encryption/decryption
- identity key persistence helpers

### 3.5 Certificate Manager

`internal/certs/certs.go`

Responsibilities:

- issue/load self-signed Ed25519 certificates
- ensure certificate public key matches node identity
- validate peer certificates during TLS setup

## 4. Security Considerations

- **Replay Control**: join requests carry timestamps and are rejected outside a bounded window.
- **Peer Spoofing Defense**: established RPCs are bound to the caller's TLS identity, not just caller-supplied node IDs.
- **Route Injection Defense**: route advertisements are signed.
- **Trust Distribution**: signed peer bundles reduce the risk of ad hoc peer admission drift.
- **Stealth Boundary**: SNI masquerading helps reduce protocol fingerprinting during TLS setup but is not sufficient on its own against sophisticated observers.

## 5. Current Gaps

- Full production confidence still requires live validation of NAT traversal, exit-node routing, throughput, and recovery.
- Trust bundle distribution and reload behavior still need operational discipline in deployment.
