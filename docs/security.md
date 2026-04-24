# 🔐 AegisRay Security Model

AegisRay adopts a **Zero-Trust** security philosophy. Every packet, peer, and route must be authenticated and authorized.

## 🆔 Identity System

*   **Node ID**: An AegisRay Node ID is not random; it is cryptographically bound to the Identity Key.
    ```go
    NodeID = SHA256(Ed25519_PublicKey_Bytes).Hex().Substring(0, 32)
    ```
*   **Verification**: When a peer connects, it sends its Public Key. The receiver calculates the hash. If `Hash(Key) != Claimed_ID`, the connection is immediately rejected. This prevents identity spoofing.
*   **Transport Binding**: The same Ed25519 identity key is reused for the node's self-signed TLS certificate, so the transport certificate and mesh identity are cryptographically tied together.

## 🤝 The Aegis Handshake

The handshake establishes trust and a session key between two nodes over gRPC with mutual TLS.

### 1. JOIN Request (Initiator -> Responder)
*   **Payload**: `NodeID`, `MeshIP`, `NetworkName`, `Timestamp`, and connection metadata.
*   **Signature**: The initiator signs the request with its Ed25519 identity key.
*   **Action**: The responder verifies the request signature and checks that the presented TLS certificate contains the same public key as the claimed mesh identity.

### 2. JOIN Response (Responder -> Initiator)
*   **Payload**: `Responder_NodeID`, `Status: ACCEPT`.
*   **Signature**: Responder signs the response.
*   **Action**: Initiator verifies the response signature and the responder's TLS transport binding.

### 3. Admission Control
*   **Production Default**: A node must be authorized by one of:
    *   a signed peer bundle referenced by `trust_root_public_key_file` and `authorized_peers_file`
    *   direct public keys in `authorized_peer_keys`
*   **Lab Override**: `allow_unauthenticated_peers: true` exists only for local testing and bypasses zero-trust admission.

### 4. Session Keys
*   Peers derive shared secrets with X25519.
*   Payload encryption uses XChaCha20-Poly1305 on a per-peer basis.


## 🚧 Threat Model & Mitigations

| Threat | Mitigation |
| :--- | :--- |
| **Spoofing** | ID-Key binding and TLS transport binding prevent impersonation. |
| **Man-in-the-Middle** | Mutual TLS plus signed handshake messages ensure the remote peer owns the claimed identity key. |
| **Replay Attacks** | Timestamp checks in the join flow and per-packet AEAD nonces reduce replay risk. |
| **Route Injection** | Route Advertisements are signed. Spoofed routes fail sig check. |
| **Traffic Analysis** | **SNI masquerading** makes the TLS handshake resemble common HTTPS destinations. It improves stealth, but it does not eliminate all traffic fingerprinting. |
