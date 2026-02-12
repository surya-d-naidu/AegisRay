# 🔐 AegisRay Security Model

AegisRay adopts a **Zero-Trust** security philosophy. Every packet, peer, and route must be authenticated and authorized.

## 🆔 Identity System

*   **Node ID**: An AegisRay Node ID is not random; it is cryptographically bound to the Identity Key.
    ```go
    NodeID = SHA256(RSA_2048_PublicKey_Bytes).Hex().Substring(0, 32)
    ```
*   **Verification**: When a peer connects, it sends its Public Key. The receiver calculates the hash. If `Hash(Key) != Claimed_ID`, the connection is immediately rejected. This prevents identity spoofing.

## 🤝 The Aegis Handshake

The handshake establishes trust and a session key between two nodes. It occurs over an initial gRPC channel (potentially insecure or TLS-self-signed).

### 1. JOIN Request (Initiator -> Responder)
*   **Payload**: `NodeID`, `MeshIP`, `Timestamp`, `Nonce`.
*   **Signature**: The Initiator signs `SHA256(Payload)` with their **Private Key**.
*   **Action**: Responder verifies signature against Initiator's ID/Public Key.

### 2. JOIN Response (Responder -> Initiator)
*   **Payload**: `Responder_NodeID`, `Status: ACCEPT`.
*   **Signature**: Responder signs the response.
*   **Action**: Initiator verifies Responder's signature.


## 🚧 Threat Model & Mitigations

| Threat | Mitigation |
| :--- | :--- |
| **Spoofing** | ID-Key Binding checks prevent impersonation. |
| **Man-in-the-Middle** | Handshake Signatures ensure you are talking to the key owner. |
| **Replay Attacks** | GCM Nonces and Timestamp checks in Handshake. |
| **Route Injection** | Route Advertisements are signed. Spoofed routes fail sig check. |
| **Traffic Analysis** | **SNI Masquerading** wraps traffic in HTTPS, making it look like web browsing. |
