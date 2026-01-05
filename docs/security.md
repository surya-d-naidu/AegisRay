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

### 3. Key Exchange (Initiator -> Responder)
*   **Generation**: Initiator generates a random 32-byte **AES-256** key (`SessionKey`).
*   **Encryption**: `EncryptedKey = RSA_Encrypt(Responder_PublicKey, SessionKey)`.
*   **Signature**: `KeySig = RSA_Sign(Initiator_PrivateKey, EncryptedKey)`.
*   **Transmission**: Sends `[KeySig] + [EncryptedKey]`.
*   **Action**: Responder:
    1.  Verifies `KeySig` using Initiator's Public Key.
    2.  Decrypts `EncryptedKey` using its Private Key.
    3.  Installs `SessionKey` for this peer.

## 🛡️ Traffic Encryption

All data traffic (and routing control traffic) is encrypted using **AES-256-GCM**.

*   **Mode**: Galois/Counter Mode (GCM).
*   **Properties**: Authenticated Encryption with Associated Data (AEAD). Provides both confidentiality and integrity.
*   **Nonce**: Unique per-packet nonce.
*   **Scope**: Keys are **Per-Peer**.
    *   Node A uses `Key_AB` to talk to Node B.
    *   Node A uses `Key_AC` to talk to Node C.
    *   If `Key_AB` is compromised, Traffic to C remains secure.

## 🔄 Perfect Forward Secrecy (PFS)

*   **Mechanism**: Periodic Key Rotation.
*   **Interval**: Every **1 Hour** (Default).
*   **Process**:
    1.  Node checks `LastKeyRotation` timestamp for each peer.
    2.  If `> 1h`, Node generates a *new* Session Key.
    3.  Performs a fresh **Key Exchange**.
    4.  Old key is discarded from memory.
*   **Benefit**: If an attacker steals a node's keys after a session, they cannot decrypt past traffic recorded more than an hour ago.

## 🚧 Threat Model & Mitigations

| Threat | Mitigation |
| :--- | :--- |
| **Spoofing** | ID-Key Binding checks prevent impersonation. |
| **Man-in-the-Middle** | Handshake Signatures ensure you are talking to the key owner. |
| **Replay Attacks** | GCM Nonces and Timestamp checks in Handshake. |
| **Route Injection** | Route Advertisements are signed. Spoofed routes fail sig check. |
| **Traffic Analysis** | **SNI Masquerading** wraps traffic in HTTPS, making it look like web browsing. |
