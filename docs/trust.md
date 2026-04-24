# Trust Bundle Operations

This guide covers the operator workflow for AegisRay's zero-trust peer admission model.

## What This Solves

Production nodes now require an authorization source before peers can join:

- a signed peer bundle via `trust_root_public_key_file` and `authorized_peers_file`
- or direct key pinning with `authorized_peer_keys`

For anything larger than a tiny static mesh, use the signed bundle flow.

## Build the Tool

```bash
make trustctl
```

This produces `bin/aegisray-trust`.

## 1. Generate a Trust Root

```bash
./bin/aegisray-trust gen-root \
  -out-private /etc/aegisray/trust-root.key \
  -out-public /etc/aegisray/trust-root.pem
```

- `trust-root.key` stays with the operator and should not be copied onto every node.
- `trust-root.pem` is distributed to nodes so they can verify signed bundles.

## 2. Extract a Node Identity

From a node's identity key:

```bash
./bin/aegisray-trust show-node -identity-key certs/identity.key
```

Or from a PEM public key:

```bash
./bin/aegisray-trust show-node -public-key peer-public.pem
```

The command prints:

```json
{
  "node_id": "...",
  "public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

## 3. Create and Sign an Authorized Peer Bundle

```bash
./bin/aegisray-trust sign-bundle \
  -network corp-net \
  -root-key /etc/aegisray/trust-root.key \
  -peer-key-file peers/alice.pem \
  -peer-key-file peers/bob.pem \
  -peer-key-file peers/gateway.pem \
  -out /etc/aegisray/authorized-peers.json
```

Optional common expiry:

```bash
./bin/aegisray-trust sign-bundle \
  -network corp-net \
  -root-key /etc/aegisray/trust-root.key \
  -peer-key-file peers/alice.pem \
  -expires-at 2026-12-31T23:59:59Z \
  -out /etc/aegisray/authorized-peers.json
```

## 4. Verify a Bundle

```bash
./bin/aegisray-trust verify-bundle \
  -network corp-net \
  -root-public-key /etc/aegisray/trust-root.pem \
  -bundle /etc/aegisray/authorized-peers.json
```

## 5. Configure Nodes

```yaml
use_tls: true
stealth_mode: true
stealth_domains:
  - "cloudflare.com"
  - "google.com"

trust_root_public_key_file: "/etc/aegisray/trust-root.pem"
authorized_peers_file: "/etc/aegisray/authorized-peers.json"
```

SNI masquerading remains part of the stealth layer here: when `stealth_mode: true` is enabled, outbound peer dials use a hostname from `stealth_domains` in the TLS SNI field so connection setup resembles ordinary HTTPS.

## Rotation and Revocation

To revoke a node:

1. Remove its public key from the bundle input set.
2. Re-sign the bundle with `sign-bundle`.
3. Distribute the updated `authorized-peers.json` to nodes.
4. Restart or reload nodes according to your deployment process.

To rotate a node identity:

1. Generate the node's new identity key.
2. Export its public key.
3. Replace the old key in the bundle.
4. Re-sign and redistribute.

## Lab Mode

For local-only testing, you can opt out explicitly:

```yaml
allow_unauthenticated_peers: true
```

Do not use that setting on Internet-facing or shared deployments.
