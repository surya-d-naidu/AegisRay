# Production Deployment Checklist

Use this document when promoting a node from a lab mesh to a real deployment.

## Required Controls

1. Enable TLS.
2. Configure peer authorization.
3. Open the gRPC listen port intentionally.
4. Decide whether the node is a client, relay, site router, or exit node.
5. Enable `stealth_mode` only when you also set realistic `stealth_domains`.

## Minimum Secure Config

```yaml
node_name: "gateway-01"
network_name: "corp-net"
network_cidr: "100.64.0.0/16"
listen_port: 51820

use_tls: true
stealth_mode: true
stealth_domains:
  - "cloudflare.com"
  - "google.com"

trust_root_public_key_file: "/etc/aegisray/trust-root.pem"
authorized_peers_file: "/etc/aegisray/authorized-peers.json"

auto_discovery: true
enable_tun: false
mesh_routing: true
```

## Admission Policy

Production nodes fail closed if no authorization source is configured.

Choose one:

- Signed peer bundle via `trust_root_public_key_file` and `authorized_peers_file`
- Direct key pinning with `authorized_peer_keys`

Do not use `allow_unauthenticated_peers: true` outside isolated test environments.

## Stealth Model

SNI masquerading is used to make outbound TLS handshakes resemble normal HTTPS traffic. It helps reduce obvious custom-protocol fingerprints during session setup, but it does not guarantee invisibility against a sophisticated DPI or traffic-analysis system.

Treat it as one layer in the transport design, not as your only control.

## Operational Checks

- Verify the API binds only where you intend. The default is `127.0.0.1`.
- Persist identity and TLS material on durable storage.
- Monitor `/health` and `/status`.
- For exit nodes or site routers, enable host IP forwarding and NAT rules explicitly.
- Keep the peer authorization bundle under change control.
