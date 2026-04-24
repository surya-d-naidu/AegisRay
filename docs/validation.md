# Deployment Validation

This document defines the minimum runtime checks still required before calling an AegisRay deployment production-ready.

## What This Covers

The codebase now has:

- fail-closed peer admission
- trust bundle tooling
- TLS identity binding
- SNI masquerading on outbound TLS handshakes

What still needs proof is the live behavior of a running mesh.

## Smoke Validation

For the two-node Docker setup:

```bash
make validate-smoke
```

That target:

1. builds and starts `docker-compose.test.yml`
2. waits for `/health` on each node
3. polls `/status`
4. fails unless each node reports at least one connected peer
5. tears the environment down

The underlying script is [scripts/validate_mesh_deployment.py](../scripts/validate_mesh_deployment.py).

## Manual Simulation Validation

For the larger simulation environment, run the validator directly with explicit expectations:

```bash
python3 scripts/validate_mesh_deployment.py \
  --compose-file simulations/docker-compose.yml \
  --startup \
  --timeout 180 \
  --service exit-node-us:1:8080 \
  --service exit-node-eu:1:8080 \
  --service client-alice:1:8080 \
  --service client-bob:1:8080
```

Adjust peer-count thresholds once you know the stable expected topology for each scenario.

## Production Validation Checklist

Before sign-off, validate all of the following on a real target environment:

1. Node startup
Each node reaches `/health` and stays healthy across restart.

2. Peer admission
Authorized peers join successfully. Unauthorized peers are rejected.

3. gRPC control plane
Join, heartbeat, discovery, route advertisement, and `SendPacket` work under TLS.

4. Stealth transport
When `stealth_mode: true` is enabled, packet captures show outbound TLS handshakes using the configured SNI masquerading domains.

5. Routing
Nodes learn peers and routes, and `/status` reflects the expected peer counts.

6. Exit-node behavior
Client traffic traverses the exit node when `default_route` and `exit_node` are enabled.

7. Failure recovery
Restart a relay or exit node and verify reconnection and traffic recovery.

8. Trust bundle rollout
Replace `authorized-peers.json`, restart or reload nodes, and confirm new peers are admitted and revoked peers are blocked.

## Important Boundary

Passing the smoke validator is necessary, but not sufficient, for production readiness.

It proves:

- the containers start
- the HTTP status surface works
- the mesh forms at least minimally

It does not prove:

- NAT traversal under real networks
- throughput under load
- stealth efficacy against real DPI
- operational resilience under upgrades and failures
