#!/usr/bin/env python3
"""
Validate an AegisRay deployment running under docker compose.

This script is intentionally conservative:
- it waits for each requested service to answer /health
- it fetches /status from inside each container
- it enforces a minimum peer count per service

It does not prove production readiness on its own, but it turns the
current smoke/integration expectations into a repeatable gate.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class ServiceExpectation:
    name: str
    min_peers: int
    api_port: int


def run(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, check=False, text=True, capture_output=True)
    if check and result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        details = "\n".join(part for part in [stdout, stderr] if part)
        raise RuntimeError(f"command failed ({' '.join(cmd)}):\n{details}")
    return result


def compose_cmd(compose_file: str, extra: List[str]) -> List[str]:
    return ["docker", "compose", "-f", compose_file, *extra]


def parse_expectations(items: List[str], default_api_port: int) -> List[ServiceExpectation]:
    expectations: List[ServiceExpectation] = []
    for item in items:
        parts = item.split(":")
        if len(parts) == 1:
            expectations.append(ServiceExpectation(name=parts[0], min_peers=1, api_port=default_api_port))
        elif len(parts) == 2:
            expectations.append(ServiceExpectation(name=parts[0], min_peers=int(parts[1]), api_port=default_api_port))
        elif len(parts) == 3:
            expectations.append(ServiceExpectation(name=parts[0], min_peers=int(parts[1]), api_port=int(parts[2])))
        else:
            raise ValueError(f"invalid --service value {item!r}; expected service[:min_peers[:api_port]]")
    return expectations


def curl_json(compose_file: str, service: str, path: str, api_port: int) -> Dict:
    cmd = compose_cmd(
        compose_file,
        ["exec", "-T", service, "sh", "-lc", f"curl -sf http://127.0.0.1:{api_port}{path}"],
    )
    result = run(cmd)
    return json.loads(result.stdout)


def wait_for_health(compose_file: str, expectation: ServiceExpectation, deadline: float) -> None:
    while time.time() < deadline:
        try:
            curl_json(compose_file, expectation.name, "/health", expectation.api_port)
            return
        except Exception:
            time.sleep(2)
    raise TimeoutError(f"{expectation.name} did not become healthy on port {expectation.api_port}")


def validate_status(compose_file: str, expectation: ServiceExpectation) -> Dict:
    status = curl_json(compose_file, expectation.name, "/status", expectation.api_port)
    network = status.get("network", {})
    peer_count = int(network.get("peer_count", 0))
    connected_peer_count = sum(1 for peer in status.get("peers", []) if peer.get("connected"))
    if peer_count < expectation.min_peers:
        raise RuntimeError(
            f"{expectation.name} reported peer_count={peer_count}, expected at least {expectation.min_peers}"
        )
    if connected_peer_count < expectation.min_peers:
        raise RuntimeError(
            f"{expectation.name} reported connected_peer_count={connected_peer_count}, expected at least {expectation.min_peers}"
        )
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an AegisRay docker compose deployment")
    parser.add_argument("--compose-file", required=True, help="docker compose file to validate")
    parser.add_argument(
        "--service",
        action="append",
        required=True,
        help="service[:min_peers[:api_port]] expectation; repeatable",
    )
    parser.add_argument("--timeout", type=int, default=120, help="seconds to wait for health and mesh formation")
    parser.add_argument("--startup", action="store_true", help="run docker compose up -d --build before validation")
    parser.add_argument("--teardown", action="store_true", help="run docker compose down after validation")
    parser.add_argument("--default-api-port", type=int, default=8080, help="default in-container API port")

    args = parser.parse_args()
    expectations = parse_expectations(args.service, args.default_api_port)

    try:
        if args.startup:
            print(f"bringing up {args.compose_file}")
            run(compose_cmd(args.compose_file, ["up", "-d", "--build"]))

        deadline = time.time() + args.timeout

        print("waiting for service health")
        for expectation in expectations:
            wait_for_health(args.compose_file, expectation, deadline)
            print(f"  healthy: {expectation.name}")

        print("validating mesh status")
        summaries = {}
        while time.time() < deadline:
            try:
                summaries = {}
                for expectation in expectations:
                    status = validate_status(args.compose_file, expectation)
                    summaries[expectation.name] = {
                        "mesh_ip": status.get("node", {}).get("mesh_ip"),
                        "peer_count": status.get("network", {}).get("peer_count"),
                        "connected_peer_count": sum(1 for peer in status.get("peers", []) if peer.get("connected")),
                        "routing": status.get("routing", {}).get("enabled"),
                        "p2p_discovery": status.get("p2p_discovery", {}).get("enabled"),
                    }
                break
            except Exception:
                time.sleep(3)
        else:
            raise TimeoutError("mesh did not reach expected peer counts before timeout")

        print(json.dumps(summaries, indent=2))
        print("validation passed")
        return 0
    except Exception as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if args.teardown:
            run(compose_cmd(args.compose_file, ["down"]), check=False)


if __name__ == "__main__":
    sys.exit(main())
