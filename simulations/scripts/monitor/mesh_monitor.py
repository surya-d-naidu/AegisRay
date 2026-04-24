#!/usr/bin/env python3
"""
AegisRay Mesh Monitor
Polls mesh node /health and /peers endpoints and logs status.
Designed for air-gapped simulation (no external dependencies).
"""

import json
import logging
import os
import sys
import time

import requests

MESH_NODES = os.environ.get(
    "MESH_NODES",
    "exit-node-us,exit-node-eu,client-alice,client-bob,client-charlie,client-mobile",
).split(",")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "10"))
API_PORT = int(os.environ.get("API_PORT", "8080"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [monitor] %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def check_node(node: str) -> dict:
    """Check a single node's health and peer list."""
    base = f"http://{node}:{API_PORT}"
    result = {"node": node, "healthy": False, "peers": []}

    try:
        resp = requests.get(f"{base}/health", timeout=5)
        result["healthy"] = resp.status_code == 200
    except requests.RequestException:
        pass

    try:
        resp = requests.get(f"{base}/api/peers", timeout=5)
        if resp.status_code == 200:
            result["peers"] = resp.json().get("peers", [])
    except requests.RequestException:
        pass

    return result


def run():
    logger.info("Mesh monitor starting (interval=%ds, nodes=%s)", POLL_INTERVAL, MESH_NODES)
    while True:
        statuses = [check_node(n) for n in MESH_NODES]
        healthy = sum(1 for s in statuses if s["healthy"])
        logger.info(
            "Status: %d/%d nodes healthy | %s",
            healthy,
            len(MESH_NODES),
            json.dumps(statuses, default=str),
        )
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        logger.info("Monitor stopped")
