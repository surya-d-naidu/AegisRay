#!/usr/bin/env python3
"""
AegisRay Traffic Generator
Generates internal mesh traffic between nodes for simulation testing.
All traffic stays within the air-gapped Docker network.
"""

import logging
import os
import random
import sys
import time

import requests

TARGET_NODES = os.environ.get("TARGET_NODES", "alice,bob,charlie").split(",")
EXIT_NODES = ["exit-node-us", "exit-node-eu"]
API_PORT = int(os.environ.get("API_PORT", "8080"))
SIMULATION_MODE = os.environ.get("SIMULATION_MODE", "realistic")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [traffic] %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# Map short names to container hostnames
NODE_HOSTS = {
    "alice": "client-alice",
    "bob": "client-bob",
    "charlie": "client-charlie",
    "mobile": "client-mobile",
}


def hit_health(host: str) -> bool:
    """Send a GET /health request to an internal node."""
    try:
        resp = requests.get(f"http://{host}:{API_PORT}/health", timeout=5)
        return resp.status_code == 200
    except requests.RequestException:
        return False


def hit_peers(host: str) -> bool:
    """Query /api/peers on an internal node."""
    try:
        resp = requests.get(f"http://{host}:{API_PORT}/api/peers", timeout=5)
        return resp.status_code == 200
    except requests.RequestException:
        return False


def generate_round():
    """Run one round of traffic generation against mesh nodes."""
    all_hosts = [NODE_HOSTS.get(n, n) for n in TARGET_NODES] + EXIT_NODES
    target = random.choice(all_hosts)
    action = random.choice([hit_health, hit_peers])
    ok = action(target)
    logger.info("%-12s -> %s : %s", action.__name__, target, "OK" if ok else "FAIL")


def run():
    logger.info("Traffic generator starting (mode=%s, targets=%s)", SIMULATION_MODE, TARGET_NODES)

    # Wait for nodes to come up
    logger.info("Waiting 30s for mesh to stabilize...")
    time.sleep(30)

    while True:
        generate_round()
        # Vary interval based on simulation mode
        delay = random.uniform(0.5, 3.0) if SIMULATION_MODE == "realistic" else 1.0
        time.sleep(delay)


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        logger.info("Traffic generator stopped")
