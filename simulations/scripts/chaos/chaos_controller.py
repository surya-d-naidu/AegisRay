#!/usr/bin/env python3
"""
AegisRay Chaos Controller
Injects failures into the mesh simulation using the Docker API.
Pauses/unpauses containers to simulate network partitions and node restarts.
"""

import logging
import os
import random
import sys
import time

import docker

CHAOS_LEVEL = os.environ.get("CHAOS_LEVEL", "moderate")
TARGET_SERVICES = os.environ.get(
    "TARGET_SERVICES", "client-alice,client-bob,client-charlie"
).split(",")
# Map service names to container names
CONTAINER_PREFIX = "sim-"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [chaos] %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# Chaos intervals by level (seconds between events)
INTERVALS = {"low": 120, "moderate": 60, "high": 30}


def get_client() -> docker.DockerClient:
    return docker.DockerClient(base_url="unix:///var/run/docker.sock")


def pause_container(client: docker.DockerClient, name: str, duration: int):
    """Pause a container for `duration` seconds, then unpause it."""
    container_name = f"{CONTAINER_PREFIX}{name}"
    try:
        container = client.containers.get(container_name)
        logger.info("PAUSE %s for %ds", container_name, duration)
        container.pause()
        time.sleep(duration)
        container.unpause()
        logger.info("UNPAUSE %s", container_name)
    except docker.errors.NotFound:
        logger.warning("Container %s not found", container_name)
    except docker.errors.APIError as e:
        logger.error("Docker API error for %s: %s", container_name, e)


def restart_container(client: docker.DockerClient, name: str):
    """Restart a container to simulate a node crash and recovery."""
    container_name = f"{CONTAINER_PREFIX}{name}"
    try:
        container = client.containers.get(container_name)
        logger.info("RESTART %s", container_name)
        container.restart(timeout=10)
    except docker.errors.NotFound:
        logger.warning("Container %s not found", container_name)
    except docker.errors.APIError as e:
        logger.error("Docker API error for %s: %s", container_name, e)


def run():
    interval = INTERVALS.get(CHAOS_LEVEL, 60)
    logger.info(
        "Chaos controller starting (level=%s, interval=%ds, targets=%s)",
        CHAOS_LEVEL,
        interval,
        TARGET_SERVICES,
    )

    # Let the mesh stabilize before injecting chaos
    logger.info("Waiting 90s for mesh to stabilize before chaos...")
    time.sleep(90)

    client = get_client()

    while True:
        target = random.choice(TARGET_SERVICES)
        scenario = random.choice(["pause", "restart"])

        if scenario == "pause":
            duration = random.randint(5, 20)
            pause_container(client, target, duration)
        else:
            restart_container(client, target)

        jitter = random.uniform(0.5, 1.5)
        time.sleep(interval * jitter)


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        logger.info("Chaos controller stopped")
