#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

if [ -z "$1" ]; then
    echo "Usage: ./scripts/deploy_remote.sh <user@host>"
    echo "Example: ./scripts/deploy_remote.sh ubuntu@123.45.67.89"
    exit 1
fi

REMOTE="$1"
BINARY_LOCAL="bin/aegisray-mesh"
SCRIPT_LOCAL="scripts/deploy_proxy.sh"

echo -e "${GREEN}==> Building binary for Linux/AMD64...${NC}"
# Force linux/amd64 build for standard VPS
GOOS=linux GOARCH=amd64 make build

if [ ! -f "$BINARY_LOCAL" ]; then
    echo "Error: Binary not found at $BINARY_LOCAL"
    exit 1
fi

echo -e "${GREEN}==> Uploading files to $REMOTE...${NC}"
# Create temp dir
ssh "$REMOTE" "mkdir -p ~/aegis_install"
# Upload binary and script
scp "$BINARY_LOCAL" "$REMOTE:~/aegis_install/"
scp "$SCRIPT_LOCAL" "$REMOTE:~/aegis_install/install.sh"

echo -e "${GREEN}==> Running installation on remote server (sudo required)...${NC}"
# Run install script
# We use -t to force pseudo-terminal allocation for sudo prompt if needed
ssh -t "$REMOTE" "cd ~/aegis_install && chmod +x install.sh && sudo ./install.sh"

echo -e "${GREEN}==> Cleaning up remote files...${NC}"
ssh "$REMOTE" "rm -rf ~/aegis_install"

echo -e "${GREEN}==> Deployment Complete!${NC}"
