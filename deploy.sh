#!/bin/bash
# AegisRay VPS Deploy

set -e

echo "🚀 AegisRay VPS Deployment"
echo "========================="

# Check requirements
command -v docker >/dev/null || { echo "❌ Install Docker first: curl -fsSL https://get.docker.com | sh"; exit 1; }
command -v docker-compose >/dev/null || { echo "❌ Install Docker Compose"; exit 1; }
[ -f "docker-compose.prod.yml" ] || { echo "❌ docker-compose.prod.yml not found"; exit 1; }

# Setup firewall
echo "🔥 Configuring firewall..."
if command -v ufw >/dev/null 2>&1; then
    sudo ufw allow 443/tcp comment "HTTPS/gRPC"
    sudo ufw allow 80/tcp comment "HTTP proxy" 
    sudo ufw --force enable >/dev/null 2>&1
    echo "✅ Firewall configured"
fi

# Deploy
echo "📦 Starting AegisRay..."
docker-compose -f docker-compose.prod.yml up -d --build

# Check status
sleep 5
if docker-compose -f docker-compose.prod.yml ps | grep -q "Up"; then
    SERVER_IP=$(curl -s https://ipinfo.io/ip 2>/dev/null || echo "YOUR_VPS_IP")
    echo ""
    echo "🎉 Deployment Complete!"
    echo "======================="
    echo "Server: $SERVER_IP:443"
    echo "HTTP Proxy: $SERVER_IP:80" 
    echo "SOCKS Proxy: $SERVER_IP:1080"
    echo ""
    echo "📝 Next: Update configs/client.yaml"
    echo "Set: server_address: \"$SERVER_IP:443\""
else
    echo "❌ Deployment failed"
    docker-compose -f docker-compose.prod.yml logs
    exit 1
fi
