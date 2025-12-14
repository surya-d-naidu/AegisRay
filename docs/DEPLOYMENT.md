# 🚀 AegisRay Deployment Guide

Comprehensive deployment guide for AegisRay P2P Mesh VPN in various environments.

## 📋 Prerequisites

### System Requirements

#### Minimum Requirements
- **CPU**: 1 vCPU (2+ recommended for production)
- **RAM**: 512 MB (1 GB+ recommended for production) 
- **Storage**: 100 MB free space
- **Network**: Stable internet connection with open ports

#### Supported Platforms
- **Linux**: Ubuntu 20.04+, CentOS 8+, Debian 11+, RHEL 8+
- **macOS**: 11.0+ (Big Sur and later)
- **Windows**: Windows 10/11, Windows Server 2019+
- **Docker**: Any platform supporting Docker 20.10+

### Required Ports
```bash
# Core mesh communication
443/tcp    # Primary mesh traffic (configurable)
9090/tcp   # gRPC API (optional, for SDK access)

# Management interfaces  
8080/tcp   # HTTP API (optional, can be firewalled)

# P2P discovery (outbound only)
19302/udp  # STUN servers
3478/udp   # Additional STUN servers
```

---

## 🐳 Docker Deployment (Recommended)

### Single Node Deployment

#### 1. Quick Start
```bash
# Clone repository
git clone https://github.com/surya-d-naidu/AegisRay.git
cd AegisRay

# Build image
docker build -f Dockerfile.server -t aegisray:latest .

# Run single node
docker run -d \
  --name aegisray-node \
  --privileged \
  -p 443:443 \
  -p 8080:8080 \
  -v $(pwd)/configs:/app/configs \
  -v $(pwd)/certs:/app/certs \
  aegisray:latest
```

#### 2. Custom Configuration
```bash
# Create custom config
cp configs/server.yaml configs/production.yaml
vim configs/production.yaml

# Run with custom config
docker run -d \
  --name aegisray-prod \
  --privileged \
  -p 443:443 \
  -p 8080:8080 \
  -e AEGIS_CONFIG=/app/configs/production.yaml \
  -v $(pwd)/configs:/app/configs \
  -v $(pwd)/certs:/app/certs \
  aegisray:latest
```

### Multi-Node Mesh Deployment

#### 1. Docker Compose Setup
```yaml
# docker-compose.mesh.yml
version: '3.8'

services:
  # Exit node (internet gateway)
  exit-node:
    build:
      context: .
      dockerfile: Dockerfile.server
    privileged: true
    ports:
      - "443:443"
      - "8081:8080"
    volumes:
      - ./configs/exit-node.yaml:/app/configs/server.yaml:ro
      - ./certs:/app/certs:ro
    environment:
      - AEGIS_NODE_TYPE=exit
    networks:
      - mesh
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Relay nodes
  relay-node-1:
    build:
      context: .
      dockerfile: Dockerfile.server  
    privileged: true
    ports:
      - "8082:8080"
    volumes:
      - ./configs/relay-1.yaml:/app/configs/server.yaml:ro
      - ./certs:/app/certs:ro
    environment:
      - AEGIS_NODE_TYPE=relay
      - AEGIS_BOOTSTRAP_PEER=exit-node:443
    networks:
      - mesh
    depends_on:
      - exit-node

  relay-node-2:
    build:
      context: .
      dockerfile: Dockerfile.server
    privileged: true 
    ports:
      - "8083:8080"
    volumes:
      - ./configs/relay-2.yaml:/app/configs/server.yaml:ro
      - ./certs:/app/certs:ro
    environment:
      - AEGIS_NODE_TYPE=relay
      - AEGIS_BOOTSTRAP_PEER=exit-node:443
    networks:
      - mesh
    depends_on:
      - exit-node

networks:
  mesh:
    driver: bridge
```

#### 2. Deploy Mesh Network
```bash
# Start complete mesh
docker-compose -f docker-compose.mesh.yml up -d

# Scale relay nodes
docker-compose -f docker-compose.mesh.yml up -d --scale relay-node-1=3

# Monitor deployment
docker-compose -f docker-compose.mesh.yml logs -f

# Check mesh status
curl http://localhost:8081/status | jq .peers
curl http://localhost:8082/status | jq .peers
```

---

## ☁️ Cloud Provider Deployment

### AWS EC2 Deployment

#### 1. Launch Instance
```bash
# Create security group
aws ec2 create-security-group \
  --group-name aegisray-sg \
  --description "AegisRay Mesh VPN Security Group"

# Add rules
aws ec2 authorize-security-group-ingress \
  --group-name aegisray-sg \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-name aegisray-sg \
  --protocol tcp \
  --port 443 \
  --cidr 0.0.0.0/0

# Launch instance
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --count 1 \
  --instance-type t3.medium \
  --key-name your-key-pair \
  --security-groups aegisray-sg \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=AegisRay-Node}]'
```

#### 2. Instance Setup Script
```bash
#!/bin/bash
# user-data script for EC2

# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
sudo usermod -aG docker ubuntu

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Clone and setup AegisRay
cd /home/ubuntu
git clone https://github.com/surya-d-naidu/AegisRay.git
cd AegisRay

# Configure for production
cp configs/server.yaml configs/production.yaml
# Edit production.yaml with public IP and domain

# Generate certificates
make certs

# Start service
docker-compose -f docker-compose.prod.yml up -d

# Setup monitoring
curl -sSL https://raw.githubusercontent.com/aegisray/monitoring/main/install.sh | bash
```

### Google Cloud Platform

#### 1. Create VM Instance
```bash
# Create instance
gcloud compute instances create aegisray-node \
  --zone=us-central1-a \
  --machine-type=e2-medium \
  --subnet=default \
  --network-tier=PREMIUM \
  --maintenance-policy=MIGRATE \
  --tags=aegisray-server \
  --image=ubuntu-2004-focal-v20231101 \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=20GB \
  --boot-disk-type=pd-standard

# Create firewall rule
gcloud compute firewall-rules create allow-aegisray \
  --allow tcp:443,tcp:8080 \
  --source-ranges 0.0.0.0/0 \
  --target-tags aegisray-server
```

#### 2. Deployment Script
```bash
# SSH to instance
gcloud compute ssh aegisray-node --zone=us-central1-a

# Run deployment
curl -sSL https://raw.githubusercontent.com/surya-d-naidu/AegisRay/main/scripts/gcp-deploy.sh | bash
```

### DigitalOcean Droplet

#### 1. Create Droplet
```bash
# Using doctl CLI
doctl compute droplet create aegisray-node \
  --size s-2vcpu-2gb \
  --image ubuntu-20-04-x64 \
  --region nyc1 \
  --ssh-keys $SSH_KEY_ID \
  --tag-names aegisray,vpn
```

#### 2. One-Click Deploy
```bash
#!/bin/bash
# DigitalOcean deployment script

# Update and install dependencies
apt update && apt upgrade -y
apt install -y docker.io docker-compose git make

# Clone and setup
cd /opt
git clone https://github.com/surya-d-naidu/AegisRay.git
cd AegisRay

# Configure
PUBLIC_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address)
sed -i "s/127.0.0.1/$PUBLIC_IP/g" configs/server.yaml

# Deploy
make setup
make build
docker-compose -f docker-compose.prod.yml up -d

# Setup systemd service for auto-start
systemctl enable docker
```

---

## 🖥️ Bare Metal Deployment

### Ubuntu/Debian Setup

#### 1. System Preparation
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y \
  curl \
  wget \
  git \
  make \
  build-essential \
  ca-certificates \
  software-properties-common

# Install Go 1.21+
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

#### 2. AegisRay Installation
```bash
# Clone repository
git clone https://github.com/surya-d-naidu/AegisRay.git
cd AegisRay

# Build from source
make setup
make build

# Create system user
sudo useradd -r -s /bin/false -d /var/lib/aegisray aegisray
sudo mkdir -p /var/lib/aegisray
sudo chown aegisray:aegisray /var/lib/aegisray

# Install binaries
sudo cp bin/server /usr/local/bin/aegisray-server
sudo cp bin/client /usr/local/bin/aegisray-client
sudo chmod +x /usr/local/bin/aegisray-*

# Setup directories
sudo mkdir -p /etc/aegisray
sudo cp configs/server.yaml /etc/aegisray/
sudo chown -R aegisray:aegisray /etc/aegisray

# Generate certificates
sudo mkdir -p /etc/aegisray/certs
cd /etc/aegisray/certs
sudo openssl genrsa -out server.key 2048
sudo openssl req -new -x509 -key server.key -out server.crt -days 365
sudo chown aegisray:aegisray /etc/aegisray/certs/*
```

#### 3. Systemd Service Setup
```bash
# Create service file
sudo tee /etc/systemd/system/aegisray.service << EOF
[Unit]
Description=AegisRay Mesh VPN Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=aegisray
Group=aegisray
ExecStart=/usr/local/bin/aegisray-server --config /etc/aegisray/server.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
LimitNOFILE=65536

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/aegisray /etc/aegisray

# Network capabilities
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable aegisray
sudo systemctl start aegisray

# Check status
sudo systemctl status aegisray
```

### CentOS/RHEL Setup

#### 1. System Preparation
```bash
# Update system
sudo dnf update -y

# Install EPEL and dependencies
sudo dnf install -y epel-release
sudo dnf install -y \
  curl \
  wget \
  git \
  make \
  gcc \
  openssl-devel

# Install Go
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Configure firewall
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

#### 2. SELinux Configuration
```bash
# Create SELinux policy for AegisRay
sudo tee /etc/selinux/local/aegisray.te << EOF
module aegisray 1.0;

require {
    type unconfined_t;
    type admin_home_t;
    class tun_socket { create };
    class capability { net_admin };
}

allow unconfined_t self:tun_socket create;
allow unconfined_t self:capability net_admin;
EOF

# Compile and install policy
cd /etc/selinux/local
sudo checkmodule -M -m -o aegisray.mod aegisray.te
sudo semodule_package -o aegisray.pp -m aegisray.mod
sudo semodule -i aegisray.pp

# Set context for AegisRay files
sudo setsebool -P nis_enabled 1
```

---

## ☸️ Kubernetes Deployment

### Basic Deployment

#### 1. Namespace and ConfigMap
```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: aegisray

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aegisray-config
  namespace: aegisray
data:
  server.yaml: |
    listen_address: "0.0.0.0:443"
    mesh_ip: "10.100.0.1/16"
    node_id: "k8s-node-001"
    
    p2p:
      enabled: true
      stun_servers:
        - "stun.l.google.com:19302"
      discovery_interval: "30s"
    
    tls:
      enabled: true
      cert_file: "/app/certs/tls.crt"
      key_file: "/app/certs/tls.key"
    
    mesh:
      enable_tun: false  # Disabled for containers
      route_advertisement: true
      exit_node: true
    
    http:
      enabled: true
      port: 8080
    
    log:
      level: "info"
      format: "json"
```

#### 2. Secret for TLS Certificates
```yaml
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: aegisray-certs
  namespace: aegisray
type: kubernetes.io/tls
data:
  tls.crt: # base64 encoded certificate
  tls.key: # base64 encoded private key
```

#### 3. Deployment
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aegisray-mesh
  namespace: aegisray
  labels:
    app: aegisray
spec:
  replicas: 3
  selector:
    matchLabels:
      app: aegisray
  template:
    metadata:
      labels:
        app: aegisray
    spec:
      containers:
      - name: aegisray
        image: aegisray:latest
        ports:
        - containerPort: 443
          name: mesh
          protocol: TCP
        - containerPort: 8080
          name: http
          protocol: TCP
        - containerPort: 9090
          name: grpc
          protocol: TCP
        
        env:
        - name: AEGIS_CONFIG
          value: "/app/configs/server.yaml"
        - name: POD_IP
          valueFrom:
            fieldRef:
              fieldPath: status.podIP
        
        volumeMounts:
        - name: config
          mountPath: /app/configs
          readOnly: true
        - name: certs
          mountPath: /app/certs
          readOnly: true
        
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        
        resources:
          requests:
            cpu: "100m"
            memory: "128Mi"
          limits:
            cpu: "500m"
            memory: "512Mi"
        
        securityContext:
          capabilities:
            add:
            - NET_ADMIN
            - NET_RAW
          runAsNonRoot: true
          runAsUser: 1000
      
      volumes:
      - name: config
        configMap:
          name: aegisray-config
      - name: certs
        secret:
          secretName: aegisray-certs
      
      serviceAccountName: aegisray
```

#### 4. Service and Ingress
```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: aegisray-service
  namespace: aegisray
spec:
  selector:
    app: aegisray
  ports:
  - name: mesh
    port: 443
    targetPort: 443
    protocol: TCP
  - name: http
    port: 8080
    targetPort: 8080
    protocol: TCP
  type: LoadBalancer

---
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: aegisray-ingress
  namespace: aegisray
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - mesh.yourdomain.com
    secretName: aegisray-tls
  rules:
  - host: mesh.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: aegisray-service
            port:
              number: 8080
```

#### 5. RBAC Configuration
```yaml
# k8s/rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: aegisray
  namespace: aegisray

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: aegisray
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints"]
  verbs: ["get", "list", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: aegisray
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: aegisray
subjects:
- kind: ServiceAccount
  name: aegisray
  namespace: aegisray
```

### Deploy to Kubernetes
```bash
# Apply all configurations
kubectl apply -f k8s/

# Wait for deployment
kubectl rollout status deployment/aegisray-mesh -n aegisray

# Check pods
kubectl get pods -n aegisray

# Check service
kubectl get svc -n aegisray

# View logs
kubectl logs -f deployment/aegisray-mesh -n aegisray
```

---

## 🔧 Production Configuration

### High Availability Setup

#### 1. Load Balancer Configuration (HAProxy)
```bash
# /etc/haproxy/haproxy.cfg
global
    log stdout local0
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    mode tcp
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option tcplog

frontend aegisray_frontend
    bind *:443
    mode tcp
    default_backend aegisray_nodes

backend aegisray_nodes
    mode tcp
    balance roundrobin
    option tcp-check
    tcp-check connect
    tcp-check send "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n"
    tcp-check expect string "200 OK"
    
    server node1 10.0.1.10:443 check inter 5000ms
    server node2 10.0.1.11:443 check inter 5000ms
    server node3 10.0.1.12:443 check inter 5000ms

# Statistics interface
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 30s
```

#### 2. Database Backend (for persistent state)
```yaml
# docker-compose.ha.yml
version: '3.8'

services:
  # Redis for peer state caching
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis-data:/data
    networks:
      - aegisray

  # PostgreSQL for configuration and metrics
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: aegisray
      POSTGRES_USER: aegisray
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./sql/init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - aegisray

  # AegisRay nodes with shared state
  aegisray-node-1:
    build: .
    environment:
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=postgres://aegisray:secure_password@postgres:5432/aegisray
      - NODE_ID=ha-node-1
    networks:
      - aegisray
    depends_on:
      - redis
      - postgres

volumes:
  redis-data:
  postgres-data:

networks:
  aegisray:
```

### Monitoring and Observability

#### 1. Prometheus Configuration
```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "aegisray-rules.yml"

scrape_configs:
  - job_name: 'aegisray'
    static_configs:
      - targets: 
        - 'node1:8080'
        - 'node2:8080'
        - 'node3:8080'
    metrics_path: '/metrics'
    scrape_interval: 15s
    
  - job_name: 'aegisray-mesh'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names: ['aegisray']
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        action: keep
        regex: aegisray
      - source_labels: [__meta_kubernetes_pod_ip]
        target_label: __address__
        replacement: '${1}:8080'
```

#### 2. Grafana Dashboard
```json
{
  "dashboard": {
    "id": null,
    "title": "AegisRay Mesh Network",
    "panels": [
      {
        "title": "Connected Peers",
        "type": "stat",
        "targets": [
          {
            "expr": "aegisray_peers_connected",
            "legendFormat": "{{instance}}"
          }
        ]
      },
      {
        "title": "Network Traffic",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(aegisray_bytes_transferred_total[5m])",
            "legendFormat": "{{direction}} - {{instance}}"
          }
        ]
      },
      {
        "title": "Mesh Topology",
        "type": "nodeGraph",
        "targets": [
          {
            "expr": "aegisray_peer_connections",
            "format": "table"
          }
        ]
      }
    ]
  }
}
```

---

## 🔒 Security Hardening

### TLS Configuration
```yaml
# Enhanced TLS settings
tls:
  enabled: true
  cert_file: "/etc/aegisray/certs/server.crt"
  key_file: "/etc/aegisray/certs/server.key"
  
  # Advanced settings
  min_version: "1.3"
  cipher_suites:
    - "TLS_AES_256_GCM_SHA384"
    - "TLS_AES_128_GCM_SHA256"
  
  # Certificate validation
  verify_client_cert: true
  client_ca_file: "/etc/aegisray/certs/client-ca.crt"
  
  # SNI masquerading
  sni_domains:
    - "cdn.cloudflare.com"
    - "assets.github.com"
    - "api.microsoft.com"
```

### Firewall Configuration
```bash
# UFW (Ubuntu)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 443/tcp comment 'AegisRay mesh'
sudo ufw enable

# iptables (CentOS/RHEL)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables-save > /etc/iptables/rules.v4
```

---

## 📊 Performance Optimization

### System Tuning
```bash
# Network buffer optimization
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.rmem_default = 87380' >> /etc/sysctl.conf
echo 'net.core.wmem_default = 65536' >> /etc/sysctl.conf

# Connection limits
echo 'net.core.somaxconn = 65535' >> /etc/sysctl.conf
echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf

# File descriptor limits
echo 'fs.file-max = 1048576' >> /etc/sysctl.conf
echo '* soft nofile 1048576' >> /etc/security/limits.conf
echo '* hard nofile 1048576' >> /etc/security/limits.conf

# Apply changes
sysctl -p
```

### Application Tuning
```yaml
# Performance-optimized configuration
mesh:
  # Connection pooling
  max_peers: 200
  connection_pool_size: 50
  
  # Buffer sizes
  read_buffer_size: 65536
  write_buffer_size: 65536
  
  # Timeouts
  connection_timeout: "30s"
  keep_alive_interval: "15s"
  peer_timeout: "60s"
  
  # Compression
  compression:
    enabled: true
    level: 6
    algorithm: "lz4"
```

---

## 🧪 Testing and Validation

### Deployment Testing
```bash
#!/bin/bash
# test-deployment.sh

echo "Testing AegisRay deployment..."

# Test health endpoint
echo "Checking health endpoint..."
if curl -f -s http://localhost:8080/health > /dev/null; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed"
    exit 1
fi

# Test mesh connectivity
echo "Testing mesh connectivity..."
PEERS=$(curl -s http://localhost:8080/status | jq -r '.peers | length')
if [ "$PEERS" -gt 0 ]; then
    echo "✅ Mesh connectivity: $PEERS peers connected"
else
    echo "❌ No peers connected"
    exit 1
fi

# Test packet forwarding
echo "Testing packet forwarding..."
PACKETS=$(curl -s http://localhost:8080/status | jq -r '.packet_stats.total_forwarded')
if [ "$PACKETS" -gt 0 ]; then
    echo "✅ Packet forwarding active: $PACKETS packets"
else
    echo "⚠️  No packets forwarded yet (this may be normal)"
fi

echo "✅ All tests passed!"
```

### Load Testing
```bash
# Install vegeta load testing tool
go install github.com/tsenart/vegeta/attack@latest

# Create test targets
echo "GET http://localhost:8080/health" | \
vegeta attack -rate=100 -duration=60s | \
vegeta report -type=text

# Test gRPC endpoints
ghz --insecure \
    --proto proto/mesh/mesh.proto \
    --call mesh.MeshService.DiscoverPeers \
    --data '{}' \
    --rps 50 \
    --duration 30s \
    localhost:9090
```

---

**For additional deployment scenarios and troubleshooting, see the [troubleshooting guide](TROUBLESHOOTING.md).**
