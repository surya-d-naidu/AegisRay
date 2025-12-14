# AegisRay Configuration Reference

Complete configuration reference for AegisRay P2P mesh VPN, covering all options for nodes, security, networking, and performance tuning.

## 📋 Table of Contents

- [Configuration File Structure](#configuration-file-structure)
- [Node Configuration](#node-configuration)
- [Network Settings](#network-settings)
- [Security Configuration](#security-configuration)
- [Performance Tuning](#performance-tuning)
- [Logging & Monitoring](#logging--monitoring)
- [Environment Variables](#environment-variables)
- [Example Configurations](#example-configurations)

## 📄 Configuration File Structure

AegisRay uses YAML configuration files with a hierarchical structure:

```yaml
# /etc/aegisray/node.yaml or ~/.config/aegisray/node.yaml

# Node Identity & Basic Settings
node_name: "my-aegisray-node"
node_id: ""                    # Auto-generated if empty
listen_port: 443
mesh_ip: ""                    # Auto-assigned if empty

# Network Configuration
network:
  name: "default"
  cidr: "100.64.0.0/16"
  mtu: 1420
  enable_ipv6: false

# Peer Discovery
discovery:
  static_peers:
    - "exit1.example.com:443"
    - "exit2.example.com:443"
  auto_discovery: true
  gossip_interval: "30s"
  bootstrap_timeout: "60s"

# Security Settings  
security:
  use_tls: true
  certificate_path: "/etc/aegisray/certs"
  stealth_mode: true
  stealth_domains:
    - "cloudflare.com"
    - "googleapis.com"

# Performance Settings
performance:
  max_peers: 20
  packet_buffer_size: 10000
  compression: true
  enable_fast_path: true

# Logging
logging:
  level: "info"
  file: "/var/log/aegisray.log"
  max_size: "100MB" 
  max_files: 5

# HTTP API
api:
  enabled: true
  listen_addr: "127.0.0.1:8080"
  enable_cors: false
  auth_token: ""
```

## 🏷️ Node Configuration

### Basic Node Identity

```yaml
node_name: "corporate-exit-us-east"
node_id: ""                              # Leave empty for auto-generation
description: "US East Coast exit node"
tags:
  - "exit-node"
  - "us-east"
  - "high-bandwidth"
```

**Options:**
- `node_name`: Human-readable identifier (required)
- `node_id`: Unique identifier (auto-generated if empty)
- `description`: Optional node description
- `tags`: List of tags for node categorization

### Network Binding

```yaml
listen_port: 443                         # Port to listen on
listen_addr: "0.0.0.0"                  # Interface to bind (default: all)
public_addr: "exit1.mycompany.com"       # Public address for peer connections
external_port: 443                      # External port if different from listen_port
```

**Port Recommendations:**
- `443` (HTTPS) - Best for firewall traversal
- `80` (HTTP) - Alternative for restrictive networks  
- `8443` - Common alternative port
- `Custom` - Any port for private networks

### Node Type & Role

```yaml
node_type: "exit"                        # Node type: client, exit, relay, coordinator
capabilities:
  internet_gateway: true                 # Can provide internet access
  traffic_relay: true                    # Can relay traffic for others
  peer_coordinator: false                # Helps with peer discovery
  mobile_friendly: false                 # Optimized for mobile clients
```

**Node Types:**
- `client`: Regular client node
- `exit`: Internet gateway node
- `relay`: Traffic forwarding node  
- `coordinator`: Peer discovery helper

## 🌐 Network Settings

### Mesh Network Configuration

```yaml
network:
  name: "corporate-mesh"                 # Mesh network identifier
  cidr: "100.64.0.0/16"                # Mesh IP address space
  mesh_ip: "100.64.1.42"               # This node's mesh IP (auto-assigned if empty)
  
  # Interface Settings
  tun_name: "aegis0"                    # TUN interface name
  mtu: 1420                            # Maximum transmission unit
  enable_ipv6: false                   # IPv6 support (experimental)
  
  # Routing
  default_route: true                   # Route all traffic through mesh
  split_tunneling: false               # Route only specific subnets
  routes:                              # Custom routes
    - "10.0.0.0/8"                    # Corporate network
    - "192.168.0.0/16"                # Private networks
```

### Network Isolation & Segmentation

```yaml
network:
  # Multi-tenant support
  isolation_mode: "strict"             # none, loose, strict
  allowed_networks:
    - "100.64.0.0/16"                 # Mesh network
    - "10.0.0.0/8"                    # Corporate LAN
  
  blocked_networks:
    - "169.254.0.0/16"                # Link-local (AWS metadata)
    - "127.0.0.0/8"                   # Localhost
```

### DNS Configuration

```yaml
dns:
  servers:
    - "1.1.1.1"                       # Cloudflare DNS
    - "8.8.8.8"                       # Google DNS
  search_domains:
    - "internal.corp.com"
  mesh_dns: true                       # Resolve mesh node names
  cache_size: 1000                     # DNS cache entries
```

## 🔒 Security Configuration

### TLS & Certificate Settings

```yaml
security:
  use_tls: true                        # Enable TLS (required)
  tls_version: "1.3"                   # Minimum TLS version
  
  # Certificate Configuration
  certificate_path: "/etc/aegisray/certs"
  ca_cert: "ca.crt"                   # CA certificate file
  node_cert: "node.crt"              # Node certificate
  node_key: "node.key"               # Node private key
  
  # Certificate Generation
  auto_generate_certs: true           # Auto-generate if missing
  cert_validity_days: 365            # Certificate validity period
  
  # Client Certificate Authentication
  verify_client_certs: true          # Require client certificates
  allowed_cas: []                    # Additional trusted CAs
```

### Stealth & DPI Evasion

```yaml
stealth:
  enabled: true                       # Enable stealth mode
  
  # SNI Masquerading
  domains:
    - "cloudflare.com"               # Popular CDN
    - "fastly.com"                   # Another CDN
    - "googleapis.com"               # Google APIs
    - "github.com"                   # Code hosting
  
  domain_rotation:
    enabled: true                    # Rotate SNI domains
    interval: "1h"                   # Rotation frequency
    
  # Traffic Obfuscation
  padding:
    enabled: true                    # Add random padding
    min_size: 64                     # Minimum padding bytes
    max_size: 256                    # Maximum padding bytes
    
  timing:
    jitter_ms: 100                   # Random timing jitter
    batch_delay_ms: 50               # Batch processing delay
```

### Encryption Settings

```yaml
encryption:
  algorithm: "chacha20-poly1305"      # Encryption algorithm
  key_rotation:
    enabled: true                    # Enable key rotation
    interval: "24h"                  # Rotation frequency
    data_limit: "1GB"               # Rotate after this much data
  
  # Perfect Forward Secrecy
  pfs_enabled: true                  # Enable PFS
  ecdh_curve: "X25519"              # ECDH curve for key exchange
```

## ⚡ Performance Tuning

### Connection Management

```yaml
performance:
  # Peer Connections
  max_peers: 20                      # Maximum concurrent peers
  min_peers: 3                       # Minimum peers to maintain
  peer_timeout: "60s"                # Peer connection timeout
  
  # Connection Pooling
  connection_pool_size: 100          # gRPC connection pool
  keepalive_time: "30s"             # TCP keepalive interval
  keepalive_timeout: "10s"          # Keepalive probe timeout
  
  # Retry Logic
  max_retries: 3                     # Connection retry attempts
  retry_backoff: "exponential"       # Backoff strategy: linear, exponential
  base_retry_delay: "1s"            # Initial retry delay
```

### Buffer & Memory Settings

```yaml
performance:
  # Packet Buffers
  packet_buffer_size: 10000          # Packet buffer pool size
  max_packet_size: 65535            # Maximum packet size
  
  # Memory Limits
  max_memory_mb: 512                 # Maximum memory usage
  gc_target_percent: 100            # Go garbage collector target
  
  # Worker Threads
  worker_threads: 0                  # 0 = auto-detect CPU cores
  io_threads: 4                      # I/O worker threads
```

### Quality of Service (QoS)

```yaml
qos:
  enabled: true                      # Enable QoS
  
  # Traffic Classes
  high_priority:
    - "dns"                         # DNS queries
    - "ssh"                         # SSH connections
    - "voip"                        # VoIP traffic
  
  medium_priority:
    - "http"                        # Web browsing
    - "https"                       # Secure web
    
  low_priority:
    - "bittorrent"                  # P2P file sharing
    - "backup"                      # Backup traffic
  
  # Bandwidth Limits
  bandwidth_limits:
    total_mbps: 100                 # Total bandwidth limit
    per_peer_mbps: 50               # Per-peer limit
    burst_mbps: 200                 # Burst allowance
```

## 📊 Logging & Monitoring

### Log Configuration

```yaml
logging:
  level: "info"                      # Log level: trace, debug, info, warn, error
  format: "json"                     # Format: text, json
  
  # File Logging
  file: "/var/log/aegisray.log"     # Log file path
  max_size: "100MB"                 # Maximum log file size
  max_files: 5                      # Number of rotated files
  compress: true                    # Compress rotated files
  
  # Component-specific Levels
  component_levels:
    p2p_discovery: "debug"          # P2P discovery debugging
    mesh_router: "info"             # Routing information
    packet_forwarder: "warn"        # Only warnings for packet forwarding
```

### Metrics & Monitoring

```yaml
monitoring:
  # Prometheus Metrics
  prometheus:
    enabled: true
    listen_addr: "127.0.0.1:9090"
    path: "/metrics"
    
  # Health Checks
  health_check:
    enabled: true
    interval: "30s"                 # Health check frequency
    timeout: "10s"                  # Health check timeout
    
  # Statistics Collection
  stats:
    enabled: true
    collection_interval: "10s"      # Statistics collection frequency
    retention_period: "24h"         # How long to keep stats
```

## 🔧 Environment Variables

Environment variables override configuration file settings:

### Node Settings
```bash
export AEGISRAY_NODE_NAME="mobile-client"
export AEGISRAY_LISTEN_PORT="443"  
export AEGISRAY_MESH_IP="100.64.1.42"
export AEGISRAY_PUBLIC_ADDR="client.example.com"
```

### Network Settings
```bash
export AEGISRAY_NETWORK_NAME="corporate-mesh"
export AEGISRAY_NETWORK_CIDR="100.64.0.0/16"
export AEGISRAY_TUN_NAME="aegis0"
export AEGISRAY_MTU="1420"
```

### Security Settings
```bash
export AEGISRAY_USE_TLS="true"
export AEGISRAY_CERT_PATH="/etc/ssl/aegisray"
export AEGISRAY_STEALTH_MODE="true"
export AEGISRAY_SNI_DOMAIN="cloudflare.com"
```

### Logging Settings
```bash
export AEGISRAY_LOG_LEVEL="debug"
export AEGISRAY_LOG_FILE="/var/log/aegisray.log"
export AEGISRAY_LOG_FORMAT="json"
```

### API Settings
```bash
export AEGISRAY_API_ENABLED="true"
export AEGISRAY_API_LISTEN="127.0.0.1:8080"
export AEGISRAY_API_TOKEN="secret-token-here"
```

## 📚 Example Configurations

### 1. Mobile Client Configuration

```yaml
# ~/.config/aegisray/mobile.yaml
node_name: "mobile-phone"
node_type: "client"
listen_port: 8443                     # Non-privileged port

network:
  name: "personal-mesh"
  cidr: "100.64.0.0/16"
  default_route: true                 # Route all traffic through mesh

discovery:
  static_peers:
    - "home.mydomain.com:443"        # Home server
    - "vps.mydomain.com:443"         # VPS exit node
  auto_discovery: true
  gossip_interval: "60s"             # Longer interval for mobile

security:
  stealth_mode: true
  stealth_domains:
    - "googleapis.com"               # Common on mobile

performance:
  max_peers: 5                       # Limited for mobile
  packet_buffer_size: 1000          # Smaller buffers

logging:
  level: "warn"                      # Minimal logging
  file: "/tmp/aegisray.log"         # Temporary log location
```

### 2. Exit Node Configuration

```yaml
# /etc/aegisray/exit-node.yaml
node_name: "exit-us-east-1"
node_type: "exit"
listen_port: 443
public_addr: "exit1.mycompany.com"

network:
  name: "corporate-mesh"
  cidr: "100.64.0.0/16"
  mesh_ip: "100.64.0.1"             # Static exit node IP
  default_route: false               # Don't route through mesh

capabilities:
  internet_gateway: true             # Provide internet access
  traffic_relay: true                # Relay for others
  
discovery:
  static_peers:
    - "exit2.mycompany.com:443"     # Other exit nodes
  auto_discovery: true

security:
  stealth_mode: true
  stealth_domains:
    - "cloudflare.com"
    - "fastly.com"
    
performance:
  max_peers: 50                      # High capacity
  packet_buffer_size: 50000         # Large buffers
  
qos:
  enabled: true
  bandwidth_limits:
    total_mbps: 1000                 # Gigabit connection
    per_peer_mbps: 100              # Generous per-peer

monitoring:
  prometheus:
    enabled: true
  health_check:
    enabled: true
    
logging:
  level: "info" 
  file: "/var/log/aegisray.log"
```

### 3. Corporate Client Configuration

```yaml
# /etc/aegisray/corporate-client.yaml
node_name: "workstation-${HOSTNAME}"
node_type: "client"
listen_port: 443

network:
  name: "corp-mesh"
  cidr: "100.64.0.0/16"
  split_tunneling: true              # Only route specific traffic
  routes:
    - "10.0.0.0/8"                  # Corporate networks
    - "172.16.0.0/12"               # Private networks

discovery:
  static_peers:
    - "exit-internal.corp.com:443"   # Internal exit node
    - "exit-external.corp.com:443"   # External exit node
  
security:
  verify_client_certs: true          # Strict authentication
  stealth_mode: true
  
performance:
  max_peers: 10
  
logging:
  level: "info"
  file: "/var/log/aegisray.log"
  
monitoring:
  health_check:
    enabled: true
```

### 4. High-Security Configuration

```yaml
# /etc/aegisray/high-security.yaml
node_name: "secure-client"
node_type: "client"

security:
  use_tls: true
  tls_version: "1.3"                 # Latest TLS only
  verify_client_certs: true
  
  stealth:
    enabled: true
    domains:
      - "github.com"                 # Legitimate domains only
      - "stackoverflow.com"
    domain_rotation:
      enabled: true
      interval: "15m"                # Frequent rotation
      
    padding:
      enabled: true
      min_size: 128
      max_size: 512                  # Large padding
      
    timing:
      jitter_ms: 200                 # High timing jitter
      
encryption:
  key_rotation:
    enabled: true
    interval: "1h"                   # Frequent key rotation
    data_limit: "100MB"             # Low data limits
    
logging:
  level: "warn"                      # Minimal logging
  file: ""                          # No file logging (security)
  
performance:
  max_peers: 3                       # Minimal peer count
```

### 5. Development/Testing Configuration

```yaml
# configs/dev.yaml  
node_name: "dev-node-${USER}"
node_type: "client"
listen_port: 8443

network:
  name: "dev-mesh"
  cidr: "100.127.0.0/16"           # Development range

discovery:
  static_peers:
    - "localhost:8444"              # Local test nodes
    - "localhost:8445"
  gossip_interval: "10s"            # Fast discovery

security:
  use_tls: true
  auto_generate_certs: true         # Auto-generate for testing
  stealth_mode: false               # Disable for debugging

performance:
  max_peers: 5

logging:
  level: "debug"                    # Verbose logging
  format: "text"                    # Human-readable
  file: "/tmp/aegisray-dev.log"

monitoring:
  prometheus:
    enabled: true
    listen_addr: "127.0.0.1:9090"  # Development metrics
```

## 🔍 Configuration Validation

### Validation Commands

```bash
# Validate configuration file
aegisray-mesh --validate-config /etc/aegisray/node.yaml

# Check configuration with verbose output
aegisray-mesh --config /etc/aegisray/node.yaml --dry-run

# Generate default configuration
aegisray-mesh --generate-config > default.yaml

# Show current effective configuration
curl http://localhost:8080/api/config
```

### Common Configuration Errors

**Port Conflicts:**
```yaml
# ❌ Wrong - conflicting ports
listen_port: 8080
api:
  listen_addr: "0.0.0.0:8080"      # Same port!

# ✅ Correct - different ports  
listen_port: 443
api:
  listen_addr: "127.0.0.1:8080"   # Different port
```

**Network Overlaps:**
```yaml
# ❌ Wrong - overlapping networks
network:
  cidr: "10.0.0.0/8"              # Conflicts with local network
  
# ✅ Correct - dedicated range
network:
  cidr: "100.64.0.0/16"           # Dedicated mesh range
```

**Certificate Paths:**
```yaml
# ❌ Wrong - relative paths
security:
  certificate_path: "certs/"       # Relative path

# ✅ Correct - absolute paths
security:
  certificate_path: "/etc/aegisray/certs"  # Absolute path
```

---

This configuration reference covers all available options for customizing AegisRay deployments. Use these settings to optimize for your specific network topology, security requirements, and performance needs.
