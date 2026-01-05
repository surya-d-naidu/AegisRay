# 🛠️ AegisRay Configuration Guide

This guide provides detailed instructions and examples for creating `mesh.yaml` configuration files for different node roles.

## 📄 File Location
By default, the AegisRay binary looks for the configuration file at `configs/mesh.yaml`.
You can override this location using the `-config` flag:
```bash
./aegisray-mesh -config=/etc/aegisray/my-config.yaml
```

---

## 🏗️ Configuration Scenarios

Choose the configuration template that best matches your node's role in the network.

### 1. Standard Mesh Peer (Default)
**Use Case**: A standard participant in the mesh (e.g., a server or laptop). It communicates with other mesh nodes but doesn't route traffic for anyone else.

```yaml
node_name: "desktop-alice"
mesh_ip: "100.64.0.10"       # Unique IP in your mesh subnet
listen_port: 51820
network_name: "corp-net"
network_cidr: "100.64.0.0/16"

# Security
use_tls: true
stealth_mode: true           # Hide traffic as HTTPS
stealth_domains:
  - "cloudflare.com"

# Discovery
auto_discovery: true
static_peers:
  - "1.2.3.4:51820"          # Connect to a known public node

# Routing
enable_tun: true             # Create local interface for traffic
mesh_routing: false          # Do NOT relay traffic for others
exit_node: false
```

### 2. Mesh Gateway / Relay Node
**Use Case**: A node with a stable Public IP that helps other nodes connect (NAT Traversal) and relays traffic between them. Usually runs on a VPS or Cloud Server.

```yaml
node_name: "gateway-01"
# No mesh_ip specified -> Auto-assign from CIDR
listen_port: 51820
network_name: "corp-net"

# Performance
mtu: 1420

# Routing Roles
mesh_routing: true           # I WILL relay traffic for others
accept_routes: true

# Discovery
static_peers: []             # I am a bootstrap node, others connect to me
```

### 3. Exit Node (Internet Gateway)
**Use Case**: A node that allows other mesh peers to route their *Internet* traffic through it (like a traditional VPN).

```yaml
node_name: "exit-us-east"
mesh_ip: "100.64.0.1"
listen_port: 51820

# The Critical Setting
exit_node: true              # Advertises 0.0.0.0/0 route to the mesh

# OS Requirement: Ensure 'sysctl -w net.ipv4.ip_forward=1' is set!
```

### 4. Site-to-Site Router
**Use Case**: A node sitting in an office LAN (e.g., `192.168.1.x`) that allows mesh peers to access printers/servers on that LAN.

```yaml
node_name: "office-router"
mesh_ip: "100.64.0.50"

# Advertise Local LAN
advertise_routes:
  - "192.168.1.0/24"         # Tell the mesh: "Send 192.168.1.x traffic to me"

mesh_routing: true
```

---

## 🔍 Field Reference

### Global Settings
| Field | Type | Description |
| :--- | :--- | :--- |
| `node_name` | string | Unique identifier for logs/status. |
| `mesh_ip` | IP Address | The internal overlay IP. Must be unique. |
| `listen_port` | int | UDP port for P2P traffic. Open this in your firewall. |
| `network_cidr` | CIDR | The subnet scope of the mesh (e.g., `100.64.0.0/16`). |

### Stealth & Security
| Field | Type | Description |
| :--- | :--- | :--- |
| `use_tls` | bool | **Required** for stealth. Wraps packets in TLS. |
| `stealth_mode` | bool | Masquerades Handshakes as HTTPS traffic. |
| `stealth_domains` | list | Domains to spoof in SNI (e.g., google.com). |

### Connectivity
| Field | Type | Description |
| :--- | :--- | :--- |
| `static_peers` | list | `IP:Port` of known nodes to bootstrap connection. |
| `stun_servers` | list | Custom STUN servers for NAT detection. |
| `upnp_enabled` | bool | Attempt to open ports on home routers automatically. |

### Advanced Routing
| Field | Type | Description |
| :--- | :--- | :--- |
| `enable_tun` | bool | Creates the OS virtual interface (`aegis0`). Set `false` for pure relays. |
| `mesh_routing` | bool | If `true`, this node accepts transit packets not destined for itself. |
| `exit_node` | bool | If `true`, captures all traffic matching `0.0.0.0/0`. |
