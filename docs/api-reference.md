# AegisRay API Reference

Complete REST API and gRPC API documentation for AegisRay mesh VPN management, monitoring, and integration.

## 📋 Table of Contents

- [REST API](#rest-api)
  - [Authentication](#authentication)
  - [Node Management](#node-management)
  - [Peer Management](#peer-management)
  - [Network Status](#network-status)
  - [Configuration](#configuration)
  - [Monitoring & Stats](#monitoring--stats)
- [gRPC API](#grpc-api)
  - [Mesh Service](#mesh-service)
  - [Discovery Service](#discovery-service)
  - [Management Service](#management-service)
- [WebSocket API](#websocket-api)
- [Error Handling](#error-handling)
- [SDK Examples](#sdk-examples)

## 🌐 REST API

The REST API provides comprehensive management and monitoring capabilities for AegisRay mesh nodes.

### Base URL
```
http://localhost:8080
```

### Authentication

AegisRay supports multiple authentication methods:

**1. API Token (Recommended)**
```bash
curl -H "Authorization: Bearer your-secret-token" \
     http://localhost:8080/api/status
```

**2. Basic Authentication**  
```bash
curl -u "admin:password" \
     http://localhost:8080/api/status
```

**3. Client Certificates**
```bash
curl --cert client.crt --key client.key \
     https://localhost:8080/api/status
```

**Configuration:**
```yaml
api:
  auth_token: "your-secret-token"
  basic_auth:
    username: "admin"
    password: "secure-password"
  client_certs: true
```

---

## 🏥 Health & Status Endpoints

### GET /health
Basic health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "node_id": "aegis-node-abc123", 
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z",
  "uptime_seconds": 86400
}
```

**Status Codes:**
- `200 OK` - Node is healthy
- `503 Service Unavailable` - Node is unhealthy

### GET /status
Comprehensive node status information.

**Response:**
```json
{
  "node": {
    "id": "aegis-node-abc123",
    "name": "exit-us-east-1", 
    "type": "exit",
    "version": "1.0.0",
    "mesh_ip": "100.64.0.1",
    "listen_addr": "0.0.0.0:443",
    "public_addr": "exit1.example.com:443",
    "uptime_seconds": 86400,
    "started_at": "2024-01-14T10:30:00Z"
  },
  "network": {
    "name": "corporate-mesh",
    "cidr": "100.64.0.0/16",
    "tun_interface": "aegis0",
    "mtu": 1420,
    "routes_count": 15
  },
  "mesh": {
    "peer_count": 8,
    "connected_peers": 6,
    "route_table_size": 25,
    "last_discovery": "2024-01-15T10:25:00Z"
  },
  "security": {
    "tls_enabled": true,
    "stealth_mode": true,
    "current_sni_domain": "cloudflare.com"
  },
  "performance": {
    "packets_sent": 1234567,
    "packets_received": 987654,
    "bytes_sent": 524288000,
    "bytes_received": 419430400,
    "packet_loss_rate": 0.001,
    "avg_latency_ms": 25.4
  }
}
```

---

## 👥 Peer Management

### GET /peers
List all known peers and their status.

**Query Parameters:**
- `connected_only` (bool) - Show only connected peers
- `type` (string) - Filter by peer type (client, exit, relay)
- `limit` (int) - Maximum number of peers to return

**Example:**
```bash
curl "http://localhost:8080/peers?connected_only=true&limit=10"
```

**Response:**
```json
{
  "peers": [
    {
      "id": "peer-def456",
      "name": "mobile-client-1",
      "type": "client", 
      "mesh_ip": "100.64.1.42",
      "public_addr": "client1.example.com:8443",
      "connection_status": "connected",
      "last_seen": "2024-01-15T10:29:50Z",
      "latency_ms": 15.2,
      "bandwidth_mbps": 25.5,
      "packets_sent": 5432,
      "packets_received": 4321,
      "connection_time": "2024-01-15T09:30:00Z",
      "version": "1.0.0",
      "capabilities": [
        "traffic_relay"
      ]
    }
  ],
  "total_count": 8,
  "connected_count": 6
}
```

### POST /api/peers
Add a static peer to the mesh.

**Request Body:**
```json
{
  "address": "peer.example.com:443",
  "name": "backup-exit-node",
  "type": "exit",
  "persistent": true,
  "priority": 100
}
```

**Response:**
```json
{
  "success": true,
  "peer_id": "peer-xyz789",
  "message": "Peer added successfully"
}
```

### DELETE /api/peers/{peer_id}
Remove a peer from the mesh.

**Example:**
```bash
curl -X DELETE http://localhost:8080/api/peers/peer-def456
```

**Response:**
```json
{
  "success": true,
  "message": "Peer removed successfully"
}
```

### POST /api/peers/{peer_id}/connect
Force connection to a specific peer.

**Response:**
```json
{
  "success": true,
  "connection_status": "connecting",
  "message": "Connection initiated"
}
```

### POST /api/peers/{peer_id}/disconnect  
Disconnect from a specific peer.

**Response:**
```json
{
  "success": true,
  "connection_status": "disconnected", 
  "message": "Peer disconnected"
}
```

---

## 🛣️ Routing & Network

### GET /api/routes
Get the current routing table.

**Response:**
```json
{
  "routes": [
    {
      "destination": "0.0.0.0/0",
      "next_hop": "100.64.0.1", 
      "interface": "aegis0",
      "cost": 100,
      "latency_ms": 25.4,
      "bandwidth_mbps": 100.0,
      "reliability": 0.995,
      "last_updated": "2024-01-15T10:25:00Z"
    },
    {
      "destination": "10.0.0.0/8",
      "next_hop": "100.64.0.5",
      "interface": "aegis0", 
      "cost": 50,
      "latency_ms": 12.1,
      "bandwidth_mbps": 250.0,
      "reliability": 0.999,
      "last_updated": "2024-01-15T10:28:30Z"
    }
  ],
  "total_routes": 25,
  "last_update": "2024-01-15T10:28:30Z"
}
```

### POST /api/routes
Add a static route.

**Request Body:**
```json
{
  "destination": "192.168.100.0/24",
  "next_hop": "100.64.1.10", 
  "cost": 75,
  "persistent": true
}
```

### DELETE /api/routes/{route_id}
Remove a static route.

### GET /api/network/interfaces
Get network interface information.

**Response:**
```json
{
  "interfaces": [
    {
      "name": "aegis0",
      "type": "tun",
      "ip_addresses": ["100.64.1.42/16"],
      "mtu": 1420,
      "state": "up",
      "tx_packets": 12345,
      "rx_packets": 11234,
      "tx_bytes": 5242880,
      "rx_bytes": 4194304,
      "errors": 0,
      "dropped": 2
    }
  ]
}
```

---

## ⚙️ Configuration Management

### GET /api/config
Get current configuration.

**Response:**
```json
{
  "node": {
    "name": "exit-us-east-1",
    "type": "exit",
    "listen_port": 443
  },
  "network": {
    "name": "corporate-mesh",
    "cidr": "100.64.0.0/16"
  },
  "security": {
    "use_tls": true,
    "stealth_mode": true
  }
}
```

### PUT /api/config
Update configuration (dynamic settings only).

**Request Body:**
```json
{
  "logging": {
    "level": "debug"
  },
  "performance": {
    "max_peers": 25
  },
  "stealth": {
    "domains": ["github.com", "stackoverflow.com"]
  }
}
```

### POST /api/config/reload
Reload configuration from file.

**Response:**
```json
{
  "success": true,
  "message": "Configuration reloaded successfully",
  "restart_required": false
}
```

---

## 📊 Statistics & Monitoring

### GET /api/stats
Get comprehensive statistics.

**Query Parameters:**
- `period` - Time period: "1h", "24h", "7d", "30d"
- `granularity` - Data granularity: "1m", "5m", "1h"

**Response:**
```json
{
  "traffic": {
    "total_bytes_sent": 1073741824,
    "total_bytes_received": 858993459,
    "packets_sent": 1048576, 
    "packets_received": 823543,
    "packet_loss_rate": 0.0012,
    "average_latency_ms": 25.4
  },
  "peers": {
    "total_peers": 12,
    "connected_peers": 9,
    "average_peer_latency_ms": 18.7,
    "peer_churn_rate": 0.05
  },
  "routing": {
    "routes_in_table": 45,
    "route_changes_1h": 3,
    "convergence_time_ms": 150
  },
  "system": {
    "cpu_usage_percent": 15.2,
    "memory_usage_mb": 128,
    "disk_usage_mb": 45,
    "file_descriptors": 234
  },
  "period": {
    "start": "2024-01-15T09:30:00Z",
    "end": "2024-01-15T10:30:00Z", 
    "duration_seconds": 3600
  }
}
```

### GET /api/stats/traffic
Traffic-specific statistics.

**Response:**
```json
{
  "interfaces": {
    "aegis0": {
      "bytes_sent": 524288000,
      "bytes_received": 419430400,
      "packets_sent": 512000,
      "packets_received": 409600,
      "errors": 12,
      "dropped": 3
    }
  },
  "peers": {
    "peer-def456": {
      "bytes_sent": 104857600,
      "bytes_received": 83886080,
      "latency_ms": 15.2,
      "packet_loss_rate": 0.001
    }
  },
  "protocols": {
    "tcp": {"bytes": 314572800, "packets": 307200},
    "udp": {"bytes": 209715200, "packets": 204800},  
    "icmp": {"bytes": 1048576, "packets": 1024}
  }
}
```

### GET /api/events
Get recent events and logs.

**Query Parameters:**
- `level` - Log level filter: "error", "warn", "info", "debug"
- `component` - Component filter: "p2p_discovery", "mesh_router", etc.
- `limit` - Number of events to return (default: 100)
- `since` - RFC3339 timestamp to get events since

**Response:**
```json
{
  "events": [
    {
      "timestamp": "2024-01-15T10:25:30Z",
      "level": "info",
      "component": "p2p_discovery", 
      "message": "New peer discovered: peer-xyz789",
      "metadata": {
        "peer_id": "peer-xyz789",
        "peer_addr": "192.168.1.100:443"
      }
    },
    {
      "timestamp": "2024-01-15T10:24:15Z", 
      "level": "warn",
      "component": "mesh_router",
      "message": "Route to 10.0.0.0/8 became unreachable",
      "metadata": {
        "destination": "10.0.0.0/8",
        "previous_hop": "100.64.1.5"
      }
    }
  ],
  "total_count": 1250,
  "has_more": true
}
```

---

## 🔧 Administrative Operations

### POST /api/admin/shutdown
Gracefully shutdown the node.

**Request Body:**
```json
{
  "force": false,
  "timeout_seconds": 30
}
```

### POST /api/admin/restart
Restart the node process.

### GET /api/admin/debug
Get debug information for troubleshooting.

**Response:**
```json
{
  "goroutines": 45,
  "memory_stats": {
    "heap_alloc": 12582912,
    "heap_sys": 16777216,
    "gc_runs": 123
  },
  "connections": {
    "tcp_established": 8,
    "tcp_listen": 1,
    "udp": 2
  },
  "system": {
    "os": "linux",
    "arch": "amd64", 
    "go_version": "go1.21.5",
    "build_time": "2024-01-10T15:30:00Z"
  }
}
```

---

## 📡 gRPC API

The gRPC API provides high-performance inter-node communication.

### Mesh Service

**Service Definition:**
```protobuf
service MeshService {
    rpc ForwardPacket(PacketRequest) returns (PacketResponse);
    rpc AdvertiseRoute(RouteAdvertisement) returns (Empty);
    rpc Handshake(HandshakeRequest) returns (HandshakeResponse);
    rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
}
```

**ForwardPacket**
Forward IP packets through the mesh.

```protobuf
message PacketRequest {
    string from_node_id = 1;
    string to_node_id = 2;
    bytes packet_data = 3;
    uint64 sequence_number = 4;
    int32 ttl = 5;
    map<string, string> metadata = 6;
}

message PacketResponse {
    bool success = 1;
    string error_message = 2;
    uint64 sequence_number = 3;
}
```

**AdvertiseRoute**  
Advertise routing information to peers.

```protobuf
message RouteAdvertisement {
    string from_node_id = 1;
    repeated RouteInfo routes = 2;
    uint64 sequence_number = 3;
    int32 ttl = 4;
}

message RouteInfo {
    string destination = 1;      // CIDR notation
    string next_hop = 2;         // Next hop IP
    int32 cost = 3;             // Route cost metric
    uint32 bandwidth_kbps = 4;   // Available bandwidth
    uint32 latency_ms = 5;       // Average latency
    float reliability = 6;       // Success rate (0.0-1.0)
}
```

### Discovery Service

**Service Definition:**
```protobuf
service DiscoveryService {
    rpc DiscoverPeers(PeerDiscoveryRequest) returns (PeerDiscoveryResponse);
    rpc AnnouncePeer(PeerAnnouncement) returns (Empty);
    rpc GetBootstrapPeers(BootstrapRequest) returns (BootstrapResponse);
}
```

**DiscoverPeers**
Discover peers using gossip protocol.

```protobuf
message PeerDiscoveryRequest {
    string requesting_node_id = 1;
    repeated PeerInfo known_peers = 2;
    uint32 max_peers = 3;
}

message PeerDiscoveryResponse {
    repeated PeerInfo peers = 1;
    uint32 total_known_peers = 2;
}

message PeerInfo {
    string node_id = 1;
    string name = 2;
    string public_addr = 3;
    string mesh_ip = 4;
    NodeType type = 5;
    repeated string capabilities = 6;
    int64 last_seen = 7;         // Unix timestamp
    float reliability = 8;
}

enum NodeType {
    CLIENT = 0;
    EXIT = 1;
    RELAY = 2;
    COORDINATOR = 3;
}
```

---

## 🔌 WebSocket API

Real-time updates and live monitoring via WebSocket.

### Connection
```javascript
const ws = new WebSocket('ws://localhost:8080/api/ws');
ws.onopen = () => {
    console.log('Connected to AegisRay WebSocket');
};
```

### Event Types

**Peer Events:**
```json
{
  "type": "peer_connected",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "peer_id": "peer-abc123",
    "name": "mobile-client-5",
    "mesh_ip": "100.64.1.50"
  }
}
```

**Traffic Events:**
```json
{
  "type": "traffic_stats",
  "timestamp": "2024-01-15T10:30:05Z", 
  "data": {
    "bytes_sent_5s": 524288,
    "bytes_received_5s": 419430,
    "active_connections": 8,
    "packet_loss_rate": 0.001
  }
}
```

**Route Events:**
```json
{
  "type": "route_changed",
  "timestamp": "2024-01-15T10:30:10Z",
  "data": {
    "destination": "10.0.0.0/8",
    "old_next_hop": "100.64.1.5",
    "new_next_hop": "100.64.1.8", 
    "reason": "peer_disconnected"
  }
}
```

---

## ❌ Error Handling

### HTTP Status Codes

- `200 OK` - Success
- `201 Created` - Resource created successfully  
- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource conflict (e.g., duplicate peer)
- `429 Too Many Requests` - Rate limited
- `500 Internal Server Error` - Server error
- `503 Service Unavailable` - Node unhealthy

### Error Response Format

```json
{
  "error": {
    "code": "PEER_NOT_FOUND",
    "message": "Peer with ID 'peer-abc123' not found",
    "details": {
      "peer_id": "peer-abc123",
      "suggestion": "Check peer ID or ensure peer is connected"
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "request_id": "req-xyz789"
  }
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| `INVALID_REQUEST` | Malformed request body or parameters |
| `PEER_NOT_FOUND` | Specified peer does not exist |
| `PEER_ALREADY_EXISTS` | Peer already added |
| `CONNECTION_FAILED` | Failed to connect to peer |
| `ROUTE_NOT_FOUND` | Route does not exist |
| `INTERFACE_ERROR` | Network interface error |
| `CONFIG_INVALID` | Configuration validation failed |
| `CERTIFICATE_ERROR` | TLS certificate problem |
| `RATE_LIMITED` | Too many requests |
| `NODE_SHUTDOWN` | Node is shutting down |

---

## 📚 SDK Examples

### Go Client

```go
package main

import (
    "context"
    "fmt"
    "net/http"
    "encoding/json"
)

type AegisClient struct {
    baseURL string
    token   string
    client  *http.Client
}

func NewAegisClient(baseURL, token string) *AegisClient {
    return &AegisClient{
        baseURL: baseURL,
        token:   token,
        client:  &http.Client{},
    }
}

func (c *AegisClient) GetStatus() (*NodeStatus, error) {
    req, _ := http.NewRequest("GET", c.baseURL+"/status", nil)
    req.Header.Set("Authorization", "Bearer "+c.token)
    
    resp, err := c.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var status NodeStatus
    if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
        return nil, err
    }
    
    return &status, nil
}

func (c *AegisClient) AddPeer(addr, name string) error {
    peer := map[string]interface{}{
        "address": addr,
        "name":    name,
    }
    
    // Implementation...
    return nil
}
```

### Python Client

```python
import requests
import json
from typing import Dict, List, Optional

class AegisClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        })
    
    def get_status(self) -> Dict:
        """Get node status."""
        response = self.session.get(f'{self.base_url}/status')
        response.raise_for_status()
        return response.json()
    
    def list_peers(self, connected_only: bool = False) -> Dict:
        """List mesh peers."""
        params = {'connected_only': connected_only} if connected_only else {}
        response = self.session.get(f'{self.base_url}/peers', params=params)
        response.raise_for_status()
        return response.json()
    
    def add_peer(self, address: str, name: str = None, peer_type: str = "client") -> Dict:
        """Add a peer to the mesh."""
        data = {
            'address': address,
            'name': name or f'peer-{address}',
            'type': peer_type
        }
        response = self.session.post(f'{self.base_url}/api/peers', json=data)
        response.raise_for_status()
        return response.json()
    
    def get_stats(self, period: str = "1h") -> Dict:
        """Get node statistics."""
        params = {'period': period}
        response = self.session.get(f'{self.base_url}/api/stats', params=params)
        response.raise_for_status()
        return response.json()

# Usage example
if __name__ == "__main__":
    client = AegisClient("http://localhost:8080", "your-token")
    
    # Get node status
    status = client.get_status()
    print(f"Node: {status['node']['name']}")
    print(f"Peers: {status['mesh']['peer_count']}")
    
    # List connected peers
    peers = client.list_peers(connected_only=True)
    for peer in peers['peers']:
        print(f"  {peer['name']}: {peer['mesh_ip']} ({peer['latency_ms']:.1f}ms)")
```

### JavaScript/Node.js Client

```javascript
const axios = require('axios');

class AegisClient {
    constructor(baseURL, token) {
        this.client = axios.create({
            baseURL: baseURL,
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
    }
    
    async getStatus() {
        const response = await this.client.get('/status');
        return response.data;
    }
    
    async listPeers(connectedOnly = false) {
        const params = connectedOnly ? { connected_only: true } : {};
        const response = await this.client.get('/peers', { params });
        return response.data;
    }
    
    async addPeer(address, name, type = 'client') {
        const data = { address, name, type };
        const response = await this.client.post('/api/peers', data);
        return response.data;
    }
    
    async getStats(period = '1h') {
        const response = await this.client.get('/api/stats', { 
            params: { period } 
        });
        return response.data;
    }
    
    // WebSocket connection for real-time updates
    connectWebSocket() {
        const ws = new WebSocket(`ws://localhost:8080/api/ws`);
        
        ws.on('message', (data) => {
            const event = JSON.parse(data);
            console.log(`Event: ${event.type}`, event.data);
        });
        
        return ws;
    }
}

// Usage
const client = new AegisClient('http://localhost:8080', 'your-token');

client.getStatus().then(status => {
    console.log(`Node ${status.node.name} is ${status.node.uptime_seconds}s old`);
});
```

---

This API reference provides comprehensive documentation for integrating with and managing AegisRay mesh VPN networks programmatically. Use these endpoints to build custom dashboards, monitoring systems, and automated mesh management tools.
