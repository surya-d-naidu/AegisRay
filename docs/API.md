# 📚 AegisRay API Reference

Complete API documentation for the AegisRay P2P Mesh VPN system.

## 📡 HTTP API

### Base URL
```
http://localhost:8080
```

### Authentication
Currently, the HTTP API uses no authentication for local management. For production deployments, consider implementing API key authentication or mTLS.

---

## 🔍 Health & Status Endpoints

### `GET /health`
Health check endpoint for monitoring and load balancers.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "uptime": "2h30m45s",
  "version": "1.0.0",
  "build_time": "2025-12-13T08:00:00Z",
  "go_version": "go1.21.5"
}
```

**Response (503 Service Unavailable):**
```json
{
  "status": "unhealthy",
  "error": "mesh node disconnected",
  "uptime": "45m12s"
}
```

### `GET /status`
Comprehensive network status and statistics.

**Response (200 OK):**
```json
{
  "node_id": "mesh-node-001",
  "mesh_ip": "10.100.0.1",
  "listen_address": "0.0.0.0:443",
  "peers": [
    {
      "id": "peer-001",
      "address": "192.168.1.100:443",
      "mesh_ip": "10.100.0.2",
      "last_seen": "2025-12-13T10:30:00Z",
      "latency_ms": 45.2,
      "is_exit_node": false,
      "connection_state": "connected",
      "bytes_sent": 1048576,
      "bytes_received": 2097152,
      "metadata": {
        "location": "US-East",
        "version": "1.0.0"
      }
    }
  ],
  "routes": [
    "10.100.0.0/16",
    "192.168.100.0/24"
  ],
  "statistics": {
    "bytes_sent": 10485760,
    "bytes_received": 20971520,
    "packets_forwarded": 15000,
    "active_connections": 3,
    "total_peers_seen": 5,
    "uptime_seconds": 9045
  },
  "tun_stats": {
    "interface_name": "aegis0",
    "interface_ip": "10.100.0.1/16",
    "mtu": 1420,
    "packets_sent": 7500,
    "packets_received": 7500,
    "bytes_sent": 5242880,
    "bytes_received": 5242880,
    "errors": 0,
    "drops": 0
  },
  "packet_stats": {
    "total_forwarded": 15000,
    "forwarded_to_peers": 12000,
    "forwarded_to_exit": 3000,
    "processing_time_ms": 0.5,
    "queue_size": 0,
    "errors": 2
  }
}
```

---

## 👥 Peer Management

### `GET /peers`
List all connected peers with detailed information.

**Response (200 OK):**
```json
[
  {
    "id": "peer-001",
    "address": "192.168.1.100:443",
    "mesh_ip": "10.100.0.2",
    "last_seen": "2025-12-13T10:30:00Z",
    "latency_ms": 45.2,
    "is_exit_node": false,
    "connection_state": "connected",
    "bytes_sent": 1048576,
    "bytes_received": 2097152,
    "connection_time": "2025-12-13T09:15:00Z",
    "metadata": {
      "location": "US-East",
      "version": "1.0.0",
      "platform": "linux/amd64"
    }
  },
  {
    "id": "exit-node-001",
    "address": "203.0.113.10:443",
    "mesh_ip": "10.100.0.10",
    "last_seen": "2025-12-13T10:29:58Z",
    "latency_ms": 120.5,
    "is_exit_node": true,
    "connection_state": "connected",
    "bytes_sent": 5242880,
    "bytes_received": 10485760,
    "connection_time": "2025-12-13T09:00:00Z",
    "metadata": {
      "location": "EU-West",
      "version": "1.0.0",
      "exit_countries": ["DE", "NL", "FR"]
    }
  }
]
```

### `GET /peers/{peer_id}`
Get detailed information about a specific peer.

**Parameters:**
- `peer_id` (string): Unique peer identifier

**Response (200 OK):**
```json
{
  "id": "peer-001",
  "address": "192.168.1.100:443",
  "mesh_ip": "10.100.0.2",
  "last_seen": "2025-12-13T10:30:00Z",
  "latency_ms": 45.2,
  "is_exit_node": false,
  "connection_state": "connected",
  "bytes_sent": 1048576,
  "bytes_received": 2097152,
  "connection_time": "2025-12-13T09:15:00Z",
  "routes_advertised": [
    "192.168.100.0/24"
  ],
  "connection_history": [
    {
      "timestamp": "2025-12-13T09:15:00Z",
      "event": "connected",
      "address": "192.168.1.100:443"
    }
  ],
  "metadata": {
    "location": "US-East",
    "version": "1.0.0",
    "platform": "linux/amd64"
  }
}
```

**Response (404 Not Found):**
```json
{
  "error": "peer not found",
  "peer_id": "nonexistent-peer"
}
```

---

## 🌐 Network Management

### `POST /api/connect`
Connect to the mesh network.

**Request Body:**
```json
{
  "node_id": "my-client-001",
  "listen_address": "0.0.0.0:0",
  "static_peers": [
    "mesh-server.example.com:443",
    "192.168.1.100:443"
  ],
  "metadata": {
    "location": "US-West",
    "platform": "darwin/arm64"
  }
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "node_id": "my-client-001",
  "assigned_mesh_ip": "10.100.0.15",
  "listen_address": "0.0.0.0:54321"
}
```

**Response (400 Bad Request):**
```json
{
  "error": "invalid node_id format",
  "details": "node_id must be alphanumeric with hyphens"
}
```

### `POST /api/disconnect`
Disconnect from the mesh network.

**Response (200 OK):**
```json
{
  "success": true,
  "message": "disconnected from mesh network"
}
```

### `POST /api/peers`
Manually add a peer to the mesh network.

**Request Body:**
```json
{
  "address": "new-peer.example.com:443",
  "metadata": {
    "priority": "high",
    "location": "EU-Central"
  }
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "peer connection initiated",
  "peer_address": "new-peer.example.com:443"
}
```

### `DELETE /api/peers/{peer_id}`
Remove a peer from the mesh network.

**Parameters:**
- `peer_id` (string): Peer identifier to remove

**Response (200 OK):**
```json
{
  "success": true,
  "message": "peer removed successfully",
  "peer_id": "peer-001"
}
```

---

## 🛣️ Route Management

### `GET /routes`
List all known routes in the mesh network.

**Response (200 OK):**
```json
[
  {
    "destination": "10.100.0.0/16",
    "gateway": "local",
    "metric": 0,
    "type": "mesh_network"
  },
  {
    "destination": "192.168.100.0/24",
    "gateway": "10.100.0.2",
    "metric": 10,
    "type": "advertised",
    "advertiser": "peer-001"
  },
  {
    "destination": "0.0.0.0/0",
    "gateway": "10.100.0.10",
    "metric": 100,
    "type": "exit_node",
    "advertiser": "exit-node-001"
  }
]
```

### `POST /api/routes`
Add a custom route to the mesh network.

**Request Body:**
```json
{
  "destination": "192.168.200.0/24",
  "gateway": "10.100.0.5",
  "metric": 50
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "route added successfully",
  "route": {
    "destination": "192.168.200.0/24",
    "gateway": "10.100.0.5",
    "metric": 50
  }
}
```

### `DELETE /api/routes`
Remove a route from the mesh network.

**Request Body:**
```json
{
  "destination": "192.168.200.0/24"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "route removed successfully"
}
```

---

## 📊 Statistics and Metrics

### `GET /stats`
Get detailed network statistics.

**Response (200 OK):**
```json
{
  "network": {
    "total_peers": 5,
    "active_peers": 4,
    "total_routes": 8,
    "mesh_size": "10.100.0.0/16"
  },
  "traffic": {
    "total_bytes_sent": 10485760,
    "total_bytes_received": 20971520,
    "packets_per_second": 150.5,
    "bandwidth_utilization": 0.75
  },
  "performance": {
    "average_latency_ms": 85.2,
    "packet_loss_percent": 0.01,
    "connection_success_rate": 0.98
  },
  "security": {
    "active_tunnels": 4,
    "encryption_overhead_percent": 12.5,
    "certificate_expiry": "2026-01-01T00:00:00Z"
  }
}
```

### `GET /metrics`
Prometheus-compatible metrics endpoint.

**Response (200 OK):**
```
# HELP aegisray_peers_connected Number of connected peers
# TYPE aegisray_peers_connected gauge
aegisray_peers_connected 4

# HELP aegisray_bytes_transferred_total Total bytes transferred
# TYPE aegisray_bytes_transferred_total counter
aegisray_bytes_transferred_total{direction="sent"} 10485760
aegisray_bytes_transferred_total{direction="received"} 20971520

# HELP aegisray_packets_forwarded_total Total packets forwarded
# TYPE aegisray_packets_forwarded_total counter
aegisray_packets_forwarded_total 15000

# HELP aegisray_connection_latency_seconds Peer connection latency
# TYPE aegisray_connection_latency_seconds histogram
aegisray_connection_latency_seconds_bucket{le="0.01"} 1
aegisray_connection_latency_seconds_bucket{le="0.05"} 2
aegisray_connection_latency_seconds_bucket{le="0.1"} 3
aegisray_connection_latency_seconds_bucket{le="+Inf"} 4
aegisray_connection_latency_seconds_sum 0.341
aegisray_connection_latency_seconds_count 4
```

---

## 🔧 Configuration Management

### `GET /config`
Get current node configuration (sensitive values masked).

**Response (200 OK):**
```json
{
  "node_id": "mesh-node-001",
  "listen_address": "0.0.0.0:443",
  "mesh_ip": "10.100.0.1/16",
  "p2p": {
    "enabled": true,
    "stun_servers": [
      "stun.l.google.com:19302",
      "stun1.l.google.com:19302"
    ],
    "discovery_interval": "30s"
  },
  "mesh": {
    "enable_tun": false,
    "route_advertisement": true,
    "exit_node": true
  },
  "tls": {
    "enabled": true,
    "sni_domains": ["example.com"]
  },
  "http": {
    "enabled": true,
    "port": 8080
  }
}
```

### `PUT /api/config`
Update node configuration (requires restart for some settings).

**Request Body:**
```json
{
  "p2p": {
    "discovery_interval": "15s"
  },
  "mesh": {
    "route_advertisement": false
  }
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "configuration updated",
  "restart_required": false
}
```

---

## 🎯 gRPC API

The gRPC API provides high-performance peer-to-peer communication.

### Service Definition

```protobuf
syntax = "proto3";

package mesh;

service MeshService {
  // Network lifecycle
  rpc JoinNetwork(JoinRequest) returns (JoinResponse);
  rpc LeaveNetwork(LeaveRequest) returns (LeaveResponse);
  
  // Peer management
  rpc ConnectToPeer(ConnectToPeerRequest) returns (ConnectToPeerResponse);
  rpc DiscoverPeers(DiscoverPeersRequest) returns (DiscoverPeersResponse);
  
  // Packet forwarding
  rpc SendPacket(SendPacketRequest) returns (SendPacketResponse);
  rpc BroadcastPacket(BroadcastPacketRequest) returns (BroadcastPacketResponse);
  rpc ListenForPackets(ListenForPacketsRequest) returns (stream IncomingPacket);
  
  // Route management
  rpc AddRoute(AddRouteRequest) returns (AddRouteResponse);
  rpc RemoveRoute(RemoveRouteRequest) returns (RemoveRouteResponse);
  
  // Mesh operations
  rpc AdvertiseRoute(AdvertiseRouteRequest) returns (AdvertiseRouteResponse);
  rpc RequestRoutes(RequestRoutesRequest) returns (RequestRoutesResponse);
}
```

### Message Definitions

#### JoinRequest
```protobuf
message JoinRequest {
  string node_id = 1;
  string listen_address = 2;
  map<string, string> metadata = 3;
}
```

#### JoinResponse
```protobuf
message JoinResponse {
  bool success = 1;
  string assigned_mesh_ip = 2;
  repeated Peer initial_peers = 3;
  string error_message = 4;
}
```

#### SendPacketRequest
```protobuf
message SendPacketRequest {
  string peer_id = 1;
  bytes data = 2;
  PacketType type = 3;
  int32 ttl = 4;
}
```

#### IncomingPacket
```protobuf
message IncomingPacket {
  string peer_id = 1;
  bytes data = 2;
  PacketType type = 3;
  int64 timestamp = 4;
}
```

---

## 🚀 SDK Usage Examples

### Go SDK

#### Basic Connection
```go
package main

import (
    "context"
    "log"
    
    "github.com/aegisray/vpn-tunnel/sdk/go"
)

func main() {
    // Create client
    client, err := aegisray.NewClient(&aegisray.Config{
        NodeAddress: "mesh.example.com",
        HTTPPort:    8080,
        GRPCPort:    9090,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
    
    // Connect and join
    ctx := context.Background()
    if err := client.Connect(ctx); err != nil {
        log.Fatal(err)
    }
    
    if err := client.JoinNetwork(ctx, "my-node", "0.0.0.0:0"); err != nil {
        log.Fatal(err)
    }
    
    // Monitor status
    status, err := client.GetNetworkStatus(ctx)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Connected with IP: %s", status.MeshIP)
}
```

#### Packet Handling
```go
// Set up packet listener
handler := func(peerID string, data []byte) error {
    log.Printf("Received %d bytes from %s", len(data), peerID)
    return nil
}

if err := client.StartPacketListener(ctx, handler); err != nil {
    log.Fatal(err)
}

// Send packet to specific peer
err = client.SendPacket(ctx, "peer-001", []byte("Hello mesh!"))

// Broadcast to all peers
err = client.BroadcastPacket(ctx, []byte("Hello everyone!"))
```

---

## 🛠️ Error Codes

### HTTP Status Codes
- `200 OK`: Request successful
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Authentication required (future)
- `404 Not Found`: Resource not found
- `409 Conflict`: Resource already exists
- `500 Internal Server Error`: Server error
- `503 Service Unavailable`: Service temporarily unavailable

### Custom Error Codes
```json
{
  "error": "PEER_NOT_FOUND",
  "message": "The specified peer could not be found",
  "code": 1001,
  "details": {
    "peer_id": "nonexistent-peer",
    "suggestion": "Check peer ID and connection status"
  }
}
```

| Code | Error | Description |
|------|-------|-------------|
| 1001 | PEER_NOT_FOUND | Peer does not exist or is disconnected |
| 1002 | INVALID_MESH_IP | Invalid IP address format |
| 1003 | ROUTE_EXISTS | Route already exists in routing table |
| 1004 | CONNECTION_FAILED | Failed to establish peer connection |
| 1005 | TUN_INTERFACE_ERROR | TUN interface operation failed |

---

## 🔧 Rate Limiting

The API implements rate limiting to prevent abuse:

- **Health endpoint**: 60 requests/minute
- **Status endpoint**: 30 requests/minute  
- **Peer management**: 10 requests/minute
- **Route management**: 5 requests/minute

Rate limit headers:
```
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 25
X-RateLimit-Reset: 1640995200
```

---

## 📝 OpenAPI Specification

The complete OpenAPI 3.0 specification is available at:
```
GET /api/openapi.json
```

This can be used with tools like Swagger UI or Postman for interactive API exploration.

---

**For more examples and advanced usage, see the [examples/](../examples/) directory.**
