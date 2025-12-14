package mesh

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// HTTPServer provides REST API endpoints for mesh status and monitoring
type HTTPServer struct {
	node   *MeshNode
	server *http.Server
	logger *logrus.Logger
}

// NewHTTPServer creates a new HTTP API server
func NewHTTPServer(node *MeshNode, port int) *HTTPServer {
	mux := http.NewServeMux()

	server := &HTTPServer{
		node:   node,
		logger: node.logger,
		server: &http.Server{
			Addr:    fmt.Sprintf(":%d", port),
			Handler: mux,
		},
	}

	// Register endpoints
	mux.HandleFunc("/health", server.handleHealth)
	mux.HandleFunc("/status", server.handleStatus)
	mux.HandleFunc("/peers", server.handlePeers)
	mux.HandleFunc("/api/peers", server.handleAPIPeers)
	mux.HandleFunc("/api/nodes/status", server.handleAPINodeStatus)

	return server
}

// Start starts the HTTP API server
func (h *HTTPServer) Start() error {
	h.logger.WithField("address", h.server.Addr).Info("Starting HTTP API server")
	go func() {
		if err := h.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			h.logger.WithError(err).Error("HTTP server failed")
		}
	}()
	return nil
}

// Stop stops the HTTP API server
func (h *HTTPServer) Stop() error {
	if h.server != nil {
		return h.server.Close()
	}
	return nil
}

// Health check endpoint
func (h *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"node_id":   h.node.ID,
		"uptime":    time.Since(time.Now()), // TODO: track actual uptime
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(health)
}

// Status endpoint with detailed node information
func (h *HTTPServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	h.node.peersMu.RLock()
	peerCount := len(h.node.peers)
	peers := make([]map[string]interface{}, 0, peerCount)

	for _, peer := range h.node.peers {
		peers = append(peers, map[string]interface{}{
			"id":         peer.ID,
			"mesh_ip":    peer.MeshIP.String(),
			"connected":  peer.Connected,
			"last_seen":  peer.LastSeen,
			"latency_ms": peer.Latency.Milliseconds(),
		})
	}
	h.node.peersMu.RUnlock()

	status := map[string]interface{}{
		"node": map[string]interface{}{
			"id":          h.node.ID,
			"mesh_ip":     h.node.MeshIP.String(),
			"listen_port": h.node.ListenPort,
			"public_key":  h.node.PublicKey,
		},
		"network": map[string]interface{}{
			"name":       h.node.config.NetworkName,
			"cidr":       h.node.config.NetworkCIDR,
			"peer_count": peerCount,
		},
		"peers": peers,
		"p2p_discovery": map[string]interface{}{
			"enabled":      h.node.p2pDiscovery != nil,
			"static_peers": h.node.config.StaticPeers,
		},
		"routing": map[string]interface{}{
			"enabled": h.node.meshRouter != nil,
		},
		"packet_forwarding": h.getPacketForwardingStats(),
		"tun_interface":     h.getTUNInterfaceStats(),
		"timestamp":         time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}

// Peers endpoint - simplified peer list
func (h *HTTPServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	h.node.peersMu.RLock()
	peers := make([]map[string]interface{}, 0, len(h.node.peers))

	for _, peer := range h.node.peers {
		peers = append(peers, map[string]interface{}{
			"id":        peer.ID,
			"mesh_ip":   peer.MeshIP.String(),
			"connected": peer.Connected,
			"last_seen": peer.LastSeen.Unix(),
		})
	}
	h.node.peersMu.RUnlock()

	response := map[string]interface{}{
		"peers": peers,
		"total": len(peers),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// API Peers endpoint - detailed peer information
func (h *HTTPServer) handleAPIPeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		h.handlePeers(w, r)
	case "POST":
		// Handle peer registration if needed
		w.WriteHeader(http.StatusNotImplemented)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// API Node Status endpoint
func (h *HTTPServer) handleAPINodeStatus(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		h.handleStatus(w, r)
	case "POST":
		// Handle status updates if needed
		w.WriteHeader(http.StatusAccepted)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// getPacketForwardingStats returns packet forwarding statistics
func (h *HTTPServer) getPacketForwardingStats() map[string]interface{} {
	if h.node.packetForwarder == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	stats := h.node.packetForwarder.GetStats()
	stats["enabled"] = true
	return stats
}

// getTUNInterfaceStats returns TUN interface statistics
func (h *HTTPServer) getTUNInterfaceStats() map[string]interface{} {
	if h.node.tunInterface == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	stats := h.node.tunInterface.GetStats()
	stats["enabled"] = true
	return stats
}
