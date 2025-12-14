package mesh

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	pb "github.com/aegisray/vpn-tunnel/proto/mesh"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PacketForwarder handles IP packet forwarding through the mesh
type PacketForwarder struct {
	node   *MeshNode
	logger *logrus.Logger

	// Packet processing
	forwardingTable map[string]string // destination IP -> peer ID
	tableMutex      sync.RWMutex

	// Statistics
	stats *ForwardingStats

	// Channels
	incomingPackets chan *IPPacket
	stopCh          chan struct{}
}

// IPPacket represents a parsed IP packet
type IPPacket struct {
	Raw         []byte
	Source      net.IP
	Destination net.IP
	Protocol    uint8
	Length      uint16
}

// ForwardingStats tracks packet forwarding statistics
type ForwardingStats struct {
	PacketsReceived  int64
	PacketsForwarded int64
	PacketsDropped   int64
	BytesForwarded   int64
	LastActivity     time.Time
	mutex            sync.RWMutex
}

// NewPacketForwarder creates a new packet forwarder
func NewPacketForwarder(node *MeshNode) *PacketForwarder {
	return &PacketForwarder{
		node:            node,
		logger:          node.logger,
		forwardingTable: make(map[string]string),
		stats:           &ForwardingStats{},
		incomingPackets: make(chan *IPPacket, 1000),
		stopCh:          make(chan struct{}),
	}
}

// Start starts the packet forwarder
func (pf *PacketForwarder) Start() error {
	pf.logger.Info("Starting packet forwarder")

	// Start packet processing goroutine
	go pf.processPackets()

	// Start forwarding table maintenance
	go pf.maintainForwardingTable()

	return nil
}

// Stop stops the packet forwarder
func (pf *PacketForwarder) Stop() error {
	pf.logger.Info("Stopping packet forwarder")
	close(pf.stopCh)
	return nil
}

// ForwardPacket forwards an IP packet through the mesh
func (pf *PacketForwarder) ForwardPacket(packetData []byte) error {
	// Parse IP packet
	packet, err := pf.parseIPPacket(packetData)
	if err != nil {
		pf.updateStats(func(s *ForwardingStats) { s.PacketsDropped++ })
		return fmt.Errorf("failed to parse IP packet: %w", err)
	}

	// Update statistics
	pf.updateStats(func(s *ForwardingStats) {
		s.PacketsReceived++
		s.LastActivity = time.Now()
	})

	// Parse network CIDR
	_, networkCIDR, err := net.ParseCIDR(pf.node.config.NetworkCIDR)
	if err != nil {
		return fmt.Errorf("invalid network CIDR: %w", err)
	}

	// Check if destination is in mesh network
	if !networkCIDR.Contains(packet.Destination) {
		// Route to exit node for internet access
		return pf.forwardToExitNode(packet)
	}

	// Route within mesh network
	return pf.forwardWithinMesh(packet)
}

// parseIPPacket parses raw IP packet data
func (pf *PacketForwarder) parseIPPacket(data []byte) (*IPPacket, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("packet too short for IP header")
	}

	// Parse IPv4 header
	version := data[0] >> 4
	if version != 4 {
		return nil, fmt.Errorf("unsupported IP version: %d", version)
	}

	packet := &IPPacket{
		Raw:         data,
		Protocol:    data[9],
		Length:      binary.BigEndian.Uint16(data[2:4]),
		Source:      net.IP(data[12:16]),
		Destination: net.IP(data[16:20]),
	}

	return packet, nil
}

// forwardWithinMesh forwards packet to another mesh peer
func (pf *PacketForwarder) forwardWithinMesh(packet *IPPacket) error {
	// Find next hop for destination
	nextHop := pf.findNextHop(packet.Destination)
	if nextHop == "" {
		pf.logger.WithField("dest", packet.Destination.String()).Warn("No route to destination")
		pf.updateStats(func(s *ForwardingStats) { s.PacketsDropped++ })
		return fmt.Errorf("no route to destination")
	}

	// Send packet to next hop peer
	return pf.sendPacketToPeer(nextHop, packet)
}

// forwardToExitNode forwards packet to an exit node for internet access
func (pf *PacketForwarder) forwardToExitNode(packet *IPPacket) error {
	// Find best exit node (simple round-robin for now)
	exitNode := pf.findBestExitNode()
	if exitNode == "" {
		pf.logger.Warn("No exit nodes available")
		pf.updateStats(func(s *ForwardingStats) { s.PacketsDropped++ })
		return fmt.Errorf("no exit nodes available")
	}

	return pf.sendPacketToPeer(exitNode, packet)
}

// sendPacketToPeer sends packet to a specific peer
func (pf *PacketForwarder) sendPacketToPeer(peerID string, packet *IPPacket) error {
	// Get peer client connection
	client, exists := pf.node.p2pDiscovery.GetPeerClient(peerID)
	if !exists {
		return fmt.Errorf("peer not connected: %s", peerID)
	}

	// Create packet request
	req := &pb.PacketRequest{
		SourceId:      pf.node.ID,
		DestId:        peerID,
		PacketType:    pb.PacketType_DATA,
		EncryptedData: packet.Raw,
		Timestamp:     timestamppb.New(time.Now()),
	}

	// Send via gRPC
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.SendPacket(ctx, req)
	if err != nil {
		pf.updateStats(func(s *ForwardingStats) { s.PacketsDropped++ })
		return fmt.Errorf("failed to send packet to peer: %w", err)
	}

	// Update statistics
	pf.updateStats(func(s *ForwardingStats) {
		s.PacketsForwarded++
		s.BytesForwarded += int64(len(packet.Raw))
	})

	pf.logger.WithFields(logrus.Fields{
		"dest_peer": peerID,
		"dest_ip":   packet.Destination.String(),
		"size":      len(packet.Raw),
	}).Debug("Packet forwarded successfully")

	return nil
}

// findNextHop finds the next hop peer for a destination IP
func (pf *PacketForwarder) findNextHop(destIP net.IP) string {
	pf.tableMutex.RLock()
	defer pf.tableMutex.RUnlock()

	// Direct lookup first
	if peerID, exists := pf.forwardingTable[destIP.String()]; exists {
		return peerID
	}

	// Find peer with matching mesh IP
	pf.node.peersMu.RLock()
	defer pf.node.peersMu.RUnlock()

	for peerID, peer := range pf.node.peers {
		if peer.MeshIP.Equal(destIP) {
			// Cache the route
			pf.tableMutex.RUnlock()
			pf.tableMutex.Lock()
			pf.forwardingTable[destIP.String()] = peerID
			pf.tableMutex.Unlock()
			pf.tableMutex.RLock()

			return peerID
		}
	}

	return ""
}

// findBestExitNode finds the best available exit node
func (pf *PacketForwarder) findBestExitNode() string {
	pf.node.peersMu.RLock()
	defer pf.node.peersMu.RUnlock()

	// Simple strategy: return first connected peer (can be enhanced with load balancing)
	for peerID, peer := range pf.node.peers {
		if peer.Connected {
			return peerID
		}
	}

	return ""
}

// processPackets processes incoming packets
func (pf *PacketForwarder) processPackets() {
	for {
		select {
		case <-pf.stopCh:
			return
		case packet := <-pf.incomingPackets:
			if err := pf.ForwardPacket(packet.Raw); err != nil {
				pf.logger.WithError(err).Warn("Failed to forward packet")
			}
		}
	}
}

// maintainForwardingTable periodically cleans up the forwarding table
func (pf *PacketForwarder) maintainForwardingTable() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-pf.stopCh:
			return
		case <-ticker.C:
			pf.cleanupForwardingTable()
		}
	}
}

// cleanupForwardingTable removes stale entries
func (pf *PacketForwarder) cleanupForwardingTable() {
	pf.tableMutex.Lock()
	defer pf.tableMutex.Unlock()

	pf.node.peersMu.RLock()
	defer pf.node.peersMu.RUnlock()

	// Remove entries for disconnected peers
	for destIP, peerID := range pf.forwardingTable {
		if peer, exists := pf.node.peers[peerID]; !exists || !peer.Connected {
			delete(pf.forwardingTable, destIP)
		}
	}

	pf.logger.WithField("table_size", len(pf.forwardingTable)).Debug("Cleaned up forwarding table")
}

// updateStats safely updates forwarding statistics
func (pf *PacketForwarder) updateStats(updater func(*ForwardingStats)) {
	pf.stats.mutex.Lock()
	defer pf.stats.mutex.Unlock()
	updater(pf.stats)
}

// GetStats returns current forwarding statistics
func (pf *PacketForwarder) GetStats() map[string]interface{} {
	pf.stats.mutex.RLock()
	defer pf.stats.mutex.RUnlock()

	return map[string]interface{}{
		"packets_received":      pf.stats.PacketsReceived,
		"packets_forwarded":     pf.stats.PacketsForwarded,
		"packets_dropped":       pf.stats.PacketsDropped,
		"bytes_forwarded":       pf.stats.BytesForwarded,
		"last_activity":         pf.stats.LastActivity,
		"forwarding_table_size": len(pf.forwardingTable),
	}
}

// ReceivePacket receives a packet for processing
func (pf *PacketForwarder) ReceivePacket(packet []byte) {
	ipPacket, err := pf.parseIPPacket(packet)
	if err != nil {
		pf.logger.WithError(err).Warn("Failed to parse received packet")
		return
	}

	select {
	case pf.incomingPackets <- ipPacket:
	default:
		pf.logger.Warn("Packet processing queue full, dropping packet")
		pf.updateStats(func(s *ForwardingStats) { s.PacketsDropped++ })
	}
}
