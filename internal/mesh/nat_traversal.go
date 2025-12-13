package mesh

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// NATTraversal handles NAT traversal for peer-to-peer connections
type NATTraversal struct {
	node   *MeshNode
	logger *logrus.Logger

	// STUN/TURN servers
	stunServers []string
	turnServers []string

	// Local network info
	localAddr  *net.UDPAddr
	publicAddr *net.UDPAddr
	natType    NATType

	// Connection pool
	connections map[string]*PeerConnection
	connMu      sync.RWMutex

	// State
	running bool
	stopCh  chan struct{}
}

// PeerConnection represents a connection to a peer
type PeerConnection struct {
	PeerID       string
	LocalAddr    *net.UDPAddr
	RemoteAddr   *net.UDPAddr
	Conn         *net.UDPConn
	Connected    bool
	LastActivity time.Time

	// NAT traversal state
	HolePunched bool
	RelayUsed   bool

	mu sync.RWMutex
}

// NewNATTraversal creates a new NAT traversal manager
func NewNATTraversal(node *MeshNode, stunServers []string, turnServers []string) *NATTraversal {
	return &NATTraversal{
		node:        node,
		logger:      node.logger,
		stunServers: stunServers,
		turnServers: turnServers,
		connections: make(map[string]*PeerConnection),
		stopCh:      make(chan struct{}),
	}
}

// Start starts the NAT traversal service
func (nt *NATTraversal) Start() error {
	nt.logger.Info("Starting NAT traversal")
	nt.running = true

	// Discover local network configuration
	if err := nt.discoverNetworkConfig(); err != nil {
		return fmt.Errorf("failed to discover network config: %w", err)
	}

	// Determine NAT type
	if err := nt.determineNATType(); err != nil {
		nt.logger.WithError(err).Warn("Failed to determine NAT type, assuming restrictive")
		nt.natType = NATTypeSymmetric
	}

	nt.logger.WithFields(logrus.Fields{
		"local_addr":  nt.localAddr.String(),
		"public_addr": nt.publicAddr.String(),
		"nat_type":    nt.natType,
	}).Info("NAT traversal configuration discovered")

	// Start connection maintenance
	go nt.maintainConnections()

	return nil
}

// Stop stops the NAT traversal service
func (nt *NATTraversal) Stop() error {
	if !nt.running {
		return nil
	}

	nt.logger.Info("Stopping NAT traversal")
	nt.running = false
	close(nt.stopCh)

	// Close all connections
	nt.connMu.Lock()
	for _, conn := range nt.connections {
		if conn.Conn != nil {
			conn.Conn.Close()
		}
	}
	nt.connMu.Unlock()

	return nil
}

// EstablishConnection attempts to establish a P2P connection to a peer
func (nt *NATTraversal) EstablishConnection(peerID string, peerInfo *PeerConnectionInfo) (*PeerConnection, error) {
	nt.logger.WithFields(logrus.Fields{
		"peer_id":     peerID,
		"peer_public": peerInfo.PublicAddr.String(),
		"peer_local":  peerInfo.LocalAddr.String(),
	}).Info("Establishing P2P connection")

	// Try different connection methods in order of preference
	methods := []func(string, *PeerConnectionInfo) (*PeerConnection, error){
		nt.tryDirectConnection,
		nt.tryHolePunching,
		nt.tryTURNRelay,
	}

	for _, method := range methods {
		if conn, err := method(peerID, peerInfo); err == nil {
			nt.connMu.Lock()
			nt.connections[peerID] = conn
			nt.connMu.Unlock()

			// Start monitoring connection
			go nt.monitorConnection(conn)

			nt.logger.WithField("peer_id", peerID).Info("P2P connection established")
			return conn, nil
		} else {
			nt.logger.WithError(err).Debug("Connection method failed")
		}
	}

	return nil, fmt.Errorf("failed to establish connection to peer %s", peerID)
}

// GetConnection returns an existing connection to a peer
func (nt *NATTraversal) GetConnection(peerID string) (*PeerConnection, bool) {
	nt.connMu.RLock()
	defer nt.connMu.RUnlock()

	conn, exists := nt.connections[peerID]
	return conn, exists && conn.Connected
}

// SendPacket sends a packet to a peer
func (nt *NATTraversal) SendPacket(peerID string, packet []byte) error {
	conn, exists := nt.GetConnection(peerID)
	if !exists {
		return fmt.Errorf("no connection to peer %s", peerID)
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	_, err := conn.Conn.Write(packet)
	if err != nil {
		conn.Connected = false
		return fmt.Errorf("failed to send packet: %w", err)
	}

	conn.LastActivity = time.Now()
	return nil
}

// Private methods

func (nt *NATTraversal) discoverNetworkConfig() error {
	// Get local address
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return fmt.Errorf("failed to get local address: %w", err)
	}
	defer conn.Close()

	nt.localAddr = conn.LocalAddr().(*net.UDPAddr)

	// Check if we have STUN servers configured
	if len(nt.stunServers) == 0 {
		// Simulation mode - use local address as public address
		nt.logger.Info("Running in simulation mode, using local address as public address")
		nt.publicAddr = nt.localAddr
		return nil
	}

	// Use STUN to discover public address
	publicAddr, err := nt.stunDiscovery()
	if err != nil {
		// Fall back to local address for simulation
		nt.logger.WithError(err).Warn("STUN discovery failed, using local address as fallback")
		nt.publicAddr = nt.localAddr
		return nil
	}

	nt.publicAddr = publicAddr
	return nil
}

func (nt *NATTraversal) stunDiscovery() (*net.UDPAddr, error) {
	for _, stunServer := range nt.stunServers {
		if addr, err := nt.performSTUNRequest(stunServer); err == nil {
			return addr, nil
		}
	}
	return nil, fmt.Errorf("all STUN servers failed")
}

func (nt *NATTraversal) performSTUNRequest(stunServer string) (*net.UDPAddr, error) {
	// Simplified STUN implementation
	// In a real implementation, you'd use a proper STUN library

	conn, err := net.Dial("udp", stunServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send STUN binding request
	stunRequest := []byte{
		0x00, 0x01, // Message type: Binding Request
		0x00, 0x00, // Message length
		0x21, 0x12, 0xa4, 0x42, // Magic cookie
		// Transaction ID (12 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	_, err = conn.Write(stunRequest)
	if err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// Parse STUN response (simplified)
	if n < 20 {
		return nil, fmt.Errorf("invalid STUN response")
	}

	// Extract mapped address from response
	// This is a simplified implementation
	remoteAddr := conn.RemoteAddr().(*net.UDPAddr)
	return &net.UDPAddr{
		IP:   remoteAddr.IP,
		Port: nt.localAddr.Port, // Use local port for now
	}, nil
}

func (nt *NATTraversal) determineNATType() error {
	// Simplified NAT type detection
	// In a real implementation, you'd perform multiple STUN requests
	// to different servers to determine the exact NAT type

	if nt.localAddr.IP.Equal(nt.publicAddr.IP) {
		nt.natType = NATTypeNone
	} else if nt.localAddr.Port == nt.publicAddr.Port {
		nt.natType = NATTypeFullCone
	} else {
		nt.natType = NATTypeSymmetric
	}

	return nil
}

func (nt *NATTraversal) tryDirectConnection(peerID string, peerInfo *PeerConnectionInfo) (*PeerConnection, error) {
	// Try connecting directly to peer's public address
	conn, err := net.DialUDP("udp", nt.localAddr, peerInfo.PublicAddr)
	if err != nil {
		return nil, fmt.Errorf("direct connection failed: %w", err)
	}

	// Test connection
	if err := nt.testConnection(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("connection test failed: %w", err)
	}

	return &PeerConnection{
		PeerID:       peerID,
		LocalAddr:    nt.localAddr,
		RemoteAddr:   peerInfo.PublicAddr,
		Conn:         conn,
		Connected:    true,
		LastActivity: time.Now(),
	}, nil
}

func (nt *NATTraversal) tryHolePunching(peerID string, peerInfo *PeerConnectionInfo) (*PeerConnection, error) {
	// UDP hole punching implementation
	nt.logger.WithField("peer_id", peerID).Debug("Attempting UDP hole punching")

	// Create local UDP socket
	localConn, err := net.ListenUDP("udp", nt.localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create local socket: %w", err)
	}

	// Send hole punching packets to both public and local addresses
	holePunchPacket := []byte("AEGIS_HOLE_PUNCH")

	// Try peer's public address
	_, err1 := localConn.WriteToUDP(holePunchPacket, peerInfo.PublicAddr)

	// Try peer's local address (in case we're on the same network)
	_, err2 := localConn.WriteToUDP(holePunchPacket, peerInfo.LocalAddr)

	if err1 != nil && err2 != nil {
		localConn.Close()
		return nil, fmt.Errorf("hole punching failed")
	}

	// Wait for response
	localConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 1024)
	n, remoteAddr, err := localConn.ReadFromUDP(buffer)
	if err != nil {
		localConn.Close()
		return nil, fmt.Errorf("no response to hole punch: %w", err)
	}

	if string(buffer[:n]) != "AEGIS_HOLE_PUNCH_ACK" {
		localConn.Close()
		return nil, fmt.Errorf("invalid hole punch response")
	}

	// Convert to regular connection
	conn, err := net.DialUDP("udp", nt.localAddr, remoteAddr)
	if err != nil {
		localConn.Close()
		return nil, fmt.Errorf("failed to convert to connection: %w", err)
	}

	localConn.Close()

	return &PeerConnection{
		PeerID:       peerID,
		LocalAddr:    nt.localAddr,
		RemoteAddr:   remoteAddr,
		Conn:         conn,
		Connected:    true,
		HolePunched:  true,
		LastActivity: time.Now(),
	}, nil
}

func (nt *NATTraversal) tryTURNRelay(peerID string, peerInfo *PeerConnectionInfo) (*PeerConnection, error) {
	// TURN relay implementation (simplified)
	nt.logger.WithField("peer_id", peerID).Debug("Attempting TURN relay")

	if len(nt.turnServers) == 0 {
		return nil, fmt.Errorf("no TURN servers configured")
	}

	// TODO: Implement TURN relay protocol
	// For now, return error
	return nil, fmt.Errorf("TURN relay not implemented yet")
}

func (nt *NATTraversal) testConnection(conn *net.UDPConn) error {
	// Send test packet
	testPacket := []byte("AEGIS_TEST")
	_, err := conn.Write(testPacket)
	if err != nil {
		return err
	}

	// Wait for echo (simplified test)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	return err
}

func (nt *NATTraversal) maintainConnections() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			nt.performConnectionMaintenance()
		case <-nt.stopCh:
			return
		}
	}
}

func (nt *NATTraversal) performConnectionMaintenance() {
	nt.connMu.Lock()
	defer nt.connMu.Unlock()

	now := time.Now()
	for peerID, conn := range nt.connections {
		// Check for stale connections
		if now.Sub(conn.LastActivity) > 2*time.Minute {
			nt.logger.WithField("peer_id", peerID).Debug("Closing stale connection")
			conn.Connected = false
			if conn.Conn != nil {
				conn.Conn.Close()
			}
			delete(nt.connections, peerID)
		} else {
			// Send keepalive
			nt.sendKeepalive(conn)
		}
	}
}

func (nt *NATTraversal) sendKeepalive(conn *PeerConnection) {
	keepalive := []byte("AEGIS_KEEPALIVE")
	conn.Conn.Write(keepalive)
}

func (nt *NATTraversal) monitorConnection(conn *PeerConnection) {
	buffer := make([]byte, 65535)

	for conn.Connected {
		conn.Conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Conn.Read(buffer)
		if err != nil {
			conn.Connected = false
			break
		}

		conn.LastActivity = time.Now()

		// Process received packet
		nt.handleReceivedPacket(conn.PeerID, buffer[:n])
	}
}

func (nt *NATTraversal) handleReceivedPacket(peerID string, packet []byte) {
	// Forward packet to mesh node for processing
	meshPacket := &MeshPacket{
		SourceID:   peerID,
		DestID:     nt.node.ID,
		PacketType: DataPacket,
		Payload:    packet,
		Timestamp:  time.Now(),
	}

	select {
	case nt.node.meshPackets <- meshPacket:
	default:
		nt.logger.Warn("Mesh packet queue full, dropping packet")
	}
}

// Data structures

type PeerConnectionInfo struct {
	PublicAddr *net.UDPAddr
	LocalAddr  *net.UDPAddr
	NATType    NATType
}
