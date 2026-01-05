package mesh

import (
	"crypto/rand"
	"encoding/binary"
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

// PacketTransport defines the interface for peer connections
type PacketTransport interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
	SetReadDeadline(t time.Time) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

// PeerConnection represents a connection to a peer
type PeerConnection struct {
	PeerID       string
	LocalAddr    net.Addr
	RemoteAddr   net.Addr
	Conn         PacketTransport
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
	addr, err := net.ResolveUDPAddr("udp", stunServer)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// STUN Binding Request (RFC 5389)
	// Header: Type(2) + Length(2) + MagicCookie(4) + TransactionID(12)
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001)     // Binding Request
	binary.BigEndian.PutUint16(req[2:4], 0x0000)     // Length (0 for no attributes)
	binary.BigEndian.PutUint32(req[4:8], 0x2112A442) // Magic Cookie

	// Generate random transaction ID
	copy(req[8:20], generateTransactionID())

	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(resp)
	if err != nil {
		return nil, err
	}

	if n < 20 {
		return nil, fmt.Errorf("response too short")
	}

	// Validate Magic Cookie
	if binary.BigEndian.Uint32(resp[4:8]) != 0x2112A442 {
		return nil, fmt.Errorf("invalid magic cookie")
	}

	// Parse attributes to find mapped address
	respLen := binary.BigEndian.Uint16(resp[2:4])
	if int(respLen)+20 > n {
		return nil, fmt.Errorf("incomplete read")
	}

	attributes := resp[20 : 20+respLen]
	offset := 0
	for offset+4 <= len(attributes) {
		attrType := binary.BigEndian.Uint16(attributes[offset : offset+2])
		attrLen := binary.BigEndian.Uint16(attributes[offset+2 : offset+4])

		valOffset := offset + 4
		if valOffset+int(attrLen) > len(attributes) {
			break
		}
		value := attributes[valOffset : valOffset+int(attrLen)]

		// Check for XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
		if attrType == 0x0020 { // XOR-MAPPED-ADDRESS
			return parseXorMappedAddress(value)
		} else if attrType == 0x0001 { // MAPPED-ADDRESS
			return parseMappedAddress(value)
		}

		// Advance to next attribute (padded to 4 bytes boundary)
		pad := (4 - (attrLen % 4)) % 4
		offset += 4 + int(attrLen) + int(pad)
	}

	return nil, fmt.Errorf("mapped address attribute not found")
}

func generateTransactionID() []byte {
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		// Fallback if random fails (unlikely)
		return id
	}
	return id
}

func parseXorMappedAddress(val []byte) (*net.UDPAddr, error) {
	if len(val) < 8 {
		return nil, fmt.Errorf("invalid XOR-MAPPED-ADDRESS length")
	}
	// Family (1 byte), Port (2 bytes), Address (4 or 16 bytes)
	// Byte 0: Reserved (0)
	// Byte 1: Family (0x01 for IPv4, 0x02 for IPv6)
	family := val[1]

	port := binary.BigEndian.Uint16(val[2:4]) ^ 0x2112 // XOR with top 16 bits of Magic Cookie

	var ip net.IP
	if family == 0x01 { // IPv4
		ip = make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(val[4:8])^0x2112A442)
	} else if family == 0x02 { // IPv6
		// IPv6 XOR logic requires full transaction ID, omitting for brevity/IPv4 simplicity
		return nil, fmt.Errorf("IPv6 not fully supported in this snippet")
	} else {
		return nil, fmt.Errorf("unknown address family: %d", family)
	}

	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

func parseMappedAddress(val []byte) (*net.UDPAddr, error) {
	if len(val) < 8 {
		return nil, fmt.Errorf("invalid MAPPED-ADDRESS length")
	}
	family := val[1]
	port := binary.BigEndian.Uint16(val[2:4])

	var ip net.IP
	if family == 0x01 {
		ip = make(net.IP, 4)
		copy(ip, val[4:8])
	} else {
		return nil, fmt.Errorf("unsupported address family")
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
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
	nt.logger.WithField("peer_id", peerID).Debug("Attempting UDP hole punching")

	// Create local UDP socket
	localConn, err := net.ListenUDP("udp", nt.localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create local socket: %w", err)
	}

	holePunchPacket := []byte("AEGIS_HOLE_PUNCH")

	// Strategy: Send several packets to both endpoints with slight delays
	// This increases the chance that one side's NAT has opened a mapping
	// just as the other side's packet arrives.

	done := make(chan bool)
	foundAddr := make(chan *net.UDPAddr, 1)

	// Receiver routine
	go func() {
		buf := make([]byte, 1024)
		for {
			select {
			case <-done:
				return
			default:
				localConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				n, rAddr, err := localConn.ReadFromUDP(buf)
				if err == nil {
					msg := string(buf[:n])
					if msg == "AEGIS_HOLE_PUNCH" || msg == "AEGIS_HOLE_PUNCH_ACK" {
						// Found it!
						select {
						case foundAddr <- rAddr:
						default:
						}
						// Send Ack just in case
						localConn.WriteToUDP([]byte("AEGIS_HOLE_PUNCH_ACK"), rAddr)
						return
					}
				}
			}
		}
	}()

	// Sender routine
	go func() {
		for i := 0; i < 5; i++ {
			select {
			case <-done:
				return
			default:
				// Send to public
				localConn.WriteToUDP(holePunchPacket, peerInfo.PublicAddr)
				// Send to local (LAN optimization)
				if peerInfo.LocalAddr != nil {
					localConn.WriteToUDP(holePunchPacket, peerInfo.LocalAddr)
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
	}()

	// Wait for success or timeout
	select {
	case remoteAddr := <-foundAddr:
		close(done)

		// We have a working path. Convert to regular connection.
		// Note: net.DialUDP binds the socket to the remote address, so we can't accept from others anymore on this specialized conn object
		// But strictly speaking, for a P2P link, that's what we want.

		// However, we need to close the listener to "bind" effectively or reuse it.
		// Since we want to use 'localConn' which is already bound to localAddr,
		// we verify if we can 're-purpose' it or if we should just keep using ReadFromUDP/WriteToUDP
		// wrapped in a struct.

		// For this architecture, we'll create a new DialUDP which might pick a new ephemeral port if not careful,
		// BUT we want to reuse the hole we just punched.
		// So we should NOT close localConn if we want to keep the hole.
		// We need to upgrade this listener to a connected UDP socket if possible, or just wrap it.
		// In Go, File() allows conversion but it's complex.
		// Easiest is to keep using the PacketConn but wrapping it to look like a Conn for a specific peer.

		// IMPORTANT: The simplified Architecture expects a `*net.UDPConn` in PeerConnection which implements Read/Write.
		// A connected UDP socket (`DialUDP`) simplifies `Write` (no addr needed) and filters `Read`.
		// If we can't "connect" the existing socket easily, we might need a wrapper.

		// Let's try closing and immediately dialing from same local port.
		localConn.Close()

		conn, err := net.DialUDP("udp", nt.localAddr, remoteAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to convert to connection: %w", err)
		}

		return &PeerConnection{
			PeerID:       peerID,
			LocalAddr:    nt.localAddr,
			RemoteAddr:   remoteAddr,
			Conn:         conn,
			Connected:    true,
			HolePunched:  true,
			LastActivity: time.Now(),
		}, nil

	case <-time.After(3 * time.Second):
		close(done)
		localConn.Close()
		return nil, fmt.Errorf("hole punching timed out")
	}
}

func (nt *NATTraversal) tryTURNRelay(peerID string, peerInfo *PeerConnectionInfo) (*PeerConnection, error) {
	// TURN relay implementation placeholder
	// NOTE: A full TURN implementation requires a compliant client library (like pion/turn)
	// to handle Allocate, CreatePermission, and ChannelBind requests, as well as
	// authenticating with the TURN server using STUN Long-Term Credential mechanism.

	nt.logger.WithField("peer_id", peerID).Debug("Attempting TURN relay (Simplified)")

	if len(nt.turnServers) == 0 {
		return nil, fmt.Errorf("no TURN servers configured")
	}

	turnServer := nt.turnServers[0]
	serverAddr, err := net.ResolveUDPAddr("udp", turnServer)
	if err != nil {
		// Fallback logic
		if _, _, err := net.SplitHostPort(turnServer); err != nil {
			turnServer = turnServer + ":3478"
			serverAddr, err = net.ResolveUDPAddr("udp", turnServer)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to resolve TURN server: %w", err)
		}
	}

	conn, err := net.DialUDP("udp", nt.localAddr, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial TURN server: %w", err)
	}

	// FOR DEMO/TESTING ONLY:
	// We simulate a successful TURN allocation by just returning a wrapper.
	// In a production environment with a real TURN server, this connection would
	// immediately fail to relay traffic without proper authentication and allocation.

	// If the user provides a real TURN server, this will likely fail until the code
	// is updated to perform the TURN handshake.

	turnConn := &TurnConnection{
		Conn:       conn,
		RelayAddr:  serverAddr,
		PeerID:     peerID,
		ServerAddr: turnServer,
	}

	return &PeerConnection{
		PeerID:       peerID,
		LocalAddr:    nt.localAddr,
		RemoteAddr:   serverAddr,
		Conn:         turnConn,
		Connected:    true,
		RelayUsed:    true,
		LastActivity: time.Now(),
	}, nil
}

func (nt *NATTraversal) testConnection(conn PacketTransport) error {
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

// TurnConnection implements PacketTransport for TURN relayed connections
type TurnConnection struct {
	Conn       *net.UDPConn
	RelayAddr  *net.UDPAddr
	PeerID     string
	ServerAddr string
}

func (t *TurnConnection) Read(b []byte) (n int, err error) {
	return t.Conn.Read(b)
}

func (t *TurnConnection) Write(b []byte) (n int, err error) {
	// In a real TURN implementation, this would wrap the data in a Send Indication
	// For simulation/mock, we just write to the relay address
	return t.Conn.Write(b)
}

func (t *TurnConnection) Close() error {
	return t.Conn.Close()
}

func (t *TurnConnection) SetReadDeadline(tm time.Time) error {
	return t.Conn.SetReadDeadline(tm)
}

func (t *TurnConnection) LocalAddr() net.Addr {
	return t.Conn.LocalAddr()
}

func (t *TurnConnection) RemoteAddr() net.Addr {
	return t.RelayAddr
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
