package mesh

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/aegisray/vpn-tunnel/internal/certs"
	"github.com/aegisray/vpn-tunnel/internal/config"
	"github.com/aegisray/vpn-tunnel/internal/crypto"
	"github.com/aegisray/vpn-tunnel/internal/sni"
	pb "github.com/aegisray/vpn-tunnel/proto/mesh"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// MeshNode represents a node in the AegisRay mesh network
type MeshNode struct {
	// Node Identity
	ID         string
	PublicKey  string
	PrivateKey string

	// Network Configuration
	MeshIP     net.IP
	ListenPort int

	// Peer Management
	peers   map[string]*Peer
	peersMu sync.RWMutex

	// Services
	grpcServer   *grpc.Server
	coordinator  *Coordinator
	natTraversal *NATTraversal
	sniFaker     *sni.SNIFaker
	encryption   *crypto.EncryptionManager
	certMgr      *certs.CertificateManager

	// State
	running bool
	config  *config.MeshConfig
	logger  *logrus.Logger

	// Channels
	peerUpdates chan *PeerUpdate
	meshPackets chan *MeshPacket
	stopCh      chan struct{}
}

// Peer represents a peer in the mesh network
type Peer struct {
	ID            string
	PublicKey     string
	MeshIP        net.IP
	Endpoint      *net.UDPAddr
	AllowedIPs    []*net.IPNet
	LastHandshake time.Time
	LastSeen      time.Time

	// Connection State
	Connected  bool
	Latency    time.Duration
	PacketLoss float64

	// NAT Traversal
	NATType    NATType
	PublicAddr *net.UDPAddr
	LocalAddr  *net.UDPAddr

	// Security
	SessionKey  []byte
	KeyRotation time.Time

	mu sync.RWMutex
}

// PeerUpdate represents a peer state change
type PeerUpdate struct {
	Type   PeerUpdateType
	Peer   *Peer
	Reason string
}

// MeshPacket represents a packet in the mesh network
type MeshPacket struct {
	SourceID   string
	DestID     string
	PacketType PacketType
	Payload    []byte
	Encrypted  bool
	Timestamp  time.Time
}

// PeerUpdateType represents types of peer updates
type PeerUpdateType int

const (
	PeerJoined PeerUpdateType = iota
	PeerLeft
	PeerUpdated
	PeerConnected
	PeerDisconnected
)

// PacketType represents types of mesh packets
type PacketType int

const (
	DataPacket PacketType = iota
	ControlPacket
	HeartbeatPacket
	KeyExchangePacket
	RouteAdvertisement
)

// NATType represents different NAT types
type NATType int

const (
	NATTypeUnknown        NATType = iota
	NATTypeNone                   // Direct connection
	NATTypeFullCone               // Easy to traverse
	NATTypeRestrictedCone         // Moderate difficulty
	NATTypePortRestricted         // Hard to traverse
	NATTypeSymmetric              // Very hard to traverse
)

// NewMeshNode creates a new mesh network node
func NewMeshNode(cfg *config.MeshConfig) (*MeshNode, error) {
	// Generate node ID
	nodeID, err := generateNodeID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate node ID: %w", err)
	}

	// Create encryption manager
	encryption, err := crypto.NewEncryptionManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption manager: %w", err)
	}

	// Get public key
	publicKey, err := encryption.GetPublicKeyPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Setup logger
	logger := logrus.New()
	if level, err := logrus.ParseLevel(cfg.LogLevel); err == nil {
		logger.SetLevel(level)
	}

	// Parse mesh IP
	meshIP := net.ParseIP(cfg.MeshIP)
	if meshIP == nil {
		return nil, fmt.Errorf("invalid mesh IP: %s", cfg.MeshIP)
	}

	node := &MeshNode{
		ID:          nodeID,
		PublicKey:   publicKey,
		MeshIP:      meshIP,
		ListenPort:  cfg.ListenPort,
		peers:       make(map[string]*Peer),
		encryption:  encryption,
		config:      cfg,
		logger:      logger,
		peerUpdates: make(chan *PeerUpdate, 100),
		meshPackets: make(chan *MeshPacket, 1000),
		stopCh:      make(chan struct{}),
	}

	// Initialize SNI faker for stealth
	node.sniFaker = sni.NewSNIFaker(cfg.StealthDomains...)

	// Initialize certificate manager
	if cfg.UseTLS {
		node.certMgr = certs.NewCertificateManager(cfg.CertFile, cfg.KeyFile)
	}

	// Initialize NAT traversal
	node.natTraversal = NewNATTraversal(node)

	// Initialize coordinator (handles peer discovery and coordination)
	node.coordinator = NewCoordinator(node, cfg.Coordinators)

	return node, nil
}

// Start starts the mesh node
func (n *MeshNode) Start() error {
	n.logger.WithFields(logrus.Fields{
		"node_id": n.ID,
		"mesh_ip": n.MeshIP.String(),
		"port":    n.ListenPort,
	}).Info("Starting mesh node")

	n.running = true

	// Start gRPC server for peer communication
	if err := n.startGRPCServer(); err != nil {
		return fmt.Errorf("failed to start gRPC server: %w", err)
	}

	// Start NAT traversal
	if err := n.natTraversal.Start(); err != nil {
		return fmt.Errorf("failed to start NAT traversal: %w", err)
	}

	// Connect to coordinators for initial peer discovery
	if err := n.coordinator.Start(); err != nil {
		return fmt.Errorf("failed to start coordinator: %w", err)
	}

	// Start background routines
	go n.handlePeerUpdates()
	go n.handleMeshPackets()
	go n.maintainPeers()
	go n.rotateKeys()

	n.logger.Info("Mesh node started successfully")
	return nil
}

// Stop stops the mesh node
func (n *MeshNode) Stop() error {
	if !n.running {
		return nil
	}

	n.logger.Info("Stopping mesh node")
	n.running = false

	// Signal stop to all goroutines
	close(n.stopCh)

	// Stop services
	if n.coordinator != nil {
		n.coordinator.Stop()
	}

	if n.natTraversal != nil {
		n.natTraversal.Stop()
	}

	if n.grpcServer != nil {
		n.grpcServer.GracefulStop()
	}

	// Disconnect from all peers
	n.peersMu.Lock()
	for _, peer := range n.peers {
		n.disconnectPeerUnsafe(peer)
	}
	n.peersMu.Unlock()

	n.logger.Info("Mesh node stopped")
	return nil
}

// AddPeer adds a new peer to the mesh
func (n *MeshNode) AddPeer(peerInfo *PeerInfo) error {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()

	if _, exists := n.peers[peerInfo.ID]; exists {
		return fmt.Errorf("peer %s already exists", peerInfo.ID)
	}

	peer := &Peer{
		ID:         peerInfo.ID,
		PublicKey:  peerInfo.PublicKey,
		MeshIP:     net.ParseIP(peerInfo.MeshIP),
		Endpoint:   peerInfo.Endpoint,
		AllowedIPs: peerInfo.AllowedIPs,
		LastSeen:   time.Now(),
	}

	n.peers[peerInfo.ID] = peer

	// Notify about new peer
	select {
	case n.peerUpdates <- &PeerUpdate{Type: PeerJoined, Peer: peer}:
	default:
		n.logger.Warn("Peer update channel full")
	}

	n.logger.WithField("peer_id", peerInfo.ID).Info("Added peer")
	return nil
}

// RemovePeer removes a peer from the mesh
func (n *MeshNode) RemovePeer(peerID string) error {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()

	peer, exists := n.peers[peerID]
	if !exists {
		return fmt.Errorf("peer %s not found", peerID)
	}

	n.disconnectPeerUnsafe(peer)
	delete(n.peers, peerID)

	// Notify about peer removal
	select {
	case n.peerUpdates <- &PeerUpdate{Type: PeerLeft, Peer: peer}:
	default:
		n.logger.Warn("Peer update channel full")
	}

	n.logger.WithField("peer_id", peerID).Info("Removed peer")
	return nil
}

// SendPacket sends a packet through the mesh
func (n *MeshNode) SendPacket(destIP net.IP, packet []byte) error {
	// Find peer by mesh IP
	var targetPeer *Peer

	n.peersMu.RLock()
	for _, peer := range n.peers {
		if peer.MeshIP.Equal(destIP) {
			targetPeer = peer
			break
		}

		// Check if destination is in peer's allowed IPs
		for _, allowedNet := range peer.AllowedIPs {
			if allowedNet.Contains(destIP) {
				targetPeer = peer
				break
			}
		}
	}
	n.peersMu.RUnlock()

	if targetPeer == nil {
		return fmt.Errorf("no route to destination %s", destIP.String())
	}

	// Encrypt packet
	encryptedPacket, err := n.encryption.Encrypt(packet)
	if err != nil {
		return fmt.Errorf("failed to encrypt packet: %w", err)
	}

	// Create mesh packet
	meshPacket := &MeshPacket{
		SourceID:   n.ID,
		DestID:     targetPeer.ID,
		PacketType: DataPacket,
		Payload:    encryptedPacket,
		Encrypted:  true,
		Timestamp:  time.Now(),
	}

	// Send through mesh
	select {
	case n.meshPackets <- meshPacket:
		return nil
	default:
		return fmt.Errorf("mesh packet queue full")
	}
}

// GetPeers returns a list of all peers
func (n *MeshNode) GetPeers() []*Peer {
	n.peersMu.RLock()
	defer n.peersMu.RUnlock()

	peers := make([]*Peer, 0, len(n.peers))
	for _, peer := range n.peers {
		peers = append(peers, peer)
	}

	return peers
}

// GetNodeInfo returns information about this node
func (n *MeshNode) GetNodeInfo() *NodeInfo {
	return &NodeInfo{
		ID:         n.ID,
		PublicKey:  n.PublicKey,
		MeshIP:     n.MeshIP.String(),
		ListenPort: n.ListenPort,
		PeerCount:  len(n.peers),
	}
}

// Private methods

func (n *MeshNode) startGRPCServer() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", n.ListenPort))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	var opts []grpc.ServerOption

	if n.config.UseTLS && n.certMgr != nil {
		tlsConfig := n.certMgr.GetServerTLSConfig()
		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.Creds(creds))
	}

	n.grpcServer = grpc.NewServer(opts...)
	pb.RegisterMeshServiceServer(n.grpcServer, n)

	go func() {
		if err := n.grpcServer.Serve(lis); err != nil {
			n.logger.WithError(err).Error("gRPC server error")
		}
	}()

	return nil
}

func (n *MeshNode) handlePeerUpdates() {
	for {
		select {
		case update := <-n.peerUpdates:
			n.processPeerUpdate(update)
		case <-n.stopCh:
			return
		}
	}
}

func (n *MeshNode) handleMeshPackets() {
	for {
		select {
		case packet := <-n.meshPackets:
			n.processMeshPacket(packet)
		case <-n.stopCh:
			return
		}
	}
}

func (n *MeshNode) maintainPeers() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			n.performPeerMaintenance()
		case <-n.stopCh:
			return
		}
	}
}

func (n *MeshNode) rotateKeys() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			n.performKeyRotation()
		case <-n.stopCh:
			return
		}
	}
}

func (n *MeshNode) processPeerUpdate(update *PeerUpdate) {
	n.logger.WithFields(logrus.Fields{
		"peer_id": update.Peer.ID,
		"type":    update.Type,
		"reason":  update.Reason,
	}).Debug("Processing peer update")

	switch update.Type {
	case PeerJoined:
		n.handlePeerJoined(update.Peer)
	case PeerLeft:
		n.handlePeerLeft(update.Peer)
	case PeerConnected:
		n.handlePeerConnected(update.Peer)
	case PeerDisconnected:
		n.handlePeerDisconnected(update.Peer)
	}
}

func (n *MeshNode) processMeshPacket(packet *MeshPacket) {
	n.logger.WithFields(logrus.Fields{
		"source": packet.SourceID,
		"dest":   packet.DestID,
		"type":   packet.PacketType,
		"size":   len(packet.Payload),
	}).Debug("Processing mesh packet")

	// TODO: Implement packet processing based on type
	switch packet.PacketType {
	case DataPacket:
		n.handleDataPacket(packet)
	case ControlPacket:
		n.handleControlPacket(packet)
	case HeartbeatPacket:
		n.handleHeartbeatPacket(packet)
	case KeyExchangePacket:
		n.handleKeyExchangePacket(packet)
	}
}

func (n *MeshNode) performPeerMaintenance() {
	n.peersMu.RLock()
	defer n.peersMu.RUnlock()

	now := time.Now()
	for _, peer := range n.peers {
		// Check for stale peers
		if now.Sub(peer.LastSeen) > 5*time.Minute {
			peer.Connected = false
			// TODO: Attempt reconnection
		}

		// Send heartbeat
		n.sendHeartbeatToPeer(peer)
	}
}

func (n *MeshNode) performKeyRotation() {
	// TODO: Implement key rotation logic
	n.logger.Debug("Performing key rotation")
}

func (n *MeshNode) disconnectPeerUnsafe(peer *Peer) {
	peer.Connected = false
	// TODO: Close connections, cleanup state
}

func (n *MeshNode) handlePeerJoined(peer *Peer) {
	// TODO: Implement peer join logic
}

func (n *MeshNode) handlePeerLeft(peer *Peer) {
	// TODO: Implement peer leave logic
}

func (n *MeshNode) handlePeerConnected(peer *Peer) {
	// TODO: Implement peer connection logic
}

func (n *MeshNode) handlePeerDisconnected(peer *Peer) {
	// TODO: Implement peer disconnection logic
}

func (n *MeshNode) handleDataPacket(packet *MeshPacket) {
	// TODO: Decrypt and forward data packet
}

func (n *MeshNode) handleControlPacket(packet *MeshPacket) {
	// TODO: Process control packet
}

func (n *MeshNode) handleHeartbeatPacket(packet *MeshPacket) {
	// TODO: Process heartbeat
}

func (n *MeshNode) handleKeyExchangePacket(packet *MeshPacket) {
	// TODO: Process key exchange
}

func (n *MeshNode) sendHeartbeatToPeer(peer *Peer) {
	// TODO: Send heartbeat to peer
}

// Helper functions

func generateNodeID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Data structures for external interfaces

type PeerInfo struct {
	ID         string
	PublicKey  string
	MeshIP     string
	Endpoint   *net.UDPAddr
	AllowedIPs []*net.IPNet
}

type NodeInfo struct {
	ID         string
	PublicKey  string
	MeshIP     string
	ListenPort int
	PeerCount  int
}
