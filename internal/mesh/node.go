package mesh

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/surya-d-naidu/AegisRay/internal/certs"
	"github.com/surya-d-naidu/AegisRay/internal/config"
	"github.com/surya-d-naidu/AegisRay/internal/crypto"
	"github.com/surya-d-naidu/AegisRay/internal/sni"
	"github.com/surya-d-naidu/AegisRay/internal/trust"
	pb "github.com/surya-d-naidu/AegisRay/proto/mesh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MeshNode represents a node in the AegisRay mesh network
type MeshNode struct {
	pb.UnimplementedMeshServiceServer

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
	grpcServer      *grpc.Server
	httpServer      *HTTPServer
	p2pDiscovery    *P2PDiscovery
	meshRouter      *MeshRouter
	natTraversal    *NATTraversal
	sniFaker        *sni.SNIFaker
	encryption      *crypto.EncryptionManager
	certMgr         *certs.CertificateManager
	tunInterface    *TUNInterface
	packetForwarder *PacketForwarder
	trustPolicy     *trust.Policy

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
	SessionKey          []byte
	KeyRotation         time.Time
	PendingEphemeralKey *ecdh.PrivateKey // For ECDH Handshake

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
	Metadata   *pb.PacketMetadata
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

const (
	KeyRotationInterval = 1 * time.Hour
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
	// Setup logger
	logger := logrus.New()
	if level, err := logrus.ParseLevel(cfg.LogLevel); err == nil {
		logger.SetLevel(level)
	}

	// Load or generate long-term Ed25519 identity key
	var identityKey ed25519.PrivateKey
	if cfg.IdentityKeyFile != "" {
		loadedKey, err := crypto.LoadIdentityKey(cfg.IdentityKeyFile)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to load identity key: %w", err)
			}
		} else {
			identityKey = loadedKey
		}
	}

	// Create encryption manager
	encryption, err := crypto.NewEncryptionManager(identityKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption manager: %w", err)
	}

	trustPolicy, err := trust.LoadPolicy(cfg.NetworkName, cfg.TrustRootPublicKeyFile, cfg.AuthorizedPeersFile, cfg.AuthorizedPeerKeys, cfg.AllowUnauthenticated)
	if err != nil {
		return nil, fmt.Errorf("failed to load trust policy: %w", err)
	}

	// If we generated a new key and have a persistence path, save it
	if len(identityKey) == 0 && cfg.IdentityKeyFile != "" {
		if err := crypto.SaveIdentityKey(encryption.GetPrivateKey(), cfg.IdentityKeyFile); err != nil {
			logger.WithError(err).Warn("Failed to persist identity key")
		} else {
			logger.WithField("path", cfg.IdentityKeyFile).Info("Persisted new identity key")
		}
	}

	// Get public key
	publicKey, err := encryption.GetPublicKeyPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Generate node ID from public key
	nodeID := generateNodeID(string(publicKey))

	// Parse mesh IP (auto-assign if empty for clients)
	var meshIP net.IP
	if cfg.MeshIP == "" {
		// Auto-assign IP for clients from network CIDR
		logger.Info("Auto-assigning mesh IP for client node")
		autoIPStr, err := cfg.GetNodeMeshIP(nodeID)
		if err != nil {
			return nil, fmt.Errorf("failed to auto-assign mesh IP: %w", err)
		}
		autoIP := net.ParseIP(autoIPStr)
		meshIP = autoIP
	} else {
		meshIP = net.ParseIP(cfg.MeshIP)
		if meshIP == nil {
			return nil, fmt.Errorf("invalid mesh IP: %s", cfg.MeshIP)
		}
	}

	node := &MeshNode{
		ID:          nodeID,
		PublicKey:   string(publicKey),
		MeshIP:      meshIP,
		ListenPort:  cfg.ListenPort,
		peers:       make(map[string]*Peer),
		encryption:  encryption,
		trustPolicy: trustPolicy,
		config:      cfg,
		logger:      logger,
		peerUpdates: make(chan *PeerUpdate, 100),
		meshPackets: make(chan *MeshPacket, 1000),
		stopCh:      make(chan struct{}),
	}

	// Initialize SNI faker for stealth
	node.sniFaker = sni.NewSNIFaker(cfg.StealthDomains...)

	// Initialize certificate manager and load/generate certificate
	if cfg.UseTLS {
		node.certMgr = certs.NewCertificateManager(cfg.CertFile, cfg.KeyFile, encryption.GetPrivateKey())

		// Load or generate certificate
		hosts := []string{"localhost", "127.0.0.1", meshIP.String()}
		if _, err := node.certMgr.LoadOrGenerateCertificate(hosts); err != nil {
			return nil, fmt.Errorf("failed to setup certificate: %w", err)
		}
	}

	// Initialize NAT traversal
	node.natTraversal = NewNATTraversal(node, cfg.STUNServers, cfg.TURNServers)

	// Initialize P2P discovery (replaces centralized coordinator)
	node.p2pDiscovery = NewP2PDiscovery(node, cfg.StaticPeers)

	// Initialize mesh router for traffic routing
	node.meshRouter = NewMeshRouter(node)

	// Initialize HTTP API server
	node.httpServer = NewHTTPServer(node, cfg.APIBindAddress, cfg.APIPort)

	// Initialize TUN interface for IP traffic
	if cfg.EnableTUN {
		tun, err := NewTUNInterface(node.MeshIP, cfg.NetworkCIDR, cfg.DefaultRoute, cfg.MTU, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create TUN interface: %w", err)
		}
		node.tunInterface = tun
	}

	// Initialize packet forwarder
	node.packetForwarder = NewPacketForwarder(node)

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

	// Start P2P discovery for peer-to-peer mesh networking
	if err := n.p2pDiscovery.Start(); err != nil {
		return fmt.Errorf("failed to start P2P discovery: %w", err)
	}

	// Start mesh router for traffic routing
	if err := n.meshRouter.Start(); err != nil {
		return fmt.Errorf("failed to start mesh router: %w", err)
	}

	// Start packet forwarder
	if err := n.packetForwarder.Start(); err != nil {
		return fmt.Errorf("failed to start packet forwarder: %w", err)
	}

	// Start TUN interface if enabled
	if n.tunInterface != nil {
		if err := n.tunInterface.Start(); err != nil {
			return fmt.Errorf("failed to start TUN interface: %w", err)
		}

		// Connect TUN interface to packet forwarder
		go n.bridgeTUNToMesh()
	}

	// Start HTTP API server
	if err := n.httpServer.Start(); err != nil {
		return fmt.Errorf("failed to start HTTP server: %w", err)
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
	if n.httpServer != nil {
		n.httpServer.Stop()
	}

	if n.tunInterface != nil {
		n.tunInterface.Stop()
	}

	if n.packetForwarder != nil {
		n.packetForwarder.Stop()
	}

	if n.p2pDiscovery != nil {
		n.p2pDiscovery.Stop()
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
	if !n.isPeerAuthorized(peerInfo.ID, peerInfo.PublicKey) {
		return fmt.Errorf("peer %s is not authorized", peerInfo.ID)
	}

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

// SendMeshPacket sends a packet through the mesh
func (n *MeshNode) SendMeshPacket(destIP net.IP, packet []byte) error {
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

	// Encrypt packet with peer-specific session key
	encryptedPacket, err := n.encryption.PeerEncrypt(targetPeer.ID, packet)
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

	// Route through mesh router
	return n.meshRouter.RoutePacket(meshPacket)
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
	// Create a snapshot of peers to avoid holding the lock during reconnection attempts
	peers := make([]*Peer, 0, len(n.peers))
	for _, peer := range n.peers {
		peers = append(peers, peer)
	}
	n.peersMu.RUnlock()

	now := time.Now()
	for _, peer := range peers {
		peer.mu.Lock()
		isStale := now.Sub(peer.LastSeen) > 5*time.Minute
		isConnected := peer.Connected
		peerID := peer.ID
		peer.mu.Unlock()

		if isStale {
			if isConnected {
				n.logger.WithField("peer_id", peerID).Warn("Peer is stale, marking disconnected")
				peer.mu.Lock()
				peer.Connected = false
				peer.mu.Unlock()
			}
			// Attempt reconnection for stale or disconnected peers
			go n.AttemptPeerReconnection(peer)
		}

		// Also send heartbeats to active peers
		if isConnected {
			n.sendHeartbeatToPeer(peer)
		}
	}
}

// AttemptPeerReconnection attempts to reconnect to a lost peer
func (n *MeshNode) AttemptPeerReconnection(peer *Peer) {
	peer.mu.RLock()
	peerID := peer.ID
	endpoint := peer.Endpoint
	publicAddr := peer.PublicAddr
	peer.mu.RUnlock()

	n.logger.WithField("peer_id", peerID).Info("Attempting to reconnect to peer")

	// 1. Try last known direct endpoint
	if endpoint != nil {
		if err := n.p2pDiscovery.connectToPeer(endpoint.String()); err == nil {
			n.logger.WithField("peer_id", peerID).Info("Successfully reconnected via direct endpoint")
			return
		}
	}

	// 2. Try last known public address
	if publicAddr != nil && (endpoint == nil || publicAddr.String() != endpoint.String()) {
		if err := n.p2pDiscovery.connectToPeer(publicAddr.String()); err == nil {
			n.logger.WithField("peer_id", peerID).Info("Successfully reconnected via public address")
			return
		}
	}

	// 3. Try NAT Traversal fallback if enabled
	if n.natTraversal != nil {
		n.logger.WithField("peer_id", peerID).Debug("Triggering NAT traversal fallback for reconnection")
		// We can't call tryHolePunching directly as it needs PeerConnectionInfo
		// but P2PDiscovery might have it.
		// For now, we'll rely on the node's background discovery to find it again.
	}
}

func (n *MeshNode) performKeyRotation() {
	n.peersMu.RLock()
	peers := make([]*Peer, 0, len(n.peers))
	for _, peer := range n.peers {
		peers = append(peers, peer)
	}
	n.peersMu.RUnlock()

	now := time.Now()
	for _, peer := range peers {
		peer.mu.RLock()
		if !peer.Connected {
			peer.mu.RUnlock()
			continue
		}
		needsRotation := now.Sub(peer.KeyRotation) > KeyRotationInterval
		peer.mu.RUnlock()

		if needsRotation {
			n.logger.WithField("peer_id", peer.ID).Info("Starting periodic key rotation")
			go n.sendKeyExchange(peer)
		}
	}
}

func (n *MeshNode) disconnectPeerUnsafe(peer *Peer) {
	peer.Connected = false
	// Close any active connections or streams if stored
	n.logger.WithField("peer_id", peer.ID).Debug("Disconnected peer")
}

func (n *MeshNode) handlePeerJoined(peer *Peer) {
	n.logger.WithField("peer_id", peer.ID).Info("Peer joined mesh")
	go n.sendHeartbeatToPeer(peer)

	// Initiate key exchange if we are the "initiator" or just to be safe
	// In P2P, both can send, the last one wins or we use a deterministic priority (e.g. ID comparison)
	if n.ID < peer.ID {
		go n.sendKeyExchange(peer)
	}
}

func (n *MeshNode) handlePeerLeft(peer *Peer) {
	n.logger.WithField("peer_id", peer.ID).Info("Peer left mesh")
	n.disconnectPeerUnsafe(peer)
}

func (n *MeshNode) handlePeerConnected(peer *Peer) {
	peer.mu.Lock()
	peer.Connected = true
	peer.LastSeen = time.Now()
	peer.mu.Unlock()
	n.logger.WithField("peer_id", peer.ID).Info("Peer connected")
}

func (n *MeshNode) handlePeerDisconnected(peer *Peer) {
	peer.mu.Lock()
	peer.Connected = false
	peer.mu.Unlock()
	n.logger.WithField("peer_id", peer.ID).Info("Peer disconnected")
}

func (n *MeshNode) handleDataPacket(packet *MeshPacket) {
	// Verify destination is us
	if packet.DestID != n.ID {
		// If not for us, route it
		if err := n.meshRouter.RoutePacket(packet); err != nil {
			n.logger.WithError(err).Warn("Failed to route misdirected packet")
		}
		return
	}

	// Decrypt payload with peer-specific session key
	data, err := n.encryption.PeerDecrypt(packet.SourceID, packet.Payload)
	if err != nil {
		n.logger.WithError(err).WithField("source", packet.SourceID).Error("Failed to decrypt data packet")
		return
	}

	// Write to TUN interface
	if n.tunInterface != nil {
		n.tunInterface.SendPacket(data)
	}
}

func (n *MeshNode) handleControlPacket(packet *MeshPacket) {
	// Process control messages (e.g. key exchange initiation, etc)
	n.logger.WithField("source", packet.SourceID).Debug("Received control packet")
}

func (n *MeshNode) handleHeartbeatPacket(packet *MeshPacket) {
	n.peersMu.RLock()
	peer, exists := n.peers[packet.SourceID]
	n.peersMu.RUnlock()

	if exists {
		peer.mu.Lock()
		peer.LastSeen = time.Now()
		if !packet.Timestamp.IsZero() {
			peer.Latency = time.Since(packet.Timestamp)
		}
		peer.Connected = true
		peer.mu.Unlock()

		if n.p2pDiscovery != nil {
			n.p2pDiscovery.markPeerSeen(packet.SourceID)
		}
	}
}

func (n *MeshNode) handleKeyExchangePacket(packet *MeshPacket) {
	n.logger.WithField("source", packet.SourceID).Debug("Received key exchange packet")

	n.peersMu.RLock()
	peer, exists := n.peers[packet.SourceID]
	n.peersMu.RUnlock()

	if !exists {
		n.logger.WithField("source", packet.SourceID).Warn("Received key exchange from unknown peer")
		return
	}

	// The payload is [SignatureLen(4 bytes)][Signature][Pubkey(32 bytes)] for ECDH
	if len(packet.Payload) < 4 {
		return
	}
	sigLen := binary.BigEndian.Uint32(packet.Payload[:4])
	if uint32(len(packet.Payload)) < 4+sigLen {
		return
	}
	signature := packet.Payload[4 : 4+sigLen]
	peerPubKeyBytes := packet.Payload[4+sigLen:]

	// 1. Verify signature using peer's Ed25519 identity key (Authenticity)
	if err := crypto.Verify(peerPubKeyBytes, signature, []byte(peer.PublicKey)); err != nil {
		n.logger.WithError(err).WithField("source", packet.SourceID).Error("Key exchange signature verification failed")
		return
	}

	// 2. ECDH Key Agreement (Forward Secrecy)
	peer.mu.Lock()

	// Determine our private key for this exchange
	var myPrivKey *ecdh.PrivateKey

	if peer.PendingEphemeralKey != nil {
		// We initiated this exchange, use our pending key
		myPrivKey = peer.PendingEphemeralKey
		// Clear pending key to prevent reuse
		peer.PendingEphemeralKey = nil
	} else {
		// We are responder, generate a new ephemeral key pair
		var err error
		myPrivKey, _, err = crypto.GenerateEphemeralKey()
		if err != nil {
			peer.mu.Unlock()
			n.logger.WithError(err).Error("Failed to generate ephemeral key for response")
			return
		}

		// Send our public key back to complete the exchange
		go n.sendEphemeralKey(peer, myPrivKey)
	}
	peer.mu.Unlock()

	// 3. Derive Shared Session Key
	sessionKey, err := crypto.DeriveSharedKey(myPrivKey, peerPubKeyBytes)
	if err != nil {
		n.logger.WithError(err).Error("Failed to derive session key")
		return
	}

	// 4. Install the session key
	if err := n.encryption.SetPeerKey(packet.SourceID, sessionKey); err != nil {
		n.logger.WithError(err).Error("Failed to install session key")
		return
	}

	peer.mu.Lock()
	peer.KeyRotation = time.Now()
	peer.mu.Unlock()

	n.logger.WithField("peer_id", packet.SourceID).Info("Successfully established secure session key via ECDH")
}

func (n *MeshNode) sendKeyExchange(peer *Peer) {
	n.logger.WithField("peer_id", peer.ID).Info("Initiating key exchange")

	// 1. Generate a new ephemeral key pair
	privKey, _, err := crypto.GenerateEphemeralKey()
	if err != nil {
		n.logger.WithError(err).Error("Failed to generate ephemeral key")
		return
	}

	// Store pending key
	peer.mu.Lock()
	peer.PendingEphemeralKey = privKey
	peer.mu.Unlock()

	// 2. Send public key
	n.sendEphemeralKey(peer, privKey)
}

func (n *MeshNode) sendEphemeralKey(peer *Peer, privKey *ecdh.PrivateKey) {
	pubKeyBytes := privKey.PublicKey().Bytes()

	// 1. Sign our public key with our Ed25519 private key (Authentication)
	signature, err := n.encryption.Sign(pubKeyBytes)
	if err != nil {
		n.logger.WithError(err).Error("Failed to sign ephemeral key")
		return
	}

	// 2. Construct payload: [SigLen][Signature][PubKey]
	payload := make([]byte, 4+len(signature)+len(pubKeyBytes))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(signature)))
	copy(payload[4:], signature)
	copy(payload[4+len(signature):], pubKeyBytes)

	// 3. Send via MeshService
	client, exists := n.p2pDiscovery.GetPeerClient(peer.ID)
	if !exists {
		return
	}

	req := &pb.PacketRequest{
		SourceId:      n.ID,
		DestId:        peer.ID,
		PacketType:    pb.PacketType_KEY_EXCHANGE,
		EncryptedData: payload,
		Timestamp:     timestamppb.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.SendPacket(ctx, req); err != nil {
		n.logger.WithError(err).Warn("Failed to send key exchange packet")
		return
	}
}

func (n *MeshNode) sendHeartbeatToPeer(peer *Peer) {
	client, exists := n.p2pDiscovery.GetPeerClient(peer.ID)
	if !exists {
		return
	}

	req := &pb.PacketRequest{
		SourceId:   n.ID,
		DestId:     peer.ID,
		PacketType: pb.PacketType_HEARTBEAT,
		Timestamp:  timestamppb.New(time.Now()),
	}

	// Send asynchronously
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := client.SendPacket(ctx, req); err != nil {
			n.logger.WithError(err).Debug("Failed to send heartbeat")
		}
	}()
}

// bridgeTUNToMesh bridges TUN interface traffic to mesh network
func (n *MeshNode) bridgeTUNToMesh() {
	n.logger.Info("Starting TUN to mesh bridge")

	for {
		select {
		case <-n.stopCh:
			n.logger.Info("Stopping TUN to mesh bridge")
			return
		case packet := <-n.tunInterface.ReceivePacket():
			// Forward packet through mesh
			if err := n.packetForwarder.ForwardPacket(packet); err != nil {
				n.logger.WithError(err).Debug("Failed to forward packet from TUN")
			}
		}
	}
}

// HandleIncomingMeshPacket handles packets received from mesh peers
func (n *MeshNode) HandleIncomingMeshPacket(packet []byte) {
	if n.tunInterface != nil {
		// Send packet to TUN interface
		n.tunInterface.SendPacket(packet)
	}
}

// Helper functions

func generateNodeID(publicKey string) string {
	nodeID, err := trust.NodeIDFromPublicKeyPEM(publicKey)
	if err == nil {
		return nodeID
	}

	hash := sha256.Sum256([]byte(publicKey))
	return hex.EncodeToString(hash[:16])
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

// gRPC Service Implementation

func (n *MeshNode) JoinNetwork(ctx context.Context, req *pb.JoinRequest) (*pb.JoinResponse, error) {
	n.logger.WithFields(logrus.Fields{
		"peer_id":      req.NodeId,
		"peer_mesh_ip": req.MeshIp,
		"network":      req.NetworkName,
	}).Info("Processing peer join request")

	// Validate network name
	if req.NetworkName != n.config.NetworkName {
		return &pb.JoinResponse{
			Success: false,
			Error:   fmt.Sprintf("network mismatch: expected %s, got %s", n.config.NetworkName, req.NetworkName),
		}, nil
	}

	if req.NodeId != generateNodeID(req.PublicKey) {
		return &pb.JoinResponse{
			Success: false,
			Error:   "node identity does not match public key",
		}, nil
	}

	if n.config.UseTLS {
		if err := n.verifyTransportIdentity(ctx, req.PublicKey); err != nil {
			n.logger.WithError(err).Warn("Transport identity verification failed")
			return &pb.JoinResponse{
				Success: false,
				Error:   "transport identity verification failed",
			}, nil
		}
	}

	// Verify request signature
	if req.Signature == "" {
		return &pb.JoinResponse{
			Success: false,
			Error:   "missing signature",
		}, nil
	}

	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return &pb.JoinResponse{
			Success: false,
			Error:   "invalid signature encoding",
		}, nil
	}

	// Check timestamp to prevent replay attacks
	if req.Timestamp != nil {
		ts := req.Timestamp.AsTime()
		if time.Since(ts) > 30*time.Second || time.Until(ts) > 30*time.Second {
			n.logger.WithField("timestamp", ts).Warn("Peer join request timestamp out of bounds")
			return &pb.JoinResponse{
				Success: false,
				Error:   "request expired",
			}, nil
		}
	} else {
		return &pb.JoinResponse{
			Success: false,
			Error:   "missing timestamp",
		}, nil
	}

	// Data to verify: NodeID + MeshIP + NetworkName + Timestamp
	verifyData := []byte(req.NodeId + req.MeshIp + req.NetworkName + req.Timestamp.String())

	if err := crypto.Verify(verifyData, sigBytes, []byte(req.PublicKey)); err != nil {
		n.logger.WithError(err).Warn("Peer signature verification failed")
		return &pb.JoinResponse{
			Success: false,
			Error:   "signature verification failed",
		}, nil
	}

	if !n.isPeerAuthorized(req.NodeId, req.PublicKey) {
		n.logger.WithField("peer_id", req.NodeId).Warn("Unauthorized peer join request rejected")
		return &pb.JoinResponse{
			Success: false,
			Error:   "peer is not authorized",
		}, nil
	}

	// Trigger reverse connection if we don't have one (needed for bidirectional P2P)
	if n.p2pDiscovery != nil && req.ConnectionInfo != nil {
		go n.p2pDiscovery.EnsureConnection(req.NodeId, req.ConnectionInfo.PublicAddress)
	}

	// Resolve endpoint
	var endpoint *net.UDPAddr
	if req.ConnectionInfo != nil {
		if addr, err := net.ResolveUDPAddr("udp", req.ConnectionInfo.PublicAddress); err == nil {
			endpoint = addr
		}
	}

	// Add peer to our peer list
	peer := &Peer{
		ID:        req.NodeId,
		PublicKey: req.PublicKey,
		MeshIP:    net.ParseIP(req.MeshIp),
		Endpoint:  endpoint,
		AllowedIPs: []*net.IPNet{
			{IP: net.ParseIP(req.MeshIp), Mask: net.CIDRMask(32, 32)},
		},
		Connected:     true,
		LastSeen:      time.Now(),
		LastHandshake: time.Now(),
	}

	n.peersMu.Lock()
	n.peers[req.NodeId] = peer
	n.peersMu.Unlock()

	// Notify about peer join to trigger initial handshake actions (Key Exchange, Heartbeat)
	select {
	case n.peerUpdates <- &PeerUpdate{Type: PeerJoined, Peer: peer}:
	default:
		n.logger.Warn("Peer update channel full")
	}

	// Build peer list response (our current peers)
	var peerList []*pb.PeerInfo
	n.peersMu.RLock()
	for _, p := range n.peers {
		if p.ID == req.NodeId {
			continue // Don't include the requesting peer
		}
		// Prepare ConnectionInfo
		connInfo := &pb.ConnectionInfo{
			PublicAddress: "",
			Port:          0,
			NatType:       pb.NATType_UNKNOWN,
		}
		if p.Endpoint != nil {
			connInfo.PublicAddress = p.Endpoint.String()
			connInfo.Port = int32(p.Endpoint.Port)
		}

		peerInfo := &pb.PeerInfo{
			Id:             p.ID,
			PublicKey:      p.PublicKey,
			MeshIp:         p.MeshIP.String(),
			AllowedIps:     []string{p.MeshIP.String() + "/32"},
			LastSeen:       timestamppb.New(p.LastSeen),
			ConnectionInfo: connInfo,
			Status: &pb.NodeStatus{
				PeerCount:    int32(len(n.peers)),
				Capabilities: []string{"p2p", "mesh-routing"},
				Version:      "1.0.0",
			},
		}
		peerList = append(peerList, peerInfo)
	}
	n.peersMu.RUnlock()

	// Include ourselves in the response so the joiner knows who they connected to
	selfPeer := &pb.PeerInfo{
		Id:         n.ID,
		PublicKey:  n.PublicKey,
		MeshIp:     n.MeshIP.String(),
		AllowedIps: []string{n.MeshIP.String() + "/32"},
		LastSeen:   timestamppb.Now(),
		ConnectionInfo: &pb.ConnectionInfo{
			PublicAddress: n.getPublicAddress(),
			Port:          int32(n.ListenPort),
			NatType:       pb.NATType_UNKNOWN,
		},
		Status: &pb.NodeStatus{
			PeerCount:    int32(len(n.peers)),
			Capabilities: []string{"p2p", "mesh-routing"},
			Version:      "1.0.0",
		},
	}
	peerList = append(peerList, selfPeer)

	// Network info
	networkInfo := &pb.NetworkInfo{
		Name:       n.config.NetworkName,
		Cidr:       n.config.NetworkCIDR,
		DnsServers: n.config.DNSServers,
		TotalNodes: int32(len(n.peers) + 1),
		Version:    "1.0.0",
	}

	n.logger.WithField("peer_count", len(peerList)).Info("Peer joined mesh network")

	resp := &pb.JoinResponse{
		Success:     true,
		AssignedIp:  req.MeshIp,
		Peers:       peerList,
		NetworkInfo: networkInfo,
	}

	// Sign response
	signData := []byte(resp.AssignedIp + n.ID + n.config.NetworkName)
	signature, err := n.encryption.Sign(signData)
	if err == nil {
		resp.Signature = base64.StdEncoding.EncodeToString(signature)
	}

	return resp, nil
}

func (n *MeshNode) verifyTransportIdentity(ctx context.Context, claimedPublicKey string) error {
	transportPublicKey, _, err := transportIdentityFromContext(ctx)
	if err != nil {
		return err
	}

	if string(transportPublicKey) != claimedPublicKey {
		return fmt.Errorf("transport certificate public key does not match claimed node identity")
	}

	return nil
}

func (n *MeshNode) verifyEstablishedPeerIdentity(ctx context.Context, claimedNodeID string) error {
	if claimedNodeID == "" {
		return fmt.Errorf("missing node identity")
	}
	if !n.config.UseTLS {
		return nil
	}

	transportPublicKey, derivedNodeID, err := transportIdentityFromContext(ctx)
	if err != nil {
		return err
	}
	if derivedNodeID != claimedNodeID {
		return fmt.Errorf("transport identity does not match claimed node id")
	}
	if !n.isPeerAuthorized(derivedNodeID, string(transportPublicKey)) {
		return fmt.Errorf("peer is not authorized")
	}

	n.peersMu.RLock()
	peerEntry, exists := n.peers[claimedNodeID]
	n.peersMu.RUnlock()
	if exists && peerEntry.PublicKey != "" && peerEntry.PublicKey != string(transportPublicKey) {
		return fmt.Errorf("transport identity does not match registered peer key")
	}

	return nil
}

func transportIdentityFromContext(ctx context.Context) ([]byte, string, error) {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok || peerInfo.AuthInfo == nil {
		return nil, "", fmt.Errorf("missing peer auth info")
	}

	tlsInfo, ok := peerInfo.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, "", fmt.Errorf("unexpected auth info type %T", peerInfo.AuthInfo)
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, "", fmt.Errorf("missing presented peer certificate")
	}

	cert := tlsInfo.State.PeerCertificates[0]
	if err := certs.ValidatePeerCertificate(cert); err != nil {
		return nil, "", err
	}

	transportPublicKey, err := crypto.PublicKeyPEMFromCertificate(cert)
	if err != nil {
		return nil, "", fmt.Errorf("failed to extract transport public key: %w", err)
	}

	nodeID, err := trust.NodeIDFromPublicKeyPEM(string(transportPublicKey))
	if err != nil {
		return nil, "", fmt.Errorf("failed to derive transport node id: %w", err)
	}

	return transportPublicKey, nodeID, nil
}

func (n *MeshNode) isPeerAuthorized(nodeID, publicKey string) bool {
	if n.trustPolicy == nil {
		return true
	}
	return n.trustPolicy.IsAuthorized(nodeID, publicKey)
}

func (n *MeshNode) LeaveNetwork(ctx context.Context, req *pb.LeaveRequest) (*pb.LeaveResponse, error) {
	if err := n.verifyEstablishedPeerIdentity(ctx, req.NodeId); err != nil {
		return &pb.LeaveResponse{Success: false, Message: err.Error()}, nil
	}

	n.logger.WithField("peer_id", req.NodeId).Info("Peer requesting to leave network")

	n.peersMu.Lock()
	if peer, exists := n.peers[req.NodeId]; exists {
		// Disconnect locally
		n.disconnectPeerUnsafe(peer)
		delete(n.peers, req.NodeId)
		// Notify others
		select {
		case n.peerUpdates <- &PeerUpdate{Type: PeerLeft, Peer: peer}:
		default:
		}
	}
	n.peersMu.Unlock()

	return &pb.LeaveResponse{
		Success: true,
	}, nil
}

func (n *MeshNode) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if err := n.verifyEstablishedPeerIdentity(ctx, req.NodeId); err != nil {
		return &pb.HeartbeatResponse{
			Alive:     false,
			Timestamp: timestamppb.Now(),
		}, nil
	}

	n.logger.WithField("peer_id", req.NodeId).Debug("Received heartbeat")

	// Update peer's last seen time
	n.peersMu.Lock()
	if peer, exists := n.peers[req.NodeId]; exists {
		peer.LastSeen = time.Now()
		peer.Connected = true
	}
	n.peersMu.Unlock()

	if n.p2pDiscovery != nil {
		n.p2pDiscovery.markPeerSeen(req.NodeId)
	}

	return &pb.HeartbeatResponse{
		Alive:     true,
		Timestamp: timestamppb.Now(),
	}, nil
}

func (n *MeshNode) DiscoverPeers(ctx context.Context, req *pb.DiscoveryRequest) (*pb.DiscoveryResponse, error) {
	if err := n.verifyEstablishedPeerIdentity(ctx, req.NodeId); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	if req.NetworkName != "" && req.NetworkName != n.config.NetworkName {
		return nil, status.Error(codes.InvalidArgument, "network mismatch")
	}

	n.logger.WithField("requester", req.NodeId).Debug("Processing peer discovery request")

	// Build peer list
	var peerList []*pb.PeerInfo
	n.peersMu.RLock()
	count := 0
	maxPeers := int(req.MaxPeers)
	if maxPeers <= 0 {
		maxPeers = 50 // Default limit
	}

	for _, p := range n.peers {
		if count >= maxPeers {
			break
		}
		if p.ID == req.NodeId {
			continue // Don't include the requesting peer
		}

		peerInfo := &pb.PeerInfo{
			Id:         p.ID,
			PublicKey:  p.PublicKey,
			MeshIp:     p.MeshIP.String(),
			AllowedIps: []string{p.MeshIP.String() + "/32"},
			LastSeen:   timestamppb.New(p.LastSeen),
			ConnectionInfo: &pb.ConnectionInfo{
				NatType: pb.NATType_UNKNOWN,
			},
			Status: &pb.NodeStatus{
				PeerCount:    int32(len(n.peers)),
				Capabilities: []string{"p2p", "mesh-routing"},
				Version:      "1.0.0",
			},
		}
		if p.Endpoint != nil {
			peerInfo.ConnectionInfo.PublicAddress = p.Endpoint.String()
			peerInfo.ConnectionInfo.Port = int32(p.Endpoint.Port)
		}
		peerList = append(peerList, peerInfo)
		count++
	}
	n.peersMu.RUnlock()

	// Include ourselves in the peer list
	selfPeer := &pb.PeerInfo{
		Id:         n.ID,
		PublicKey:  n.PublicKey,
		MeshIp:     n.MeshIP.String(),
		AllowedIps: []string{n.MeshIP.String() + "/32"},
		LastSeen:   timestamppb.Now(),
		ConnectionInfo: &pb.ConnectionInfo{
			PublicAddress: n.getPublicAddress(),
			Port:          int32(n.ListenPort),
			NatType:       pb.NATType_UNKNOWN,
		},
		Status: &pb.NodeStatus{
			PeerCount:    int32(len(n.peers)),
			Capabilities: []string{"p2p", "mesh-routing"},
			Version:      "1.0.0",
		},
	}
	peerList = append(peerList, selfPeer)

	networkInfo := &pb.NetworkInfo{
		Name:       n.config.NetworkName,
		Cidr:       n.config.NetworkCIDR,
		DnsServers: n.config.DNSServers,
		TotalNodes: int32(len(n.peers) + 1),
		Version:    "1.0.0",
	}

	return &pb.DiscoveryResponse{
		Peers:       peerList,
		NetworkInfo: networkInfo,
		TotalPeers:  int32(len(peerList)),
	}, nil
}

func (n *MeshNode) RequestIntroduction(ctx context.Context, req *pb.IntroductionRequest) (*pb.IntroductionResponse, error) {
	if err := n.verifyEstablishedPeerIdentity(ctx, req.RequesterId); err != nil {
		return &pb.IntroductionResponse{Success: false}, nil
	}

	// Acting as an introducer (STUN/TURN like role)
	n.peersMu.RLock()
	targetPeer, exists := n.peers[req.TargetId]
	n.peersMu.RUnlock()

	if !exists || targetPeer.Endpoint == nil {
		return &pb.IntroductionResponse{Success: false}, nil
	}

	return &pb.IntroductionResponse{
		Success: true,
		TargetConnection: &pb.ConnectionInfo{
			PublicAddress: targetPeer.Endpoint.String(),
			Port:          int32(targetPeer.Endpoint.Port),
			NatType:       pb.NATType(targetPeer.NATType),
		},
	}, nil
}

func (n *MeshNode) SendPacket(ctx context.Context, req *pb.PacketRequest) (*pb.PacketResponse, error) {
	if err := n.verifyEstablishedPeerIdentity(ctx, req.SourceId); err != nil {
		return &pb.PacketResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	n.logger.WithFields(logrus.Fields{
		"source": req.SourceId,
		"dest":   req.DestId,
		"type":   req.PacketType,
	}).Debug("Received packet for routing")

	// Create mesh packet
	meshPacket := &MeshPacket{
		SourceID:   req.SourceId,
		DestID:     req.DestId,
		PacketType: PacketType(req.PacketType),
		Payload:    req.EncryptedData,
		Encrypted:  len(req.EncryptedData) > 0,
		Timestamp:  time.Now(),
		Metadata:   req.Metadata,
	}

	// Route through mesh
	if err := n.meshRouter.RoutePacket(meshPacket); err != nil {
		n.logger.WithError(err).Error("Failed to route packet")
		return &pb.PacketResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.PacketResponse{
		Success:   true,
		PacketId:  req.PacketId,
		Timestamp: timestamppb.Now(),
	}, nil
}

func (n *MeshNode) AdvertiseRoutes(ctx context.Context, req *pb.RouteAdvertisement) (*pb.RouteResponse, error) {
	if err := n.verifyEstablishedPeerIdentity(ctx, req.NodeId); err != nil {
		return &pb.RouteResponse{Success: false, Error: err.Error()}, nil
	}

	n.logger.WithFields(logrus.Fields{
		"advertiser":  req.NodeId,
		"route_count": len(req.Routes),
	}).Debug("Received route advertisement")

	// Process route advertisement through mesh router
	if err := n.meshRouter.ProcessRouteAdvertisement(req); err != nil {
		return &pb.RouteResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.RouteResponse{
		Success: true,
	}, nil
}

func (n *MeshNode) RequestRoutes(ctx context.Context, req *pb.RouteRequest) (*pb.RouteResponse, error) {
	if err := n.verifyEstablishedPeerIdentity(ctx, req.NodeId); err != nil {
		return &pb.RouteResponse{Success: false, Error: err.Error()}, nil
	}

	// Trigger an advertisement to the requester
	go func() {
		// Sleep slightly to allow response to return
		time.Sleep(100 * time.Millisecond)
		if n.meshRouter != nil {
			n.meshRouter.AdvertiseRoutes()
		}
	}()

	return &pb.RouteResponse{
		Success: true,
	}, nil
}

func (n *MeshNode) InitiateHolePunch(ctx context.Context, req *pb.HolePunchRequest) (*pb.HolePunchResponse, error) {
	if err := n.verifyEstablishedPeerIdentity(ctx, req.RequesterId); err != nil {
		return &pb.HolePunchResponse{Success: false}, nil
	}

	n.logger.WithFields(logrus.Fields{
		"target": req.TargetId,
	}).Debug("Hole punch request received")

	// Forward to NAT traversal component if available
	if n.natTraversal != nil {
		// n.natTraversal.HandleHolePunch(req) // If method existed
	}

	return &pb.HolePunchResponse{
		Success: true,
	}, nil
}

func (n *MeshNode) ExchangeConnectionInfo(ctx context.Context, req *pb.ConnectionInfoRequest) (*pb.ConnectionInfoResponse, error) {
	if err := n.verifyEstablishedPeerIdentity(ctx, req.NodeId); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}

	n.logger.WithField("peer_id", req.NodeId).Debug("Connection info exchange")

	// Update peer info if we know them
	n.peersMu.Lock()
	if peer, exists := n.peers[req.NodeId]; exists {
		if req.LocalInfo != nil {
			peer.NATType = NATType(req.LocalInfo.NatType)
		}
	}
	n.peersMu.Unlock()

	return &pb.ConnectionInfoResponse{
		PublicInfo: &pb.ConnectionInfo{
			PublicAddress: n.getPublicAddress(),
			Port:          int32(n.ListenPort),
			NatType:       pb.NATType_UNKNOWN,
		},
	}, nil
}

// getPublicAddress returns the best known public address for this node
func (n *MeshNode) getPublicAddress() string {
	if n.natTraversal != nil && n.natTraversal.publicAddr != nil {
		return fmt.Sprintf("%s:%d", n.natTraversal.publicAddr.IP.String(), n.ListenPort)
	}
	// Fallback to mesh IP (though likely unreachable) or better, the listen port on all interfaces
	// Since we don't know the host IP easily, we might fallback to a reasonable default or MeshIP
	return fmt.Sprintf("%s:%d", n.MeshIP.String(), n.ListenPort)
}
