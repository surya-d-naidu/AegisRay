package mesh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
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

	// Parse mesh IP (auto-assign if empty for clients)
	var meshIP net.IP
	if cfg.MeshIP == "" {
		// Auto-assign IP for clients from network CIDR
		logger.Info("Auto-assigning mesh IP for client node")
		autoIP, err := autoAssignMeshIP(cfg.NetworkCIDR, nodeID)
		if err != nil {
			return nil, fmt.Errorf("failed to auto-assign mesh IP: %w", err)
		}
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
		node.certMgr = certs.NewCertificateManager(cfg.CertFile, cfg.KeyFile)

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

	// Initialize HTTP API server (port 8080)
	node.httpServer = NewHTTPServer(node, 8080)

	// Initialize TUN interface for IP traffic
	if cfg.EnableTUN {
		tunInterface, err := NewTUNInterface(node.MeshIP, cfg.NetworkCIDR, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create TUN interface: %w", err)
		}
		node.tunInterface = tunInterface
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
	// Close any active connections or streams if stored
	n.logger.WithField("peer_id", peer.ID).Debug("Disconnected peer")
}

func (n *MeshNode) handlePeerJoined(peer *Peer) {
	n.logger.WithField("peer_id", peer.ID).Info("Peer joined mesh")
	go n.sendHeartbeatToPeer(peer)
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

	// Decrypt payload
	data, err := n.encryption.Decrypt(packet.Payload)
	if err != nil {
		n.logger.WithError(err).Error("Failed to decrypt data packet")
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
	}
}

func (n *MeshNode) handleKeyExchangePacket(packet *MeshPacket) {
	// Placeholder for key exchange logic
	n.logger.WithField("source", packet.SourceID).Debug("Received key exchange packet")
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

func generateNodeID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// autoAssignMeshIP generates a unique IP address within the given CIDR for a node
func autoAssignMeshIP(networkCIDR, nodeID string) (net.IP, error) {
	_, network, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid network CIDR: %w", err)
	}

	// Use SHA256 hash of nodeID to generate deterministic but random IP
	hash := sha256.Sum256([]byte(nodeID))

	// Convert first 4 bytes of hash to IP offset
	offset := binary.BigEndian.Uint32(hash[:4])

	// Get the network address and mask size
	networkAddr := network.IP.To4()
	if networkAddr == nil {
		return nil, fmt.Errorf("only IPv4 networks supported")
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("invalid IPv4 mask")
	}

	// Calculate available host addresses
	hostBits := uint32(32 - ones)
	maxHosts := uint32(1<<hostBits) - 2 // Exclude network and broadcast

	if maxHosts == 0 {
		return nil, fmt.Errorf("network too small for host assignment")
	}

	// Generate host part (avoid .0 and .1 which are typically reserved)
	hostPart := (offset % maxHosts) + 2
	if hostPart >= maxHosts {
		hostPart = 2
	}

	// Combine network and host parts
	networkInt := binary.BigEndian.Uint32(networkAddr)
	assignedIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(assignedIP, networkInt+hostPart)

	return assignedIP, nil
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

	// Data to verify: NodeID + MeshIP + NetworkName + Timestamp
	verifyData := []byte(req.NodeId + req.MeshIp + req.NetworkName + req.Timestamp.String())

	if err := crypto.Verify(verifyData, sigBytes, []byte(req.PublicKey)); err != nil {
		n.logger.WithError(err).Warn("Peer signature verification failed")
		return &pb.JoinResponse{
			Success: false,
			Error:   "signature verification failed",
		}, nil
	}

	// Add peer to our peer list
	peer := &Peer{
		ID:        req.NodeId,
		PublicKey: req.PublicKey,
		MeshIP:    net.ParseIP(req.MeshIp),
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

	// Build peer list response (our current peers)
	var peerList []*pb.PeerInfo
	n.peersMu.RLock()
	for _, p := range n.peers {
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
				PublicAddress: p.Endpoint.String(),
				Port:          int32(p.Endpoint.Port),
				NatType:       pb.NATType_UNKNOWN,
			},
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

	return &pb.JoinResponse{
		Success:     true,
		AssignedIp:  req.MeshIp, // In P2P mesh, peers choose their own IPs
		Peers:       peerList,
		NetworkInfo: networkInfo,
	}, nil
}

func (n *MeshNode) LeaveNetwork(ctx context.Context, req *pb.LeaveRequest) (*pb.LeaveResponse, error) {
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
	n.logger.WithField("peer_id", req.NodeId).Debug("Received heartbeat")

	// Update peer's last seen time
	n.peersMu.Lock()
	if peer, exists := n.peers[req.NodeId]; exists {
		peer.LastSeen = time.Now()
		peer.Connected = true
	}
	n.peersMu.Unlock()

	return &pb.HeartbeatResponse{
		Alive:     true,
		Timestamp: timestamppb.Now(),
	}, nil
}

func (n *MeshNode) DiscoverPeers(ctx context.Context, req *pb.DiscoveryRequest) (*pb.DiscoveryResponse, error) {
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
				PublicAddress: p.Endpoint.String(),
				Port:          int32(p.Endpoint.Port),
				NatType:       pb.NATType_UNKNOWN,
			},
			Status: &pb.NodeStatus{
				PeerCount:    int32(len(n.peers)),
				Capabilities: []string{"p2p", "mesh-routing"},
				Version:      "1.0.0",
			},
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
	// Acting as an introducer (STUN/TURN like role)
	n.peersMu.RLock()
	targetPeer, exists := n.peers[req.TargetId]
	n.peersMu.RUnlock()

	if !exists {
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

func (n *MeshNode) StreamPackets(stream pb.MeshService_StreamPacketsServer) error {
	// Receive initial packet to establish identity/session
	initPacket, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive init packet: %w", err)
	}

	sessionID := initPacket.SessionId
	if sessionID == "" {
		// If no session ID, we might derive it from context or generate one,
		// but for now let's assume valid session initiation involves a non-empty ID
		// or at least a valid source ID.
		if initPacket.Metadata != nil && len(initPacket.Metadata.Path) > 0 {
			// Fallback logic if needed, but standard flow expects SessionId or SourceId
		}
		// In this architecture, usually the Peer handshake happens before Streaming.
		// We'll assume the stream is tied to the Peer ID found in the packet SourceId if SessionId is generic.
	}

	// Note: StreamPacket proto does NOT have a SourceId field.
	// We must rely on SessionId to identify the peer.
	// In a real implementation, we would look up the SessionID in a session manager to find the PeerID.
	// For this prototype, we'll assume the external Peer Handshake exchanged this SessionID.

	n.logger.WithFields(logrus.Fields{
		"session_id": sessionID,
	}).Info("Starting packet stream")

	// READ LOOP: Receive from stream -> Route to Mesh
	// We process the init packet first
	n.processStreamPacket(initPacket)

	for {
		packet, err := stream.Recv()
		if err != nil {
			if err != io.EOF {
				n.logger.WithError(err).Error("Stream read error")
			}
			return err
		}
		n.processStreamPacket(packet)
	}
}

func (n *MeshNode) processStreamPacket(sp *pb.StreamPacket) {
	if sp.IsControl {
		// Handle control messages (ping/pong, etc)
		return
	}

	// Convert StreamPacket to MeshPacket
	// Note: StreamPacket in proto definition (lines 127-133) doesn't have Source/Dest fields directly?
	// Wait, looking at proto:
	// message StreamPacket { string session_id = 1; bytes data = 2; uint32 sequence = 3; bool is_control = 4; PacketMetadata metadata = 5; }
	// It seems missing Source/Dest IDs which are critical for routing.
	// The standard PacketRequest (line 108) has them.
	// We must assume the 'data' payload IS the MeshPacket (serialized) OR the proto design implies point-to-point.
	// Attempting to deserialize 'data' as MeshPacket or assuming point-to-point to THIS node?
	// If it's a mesh, it needs routing info.
	// Let's assume 'data' contains the encrypted payload including headers, OR
	// we need to inspect the 'metadata' path.

	// For this implementation, we'll wrap the data into a MeshPacket assuming it's destined for US if not specified,
	// or we'd need to peek inside.
	// However, looking at PacketRequest, it has Source/Dest. StreamPacket is minimized.
	// Let's assume StreamPacket is for point-to-point tunnel data between neighbor peers.

	meshPacket := &MeshPacket{
		// Source is the connected peer
		// Dest is unknown without parsing 'data' or having headers.
		// THIS IS A LIMITATION OF THE CURRENT PROTO DEFINITION.
		// We will assume the payload describes the destination or it's for us.
		PacketType: DataPacket,
		Payload:    sp.Data,
		Encrypted:  true,
		Timestamp:  time.Now(),
	}

	// Send to Router
	// The router expects SourceID/DestID.
	// We might need to decrypt to find out, or the proto needs update.
	// Proceeding with "Best Effort" routing (assuming local delivery)

	n.handleDataPacket(meshPacket)
}

func (n *MeshNode) AdvertiseRoutes(ctx context.Context, req *pb.RouteAdvertisement) (*pb.RouteResponse, error) {
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
