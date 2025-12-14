package mesh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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
				PublicAddress: fmt.Sprintf("%s:%d", p.MeshIP.String(), n.ListenPort),
				Port:          int32(n.ListenPort),
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
	// TODO: Implement network leave logic
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
				PublicAddress: fmt.Sprintf("%s:%d", p.MeshIP.String(), n.ListenPort),
				Port:          int32(n.ListenPort),
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
			PublicAddress: fmt.Sprintf("%s:%d", n.MeshIP.String(), n.ListenPort),
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
	// TODO: Implement peer introduction logic
	return &pb.IntroductionResponse{
		Success: true,
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
	// TODO: Implement packet streaming logic
	return nil
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
	// TODO: Implement route request logic
	return &pb.RouteResponse{
		Success: true,
	}, nil
}

func (n *MeshNode) InitiateHolePunch(ctx context.Context, req *pb.HolePunchRequest) (*pb.HolePunchResponse, error) {
	// TODO: Implement hole punch initiation logic
	return &pb.HolePunchResponse{
		Success: true,
	}, nil
}

func (n *MeshNode) ExchangeConnectionInfo(ctx context.Context, req *pb.ConnectionInfoRequest) (*pb.ConnectionInfoResponse, error) {
	// TODO: Implement connection info exchange logic
	return &pb.ConnectionInfoResponse{}, nil
}
