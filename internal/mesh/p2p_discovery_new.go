package mesh

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	pb "github.com/aegisray/vpn-tunnel/proto/mesh"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// P2PDiscovery handles peer-to-peer discovery without centralized coordinators
type P2PDiscovery struct {
	node   *MeshNode
	logger *logrus.Logger

	// Static peer configuration
	staticPeers []string

	// Active peer connections
	activePeers map[string]*PeerConnection
	peerClients map[string]pb.MeshServiceClient
	peerMutex   sync.RWMutex

	// Discovery state
	discovered     map[string]*P2PPeerInfo
	discoveryMutex sync.RWMutex

	// Background tasks
	running bool
	stopCh  chan struct{}
}

// P2PPeerInfo represents discovered peer information in P2P mesh
type P2PPeerInfo struct {
	ID        string
	MeshIP    net.IP
	Endpoint  string
	PublicKey string
	LastSeen  time.Time

	// P2P specific
	SupportsP2P  bool
	NATType      NATType
	Capabilities []string
	Status       string
}

// NewP2PDiscovery creates a new P2P discovery manager
func NewP2PDiscovery(node *MeshNode, staticPeers []string) *P2PDiscovery {
	return &P2PDiscovery{
		node:        node,
		logger:      node.logger,
		staticPeers: staticPeers,
		activePeers: make(map[string]*PeerConnection),
		peerClients: make(map[string]pb.MeshServiceClient),
		discovered:  make(map[string]*P2PPeerInfo),
		stopCh:      make(chan struct{}),
	}
}

// Start begins P2P discovery process
func (p2p *P2PDiscovery) Start() error {
	p2p.logger.Info("Starting P2P mesh discovery")
	p2p.running = true

	// Connect to static peers first
	if err := p2p.connectToStaticPeers(); err != nil {
		p2p.logger.WithError(err).Warn("Failed to connect to some static peers")
	}

	// Start background discovery routines
	go p2p.discoveryLoop()
	go p2p.heartbeatLoop()
	go p2p.peerMaintenanceLoop()

	p2p.logger.Info("P2P mesh discovery started")
	return nil
}

// Stop stops P2P discovery
func (p2p *P2PDiscovery) Stop() error {
	if !p2p.running {
		return nil
	}

	p2p.logger.Info("Stopping P2P discovery")
	p2p.running = false
	close(p2p.stopCh)

	// Disconnect from all peers
	p2p.peerMutex.Lock()
	for peerID := range p2p.activePeers {
		p2p.disconnectPeerUnsafe(peerID)
	}
	p2p.peerMutex.Unlock()

	return nil
}

// connectToStaticPeers establishes connections to configured static peers
func (p2p *P2PDiscovery) connectToStaticPeers() error {
	p2p.logger.WithField("static_peers", len(p2p.staticPeers)).Info("Connecting to static peers")

	for _, peerAddr := range p2p.staticPeers {
		go p2p.connectToPeer(peerAddr)
	}

	return nil
}

// connectToPeer establishes a gRPC connection to a specific peer
func (p2p *P2PDiscovery) connectToPeer(address string) error {
	p2p.logger.WithField("peer_address", address).Info("Connecting to peer")

	// Create gRPC connection with TLS
	var conn *grpc.ClientConn
	var err error

	if p2p.node.config.UseTLS {
		// Use TLS but skip verification for mesh peers (they have self-signed certs)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		creds := credentials.NewTLS(tlsConfig)
		conn, err = grpc.Dial(address, grpc.WithTransportCredentials(creds))
	} else {
		conn, err = grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	if err != nil {
		p2p.logger.WithError(err).WithField("address", address).Error("Failed to connect to peer")
		return err
	}

	// Create mesh service client
	client := pb.NewMeshServiceClient(conn)

	// Perform peer handshake
	if err := p2p.performHandshake(client, address); err != nil {
		conn.Close()
		p2p.logger.WithError(err).WithField("address", address).Error("Peer handshake failed")
		return err
	}

	return nil
}

// performHandshake performs the P2P mesh handshake with a peer
func (p2p *P2PDiscovery) performHandshake(client pb.MeshServiceClient, address string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Join the mesh network
	joinReq := &pb.JoinRequest{
		NodeId:      p2p.node.ID,
		PublicKey:   p2p.node.PublicKey,
		MeshIp:      p2p.node.MeshIP.String(),
		AllowedIps:  []string{p2p.node.MeshIP.String() + "/32"},
		NetworkName: p2p.node.config.NetworkName,
		Timestamp:   timestamppb.Now(),
		ConnectionInfo: &pb.ConnectionInfo{
			PublicAddress: address,
			LocalAddress:  p2p.node.MeshIP.String(),
			Port:          int32(p2p.node.ListenPort),
			NatType:       pb.NATType_UNKNOWN,
		},
	}

	joinResp, err := client.JoinNetwork(ctx, joinReq)
	if err != nil {
		return fmt.Errorf("join network failed: %w", err)
	}

	if !joinResp.Success {
		return fmt.Errorf("join rejected: %s", joinResp.Error)
	}

	// Store peer info from response peers
	for _, peer := range joinResp.Peers {
		if peer.Id == p2p.node.ID {
			continue // Skip self
		}

		peerInfo := &P2PPeerInfo{
			ID:           peer.Id,
			MeshIP:       net.ParseIP(peer.MeshIp),
			Endpoint:     peer.ConnectionInfo.PublicAddress,
			PublicKey:    peer.PublicKey,
			LastSeen:     time.Now(),
			SupportsP2P:  true,
			NATType:      NATType(peer.ConnectionInfo.NatType),
			Capabilities: peer.Status.Capabilities,
			Status:       "active",
		}

		p2p.discoveryMutex.Lock()
		p2p.discovered[peer.Id] = peerInfo
		p2p.discoveryMutex.Unlock()
	}

	p2p.peerMutex.Lock()
	// Store client for this connection - use the first peer ID from response
	if len(joinResp.Peers) > 0 {
		p2p.peerClients[joinResp.Peers[0].Id] = client
	}
	p2p.peerMutex.Unlock()

	p2p.logger.WithFields(logrus.Fields{
		"peers_discovered": len(joinResp.Peers),
		"network":          joinResp.NetworkInfo.Name,
	}).Info("Successfully joined mesh network via peer")

	// Request peer discovery from this peer
	go p2p.discoverPeersFrom(client)

	return nil
}

// discoverPeersFrom requests peer list from a connected peer (gossip protocol)
func (p2p *P2PDiscovery) discoverPeersFrom(client pb.MeshServiceClient) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	discoveryReq := &pb.DiscoveryRequest{
		NodeId:      p2p.node.ID,
		NetworkName: p2p.node.config.NetworkName,
		MaxPeers:    50, // Reasonable limit
	}

	discoveryResp, err := client.DiscoverPeers(ctx, discoveryReq)
	if err != nil {
		p2p.logger.WithError(err).Warn("Peer discovery request failed")
		return
	}

	// Process discovered peers
	for _, peer := range discoveryResp.Peers {
		if peer.Id == p2p.node.ID {
			continue // Skip self
		}

		peerInfo := &P2PPeerInfo{
			ID:           peer.Id,
			MeshIP:       net.ParseIP(peer.MeshIp),
			Endpoint:     peer.ConnectionInfo.PublicAddress,
			PublicKey:    peer.PublicKey,
			LastSeen:     time.Now(),
			SupportsP2P:  true,
			NATType:      NATType(peer.ConnectionInfo.NatType),
			Capabilities: peer.Status.Capabilities,
			Status:       "discovered",
		}

		p2p.discoveryMutex.Lock()
		if _, exists := p2p.discovered[peer.Id]; !exists {
			p2p.discovered[peer.Id] = peerInfo
			p2p.logger.WithField("peer_id", peer.Id).Info("Discovered new peer via gossip")

			// Attempt to connect to newly discovered peer
			go p2p.connectToPeer(peer.ConnectionInfo.PublicAddress)
		}
		p2p.discoveryMutex.Unlock()
	}
}

// discoveryLoop continuously performs peer discovery
func (p2p *P2PDiscovery) discoveryLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p2p.performPeriodicDiscovery()
		case <-p2p.stopCh:
			return
		}
	}
}

// heartbeatLoop maintains connections with active peers
func (p2p *P2PDiscovery) heartbeatLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p2p.sendHeartbeats()
		case <-p2p.stopCh:
			return
		}
	}
}

// peerMaintenanceLoop cleans up dead peers and retries connections
func (p2p *P2PDiscovery) peerMaintenanceLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p2p.maintainPeers()
		case <-p2p.stopCh:
			return
		}
	}
}

// performPeriodicDiscovery asks all connected peers for their peer lists
func (p2p *P2PDiscovery) performPeriodicDiscovery() {
	p2p.peerMutex.RLock()
	clients := make(map[string]pb.MeshServiceClient)
	for id, client := range p2p.peerClients {
		clients[id] = client
	}
	p2p.peerMutex.RUnlock()

	for _, client := range clients {
		go p2p.discoverPeersFrom(client)
	}
}

// sendHeartbeats sends heartbeat messages to all connected peers
func (p2p *P2PDiscovery) sendHeartbeats() {
	p2p.peerMutex.RLock()
	clients := make(map[string]pb.MeshServiceClient)
	for id, client := range p2p.peerClients {
		clients[id] = client
	}
	p2p.peerMutex.RUnlock()

	for peerID, client := range clients {
		go p2p.sendHeartbeat(client, peerID)
	}
}

// sendHeartbeat sends a single heartbeat to a peer
func (p2p *P2PDiscovery) sendHeartbeat(client pb.MeshServiceClient, peerID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	heartbeatReq := &pb.HeartbeatRequest{
		NodeId:    p2p.node.ID,
		Timestamp: timestamppb.Now(),
		Status: &pb.NodeStatus{
			PeerCount:    int32(len(p2p.peerClients)),
			Capabilities: []string{"p2p", "mesh-routing", "nat-traversal"},
			Version:      "1.0.0",
		},
	}

	_, err := client.Heartbeat(ctx, heartbeatReq)
	if err != nil {
		p2p.logger.WithError(err).WithField("peer_id", peerID).Warn("Heartbeat failed")
		p2p.handlePeerFailure(peerID)
	}
}

// maintainPeers cleans up failed peers and attempts reconnections
func (p2p *P2PDiscovery) maintainPeers() {
	// Clean up old discovered peers
	cutoff := time.Now().Add(-5 * time.Minute)

	p2p.discoveryMutex.Lock()
	for peerID, peer := range p2p.discovered {
		if peer.LastSeen.Before(cutoff) {
			delete(p2p.discovered, peerID)
			p2p.logger.WithField("peer_id", peerID).Debug("Removed stale peer from discovery")
		}
	}
	p2p.discoveryMutex.Unlock()
}

// handlePeerFailure handles when a peer becomes unreachable
func (p2p *P2PDiscovery) handlePeerFailure(peerID string) {
	p2p.peerMutex.Lock()
	defer p2p.peerMutex.Unlock()

	p2p.disconnectPeerUnsafe(peerID)

	// Mark peer for reconnection attempt
	p2p.discoveryMutex.Lock()
	if peer, exists := p2p.discovered[peerID]; exists {
		peer.LastSeen = time.Now().Add(-1 * time.Minute) // Mark as recently failed
		peer.Status = "failed"
	}
	p2p.discoveryMutex.Unlock()
}

// disconnectPeerUnsafe disconnects from a peer (caller must hold peerMutex)
func (p2p *P2PDiscovery) disconnectPeerUnsafe(peerID string) {
	if client, exists := p2p.peerClients[peerID]; exists {
		// Send leave network message
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		leaveReq := &pb.LeaveRequest{
			NodeId:    p2p.node.ID,
			Reason:    "disconnecting",
			Timestamp: timestamppb.Now(),
		}
		client.LeaveNetwork(ctx, leaveReq)
		cancel()

		delete(p2p.peerClients, peerID)
	}

	if conn, exists := p2p.activePeers[peerID]; exists {
		if conn.Conn != nil {
			conn.Conn.Close()
		}
		delete(p2p.activePeers, peerID)
	}
}

// GetActivePeers returns list of currently active peers
func (p2p *P2PDiscovery) GetActivePeers() map[string]*P2PPeerInfo {
	p2p.discoveryMutex.RLock()
	defer p2p.discoveryMutex.RUnlock()

	peers := make(map[string]*P2PPeerInfo)
	for id, peer := range p2p.discovered {
		peers[id] = peer
	}
	return peers
}

// GetPeerClient returns a gRPC client for communicating with a peer
func (p2p *P2PDiscovery) GetPeerClient(peerID string) (pb.MeshServiceClient, bool) {
	p2p.peerMutex.RLock()
	defer p2p.peerMutex.RUnlock()

	client, exists := p2p.peerClients[peerID]
	return client, exists
}
