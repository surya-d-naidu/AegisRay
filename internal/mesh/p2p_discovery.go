package mesh

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/surya-d-naidu/AegisRay/internal/certs"
	"github.com/surya-d-naidu/AegisRay/internal/crypto"
	"github.com/surya-d-naidu/AegisRay/internal/sni"
	pb "github.com/surya-d-naidu/AegisRay/proto/mesh"
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

	// Transport identity tracking
	transportKeyPins map[string]string
	transportPinsMu  sync.RWMutex

	// Background tasks
	running bool
	stopCh  chan struct{}
}

// P2PPeerInfo represents discovered peer information in P2P mesh
type P2PPeerInfo struct {
	ID           string
	MeshIP       net.IP
	Endpoint     string
	AltEndpoints []string
	PublicKey    string
	TransportKey string
	LastSeen     time.Time
	Persistent   bool
	NextRetryAt  time.Time
	FailureCount int

	// P2P specific
	SupportsP2P  bool
	NATType      NATType
	Capabilities []string
	Status       string
}

// NewP2PDiscovery creates a new P2P discovery manager
func NewP2PDiscovery(node *MeshNode, staticPeers []string) *P2PDiscovery {
	return &P2PDiscovery{
		node:             node,
		logger:           node.logger,
		staticPeers:      staticPeers,
		activePeers:      make(map[string]*PeerConnection),
		peerClients:      make(map[string]pb.MeshServiceClient),
		discovered:       make(map[string]*P2PPeerInfo),
		transportKeyPins: make(map[string]string),
		stopCh:           make(chan struct{}),
	}
}

// Start begins P2P discovery process
func (p2p *P2PDiscovery) Start() error {
	p2p.logger.Info("Starting P2P mesh discovery")
	p2p.running = true

	// Load discovered peers from storage
	if err := p2p.LoadPeers(); err != nil {
		p2p.logger.WithError(err).Warn("Failed to load peer store")
	}

	// Connect to static peers first
	if err := p2p.connectToStaticPeers(); err != nil {
		p2p.logger.WithError(err).Warn("Failed to connect to some static peers")
	}

	// Connect to known peers
	p2p.retryKnownPeers()

	// Start background discovery routines
	go p2p.discoveryLoop()
	go p2p.heartbeatLoop()
	go p2p.peerMaintenanceLoop()
	go p2p.knownPeerRetryLoop()

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

	// Save peers before stopping
	if err := p2p.SavePeers(); err != nil {
		p2p.logger.WithError(err).Error("Failed to save peer store")
	}

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
		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{p2p.node.certMgr.GetTLSCertificate()},
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			VerifyConnection: func(cs tls.ConnectionState) error {
				return p2p.verifyTransportCertificate(address, cs)
			},
		}

		// Apply SNI Masquerading if Stealth Mode is enabled
		if p2p.node.config.StealthMode {
			faker := sni.NewSNIFaker(p2p.node.config.StealthDomains...)
			fakeSNI := faker.GetRandomFakeSNI()

			// Optional: make it look like a subdomain (e.g., api.google.com)
			if len(fakeSNI) > 0 {
				tlsConfig.ServerName = fakeSNI
				p2p.logger.WithField("fake_sni", fakeSNI).Info("Using SNI masquerading for peer connection")
			}
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
			PublicAddress: p2p.node.getPublicAddress(),
			LocalAddress:  p2p.node.MeshIP.String(),
			Port:          int32(p2p.node.ListenPort),
			NatType:       pb.NATType_UNKNOWN,
		},
	}

	// Sign the request
	// Data to sign: NodeID + MeshIP + NetworkName + Timestamp
	signData := []byte(joinReq.NodeId + joinReq.MeshIp + joinReq.NetworkName + joinReq.Timestamp.String())
	signature, err := p2p.node.encryption.Sign(signData)
	if err != nil {
		return fmt.Errorf("failed to sign join request: %w", err)
	}
	joinReq.Signature = base64.StdEncoding.EncodeToString(signature)

	joinResp, err := client.JoinNetwork(ctx, joinReq)
	if err != nil {
		return fmt.Errorf("join network failed: %w", err)
	}

	if !joinResp.Success {
		return fmt.Errorf("join rejected: %s", joinResp.Error)
	}

	// Find the peer that responded to verify the response signature
	var responderPeer *pb.PeerInfo
	for _, peer := range joinResp.Peers {
		// Verify strict identity: NodeID must be hash of PublicKey
		if peer.Id != generateNodeID(peer.PublicKey) {
			return fmt.Errorf("peer %s has invalid identity binding", peer.Id)
		}

		// Look for the responder (B) - in this simple flow we check which one's signature matches
		if joinResp.Signature != "" {
			sigBytes, _ := base64.StdEncoding.DecodeString(joinResp.Signature)
			verifyData := []byte(joinResp.AssignedIp + peer.Id + p2p.node.config.NetworkName)
			if crypto.Verify(verifyData, sigBytes, []byte(peer.PublicKey)) == nil {
				responderPeer = peer
			}
		}
	}

	if joinResp.Signature != "" && responderPeer == nil {
		return fmt.Errorf("failed to verify JoinResponse signature from any peer")
	}

	if responderPeer != nil {
		if p2p.node.config.UseTLS {
			if err := p2p.verifyResponderTransportBinding(address, responderPeer.PublicKey); err != nil {
				return fmt.Errorf("transport binding verification failed: %w", err)
			}
		}
		if !p2p.node.isPeerAuthorized(responderPeer.Id, responderPeer.PublicKey) {
			return fmt.Errorf("responder %s is not authorized", responderPeer.Id)
		}
	}

	// Store peer info from response peers
	for _, peer := range joinResp.Peers {
		if peer.Id == p2p.node.ID {
			continue // Skip self
		}
		if !p2p.node.isPeerAuthorized(peer.Id, peer.PublicKey) {
			p2p.logger.WithField("peer_id", peer.Id).Warn("Ignoring unauthorized peer advertised in join response")
			continue
		}

		peerInfo := &P2PPeerInfo{
			ID:           peer.Id,
			MeshIP:       net.ParseIP(peer.MeshIp),
			Endpoint:     peer.ConnectionInfo.PublicAddress,
			AltEndpoints: []string{},
			PublicKey:    peer.PublicKey,
			TransportKey: p2p.getPinnedTransportKey(address),
			LastSeen:     time.Now(),
			Persistent:   true,
			SupportsP2P:  true,
			NATType:      NATType(peer.ConnectionInfo.NatType),
			Capabilities: peer.Status.Capabilities,
			Status:       "active",
		}

		// Fix: If this is the peer we are currently handshaking with, override the endpoint
		// with the address we actually used to connect. This fixes issues where the server
		// reports its internal Mesh IP as its public address.
		if peer.ConnectionInfo.PublicAddress == "" ||
			strings.HasPrefix(peer.ConnectionInfo.PublicAddress, "100.64.") ||
			strings.HasPrefix(peer.ConnectionInfo.PublicAddress, "127.0.0.") ||
			(responderPeer != nil && peer.Id == responderPeer.Id) {
			p2p.logger.WithFields(logrus.Fields{
				"reported": peer.ConnectionInfo.PublicAddress,
				"actual":   address,
			}).Info("Overriding peer endpoint with actual connection address")
			peerInfo.Endpoint = address
		} else {
			peerInfo.Endpoint = peer.ConnectionInfo.PublicAddress
		}
		p2p.recordPeerEndpoint(peerInfo, address)
		p2p.recordPeerEndpoint(peerInfo, peer.ConnectionInfo.PublicAddress)

		p2p.discoveryMutex.Lock()
		if existing, exists := p2p.discovered[peer.Id]; exists && existing != nil {
			p2p.mergePeerInfo(existing, peerInfo)
		} else {
			p2p.discovered[peer.Id] = peerInfo
		}
		p2p.discoveryMutex.Unlock()
	}

	p2p.peerMutex.Lock()
	// Store client for this connection - map it to the actual responder's ID
	if responderPeer != nil {
		p2p.peerClients[responderPeer.Id] = client
	} else if len(joinResp.Peers) > 0 {
		// Fallback for older nodes or if signature verification wasn't used/required
		// Try to find the node that claims to be the one we connected to?
		// For now, use the last one (ourselves is separate, but the responder is usually appended last in JoinNetwork implementation)
		// Actually, JoinNetwork appends selfPeer last.
		p2p.peerClients[joinResp.Peers[len(joinResp.Peers)-1].Id] = client
	}
	p2p.peerMutex.Unlock()

	// PROMOTE TO MESH NODE PEERS (Fix for "No route to destination")
	// We need to tell the main node about this peer so it can route packets
	for _, peer := range joinResp.Peers {
		if peer.Id == p2p.node.ID {
			continue // Skip self
		}

		// Re-resolve endpoint for this specific peer from the list
		endpoint := peer.ConnectionInfo.PublicAddress
		if responderPeer != nil && peer.Id == responderPeer.Id {
			endpoint = address
		}

		udpAddr, _ := net.ResolveUDPAddr("udp", endpoint)

		// Parse allowed IPs
		var allowedIPs []*net.IPNet
		for _, ipStr := range peer.AllowedIps {
			if _, ipNet, err := net.ParseCIDR(ipStr); err == nil {
				allowedIPs = append(allowedIPs, ipNet)
			}
		}

		// Add to main node
		nodePeerInfo := &PeerInfo{
			ID:         peer.Id,
			PublicKey:  peer.PublicKey,
			MeshIP:     peer.MeshIp,
			Endpoint:   udpAddr,
			AllowedIPs: allowedIPs,
		}

		if err := p2p.node.AddPeer(nodePeerInfo); err != nil {
			p2p.logger.WithError(err).Warn("Failed to promote discovered peer to mesh node")
		} else {
			p2p.logger.WithField("peer_id", peer.Id).Info("Promoted discovered peer to active mesh peer")
		}

		// If we completed a handshake with this peer, reflect that in the node status surface.
		p2p.node.peersMu.RLock()
		nodePeer, exists := p2p.node.peers[peer.Id]
		p2p.node.peersMu.RUnlock()
		if exists && nodePeer != nil {
			p2p.node.handlePeerConnected(nodePeer)
		}
	}

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
		if !p2p.node.isPeerAuthorized(peer.Id, peer.PublicKey) {
			p2p.logger.WithField("peer_id", peer.Id).Warn("Ignoring unauthorized gossip peer")
			continue
		}

		peerInfo := &P2PPeerInfo{
			ID:           peer.Id,
			MeshIP:       net.ParseIP(peer.MeshIp),
			Endpoint:     peer.ConnectionInfo.PublicAddress,
			AltEndpoints: []string{},
			PublicKey:    peer.PublicKey,
			TransportKey: p2p.getPinnedTransportKey(peer.ConnectionInfo.PublicAddress),
			LastSeen:     time.Now(),
			Persistent:   true,
			SupportsP2P:  true,
			NATType:      NATType(peer.ConnectionInfo.NatType),
			Capabilities: peer.Status.Capabilities,
			Status:       "discovered",
		}

		p2p.discoveryMutex.Lock()
		p2p.recordPeerEndpoint(peerInfo, peer.ConnectionInfo.PublicAddress)
		if existing, exists := p2p.discovered[peer.Id]; exists && existing != nil {
			p2p.mergePeerInfo(existing, peerInfo)
		} else {
			p2p.discovered[peer.Id] = peerInfo
			p2p.logger.WithField("peer_id", peer.Id).Info("Discovered new peer via gossip")
		}
		p2p.discoveryMutex.Unlock()

		go p2p.connectToPeer(peer.ConnectionInfo.PublicAddress)
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
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p2p.maintainPeers()
			p2p.retryStaticPeers()
			p2p.SavePeers() // Periodically save peers
		case <-p2p.stopCh:
			return
		}
	}
}

// knownPeerRetryLoop continuously retries persisted peers so reconnect does not depend only on static seeds.
func (p2p *P2PDiscovery) knownPeerRetryLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p2p.retryKnownPeers()
		case <-p2p.stopCh:
			return
		}
	}
}

// LoadPeers loads discovered peers from the peer store file
func (p2p *P2PDiscovery) LoadPeers() error {
	path := p2p.node.config.PeerStoreFile
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var peers map[string]*P2PPeerInfo
	if err := json.Unmarshal(data, &peers); err != nil {
		return fmt.Errorf("failed to parse peer store: %w", err)
	}

	p2p.discoveryMutex.Lock()
	defer p2p.discoveryMutex.Unlock()

	for id, peer := range peers {
		if peer != nil {
			peer.Persistent = true
		}
		// Only load peers that are not already known (though usually map is empty at start)
		if _, exists := p2p.discovered[id]; !exists {
			p2p.discovered[id] = peer
		}
	}

	p2p.logger.WithField("count", len(peers)).Info("Loaded persistent peers")
	return nil
}

// SavePeers saves discovered peers to the peer store file
func (p2p *P2PDiscovery) SavePeers() error {
	path := p2p.node.config.PeerStoreFile
	if path == "" {
		return nil
	}

	p2p.discoveryMutex.RLock()
	peers := make(map[string]*P2PPeerInfo)
	for id, peer := range p2p.discovered {
		peers[id] = peer
	}
	p2p.discoveryMutex.RUnlock()

	data, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal peers: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write peer store: %w", err)
	}

	return nil
}

// retryKnownPeers attempts to connect to all known peers
func (p2p *P2PDiscovery) retryKnownPeers() {
	p2p.discoveryMutex.RLock()
	peers := make([]*P2PPeerInfo, 0, len(p2p.discovered))
	for _, peer := range p2p.discovered {
		peers = append(peers, peer)
	}
	p2p.discoveryMutex.RUnlock()

	for _, peer := range peers {
		if peer == nil {
			continue
		}

		p2p.peerMutex.RLock()
		_, active := p2p.peerClients[peer.ID]
		p2p.peerMutex.RUnlock()
		if active {
			continue
		}

		if !peer.NextRetryAt.IsZero() && time.Now().Before(peer.NextRetryAt) {
			continue
		}

		for _, endpoint := range p2p.peerEndpoints(peer) {
			go p2p.connectToPeer(endpoint)
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
		if peer == nil {
			delete(p2p.discovered, peerID)
			continue
		}

		p2p.peerMutex.RLock()
		_, active := p2p.peerClients[peerID]
		p2p.peerMutex.RUnlock()
		if active {
			peer.LastSeen = time.Now()
			peer.Status = "active"
			peer.Persistent = true
			continue
		}

		if peer.Persistent && peer.Endpoint != "" {
			continue
		}

		if peer.LastSeen.Before(cutoff) {
			delete(p2p.discovered, peerID)
			p2p.logger.WithField("peer_id", peerID).Debug("Removed stale peer from discovery")
		}
	}
	p2p.discoveryMutex.Unlock()
}

// retryStaticPeers attempts to reconnect to configured static peers if not connected
func (p2p *P2PDiscovery) retryStaticPeers() {
	for _, addr := range p2p.staticPeers {
		connected := false

		// Check if we have an active connection to this address
		p2p.discoveryMutex.RLock()
		for id, info := range p2p.discovered {
			if info.Endpoint == addr {
				p2p.peerMutex.RLock()
				_, active := p2p.peerClients[id]
				p2p.peerMutex.RUnlock()

				if active {
					connected = true
					break
				}
			}
		}
		p2p.discoveryMutex.RUnlock()

		if !connected {
			go p2p.connectToPeer(addr)
		}
	}
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
		peer.Persistent = true
		peer.FailureCount++
		backoff := time.Duration(peer.FailureCount)
		if backoff > 6 {
			backoff = 6
		}
		peer.NextRetryAt = time.Now().Add((1 << backoff) * time.Second)
	}
	p2p.discoveryMutex.Unlock()
}

func (p2p *P2PDiscovery) verifyTransportCertificate(address string, cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("missing peer certificate")
	}

	cert := cs.PeerCertificates[0]
	if err := certs.ValidatePeerCertificate(cert); err != nil {
		return err
	}

	transportKeyPEM, err := crypto.PublicKeyPEMFromCertificate(cert)
	if err != nil {
		return fmt.Errorf("failed to extract transport key: %w", err)
	}

	pinned := p2p.getPinnedTransportKey(address)
	if pinned != "" && pinned != string(transportKeyPEM) {
		return fmt.Errorf("transport identity mismatch for %s", address)
	}

	expected := p2p.lookupExpectedTransportKey(address)
	if expected != "" && expected != string(transportKeyPEM) {
		return fmt.Errorf("presented certificate does not match known mesh identity for %s", address)
	}

	p2p.transportPinsMu.Lock()
	p2p.transportKeyPins[address] = string(transportKeyPEM)
	p2p.transportPinsMu.Unlock()
	return nil
}

func (p2p *P2PDiscovery) verifyResponderTransportBinding(address, responderPublicKey string) error {
	pinned := p2p.getPinnedTransportKey(address)
	if pinned == "" {
		return fmt.Errorf("no transport key recorded for %s", address)
	}
	if pinned != responderPublicKey {
		return fmt.Errorf("responder public key does not match TLS transport key")
	}
	return nil
}

func (p2p *P2PDiscovery) getPinnedTransportKey(address string) string {
	p2p.transportPinsMu.RLock()
	defer p2p.transportPinsMu.RUnlock()
	return p2p.transportKeyPins[address]
}

func (p2p *P2PDiscovery) lookupExpectedTransportKey(address string) string {
	p2p.discoveryMutex.RLock()
	defer p2p.discoveryMutex.RUnlock()

	for _, peer := range p2p.discovered {
		if peer.Endpoint != address {
			continue
		}
		if peer.TransportKey != "" {
			return peer.TransportKey
		}
		if peer.PublicKey != "" {
			return peer.PublicKey
		}
	}

	return ""
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

func (p2p *P2PDiscovery) markPeerSeen(peerID string) {
	p2p.discoveryMutex.Lock()
	defer p2p.discoveryMutex.Unlock()

	if peer, exists := p2p.discovered[peerID]; exists && peer != nil {
		peer.LastSeen = time.Now()
		peer.Status = "active"
		peer.Persistent = true
		peer.FailureCount = 0
		peer.NextRetryAt = time.Time{}
	}
}

// GetPeerClient returns a gRPC client for communicating with a peer
func (p2p *P2PDiscovery) GetPeerClient(peerID string) (pb.MeshServiceClient, bool) {
	p2p.peerMutex.RLock()
	defer p2p.peerMutex.RUnlock()

	client, exists := p2p.peerClients[peerID]
	return client, exists
}

// EnsureConnection ensures we have an outgoing connection to the peer
func (p2p *P2PDiscovery) EnsureConnection(peerID, address string) {
	if address != "" {
		p2p.discoveryMutex.Lock()
		if peer, exists := p2p.discovered[peerID]; exists && peer != nil {
			p2p.recordPeerEndpoint(peer, address)
			peer.Persistent = true
		}
		p2p.discoveryMutex.Unlock()
	}

	p2p.peerMutex.RLock()
	_, exists := p2p.peerClients[peerID]
	p2p.peerMutex.RUnlock()

	if !exists {
		p2p.logger.WithField("peer_id", peerID).Info("Initiating reverse connection to peer")
		go p2p.connectToPeer(address)
	}
}

func (p2p *P2PDiscovery) peerEndpoints(peer *P2PPeerInfo) []string {
	endpoints := make([]string, 0, 1+len(peer.AltEndpoints))
	if peer.Endpoint != "" {
		endpoints = append(endpoints, peer.Endpoint)
	}
	for _, endpoint := range peer.AltEndpoints {
		if endpoint == "" || slices.Contains(endpoints, endpoint) {
			continue
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

func (p2p *P2PDiscovery) recordPeerEndpoint(peer *P2PPeerInfo, endpoint string) {
	if peer == nil || endpoint == "" {
		return
	}
	if peer.Endpoint == "" {
		peer.Endpoint = endpoint
		return
	}
	if peer.Endpoint == endpoint || slices.Contains(peer.AltEndpoints, endpoint) {
		return
	}
	peer.AltEndpoints = append(peer.AltEndpoints, endpoint)
}

func (p2p *P2PDiscovery) mergePeerInfo(dst, src *P2PPeerInfo) {
	if dst == nil || src == nil {
		return
	}
	if src.MeshIP != nil {
		dst.MeshIP = src.MeshIP
	}
	if src.PublicKey != "" {
		dst.PublicKey = src.PublicKey
	}
	if src.TransportKey != "" {
		dst.TransportKey = src.TransportKey
	}
	if src.LastSeen.After(dst.LastSeen) {
		dst.LastSeen = src.LastSeen
	}
	dst.Persistent = dst.Persistent || src.Persistent
	if src.Status != "" {
		dst.Status = src.Status
	}
	p2p.recordPeerEndpoint(dst, src.Endpoint)
	for _, endpoint := range src.AltEndpoints {
		p2p.recordPeerEndpoint(dst, endpoint)
	}
}
