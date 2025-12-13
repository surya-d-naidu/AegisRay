package mesh

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Coordinator handles peer discovery and mesh coordination
type Coordinator struct {
	node   *MeshNode
	logger *logrus.Logger

	// Coordinator servers
	coordinators []string

	// Current coordinator connection
	currentCoord string
	grpcConn     *grpc.ClientConn

	// Peer discovery
	knownPeers map[string]*DiscoveredPeer
	peersMu    sync.RWMutex

	// State
	running bool
	stopCh  chan struct{}
}

// DiscoveredPeer represents a peer discovered through coordination
type DiscoveredPeer struct {
	ID         string    `json:"id"`
	PublicKey  string    `json:"public_key"`
	MeshIP     string    `json:"mesh_ip"`
	PublicAddr string    `json:"public_addr"`
	LocalAddr  string    `json:"local_addr"`
	LastSeen   time.Time `json:"last_seen"`
	NATType    NATType   `json:"nat_type"`
	AllowedIPs []string  `json:"allowed_ips"`
}

// CoordinatorInfo represents information about a coordination server
type CoordinatorInfo struct {
	URL       string `json:"url"`
	PublicKey string `json:"public_key"`
	Region    string `json:"region"`
	Load      int    `json:"load"`
}

// NewCoordinator creates a new mesh coordinator
func NewCoordinator(node *MeshNode, coordinators []string) *Coordinator {
	return &Coordinator{
		node:         node,
		logger:       node.logger,
		coordinators: coordinators,
		knownPeers:   make(map[string]*DiscoveredPeer),
		stopCh:       make(chan struct{}),
	}
}

// Start starts the coordination service
func (c *Coordinator) Start() error {
	c.logger.Info("Starting mesh coordination")
	c.running = true

	// Connect to best coordinator
	if err := c.connectToBestCoordinator(); err != nil {
		return fmt.Errorf("failed to connect to coordinator: %w", err)
	}

	// Register this node
	if err := c.registerNode(); err != nil {
		return fmt.Errorf("failed to register node: %w", err)
	}

	// Start background tasks
	go c.maintainCoordinatorConnection()
	go c.performPeerDiscovery()
	go c.shareNodeStatus()

	c.logger.Info("Mesh coordination started")
	return nil
}

// Stop stops the coordination service
func (c *Coordinator) Stop() error {
	if !c.running {
		return nil
	}

	c.logger.Info("Stopping mesh coordination")
	c.running = false
	close(c.stopCh)

	// Unregister node
	c.unregisterNode()

	// Close connection
	if c.grpcConn != nil {
		c.grpcConn.Close()
	}

	return nil
}

// DiscoverPeers discovers peers through the coordinator
func (c *Coordinator) DiscoverPeers() ([]*DiscoveredPeer, error) {
	if !c.running {
		return nil, fmt.Errorf("coordinator not running")
	}

	// Request peer list from coordinator
	peers, err := c.requestPeerList()
	if err != nil {
		return nil, fmt.Errorf("failed to get peer list: %w", err)
	}

	// Update known peers
	c.peersMu.Lock()
	for _, peer := range peers {
		c.knownPeers[peer.ID] = peer
	}
	c.peersMu.Unlock()

	return peers, nil
}

// GetKnownPeers returns all known peers
func (c *Coordinator) GetKnownPeers() []*DiscoveredPeer {
	c.peersMu.RLock()
	defer c.peersMu.RUnlock()

	peers := make([]*DiscoveredPeer, 0, len(c.knownPeers))
	for _, peer := range c.knownPeers {
		peers = append(peers, peer)
	}

	return peers
}

// RequestIntroduction requests an introduction to a specific peer
func (c *Coordinator) RequestIntroduction(peerID string) error {
	c.logger.WithField("peer_id", peerID).Info("Requesting peer introduction")

	// Send introduction request to coordinator
	return c.sendIntroductionRequest(peerID)
}

// Private methods

func (c *Coordinator) connectToBestCoordinator() error {
	// Test all coordinators and pick the best one
	bestCoord := ""
	bestLatency := time.Hour

	for _, coord := range c.coordinators {
		if latency := c.testCoordinatorLatency(coord); latency < bestLatency {
			bestCoord = coord
			bestLatency = latency
		}
	}

	if bestCoord == "" {
		return fmt.Errorf("no working coordinators found")
	}

	// Connect to best coordinator
	conn, err := c.connectToCoordinator(bestCoord)
	if err != nil {
		return fmt.Errorf("failed to connect to coordinator %s: %w", bestCoord, err)
	}

	c.currentCoord = bestCoord
	c.grpcConn = conn

	c.logger.WithFields(logrus.Fields{
		"coordinator": bestCoord,
		"latency":     bestLatency,
	}).Info("Connected to coordinator")

	return nil
}

func (c *Coordinator) testCoordinatorLatency(coordinator string) time.Duration {
	start := time.Now()

	// Simple HTTP ping to test latency
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://%s/ping", coordinator))
	if err != nil {
		return time.Hour // Return high latency on error
	}
	defer resp.Body.Close()

	return time.Since(start)
}

func (c *Coordinator) connectToCoordinator(coordinator string) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption

	// Use TLS if configured
	if c.node.config.UseTLS {
		// Create TLS credentials with SNI masquerading
		tlsConfig := c.node.certMgr.GetClientTLSConfig(coordinator, c.node.sniFaker.GetRandomFakeSNI())
		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return grpc.DialContext(ctx, coordinator, opts...)
}

func (c *Coordinator) registerNode() error {
	c.logger.Info("Registering node with coordinator")

	// Create registration request
	registration := &NodeRegistration{
		ID:         c.node.ID,
		PublicKey:  c.node.PublicKey,
		MeshIP:     c.node.MeshIP.String(),
		PublicAddr: c.node.natTraversal.publicAddr.String(),
		LocalAddr:  c.node.natTraversal.localAddr.String(),
		ListenPort: c.node.ListenPort,
		NATType:    c.node.natTraversal.natType,
		Timestamp:  time.Now(),
	}

	// Send via HTTP for simplicity (could also use gRPC)
	return c.sendHTTPRequest("POST", "/api/nodes/register", registration)
}

func (c *Coordinator) unregisterNode() error {
	c.logger.Info("Unregistering node from coordinator")

	unregistration := &NodeUnregistration{
		ID:        c.node.ID,
		Timestamp: time.Now(),
	}

	return c.sendHTTPRequest("POST", "/api/nodes/unregister", unregistration)
}

func (c *Coordinator) requestPeerList() ([]*DiscoveredPeer, error) {
	var peers []*DiscoveredPeer
	err := c.sendHTTPRequest("GET", "/api/peers", &peers)
	return peers, err
}

func (c *Coordinator) sendIntroductionRequest(peerID string) error {
	request := &IntroductionRequest{
		RequesterID: c.node.ID,
		TargetID:    peerID,
		Timestamp:   time.Now(),
	}

	return c.sendHTTPRequest("POST", "/api/introductions", request)
}

func (c *Coordinator) sendHTTPRequest(method, path string, data interface{}) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	url := fmt.Sprintf("https://%s%s", c.currentCoord, path)

	var req *http.Request
	var err error

	if method == "GET" {
		req, err = http.NewRequest(method, url, nil)
	} else {
		// POST requests with JSON body
		jsonData, _ := json.Marshal(data)
		req, err = http.NewRequest(method, url, strings.NewReader(string(jsonData)))
		req.Header.Set("Content-Type", "application/json")
	}

	if err != nil {
		return err
	}

	// Add authentication headers
	req.Header.Set("X-Node-ID", c.node.ID)
	req.Header.Set("X-Node-Signature", "TODO") // Add signature

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("coordinator request failed: %d", resp.StatusCode)
	}

	// Parse response for GET requests
	if method == "GET" {
		return json.NewDecoder(resp.Body).Decode(data)
	}

	return nil
}

func (c *Coordinator) maintainCoordinatorConnection() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.performConnectionMaintenance()
		case <-c.stopCh:
			return
		}
	}
}

func (c *Coordinator) performPeerDiscovery() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.performDiscovery()
		case <-c.stopCh:
			return
		}
	}
}

func (c *Coordinator) shareNodeStatus() {
	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.performStatusUpdate()
		case <-c.stopCh:
			return
		}
	}
}

func (c *Coordinator) performConnectionMaintenance() {
	// Check if coordinator connection is still alive
	if c.grpcConn.GetState().String() != "READY" {
		c.logger.Warn("Coordinator connection lost, attempting reconnect")
		c.grpcConn.Close()

		if err := c.connectToBestCoordinator(); err != nil {
			c.logger.WithError(err).Error("Failed to reconnect to coordinator")
		}
	}
}

func (c *Coordinator) performDiscovery() {
	peers, err := c.DiscoverPeers()
	if err != nil {
		c.logger.WithError(err).Error("Peer discovery failed")
		return
	}

	c.logger.WithField("peer_count", len(peers)).Debug("Discovered peers")

	// Try to connect to new peers
	for _, peer := range peers {
		if peer.ID != c.node.ID {
			c.attemptPeerConnection(peer)
		}
	}
}

func (c *Coordinator) performStatusUpdate() {
	status := &NodeStatus{
		ID:        c.node.ID,
		PeerCount: len(c.node.peers),
		Uptime:    time.Since(time.Now()), // TODO: Track actual uptime
		LastSeen:  time.Now(),
		Load:      c.calculateNodeLoad(),
	}

	if err := c.sendHTTPRequest("POST", "/api/nodes/status", status); err != nil {
		c.logger.WithError(err).Error("Failed to update node status")
	}
}

func (c *Coordinator) attemptPeerConnection(peer *DiscoveredPeer) {
	// Check if we already have this peer
	c.node.peersMu.RLock()
	_, exists := c.node.peers[peer.ID]
	c.node.peersMu.RUnlock()

	if exists {
		return
	}

	c.logger.WithField("peer_id", peer.ID).Debug("Attempting connection to discovered peer")

	// Create peer info for connection
	peerInfo := &PeerInfo{
		ID:        peer.ID,
		PublicKey: peer.PublicKey,
		MeshIP:    peer.MeshIP,
		// TODO: Parse addresses and allowed IPs
	}

	// Add peer to mesh
	if err := c.node.AddPeer(peerInfo); err != nil {
		c.logger.WithError(err).Debug("Failed to add peer")
	}
}

func (c *Coordinator) calculateNodeLoad() float64 {
	// Simple load calculation based on peer count and resource usage
	peerCount := float64(len(c.node.peers))
	maxPeers := 100.0 // Configurable maximum

	return peerCount / maxPeers
}

// Data structures for coordinator communication

type NodeRegistration struct {
	ID         string    `json:"id"`
	PublicKey  string    `json:"public_key"`
	MeshIP     string    `json:"mesh_ip"`
	PublicAddr string    `json:"public_addr"`
	LocalAddr  string    `json:"local_addr"`
	ListenPort int       `json:"listen_port"`
	NATType    NATType   `json:"nat_type"`
	Timestamp  time.Time `json:"timestamp"`
}

type NodeUnregistration struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
}

type NodeStatus struct {
	ID        string        `json:"id"`
	PeerCount int           `json:"peer_count"`
	Uptime    time.Duration `json:"uptime"`
	LastSeen  time.Time     `json:"last_seen"`
	Load      float64       `json:"load"`
}

type IntroductionRequest struct {
	RequesterID string    `json:"requester_id"`
	TargetID    string    `json:"target_id"`
	Timestamp   time.Time `json:"timestamp"`
}
