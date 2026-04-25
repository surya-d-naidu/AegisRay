package mesh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/surya-d-naidu/AegisRay/internal/certs"
	"github.com/surya-d-naidu/AegisRay/internal/config"
	"github.com/surya-d-naidu/AegisRay/internal/crypto"
	pb "github.com/surya-d-naidu/AegisRay/proto/mesh"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNewMeshNode_IdentityPersistence(t *testing.T) {
	// Create temp dir
	tempDir, err := os.MkdirTemp("", "node-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	keyFile := filepath.Join(tempDir, "identity.key")

	// Create config with this key file
	cfg := &config.MeshConfig{
		IdentityKeyFile: keyFile,
		ListenPort:      0, // Should be fine if not starting
		APIPort:         0,
		LogLevel:        "error",
		NetworkCIDR:     "100.64.0.0/16",
		AllowUnauthenticated: true,
	}

	// 1. Create first node instance - should generate and save key
	node1, err := NewMeshNode(cfg)
	if err != nil {
		t.Fatalf("Failed to create node 1: %v", err)
	}

	// Verify key file exists
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Error("Identity key file was not created")
	}

	// Get Node ID 1
	id1 := node1.ID

	// 2. Create second node instance with SAME config - should load key
	node2, err := NewMeshNode(cfg)
	if err != nil {
		t.Fatalf("Failed to create node 2: %v", err)
	}

	// 3. Verify IDs match (meaning same key was used)
	if node1.ID != node2.ID {
		t.Errorf("Node IDs do not match (Persistence failed). 1: %s, 2: %s", id1, node2.ID)
	}

	// Verify keys match deeply
	// We can't access node private keys directly as they are private in EncryptionManager
	// But since ID is derived from public key, matching ID implies matching public key.
	// Let's verify public keys explicitly
	if node1.PublicKey != node2.PublicKey {
		t.Error("Public keys do not match")
	}
}

func TestGenerateNodeID(t *testing.T) {
	// Generate a dummy RSA key
	// But rsa.GenerateKey needs a rand.Reader.
	// Let's use crypto.GenerateSharedKey logic or just reuse NewEncryptionManager test logic
	em, _ := crypto.NewEncryptionManager(nil)
	pemBytes, _ := em.GetPublicKeyPEM()

	id1 := generateNodeID(string(pemBytes))
	id2 := generateNodeID(string(pemBytes))

	if id1 != id2 {
		t.Error("generateNodeID is not deterministic")
	}

	if len(id1) != 32 { // 16 bytes hex encoded = 32 chars
		t.Errorf("Node ID length mismatch. Got %d, want 32", len(id1))
	}
}

func TestVerifyEstablishedPeerIdentityMatchesTransportCertificate(t *testing.T) {
	ctx, peerID, publicKey := testPeerContext(t)
	node := newTLSMeshNodeForTest(t)
	node.peers[peerID] = &Peer{ID: peerID, PublicKey: publicKey}

	if err := node.verifyEstablishedPeerIdentity(ctx, peerID); err != nil {
		t.Fatalf("expected transport identity to verify, got %v", err)
	}
}

func TestVerifyEstablishedPeerIdentityRejectsSpoofedNodeID(t *testing.T) {
	ctx, _, _ := testPeerContext(t)
	node := newTLSMeshNodeForTest(t)

	if err := node.verifyEstablishedPeerIdentity(ctx, "spoofed-node-id"); err == nil {
		t.Fatal("expected spoofed node id to be rejected")
	}
}

func TestDiscoverPeersAllowsPeerWithoutEndpoint(t *testing.T) {
	ctx, requesterID, requesterKey := testPeerContext(t)
	node := newTLSMeshNodeForTest(t)
	node.peers[requesterID] = &Peer{
		ID:        requesterID,
		PublicKey: requesterKey,
		MeshIP:    net.ParseIP("10.0.0.2"),
	}
	node.peers["peer-without-endpoint"] = &Peer{
		ID:        "peer-without-endpoint",
		PublicKey: requesterKey,
		MeshIP:    net.ParseIP("10.0.0.3"),
	}

	resp, err := node.DiscoverPeers(ctx, &pb.DiscoveryRequest{
		NodeId:      requesterID,
		NetworkName: node.config.NetworkName,
		MaxPeers:    10,
	})
	if err != nil {
		t.Fatalf("discover peers failed: %v", err)
	}

	foundNilEndpointPeer := false
	for _, peerInfo := range resp.Peers {
		if peerInfo.Id != "peer-without-endpoint" {
			continue
		}
		foundNilEndpointPeer = true
		if peerInfo.ConnectionInfo.PublicAddress != "" {
			t.Fatalf("expected empty public address, got %q", peerInfo.ConnectionInfo.PublicAddress)
		}
		if peerInfo.ConnectionInfo.Port != 0 {
			t.Fatalf("expected zero port, got %d", peerInfo.ConnectionInfo.Port)
		}
	}

	if !foundNilEndpointPeer {
		t.Fatal("expected discovered peer without endpoint to be included")
	}
}

func TestRequestIntroductionRejectsTargetWithoutEndpoint(t *testing.T) {
	ctx, requesterID, requesterKey := testPeerContext(t)
	node := newTLSMeshNodeForTest(t)
	node.peers[requesterID] = &Peer{
		ID:        requesterID,
		PublicKey: requesterKey,
		MeshIP:    net.ParseIP("10.0.0.2"),
	}
	node.peers["target-peer"] = &Peer{
		ID:        "target-peer",
		PublicKey: requesterKey,
		MeshIP:    net.ParseIP("10.0.0.3"),
	}

	resp, err := node.RequestIntroduction(ctx, &pb.IntroductionRequest{
		RequesterId: requesterID,
		TargetId:    "target-peer",
		Timestamp:   timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("request introduction failed: %v", err)
	}
	if resp.Success {
		t.Fatal("expected introduction to fail when target endpoint is missing")
	}
}

func newTLSMeshNodeForTest(t *testing.T) *MeshNode {
	t.Helper()

	tempDir := t.TempDir()
	node, err := NewMeshNode(&config.MeshConfig{
		NodeName:        "node-under-test",
		ListenPort:      51820,
		APIPort:         8080,
		MeshIP:          "10.0.0.1",
		NetworkName:     "test-net",
		NetworkCIDR:     "10.0.0.0/24",
		LogLevel:        "error",
		EnableTUN:       false,
		UseTLS:          true,
		AutoDiscovery:   false,
		AllowUnauthenticated: true,
		IdentityKeyFile: filepath.Join(tempDir, "identity.key"),
		CertFile:        filepath.Join(tempDir, "node.crt"),
		KeyFile:         filepath.Join(tempDir, "node.key"),
		PeerStoreFile:   filepath.Join(tempDir, "peers.json"),
	})
	if err != nil {
		t.Fatalf("failed to create test node: %v", err)
	}
	return node
}

func testPeerContext(t *testing.T) (context.Context, string, string) {
	t.Helper()

	tempDir := t.TempDir()
	encryption, err := crypto.NewEncryptionManager(nil)
	if err != nil {
		t.Fatalf("failed to create encryption manager: %v", err)
	}

	certMgr := certs.NewCertificateManager(
		filepath.Join(tempDir, "peer.crt"),
		filepath.Join(tempDir, "peer.key"),
		encryption.GetPrivateKey(),
	)

	tlsCert, err := certMgr.LoadOrGenerateCertificate([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("failed to generate peer certificate: %v", err)
	}
	if len(tlsCert.Certificate) == 0 {
		t.Fatal("expected certificate bytes")
	}

	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse peer certificate: %v", err)
	}

	publicKey, err := encryption.GetPublicKeyPEM()
	if err != nil {
		t.Fatalf("failed to get peer public key: %v", err)
	}

	nodeID := generateNodeID(string(publicKey))
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		},
	})

	return ctx, nodeID, string(publicKey)
}
