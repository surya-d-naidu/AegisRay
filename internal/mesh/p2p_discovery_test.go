package mesh

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	pb "github.com/surya-d-naidu/AegisRay/proto/mesh"
)

func TestMaintainPeersKeepsPersistentKnownPeers(t *testing.T) {
	p2p := &P2PDiscovery{
		logger:      logrus.New(),
		discovered:  make(map[string]*P2PPeerInfo),
		peerClients: make(map[string]pb.MeshServiceClient),
	}

	p2p.discovered["peer-1"] = &P2PPeerInfo{
		ID:         "peer-1",
		Endpoint:   "127.0.0.1:1234",
		LastSeen:   time.Now().Add(-10 * time.Minute),
		Persistent: true,
		Status:     "failed",
	}

	p2p.maintainPeers()

	if _, exists := p2p.discovered["peer-1"]; !exists {
		t.Fatal("persistent known peer should not be pruned")
	}
}

func TestMarkPeerSeenRefreshesDiscoveredPeer(t *testing.T) {
	p2p := &P2PDiscovery{
		logger:      logrus.New(),
		discovered:  make(map[string]*P2PPeerInfo),
		peerClients: make(map[string]pb.MeshServiceClient),
	}

	stale := time.Now().Add(-10 * time.Minute)
	p2p.discovered["peer-1"] = &P2PPeerInfo{
		ID:       "peer-1",
		LastSeen: stale,
		Status:   "failed",
	}

	p2p.markPeerSeen("peer-1")

	peer := p2p.discovered["peer-1"]
	if !peer.LastSeen.After(stale) {
		t.Fatal("expected LastSeen to be refreshed")
	}
	if peer.Status != "active" {
		t.Fatalf("expected peer status to be active, got %s", peer.Status)
	}
	if !peer.Persistent {
		t.Fatal("expected peer to be marked persistent")
	}
}

func TestPeerEndpointsIncludesPrimaryAndAlternates(t *testing.T) {
	p2p := &P2PDiscovery{}
	peer := &P2PPeerInfo{
		Endpoint:     "10.0.0.1:1111",
		AltEndpoints: []string{"10.0.0.2:2222", "10.0.0.1:1111", "10.0.0.3:3333"},
	}

	endpoints := p2p.peerEndpoints(peer)
	if len(endpoints) != 3 {
		t.Fatalf("expected 3 unique endpoints, got %d", len(endpoints))
	}
	if endpoints[0] != "10.0.0.1:1111" {
		t.Fatalf("expected primary endpoint first, got %s", endpoints[0])
	}
}

func TestHandlePeerFailureSetsBackoff(t *testing.T) {
	p2p := &P2PDiscovery{
		logger:      logrus.New(),
		discovered:  make(map[string]*P2PPeerInfo),
		peerClients: make(map[string]pb.MeshServiceClient),
	}

	p2p.discovered["peer-1"] = &P2PPeerInfo{
		ID:         "peer-1",
		Endpoint:   "127.0.0.1:1234",
		Persistent: true,
	}

	p2p.handlePeerFailure("peer-1")

	peer := p2p.discovered["peer-1"]
	if peer.FailureCount != 1 {
		t.Fatalf("expected failure count 1, got %d", peer.FailureCount)
	}
	if peer.NextRetryAt.IsZero() {
		t.Fatal("expected NextRetryAt to be set")
	}
}

func TestMergePeerInfoPreservesAlternateEndpoints(t *testing.T) {
	p2p := &P2PDiscovery{}
	dst := &P2PPeerInfo{
		Endpoint:     "10.0.0.1:1111",
		AltEndpoints: []string{"10.0.0.2:2222"},
	}
	src := &P2PPeerInfo{
		Endpoint:     "10.0.0.3:3333",
		AltEndpoints: []string{"10.0.0.4:4444", "10.0.0.2:2222"},
		Persistent:   true,
		Status:       "active",
		LastSeen:     time.Now(),
	}

	p2p.mergePeerInfo(dst, src)

	endpoints := p2p.peerEndpoints(dst)
	if len(endpoints) != 4 {
		t.Fatalf("expected 4 unique endpoints after merge, got %d", len(endpoints))
	}
	if !dst.Persistent {
		t.Fatal("expected persistent flag to be preserved")
	}
	if dst.Status != "active" {
		t.Fatalf("expected active status, got %s", dst.Status)
	}
}
