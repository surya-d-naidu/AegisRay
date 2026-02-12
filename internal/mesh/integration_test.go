package mesh

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/aegisray/vpn-tunnel/internal/config"
)

// getFreePort returns a free port for testing
func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func TestMeshIntegration_Handshake(t *testing.T) {
	// Setup Node 1
	port1, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}

	cfg1 := &config.MeshConfig{
		NodeName:        "node1",
		ListenPort:      port1,
		APIPort:         port1 + 100, // Different API port
		MeshIP:          "10.0.0.1",
		NetworkName:     "test-net",
		NetworkCIDR:     "10.0.0.0/24",
		LogLevel:        "debug",
		EnableTUN:       false,
		UseTLS:          false,
		AutoDiscovery:   true,
		IdentityKeyFile: "", // Ephemeral
	}

	node1, err := NewMeshNode(cfg1)
	if err != nil {
		t.Fatalf("Failed to create node 1: %v", err)
	}

	// Setup Node 2
	port2, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}

	cfg2 := &config.MeshConfig{
		NodeName:        "node2",
		ListenPort:      port2,
		APIPort:         port2 + 100,
		MeshIP:          "10.0.0.2",
		NetworkName:     "test-net",
		NetworkCIDR:     "10.0.0.0/24",
		LogLevel:        "debug",
		EnableTUN:       false,
		UseTLS:          false,
		AutoDiscovery:   true,
		IdentityKeyFile: "",
		StaticPeers:     []string{fmt.Sprintf("127.0.0.1:%d", port1)}, // Node 2 calls Node 1
	}

	node2, err := NewMeshNode(cfg2)
	if err != nil {
		t.Fatalf("Failed to create node 2: %v", err)
	}

	// Start nodes
	go func() {
		if err := node1.Start(); err != nil {
			t.Errorf("Node 1 failed: %v", err)
		}
	}()
	defer node1.Stop()

	go func() {
		if err := node2.Start(); err != nil {
			t.Errorf("Node 2 failed: %v", err)
		}
	}()
	defer node2.Stop()

	// Wait for connection and handshake
	// Node 2 has Node 1 as static peer, so it should initiate connection.
	// We wait for Node 1 to see Node 2.

	t.Log("Waiting for peers to connect...")

	connected := false
	timeout := time.After(10 * time.Second)

	for {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for peers to connect")
			return
		case <-time.After(500 * time.Millisecond):
			peers1 := node1.GetPeers()
			peers2 := node2.GetPeers()

			if len(peers1) > 0 && len(peers2) > 0 {
				// Verify connectedness
				if peers1[0].Connected && peers2[0].Connected {
					connected = true
					goto Done
				}
			}
		}
	}

Done:
	if !connected {
		t.Fatal("Nodes did not connect")
	}

	// Verify Session Keys were exchanged
	// We need to access private encryption manager fields or check peer state
	// Peer struct has SessionKey field?
	// Let's check node.peers map directly since we are in same package

	func() {
		node1.peersMu.RLock()
		defer node1.peersMu.RUnlock()

		for _, peer := range node1.peers {
			// Check if we have a key for this peer in encryption manager
			// But EncryptionManager.peerKeys is private.
			// We can try to Encrypt and see if it succeeds.
			data := []byte("ping")
			_, err := node1.encryption.PeerEncrypt(peer.ID, data)
			if err != nil {
				t.Errorf("Node 1 has no session key for peer %s: %v", peer.ID, err)
			} else {
				t.Logf("Node 1 has valid session key for peer %s", peer.ID)
			}
		}
	}()

	func() {
		node2.peersMu.RLock()
		defer node2.peersMu.RUnlock()

		for _, peer := range node2.peers {
			data := []byte("pong")
			_, err := node2.encryption.PeerEncrypt(peer.ID, data)
			if err != nil {
				t.Errorf("Node 2 has no session key for peer %s: %v", peer.ID, err)
			} else {
				t.Logf("Node 2 has valid session key for peer %s", peer.ID)
			}
		}
	}()
}
