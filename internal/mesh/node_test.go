package mesh

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aegisray/vpn-tunnel/internal/config"
	"github.com/aegisray/vpn-tunnel/internal/crypto"
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
