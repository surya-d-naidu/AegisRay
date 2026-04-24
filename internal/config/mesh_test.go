package config

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestGetNodeMeshIP_Deterministic(t *testing.T) {
	config := &MeshConfig{
		NetworkCIDR: "100.64.0.0/16",
	}

	nodeID := "node-1-identity"

	// First call
	ip1, err := config.GetNodeMeshIP(nodeID)
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	// Reset MeshIP to allow recalculation (assuming implementation checks for empty string)
	config.MeshIP = ""

	// Second call
	ip2, err := config.GetNodeMeshIP(nodeID)
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}

	if ip1 != ip2 {
		t.Errorf("GetNodeMeshIP is not deterministic. Got %s and %s", ip1, ip2)
	}
}

func TestGetNodeMeshIP_DifferentIDs(t *testing.T) {
	config := &MeshConfig{
		NetworkCIDR: "100.64.0.0/16",
	}

	// Calculate IP for node 1
	config.MeshIP = ""
	ip1, err := config.GetNodeMeshIP("node-1")
	if err != nil {
		t.Fatal(err)
	}

	// Calculate IP for node 2
	config.MeshIP = ""
	ip2, err := config.GetNodeMeshIP("node-2")
	if err != nil {
		t.Fatal(err)
	}

	if ip1 == ip2 {
		t.Errorf("Different nodes should (likely) get different IPs. Got collision %s", ip1)
	}
}

func TestGetNodeMeshIP_CIDRValidation(t *testing.T) {
	config := &MeshConfig{
		NetworkCIDR: "invalid-cidr",
	}

	if _, err := config.GetNodeMeshIP("node-1"); err == nil {
		t.Error("Expected error for invalid CIDR")
	}
}

func TestLoadMeshConfig(t *testing.T) {
	// Create a temporary config file
	content := `
node_name: test-node
mesh_ip: 10.0.0.1
listen_port: 9000
network_cidr: 10.0.0.0/24
`
	tempDir, err := os.MkdirTemp("", "config-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "mesh.yaml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Load config
	cfg, err := LoadMeshConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.NodeName != "test-node" {
		t.Errorf("Expected NodeName test-node, got %s", cfg.NodeName)
	}
	if cfg.MeshIP != "10.0.0.1" {
		t.Errorf("Expected MeshIP 10.0.0.1, got %s", cfg.MeshIP)
	}
	// Check defaults
	if cfg.LogLevel == "" {
		t.Error("LogLevel default should be set")
	}
	if cfg.MTU == 0 {
		t.Error("MTU default should be set")
	}
}

func TestValidateMeshConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *MeshConfig
		wantErr bool
	}{
		{
			name: "Valid Config",
			config: &MeshConfig{
				MeshIP:      "10.0.0.1",
				NetworkCIDR: "10.0.0.0/24",
				ListenPort:  51820,
				MTU:         1420,
			},
			wantErr: false,
		},
		{
			name: "Invalid IP",
			config: &MeshConfig{
				MeshIP: "invalid-ip",
			},
			wantErr: true,
		},
		{
			name: "Invalid CIDR",
			config: &MeshConfig{
				NetworkCIDR: "10.0.0.1", // Missing mask
			},
			wantErr: true,
		},
		{
			name: "Invalid Port",
			config: &MeshConfig{
				ListenPort: 70000,
			},
			wantErr: true,
		},
		{
			name: "Invalid MTU",
			config: &MeshConfig{
				MTU: 100, // Too small
			},
			wantErr: true,
		},
		{
			name: "Mismatched Trust Files",
			config: &MeshConfig{
				ListenPort:             51820,
				MTU:                    1420,
				TrustRootPublicKeyFile: "root.pem",
			},
			wantErr: true,
		},
		{
			name: "Unauthenticated Mode Cannot Mix With Trust Settings",
			config: &MeshConfig{
				ListenPort:             51820,
				MTU:                    1420,
				AllowUnauthenticated:   true,
				AuthorizedPeerKeys:     []string{"fake-key"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateMeshConfig(tt.config); (err != nil) != tt.wantErr {
				t.Errorf("validateMeshConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Manual verification of hash logic (Optional but good for sanity check)
func TestManualHashVerification(t *testing.T) {
	nodeID := "test-node-id"
	cidr := "10.0.0.0/24"

	config := &MeshConfig{NetworkCIDR: cidr}
	ipStr, err := config.GetNodeMeshIP(nodeID)
	if err != nil {
		t.Fatal(err)
	}

	// Manual calculation
	hash := sha256.Sum256([]byte(nodeID))
	offset := binary.BigEndian.Uint32(hash[:4])

	// 10.0.0.0/24 -> Max hosts 254
	// Offset % 254 + 2

	expectedHost := (offset % 254) + 2
	expectedIP := fmt.Sprintf("10.0.0.%d", expectedHost)

	if ipStr != expectedIP {
		t.Errorf("Manual verification failed. Got %s, Calculated %s", ipStr, expectedIP)
	}
}
