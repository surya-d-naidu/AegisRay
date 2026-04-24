package trust

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadPolicySignedBundle(t *testing.T) {
	rootPublicKey, rootPrivateKey, err := GenerateRootKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	_, peerPrivateKey, err := GenerateRootKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	peerPublicKeyPEM, err := publicKeyPEM(peerPrivateKey.Public())
	if err != nil {
		t.Fatal(err)
	}

	nodeID, err := NodeIDFromPublicKeyPEM(string(peerPublicKeyPEM))
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := SignBundle("test-net", rootPrivateKey, []PeerAuthorization{
		{
			NodeID:    nodeID,
			PublicKey: string(peerPublicKeyPEM),
			ExpiresAt: time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	tempDir := t.TempDir()
	rootKeyPath := filepath.Join(tempDir, "root.pem")
	bundlePath := filepath.Join(tempDir, "authorized.json")

	rootKeyPEM, err := publicKeyPEM(rootPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootKeyPath, rootKeyPEM, 0644); err != nil {
		t.Fatal(err)
	}

	bundleBytes, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, bundleBytes, 0644); err != nil {
		t.Fatal(err)
	}

	policy, err := LoadPolicy("test-net", rootKeyPath, bundlePath, nil, false)
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	if !policy.Required() {
		t.Fatal("Expected trust policy to require authorization")
	}
	if !policy.IsAuthorized(nodeID, string(peerPublicKeyPEM)) {
		t.Fatal("Expected peer to be authorized")
	}
}

func TestLoadPolicyRejectsTamperedBundle(t *testing.T) {
	rootPublicKey, rootPrivateKey, err := GenerateRootKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	_, peerPrivateKey, err := GenerateRootKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	peerPublicKeyPEM, err := publicKeyPEM(peerPrivateKey.Public())
	if err != nil {
		t.Fatal(err)
	}

	nodeID, err := NodeIDFromPublicKeyPEM(string(peerPublicKeyPEM))
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := SignBundle("test-net", rootPrivateKey, []PeerAuthorization{
		{NodeID: nodeID, PublicKey: string(peerPublicKeyPEM)},
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle.Entries[0].NodeID = "tampered"

	tempDir := t.TempDir()
	rootKeyPath := filepath.Join(tempDir, "root.pem")
	bundlePath := filepath.Join(tempDir, "authorized.json")

	rootKeyPEM, err := publicKeyPEM(rootPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootKeyPath, rootKeyPEM, 0644); err != nil {
		t.Fatal(err)
	}

	bundleBytes, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, bundleBytes, 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadPolicy("test-net", rootKeyPath, bundlePath, nil, false); err == nil {
		t.Fatal("Expected tampered bundle to fail verification")
	}
}

func TestLoadPolicyRejectsMissingAuthorizationSourceByDefault(t *testing.T) {
	if _, err := LoadPolicy("test-net", "", "", nil, false); err == nil {
		t.Fatal("expected missing authorization source to fail")
	}
}

func TestLoadPolicyAllowsExplicitLabMode(t *testing.T) {
	policy, err := LoadPolicy("test-net", "", "", nil, true)
	if err != nil {
		t.Fatalf("expected explicit lab mode to succeed, got %v", err)
	}
	if policy.Required() {
		t.Fatal("lab mode should not require authorization")
	}
}

func publicKeyPEM(publicKey any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
