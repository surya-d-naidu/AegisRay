package crypto

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestNewEncryptionManager(t *testing.T) {
	// Test creating without existing key
	em, err := NewEncryptionManager(nil)
	if err != nil {
		t.Fatalf("Failed to create encryption manager: %v", err)
	}

	if em.rsaKey == nil {
		t.Error("RSA key should be generated")
	}

	if em.peerKeys == nil {
		t.Error("Peer keys map should be initialized")
	}
}

func TestEncryptionDecryption(t *testing.T) {
	em, err := NewEncryptionManager(nil)
	if err != nil {
		t.Fatalf("Failed to create encryption manager: %v", err)
	}

	data := []byte("secret data")

	// Test default encryption
	encrypted, err := em.Encrypt(data)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	decrypted, err := em.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(data, decrypted) {
		t.Errorf("Decrypted data does not match original. Got %s, want %s", decrypted, data)
	}
}

func TestPeerEncryptionDecryption(t *testing.T) {
	em, err := NewEncryptionManager(nil)
	if err != nil {
		t.Fatalf("Failed to create encryption manager: %v", err)
	}

	peerID := "peer-1"
	key, err := GenerateSharedKey()
	if err != nil {
		t.Fatalf("Failed to generate shared key: %v", err)
	}

	if err := em.SetPeerKey(peerID, key); err != nil {
		t.Fatalf("Failed to set peer key: %v", err)
	}

	data := []byte("peer secret data")

	// Test peer encryption
	encrypted, err := em.PeerEncrypt(peerID, data)
	if err != nil {
		t.Fatalf("Failed to encrypt for peer: %v", err)
	}

	decrypted, err := em.PeerDecrypt(peerID, encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt from peer: %v", err)
	}

	if !bytes.Equal(data, decrypted) {
		t.Errorf("Decrypted data does not match original. Got %s, want %s", decrypted, data)
	}

	// Test with unknown peer (should fallback to default or fail depending on implementation)
	// Current implementation: Fallback to default GCM
	unknownPeerEncrypted, err := em.PeerEncrypt("unknown-peer", data)
	if err != nil {
		t.Fatalf("Failed to encrypt for unknown peer: %v", err)
	}

	unknownPeerDecrypted, err := em.PeerDecrypt("unknown-peer", unknownPeerEncrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt from unknown peer: %v", err)
	}

	if !bytes.Equal(data, unknownPeerDecrypted) {
		t.Errorf("Decrypted data (fallback) does not match original")
	}
}

func TestRSAEncryptionDecryption(t *testing.T) {
	em, err := NewEncryptionManager(nil)
	if err != nil {
		t.Fatalf("Failed to create encryption manager: %v", err)
	}

	pubKeyPEM, err := em.GetPublicKeyPEM()
	if err != nil {
		t.Fatalf("Failed to get public key PEM: %v", err)
	}

	data := []byte("rsa secret data")

	// Use standalone function for encryption
	encrypted, err := EncryptWithRSA(data, pubKeyPEM)
	if err != nil {
		t.Fatalf("Failed to encrypt with RSA: %v", err)
	}

	// Use EM method for decryption
	decrypted, err := em.DecryptWithRSA(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt with RSA: %v", err)
	}

	if !bytes.Equal(data, decrypted) {
		t.Errorf("Decrypted data does not match original. Got %s, want %s", decrypted, data)
	}
}

func TestSignVerify(t *testing.T) {
	em, err := NewEncryptionManager(nil)
	if err != nil {
		t.Fatalf("Failed to create encryption manager: %v", err)
	}

	data := []byte("signed data")
	signature, err := em.Sign(data)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	pubKeyPEM, err := em.GetPublicKeyPEM()
	if err != nil {
		t.Fatalf("Failed to get public key PEM: %v", err)
	}

	if err := Verify(data, signature, pubKeyPEM); err != nil {
		t.Errorf("Failed to verify signature: %v", err)
	}

	// Test invalid signature
	invalidSignature := make([]byte, len(signature))
	copy(invalidSignature, signature)
	invalidSignature[0] ^= 0xFF // Flip bits

	if err := Verify(data, invalidSignature, pubKeyPEM); err == nil {
		t.Error("Verification should have failed with invalid signature")
	}
}

func TestIdentityPersistence(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "aegisray-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "identity.key")

	// 1. Generate and save a key
	em, err := NewEncryptionManager(nil)
	if err != nil {
		t.Fatalf("Failed to create encryption manager: %v", err)
	}

	privKey := em.GetPrivateKey()
	if err := SaveIdentityKey(privKey, keyPath); err != nil {
		t.Fatalf("Failed to save identity key: %v", err)
	}

	// 2. Load the key back
	loadedKey, err := LoadIdentityKey(keyPath)
	if err != nil {
		t.Fatalf("Failed to load identity key: %v", err)
	}

	// 3. Compare keys (simple comparison of modulus)
	if privKey.N.Cmp(loadedKey.N) != 0 {
		t.Error("Loaded key does not match saved key")
	}

	// 4. Test loading non-existent key
	_, err = LoadIdentityKey(filepath.Join(tempDir, "nonexistent.key"))
	if err == nil {
		t.Error("Should fail to load non-existent key")
	}
	if !os.IsNotExist(err) {
		t.Errorf("Expected NotExist error, got: %v", err)
	}
}

func TestKeys(t *testing.T) {
	// Generate a shared key
	key, err := GenerateSharedKey()
	if err != nil {
		t.Fatalf("Failed to generate shared key: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Shared key length mismatch. Got %d, want 32", len(key))
	}
}

// verifyPEMBlock is a helper to verify PEM encoding
func TestGetPublicKeyPEMStructure(t *testing.T) {
	em, err := NewEncryptionManager(nil)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, err := em.GetPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}

	block, rest := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}
	if len(rest) > 0 {
		t.Error("PEM check has extra data")
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("Unexpected PEM type: %s", block.Type)
	}

	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse RSA public key from PEM: %v", err)
	}
}
