package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestNewEncryptionManager(t *testing.T) {
	em, err := NewEncryptionManager(nil)
	if err != nil {
		t.Fatalf("Failed to create encryption manager: %v", err)
	}

	if len(em.identityKey) == 0 {
		t.Error("Ed25519 key should be generated")
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

	invalidSignature := make([]byte, len(signature))
	copy(invalidSignature, signature)
	invalidSignature[0] ^= 0xFF

	if err := Verify(data, invalidSignature, pubKeyPEM); err == nil {
		t.Error("Verification should have failed with invalid signature")
	}
}

func TestIdentityPersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "aegisray-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "identity.key")

	em, err := NewEncryptionManager(nil)
	if err != nil {
		t.Fatalf("Failed to create encryption manager: %v", err)
	}

	privKey := em.GetPrivateKey()
	if err := SaveIdentityKey(privKey, keyPath); err != nil {
		t.Fatalf("Failed to save identity key: %v", err)
	}

	loadedKey, err := LoadIdentityKey(keyPath)
	if err != nil {
		t.Fatalf("Failed to load identity key: %v", err)
	}

	if !bytes.Equal(privKey, loadedKey) {
		t.Error("Loaded key does not match saved key")
	}

	_, err = LoadIdentityKey(filepath.Join(tempDir, "nonexistent.key"))
	if err == nil {
		t.Error("Should fail to load non-existent key")
	}
	if !os.IsNotExist(err) {
		t.Errorf("Expected NotExist error, got: %v", err)
	}
}

func TestKeys(t *testing.T) {
	key, err := GenerateSharedKey()
	if err != nil {
		t.Fatalf("Failed to generate shared key: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Shared key length mismatch. Got %d, want 32", len(key))
	}
}

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

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse public key from PEM: %v", err)
	}
	if _, ok := publicKey.(ed25519.PublicKey); !ok {
		t.Fatalf("Parsed public key is not Ed25519")
	}
}
