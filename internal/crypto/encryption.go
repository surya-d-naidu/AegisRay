package crypto

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptionManager handles encryption/decryption for multiple peers.
// Identity is Ed25519, while per-peer session keys use X25519 + XChaCha20-Poly1305.
type EncryptionManager struct {
	identityKey       ed25519.PrivateKey
	identityPublicKey ed25519.PublicKey
	peerKeys          map[string]cipher.AEAD
	mu                sync.RWMutex

	// Default key for backward compatibility or broadcast
	defaultAEAD cipher.AEAD
}

// NewEncryptionManager creates a new encryption manager with an optional Ed25519 identity key.
func NewEncryptionManager(identityKey ed25519.PrivateKey) (*EncryptionManager, error) {
	if len(identityKey) == 0 {
		_, generatedKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
		}
		identityKey = generatedKey
	}

	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate default key: %w", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create default XChaCha20-Poly1305: %w", err)
	}

	return &EncryptionManager{
		identityKey:       identityKey,
		identityPublicKey: identityKey.Public().(ed25519.PublicKey),
		peerKeys:          make(map[string]cipher.AEAD),
		defaultAEAD:       aead,
	}, nil
}

// GenerateSharedKey creates a random key for XChaCha20-Poly1305.
func GenerateSharedKey() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate shared key: %w", err)
	}
	return key, nil
}

// SetPeerKey sets a session key for a specific peer.
func (em *EncryptionManager) SetPeerKey(peerID string, key []byte) error {
	if len(key) != chacha20poly1305.KeySize {
		return fmt.Errorf("key must be %d bytes", chacha20poly1305.KeySize)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("failed to create XChaCha20-Poly1305 for peer %s: %w", peerID, err)
	}

	em.mu.Lock()
	em.peerKeys[peerID] = aead
	em.mu.Unlock()
	return nil
}

// PeerEncrypt encrypts data for a specific peer using their session key.
func (em *EncryptionManager) PeerEncrypt(peerID string, data []byte) ([]byte, error) {
	em.mu.RLock()
	aead, exists := em.peerKeys[peerID]
	em.mu.RUnlock()

	if !exists {
		return em.Encrypt(data)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce for peer %s: %w", peerID, err)
	}

	ciphertext := aead.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// PeerDecrypt decrypts data from a specific peer using their session key.
func (em *EncryptionManager) PeerDecrypt(peerID string, data []byte) ([]byte, error) {
	em.mu.RLock()
	aead, exists := em.peerKeys[peerID]
	em.mu.RUnlock()

	if !exists {
		return em.Decrypt(data)
	}

	if len(data) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short for peer %s", peerID)
	}

	nonce, ciphertext := data[:aead.NonceSize()], data[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt for peer %s: %w", peerID, err)
	}

	return plaintext, nil
}

// Encrypt encrypts data using the default XChaCha20-Poly1305 key.
func (em *EncryptionManager) Encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, em.defaultAEAD.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce for default encryption: %w", err)
	}

	ciphertext := em.defaultAEAD.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using the default XChaCha20-Poly1305 key.
func (em *EncryptionManager) Decrypt(data []byte) ([]byte, error) {
	if len(data) < em.defaultAEAD.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short for default decryption")
	}

	nonce, ciphertext := data[:em.defaultAEAD.NonceSize()], data[em.defaultAEAD.NonceSize():]
	plaintext, err := em.defaultAEAD.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with default key: %w", err)
	}

	return plaintext, nil
}

// GetPrivateKey returns the Ed25519 private key.
func (em *EncryptionManager) GetPrivateKey() ed25519.PrivateKey {
	return em.identityKey
}

// GetPublicKeyPEM returns the Ed25519 public key in PKIX PEM format.
func (em *EncryptionManager) GetPublicKeyPEM() ([]byte, error) {
	return PublicKeyPEM(em.identityPublicKey)
}

// PublicKeyPEM converts a public key into PKIX PEM format.
func PublicKeyPEM(publicKey any) ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}), nil
}

// Verify verifies an Ed25519 signature over the provided data.
func Verify(data []byte, signature []byte, pubKeyPEM []byte) error {
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	edPublicKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("not an Ed25519 public key")
	}

	if !ed25519.Verify(edPublicKey, data, signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// Sign signs data using the long-term Ed25519 identity key.
func (em *EncryptionManager) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(em.identityKey, data), nil
}

// LoadIdentityKey loads an Ed25519 private key from a PKCS8 PEM file.
func LoadIdentityKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unsupported identity key type %q: rotate to Ed25519 PKCS8", block.Type)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	edPrivateKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("identity key is not Ed25519")
	}

	return edPrivateKey, nil
}

// SaveIdentityKey saves an Ed25519 private key to a PKCS8 PEM file.
func SaveIdentityKey(identityKey ed25519.PrivateKey, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory for identity key: %w", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(identityKey)
	if err != nil {
		return fmt.Errorf("failed to marshal identity key: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open identity key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("failed to encode identity key: %w", err)
	}

	return nil
}

// PublicKeyPEMFromCertificate extracts the leaf certificate public key as PKIX PEM.
func PublicKeyPEMFromCertificate(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	return PublicKeyPEM(cert.PublicKey)
}

// PublicKeyFingerprint returns a stable SHA-256 fingerprint of the PEM public key.
func PublicKeyFingerprint(pubKeyPEM []byte) string {
	sum := sha256.Sum256(pubKeyPEM)
	return fmt.Sprintf("%x", sum[:])
}

// GenerateEphemeralKey generates an X25519 key pair for ECDH.
func GenerateEphemeralKey() (*ecdh.PrivateKey, []byte, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	return key, key.PublicKey().Bytes(), nil
}

// DeriveSharedKey performs an X25519 exchange and derives a session key for XChaCha20-Poly1305.
func DeriveSharedKey(priv *ecdh.PrivateKey, peerPubKeyBytes []byte) ([]byte, error) {
	peerPubKey, err := ecdh.X25519().NewPublicKey(peerPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer public key: %w", err)
	}

	sharedSecret, err := priv.ECDH(peerPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	hash := sha256.Sum256(sharedSecret)
	return hash[:], nil
}
