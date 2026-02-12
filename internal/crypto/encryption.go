package crypto

import (
	"crypto"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
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

// EncryptionManager handles encryption/decryption for multiple peers
type EncryptionManager struct {
	rsaKey   *rsa.PrivateKey
	peerKeys map[string]cipher.AEAD
	mu       sync.RWMutex

	// Default key for backward compatibility or broadcast
	defaultAEAD cipher.AEAD
}

// NewEncryptionManager creates a new encryption manager with an optional RSA key
func NewEncryptionManager(rsaKey *rsa.PrivateKey) (*EncryptionManager, error) {
	if rsaKey == nil {
		var err error
		rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
	}

	// Create a default XChaCha20-Poly1305 key
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate default key: %w", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create default XChaCha20-Poly1305: %w", err)
	}

	return &EncryptionManager{
		rsaKey:      rsaKey,
		peerKeys:    make(map[string]cipher.AEAD),
		defaultAEAD: aead,
	}, nil
}

// GenerateSharedKey creates a random key for XChaCha20-Poly1305
func GenerateSharedKey() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate shared key: %w", err)
	}
	return key, nil
}

// SetPeerKey sets a session key for a specific peer
func (em *EncryptionManager) SetPeerKey(peerID string, key []byte) error {
	// If key is not 32 bytes (KeySize), we might have an issue.
	// But let's check explicit KeySize constant.
	if len(key) != chacha20poly1305.KeySize {
		return fmt.Errorf("key must be %d bytes", chacha20poly1305.KeySize)
	}

	// Use XChaCha20-Poly1305 for extended nonce support (192-bit) which is safer for random nonces
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("failed to create XChaCha20-Poly1305 for peer %s: %w", peerID, err)
	}

	em.mu.Lock()
	em.peerKeys[peerID] = aead
	em.mu.Unlock()
	return nil
}

// PeerEncrypt encrypts data for a specific peer using their session key
func (em *EncryptionManager) PeerEncrypt(peerID string, data []byte) ([]byte, error) {
	em.mu.RLock()
	aead, exists := em.peerKeys[peerID]
	em.mu.RUnlock()

	if !exists {
		// Fallback to default AEAD if no specific key for the peer
		return em.Encrypt(data)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce for peer %s: %w", peerID, err)
	}

	ciphertext := aead.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// PeerDecrypt decrypts data from a specific peer using their session key
func (em *EncryptionManager) PeerDecrypt(peerID string, data []byte) ([]byte, error) {
	em.mu.RLock()
	aead, exists := em.peerKeys[peerID]
	em.mu.RUnlock()

	if !exists {
		// Fallback to default AEAD if no specific key for the peer
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

// Encrypt encrypts data using the default XChaCha20-Poly1305 key
func (em *EncryptionManager) Encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, em.defaultAEAD.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce for default encryption: %w", err)
	}

	ciphertext := em.defaultAEAD.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using the default XChaCha20-Poly1305 key
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

// GetPrivateKey returns the RSA private key
func (em *EncryptionManager) GetPrivateKey() *rsa.PrivateKey {
	return em.rsaKey
}

// GetPublicKeyPEM returns the RSA public key in PEM format
func (em *EncryptionManager) GetPublicKeyPEM() ([]byte, error) {
	pubKey := &em.rsaKey.PublicKey
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return pubKeyPEM, nil
}

// EncryptWithRSA encrypts data using RSA public key
func EncryptWithRSA(data []byte, pubKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, data, nil)
}

// DecryptWithRSA decrypts data using RSA private key
func (em *EncryptionManager) DecryptWithRSA(data []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, em.rsaKey, data, nil)
}

// Sign signs data using RSA-SHA256
func (em *EncryptionManager) Sign(data []byte) ([]byte, error) {
	hashed := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, em.rsaKey, crypto.SHA256, hashed[:])
}

// Verify verifies an RSA-SHA256 signature
func Verify(data []byte, signature []byte, pubKeyPEM []byte) error {
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	hashed := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hashed[:], signature)
}

// LoadIdentityKey loads an RSA private key from a PEM file
func LoadIdentityKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key PEM")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// SaveIdentityKey saves an RSA private key to a PEM file
func SaveIdentityKey(rsaKey *rsa.PrivateKey, path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory for identity key: %w", err)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
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

// GenerateEphemeralKey generates an X25519 key pair for ECDH
func GenerateEphemeralKey() (*ecdh.PrivateKey, []byte, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	return key, key.PublicKey().Bytes(), nil
}

// DeriveSharedKey performs an ECDH key exchange with a remote public key
// and returns the shared secret hashed with SHA-256 for use as a session key.
func DeriveSharedKey(priv *ecdh.PrivateKey, peerPubKeyBytes []byte) ([]byte, error) {
	peerPubKey, err := ecdh.X25519().NewPublicKey(peerPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer public key: %w", err)
	}

	sharedSecret, err := priv.ECDH(peerPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Always hash the shared secret to derive a key of correct length and properties.
	hash := sha256.Sum256(sharedSecret)
	return hash[:], nil
}
