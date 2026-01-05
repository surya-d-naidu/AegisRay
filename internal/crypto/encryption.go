package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"sync"
)

// EncryptionManager handles AES encryption/decryption for multiple peers
type EncryptionManager struct {
	rsaKey   *rsa.PrivateKey
	peerKeys map[string]cipher.AEAD
	mu       sync.RWMutex

	// Default key for backward compatibility or broadcast
	defaultGCM cipher.AEAD
}

// NewEncryptionManager creates a new encryption manager
func NewEncryptionManager() (*EncryptionManager, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Create a default key
	key := make([]byte, 32) // AES-256
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate default AES key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create default AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create default GCM: %w", err)
	}

	return &EncryptionManager{
		rsaKey:     rsaKey,
		peerKeys:   make(map[string]cipher.AEAD),
		defaultGCM: gcm,
	}, nil
}

// GenerateSharedKey creates a random 32-byte key for AES-256
func GenerateSharedKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate shared key: %w", err)
	}
	return key, nil
}

// SetPeerKey sets a session key for a specific peer
func (em *EncryptionManager) SetPeerKey(peerID string, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher for peer %s: %w", peerID, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM for peer %s: %w", peerID, err)
	}

	em.mu.Lock()
	em.peerKeys[peerID] = gcm
	em.mu.Unlock()
	return nil
}

// PeerEncrypt encrypts data for a specific peer using their session key
func (em *EncryptionManager) PeerEncrypt(peerID string, data []byte) ([]byte, error) {
	em.mu.RLock()
	gcm, exists := em.peerKeys[peerID]
	em.mu.RUnlock()

	if !exists {
		// Fallback to default GCM if no specific key for the peer
		return em.Encrypt(data)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce for peer %s: %w", peerID, err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// PeerDecrypt decrypts data from a specific peer using their session key
func (em *EncryptionManager) PeerDecrypt(peerID string, data []byte) ([]byte, error) {
	em.mu.RLock()
	gcm, exists := em.peerKeys[peerID]
	em.mu.RUnlock()

	if !exists {
		// Fallback to default GCM if no specific key for the peer
		return em.Decrypt(data)
	}

	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short for peer %s", peerID)
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt for peer %s: %w", peerID, err)
	}

	return plaintext, nil
}

// Encrypt encrypts data using the default AES-256-GCM key
func (em *EncryptionManager) Encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, em.defaultGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce for default encryption: %w", err)
	}

	ciphertext := em.defaultGCM.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using the default AES-256-GCM key
func (em *EncryptionManager) Decrypt(data []byte) ([]byte, error) {
	if len(data) < em.defaultGCM.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short for default decryption")
	}

	nonce, ciphertext := data[:em.defaultGCM.NonceSize()], data[em.defaultGCM.NonceSize():]
	plaintext, err := em.defaultGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with default key: %w", err)
	}

	return plaintext, nil
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
