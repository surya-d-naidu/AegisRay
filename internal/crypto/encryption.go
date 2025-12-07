package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

// EncryptionManager handles AES encryption/decryption
type EncryptionManager struct {
	key    []byte
	gcm    cipher.AEAD
	rsaKey *rsa.PrivateKey
}

// NewEncryptionManager creates a new encryption manager
func NewEncryptionManager() (*EncryptionManager, error) {
	// Generate AES key
	key := make([]byte, 32) // AES-256
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate RSA key pair
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &EncryptionManager{
		key:    key,
		gcm:    gcm,
		rsaKey: rsaKey,
	}, nil
}

// Encrypt encrypts data using AES-256-GCM
func (em *EncryptionManager) Encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, em.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := em.gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-256-GCM
func (em *EncryptionManager) Decrypt(data []byte) ([]byte, error) {
	if len(data) < em.gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:em.gcm.NonceSize()], data[em.gcm.NonceSize():]
	plaintext, err := em.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
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

// SetSharedKey sets a shared AES key (after key exchange)
func (em *EncryptionManager) SetSharedKey(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	em.key = key
	em.gcm = gcm
	return nil
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
