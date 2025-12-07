package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CertificateManager manages TLS certificates for AegisRay
type CertificateManager struct {
	certPath    string
	keyPath     string
	certificate *tls.Certificate
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(certPath, keyPath string) *CertificateManager {
	return &CertificateManager{
		certPath: certPath,
		keyPath:  keyPath,
	}
}

// LoadOrGenerateCertificate loads existing certificate or generates a new one
func (cm *CertificateManager) LoadOrGenerateCertificate(hosts []string) (*tls.Certificate, error) {
	// Try to load existing certificate
	if cm.certExists() {
		cert, err := cm.loadCertificate()
		if err == nil && cm.isValidCertificate(cert, hosts) {
			cm.certificate = cert
			return cert, nil
		}
	}

	// Generate new certificate
	cert, err := cm.generateCertificate(hosts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	cm.certificate = cert
	return cert, nil
}

// certExists checks if certificate files exist
func (cm *CertificateManager) certExists() bool {
	_, certErr := os.Stat(cm.certPath)
	_, keyErr := os.Stat(cm.keyPath)
	return certErr == nil && keyErr == nil
}

// loadCertificate loads certificate from files
func (cm *CertificateManager) loadCertificate() (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(cm.certPath, cm.keyPath)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// isValidCertificate checks if certificate is valid for the given hosts
func (cm *CertificateManager) isValidCertificate(cert *tls.Certificate, hosts []string) bool {
	if len(cert.Certificate) == 0 {
		return false
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}

	// Check if certificate is expired or will expire soon
	if time.Until(x509Cert.NotAfter) < 24*time.Hour {
		return false
	}

	// Check if all hosts are covered
	for _, host := range hosts {
		if err := x509Cert.VerifyHostname(host); err != nil {
			return false
		}
	}

	return true
}

// generateCertificate generates a new self-signed certificate
func (cm *CertificateManager) generateCertificate(hosts []string) (*tls.Certificate, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"AegisRay VPN"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{},
		DNSNames:     []string{},
	}

	// Add hosts to certificate
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}

	// Add common fake domains for better disguise
	fakeDomains := []string{
		"cloudflare.com",
		"*.cloudflare.com",
		"github.com",
		"*.github.com",
		"google.com",
		"*.google.com",
		"microsoft.com",
		"*.microsoft.com",
		"amazon.com",
		"*.amazon.com",
	}
	template.DNSNames = append(template.DNSNames, fakeDomains...)

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Save certificate to file
	if err := cm.saveCertificate(certDER, privateKey); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	// Create TLS certificate
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	return &cert, nil
}

// saveCertificate saves certificate and private key to files
func (cm *CertificateManager) saveCertificate(certDER []byte, privateKey *rsa.PrivateKey) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(cm.certPath), 0755); err != nil {
		return err
	}

	// Save certificate
	certOut, err := os.Create(cm.certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	// Save private key
	keyOut, err := os.Create(cm.keyPath)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	return pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
}

// GetTLSConfig returns TLS configuration for server
func (cm *CertificateManager) GetServerTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*cm.certificate},
		ServerName:   "", // Allow any SNI
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

// GetClientTLSConfig returns TLS configuration for client with fake SNI
func (cm *CertificateManager) GetClientTLSConfig(serverName, fakeSNI string) *tls.Config {
	return &tls.Config{
		ServerName:         fakeSNI, // Use fake SNI for handshake
		InsecureSkipVerify: true,    // Skip verification since we're using fake SNI
		MinVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

// CreateCustomDialer creates a custom dialer that handles SNI masquerading
func (cm *CertificateManager) CreateCustomDialer(realHost, fakeSNI string) func(string, string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		// Always connect to the real server address
		conn, err := net.Dial(network, realHost)
		if err != nil {
			return nil, err
		}

		// Wrap with TLS using fake SNI
		tlsConfig := cm.GetClientTLSConfig(realHost, fakeSNI)
		tlsConn := tls.Client(conn, tlsConfig)

		// Perform handshake with fake SNI
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed with SNI %s: %w", fakeSNI, err)
		}

		return tlsConn, nil
	}
}

// GetCertificateInfo returns information about the loaded certificate
func (cm *CertificateManager) GetCertificateInfo() (*CertificateInfo, error) {
	if cm.certificate == nil || len(cm.certificate.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate loaded")
	}

	x509Cert, err := x509.ParseCertificate(cm.certificate.Certificate[0])
	if err != nil {
		return nil, err
	}

	return &CertificateInfo{
		Subject:     x509Cert.Subject.String(),
		Issuer:      x509Cert.Issuer.String(),
		NotBefore:   x509Cert.NotBefore,
		NotAfter:    x509Cert.NotAfter,
		DNSNames:    x509Cert.DNSNames,
		IPAddresses: x509Cert.IPAddresses,
		SerialNumber: x509Cert.SerialNumber.String(),
	}, nil
}

// CertificateInfo contains information about a certificate
type CertificateInfo struct {
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	DNSNames     []string
	IPAddresses  []net.IP
	SerialNumber string
}

// String returns a formatted string representation of certificate info
func (ci *CertificateInfo) String() string {
	return fmt.Sprintf(`Certificate Information:
  Subject: %s
  Issuer: %s
  Valid From: %s
  Valid Until: %s
  DNS Names: %v
  IP Addresses: %v
  Serial Number: %s`,
		ci.Subject,
		ci.Issuer,
		ci.NotBefore.Format(time.RFC3339),
		ci.NotAfter.Format(time.RFC3339),
		ci.DNSNames,
		ci.IPAddresses,
		ci.SerialNumber,
	)
}
