package certs

import (
	"crypto/ed25519"
	"crypto/rand"
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

// CertificateManager manages TLS certificates for AegisRay.
// The mesh identity key is reused for TLS so the transport and application identity match.
type CertificateManager struct {
	certPath    string
	keyPath     string
	identityKey ed25519.PrivateKey
	certificate *tls.Certificate
}

func NewCertificateManager(certPath, keyPath string, identityKey ed25519.PrivateKey) *CertificateManager {
	return &CertificateManager{
		certPath:    certPath,
		keyPath:     keyPath,
		identityKey: identityKey,
	}
}

func (cm *CertificateManager) LoadOrGenerateCertificate(hosts []string) (*tls.Certificate, error) {
	if cm.certExists() {
		cert, err := cm.loadCertificate()
		if err == nil && cm.isValidCertificate(cert, hosts) {
			cm.certificate = cert
			return cert, nil
		}
	}

	cert, err := cm.generateCertificate(hosts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	cm.certificate = cert
	return cert, nil
}

func (cm *CertificateManager) certExists() bool {
	_, certErr := os.Stat(cm.certPath)
	_, keyErr := os.Stat(cm.keyPath)
	return certErr == nil && keyErr == nil
}

func (cm *CertificateManager) loadCertificate() (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(cm.certPath, cm.keyPath)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (cm *CertificateManager) isValidCertificate(cert *tls.Certificate, hosts []string) bool {
	if len(cert.Certificate) == 0 {
		return false
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}

	if err := ValidatePeerCertificate(x509Cert); err != nil {
		return false
	}

	for _, host := range hosts {
		if err := x509Cert.VerifyHostname(host); err != nil {
			return false
		}
	}

	if len(cm.identityKey) > 0 {
		certPubKey, ok := x509Cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return false
		}
		if !certPubKey.Equal(cm.identityKey.Public()) {
			return false
		}
	}

	return true
}

func (cm *CertificateManager) generateCertificate(hosts []string) (*tls.Certificate, error) {
	if len(cm.identityKey) == 0 {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Ed25519 TLS key: %w", err)
		}
		cm.identityKey = privateKey
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"AegisRay Mesh"},
			CommonName:   "AegisRay Mesh Node",
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{},
		IPAddresses:           []net.IP{},
	}

	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, cm.identityKey.Public(), cm.identityKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	if err := cm.saveCertificate(certDER, cm.identityKey); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  cm.identityKey,
	}

	return &cert, nil
}

func (cm *CertificateManager) saveCertificate(certDER []byte, identityKey ed25519.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(cm.certPath), 0700); err != nil {
		return err
	}

	certOut, err := os.OpenFile(cm.certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(cm.keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(identityKey)
	if err != nil {
		return err
	}

	return pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
}

// ValidatePeerCertificate performs explicit certificate validation for self-signed mesh peers.
func ValidatePeerCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("missing peer certificate")
	}
	if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		return fmt.Errorf("peer certificate is expired or not yet valid")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return fmt.Errorf("peer certificate is not self-signed correctly: %w", err)
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		return fmt.Errorf("peer certificate must use Ed25519")
	}
	return nil
}

func (cm *CertificateManager) GetServerTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*cm.certificate},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

func (cm *CertificateManager) GetClientTLSConfig(_ string, fakeSNI string) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{*cm.certificate},
		ServerName:         fakeSNI,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("missing peer certificate")
			}
			return ValidatePeerCertificate(cs.PeerCertificates[0])
		},
	}
}

func (cm *CertificateManager) GetTLSCertificate() tls.Certificate {
	return *cm.certificate
}

func (cm *CertificateManager) CreateCustomDialer(realHost, fakeSNI string) func(string, string) (net.Conn, error) {
	return func(network, _ string) (net.Conn, error) {
		conn, err := net.Dial(network, realHost)
		if err != nil {
			return nil, err
		}

		tlsConfig := cm.GetClientTLSConfig(realHost, fakeSNI)
		tlsConn := tls.Client(conn, tlsConfig)

		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed with SNI %s: %w", fakeSNI, err)
		}

		return tlsConn, nil
	}
}

func (cm *CertificateManager) GetCertificateInfo() (*CertificateInfo, error) {
	if cm.certificate == nil || len(cm.certificate.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate loaded")
	}

	x509Cert, err := x509.ParseCertificate(cm.certificate.Certificate[0])
	if err != nil {
		return nil, err
	}

	return &CertificateInfo{
		Subject:      x509Cert.Subject.String(),
		Issuer:       x509Cert.Issuer.String(),
		NotBefore:    x509Cert.NotBefore,
		NotAfter:     x509Cert.NotAfter,
		DNSNames:     x509Cert.DNSNames,
		IPAddresses:  x509Cert.IPAddresses,
		SerialNumber: x509Cert.SerialNumber.String(),
	}, nil
}

type CertificateInfo struct {
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	DNSNames     []string
	IPAddresses  []net.IP
	SerialNumber string
}

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
