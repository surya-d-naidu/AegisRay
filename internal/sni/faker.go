package sni

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// Common fake SNI hostnames that look legitimate
var fakeSNIHosts = []string{
	"cloudflare.com",
	"amazonaws.com",
	"googleusercontent.com",
	"microsoft.com",
	"azure.com",
	"fastly.com",
	"akamai.com",
	"cdnjs.cloudflare.com",
	"ajax.googleapis.com",
	"fonts.googleapis.com",
}

// SNIFaker generates fake SNI headers for firewall bypass
type SNIFaker struct {
	fakeDomains []string
}

// NewSNIFaker creates a new SNI faker
func NewSNIFaker(customDomains ...string) *SNIFaker {
	domains := make([]string, len(fakeSNIHosts))
	copy(domains, fakeSNIHosts)
	
	if len(customDomains) > 0 {
		domains = append(domains, customDomains...)
	}
	
	return &SNIFaker{
		fakeDomains: domains,
	}
}

// GetRandomFakeSNI returns a random fake SNI hostname
func (sf *SNIFaker) GetRandomFakeSNI() string {
	if len(sf.fakeDomains) == 0 {
		return "cloudflare.com"
	}
	
	// Generate random index
	b := make([]byte, 1)
	rand.Read(b)
	index := int(b[0]) % len(sf.fakeDomains)
	
	return sf.fakeDomains[index]
}

// GenerateFakeSubdomain creates a fake subdomain for the given domain
func (sf *SNIFaker) GenerateFakeSubdomain(baseDomain string) string {
	prefixes := []string{"api", "cdn", "static", "www", "assets", "img", "js", "css", "fonts"}
	
	b := make([]byte, 1)
	rand.Read(b)
	prefix := prefixes[int(b[0])%len(prefixes)]
	
	return fmt.Sprintf("%s.%s", prefix, baseDomain)
}

// CreateTLSClientHello creates a fake TLS ClientHello with fake SNI
func (sf *SNIFaker) CreateTLSClientHello(fakeSNI, realHost string) []byte {
	// This is a simplified TLS ClientHello structure
	// In a real implementation, you'd want to create a proper TLS handshake
	
	hello := &TLSClientHello{
		Version:    0x0303, // TLS 1.2
		Random:     make([]byte, 32),
		ServerName: fakeSNI,
		RealHost:   realHost,
	}
	
	// Generate random bytes
	rand.Read(hello.Random)
	
	return hello.Marshal()
}

// TLSClientHello represents a TLS ClientHello message
type TLSClientHello struct {
	Version    uint16
	Random     []byte
	ServerName string
	RealHost   string
}

// Marshal converts TLSClientHello to bytes
func (h *TLSClientHello) Marshal() []byte {
	// Simplified TLS ClientHello marshaling
	// This should be replaced with proper TLS library usage
	data := make([]byte, 0, 256)
	
	// TLS Record Header
	data = append(data, 0x16) // Handshake
	data = append(data, byte(h.Version>>8), byte(h.Version))
	
	// Length placeholder (will be filled later)
	lengthPos := len(data)
	data = append(data, 0x00, 0x00)
	
	// Handshake Header
	data = append(data, 0x01) // ClientHello
	data = append(data, 0x00, 0x00, 0x00) // Length placeholder
	
	// Version
	data = append(data, byte(h.Version>>8), byte(h.Version))
	
	// Random
	data = append(data, h.Random...)
	
	// Session ID length (0)
	data = append(data, 0x00)
	
	// Add SNI extension
	if h.ServerName != "" {
		sniExt := h.createSNIExtension()
		data = append(data, sniExt...)
	}
	
	// Update length fields
	totalLen := len(data) - lengthPos - 2
	data[lengthPos] = byte(totalLen >> 8)
	data[lengthPos+1] = byte(totalLen)
	
	return data
}

// createSNIExtension creates the SNI extension
func (h *TLSClientHello) createSNIExtension() []byte {
	serverName := h.ServerName
	if serverName == "" {
		serverName = "example.com"
	}
	
	ext := make([]byte, 0, 64)
	
	// Extensions length placeholder
	ext = append(ext, 0x00, 0x00)
	
	// SNI Extension
	ext = append(ext, 0x00, 0x00) // Extension type (SNI)
	ext = append(ext, 0x00, byte(len(serverName)+5)) // Extension length
	ext = append(ext, 0x00, byte(len(serverName)+3)) // Server name list length
	ext = append(ext, 0x00) // Name type (hostname)
	ext = append(ext, 0x00, byte(len(serverName))) // Name length
	ext = append(ext, []byte(serverName)...) // Server name
	
	// Update extensions length
	extLen := len(ext) - 2
	ext[0] = byte(extLen >> 8)
	ext[1] = byte(extLen)
	
	return ext
}

// IsCommonDomain checks if a domain is commonly used (good for fake SNI)
func IsCommonDomain(domain string) bool {
	domain = strings.ToLower(domain)
	for _, fakeDomain := range fakeSNIHosts {
		if strings.Contains(domain, fakeDomain) {
			return true
		}
	}
	return false
}
