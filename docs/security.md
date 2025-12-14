# AegisRay Security Model

Comprehensive security documentation covering threat model, encryption, authentication, stealth capabilities, and security best practices for AegisRay mesh VPN.

## 📋 Table of Contents

- [Threat Model](#threat-model)
- [Encryption Architecture](#encryption-architecture) 
- [Authentication System](#authentication-system)
- [Stealth & DPI Evasion](#stealth--dpi-evasion)
- [Network Security](#network-security)
- [Certificate Management](#certificate-management)
- [Security Best Practices](#security-best-practices)
- [Auditing & Compliance](#auditing--compliance)

## 🎯 Threat Model

### Adversary Capabilities

AegisRay is designed to protect against various adversary types:

**1. Network-Level Adversaries** 🌐
- **ISP Monitoring**: Deep packet inspection, traffic analysis
- **Government Censorship**: Protocol blocking, domain filtering
- **Corporate Firewalls**: Port blocking, protocol restrictions
- **Man-in-the-Middle**: Certificate pinning bypass attempts

**2. Infrastructure Adversaries** 🏢  
- **Compromised Exit Nodes**: Malicious operators intercepting traffic
- **Compromised Relays**: Traffic analysis and correlation attacks
- **BGP Hijacking**: Route manipulation and traffic redirection

**3. Endpoint Adversaries** 💻
- **Malware**: Keyloggers, network sniffers, credential theft
- **Physical Access**: Device compromise, certificate extraction
- **Side-Channel Attacks**: Timing analysis, power analysis

### Security Objectives

**Primary Goals:**
- **Confidentiality**: All traffic encrypted end-to-end
- **Integrity**: Tamper-proof communication channels
- **Authenticity**: Verified peer identity and certificate validation
- **Anonymity**: Traffic analysis resistance and metadata protection

**Secondary Goals:**
- **Availability**: Censorship resistance and reliability
- **Performance**: Minimal overhead from security measures
- **Auditability**: Verifiable security properties

---

## 🔐 Encryption Architecture

### Multi-Layer Encryption

AegisRay implements **defense in depth** with multiple encryption layers:

```
┌─── Application Data ───┐
│  User's original data   │ ←─ Layer 3: Application (TLS/HTTPS)
└────────────────────────┘
           │ 
           ↓ ChaCha20-Poly1305
┌─── Mesh Encryption ────┐
│  Encrypted mesh packet │ ←─ Layer 2: Mesh Network Encryption  
└────────────────────────┘
           │
           ↓ TLS 1.3
┌─── Transport Layer ────┐  
│  TLS encrypted tunnel  │ ←─ Layer 1: Transport Encryption
└────────────────────────┘
```

### Layer 1: Transport Encryption (TLS 1.3)

**Protocol**: TLS 1.3 with Perfect Forward Secrecy
**Cipher Suites**:
- `TLS_AES_256_GCM_SHA384` (Preferred)
- `TLS_CHACHA20_POLY1305_SHA256` (Mobile optimized)
- `TLS_AES_128_GCM_SHA256` (Fallback)

**Key Properties**:
- **0-RTT Resumption**: Fast connection establishment
- **Perfect Forward Secrecy**: Compromised long-term keys don't affect past sessions
- **Certificate Pinning**: Prevents CA-based attacks

**Configuration**:
```yaml
security:
  tls:
    min_version: "1.3"
    cipher_suites:
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_CHACHA20_POLY1305_SHA256"
    curves:
      - "X25519"         # Fast elliptic curve
      - "P-256"          # NIST standard curve
```

### Layer 2: Mesh Network Encryption

**Algorithm**: ChaCha20-Poly1305 (RFC 8439)
**Key Size**: 256-bit keys, 96-bit nonces
**Authentication**: Poly1305 MAC with 128-bit tags

**Advantages**:
- **Performance**: Faster than AES on mobile CPUs
- **Security**: Proven resistance to timing attacks
- **Simplicity**: Single primitive for encryption + authentication

**Packet Format**:
```
┌── Mesh Packet Header ──┐
│ Version    (1 byte)    │
│ Type       (1 byte)    │  
│ From Node  (16 bytes)  │
│ To Node    (16 bytes)  │
│ Sequence   (8 bytes)   │
│ Nonce      (12 bytes)  │
├────────────────────────┤
│ Encrypted Payload      │ ←─ ChaCha20-Poly1305
│ (Variable length)      │
├────────────────────────┤
│ Auth Tag   (16 bytes)  │ ←─ Poly1305 MAC
└────────────────────────┘
```

### Key Management

**Key Derivation**: HKDF-SHA256 for key stretching
**Key Rotation**: Automatic rotation based on time and data volume
**Key Exchange**: X25519 Elliptic Curve Diffie-Hellman

**Key Hierarchy**:
```
Master Key (256-bit)
     │ HKDF-SHA256
     ├─→ Session Key 1 (256-bit) ──→ ChaCha20-Poly1305
     ├─→ Session Key 2 (256-bit) ──→ ChaCha20-Poly1305  
     └─→ MAC Key (256-bit) ────────→ Message Authentication
```

**Key Rotation Policy**:
```yaml
encryption:
  key_rotation:
    time_interval: "4h"        # Rotate every 4 hours
    data_limit: "1GB"          # Rotate after 1GB of data
    forced_rotation: "24h"     # Force rotation daily
```

---

## 🔑 Authentication System

### Certificate-Based Authentication

AegisRay uses **mutual TLS (mTLS)** with custom PKI for peer authentication.

**Certificate Hierarchy**:
```
┌─── Root CA Certificate ───┐
│  • Self-signed            │
│  • 4096-bit RSA           │  
│  • 10-year validity       │
│  • Air-gapped generation  │
└───────────────────────────┘
            │ signs
            ↓
┌─── Intermediate CA ───────┐  
│  • Signed by Root CA      │
│  • 2048-bit RSA           │
│  • 2-year validity        │
│  • Online for signing     │
└───────────────────────────┘
            │ signs  
            ↓
┌─── Node Certificates ─────┐
│  • Client/Server certs    │
│  • ECDSA P-256            │
│  • 90-day validity        │
│  • Auto-renewal           │
└───────────────────────────┘
```

### Certificate Fields

**Node Certificate Extensions**:
```
Subject Alternative Names:
  - DNS: node-abc123.mesh.local
  - IP: 100.64.1.42
  - URI: aegis://node-abc123

Extended Key Usage:
  - Client Authentication
  - Server Authentication  
  - Code Signing (for updates)

Custom Extensions:
  - Node Type: exit/client/relay
  - Capabilities: gateway,relay,mobile
  - Region: us-east-1
```

### Certificate Validation

**Validation Process**:
1. **Chain Verification**: Validate certificate chain to trusted root
2. **Revocation Check**: Check Certificate Revocation List (CRL)  
3. **Time Validity**: Ensure certificate is within valid date range
4. **Name Matching**: Verify SAN fields match node identity
5. **Key Usage**: Validate appropriate key usage extensions

**Code Example**:
```go
func (cm *CertManager) ValidatePeerCertificate(cert *x509.Certificate) error {
    // 1. Verify certificate chain
    roots := x509.NewCertPool()
    roots.AddCert(cm.caCert)
    
    opts := x509.VerifyOptions{
        Roots:     roots,
        KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
    }
    
    chains, err := cert.Verify(opts)
    if err != nil {
        return fmt.Errorf("certificate verification failed: %w", err)
    }
    
    // 2. Check custom extensions
    nodeType := extractNodeType(cert)
    if !isValidNodeType(nodeType) {
        return errors.New("invalid node type in certificate")
    }
    
    return nil
}
```

---

## 🎭 Stealth & DPI Evasion

### SNI Masquerading

**Domain Fronting**: Hide real destination behind popular CDN domains

**Supported CDNs**:
- Cloudflare (`*.cloudflare.com`)
- Fastly (`*.fastly.com`) 
- AWS CloudFront (`*.amazonaws.com`)
- Google Cloud CDN (`*.googleapis.com`)
- Microsoft Azure CDN (`*.azure.com`)

**Implementation**:
```go
type SNIMasquerader struct {
    domains        []string
    currentDomain  string
    rotationTimer  *time.Timer
    rotationPeriod time.Duration
}

func (s *SNIMasquerader) GetTLSConfig(realHost string) *tls.Config {
    return &tls.Config{
        ServerName:         s.currentDomain,  // Fake SNI
        InsecureSkipVerify: false,           // Still verify certs
        VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
            // Custom verification for real destination
            return s.verifyRealDestination(realHost, verifiedChains)
        },
    }
}
```

### Traffic Obfuscation

**Packet Padding**: Add random padding to normalize packet sizes
```yaml
stealth:
  padding:
    enabled: true
    min_size: 64      # Minimum padding bytes
    max_size: 512     # Maximum padding bytes  
    probability: 0.8  # 80% of packets get padding
```

**Timing Obfuscation**: Add jitter to prevent timing analysis
```yaml  
stealth:
  timing:
    jitter_ms: 100           # Random delay up to 100ms
    batch_size: 10           # Group packets in batches
    batch_interval_ms: 50    # Batch transmission interval
```

**Protocol Mimicry**: Make VPN traffic look like HTTPS web browsing
```go
func (p *ProtocolMimicry) disguiseAsHTTPS(data []byte) []byte {
    // Add fake HTTP headers
    fakeHeaders := generateFakeHTTPHeaders()
    
    // Fragment data to mimic web page resources
    fragments := fragmentAsWebResources(data)
    
    // Add timing patterns similar to web browsing
    return assembleDisguisedPacket(fakeHeaders, fragments)
}
```

### Anti-Censorship Features

**Port Hopping**: Dynamically switch ports to avoid blocking
```yaml
anti_censorship:
  port_hopping:
    enabled: true
    ports: [80, 443, 8080, 8443, 9443]
    hop_interval: "10m"
    trigger_on_block: true
```

**Protocol Switching**: Fallback through multiple protocols
```yaml
anti_censorship:
  protocol_fallback:
    - "tls_1.3"      # Primary
    - "tls_1.2"      # Fallback 1  
    - "http_tunnel"   # Fallback 2
    - "dns_tunnel"    # Last resort
```

---

## 🛡️ Network Security

### Network Isolation

**Mesh Network Segmentation**:
```yaml
network:
  isolation:
    mode: "strict"              # strict, loose, none
    allowed_subnets:
      - "100.64.0.0/16"        # Mesh network
      - "10.0.0.0/8"           # Corporate LAN
    blocked_subnets:  
      - "169.254.0.0/16"       # AWS metadata
      - "127.0.0.0/8"          # Localhost
      - "224.0.0.0/4"          # Multicast
```

**Firewall Integration**:
```bash
# iptables rules for AegisRay
iptables -A INPUT -i aegis0 -j ACCEPT
iptables -A OUTPUT -o aegis0 -j ACCEPT

# Block direct internet access (force through mesh)  
iptables -A OUTPUT -o eth0 -p tcp --dport 80,443 -j DROP
iptables -A OUTPUT -o aegis0 -p tcp --dport 80,443 -j ACCEPT
```

### NAT Traversal Security

**STUN Server Validation**:
```go
func (d *P2PDiscovery) validateSTUNServer(server string) error {
    // Only allow trusted STUN servers
    trustedServers := []string{
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302", 
        "stun.cloudflare.com:3478",
    }
    
    for _, trusted := range trustedServers {
        if server == trusted {
            return nil
        }
    }
    
    return fmt.Errorf("untrusted STUN server: %s", server)
}
```

**Relay Server Authentication**: Authenticate TURN relays with shared secrets
```yaml
nat_traversal:
  turn_servers:
    - url: "turn:relay1.example.com:3478"
      username: "mesh-client"
      credential: "shared-secret-123"
      credential_type: "password"
```

---

## 📜 Certificate Management

### Certificate Lifecycle

**Generation**:
```bash
# Generate CA certificate
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt \
    -subj "/C=US/ST=CA/L=SF/O=AegisRay/CN=AegisRay Root CA"

# Generate node certificate
openssl req -new -nodes -key node.key -out node.csr \
    -subj "/C=US/ST=CA/L=SF/O=AegisRay/CN=node-$(hostname)"

# Sign with CA
openssl x509 -req -in node.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out node.crt -days 90 -sha256 -extensions v3_req
```

**Auto-Renewal**:
```go
func (cm *CertManager) AutoRenew() {
    ticker := time.NewTicker(24 * time.Hour) // Check daily
    
    for range ticker.C {
        cert, err := cm.LoadNodeCertificate()
        if err != nil {
            log.Error("Failed to load certificate: %v", err)
            continue
        }
        
        // Renew if expires within 30 days
        if time.Until(cert.NotAfter) < 30*24*time.Hour {
            if err := cm.RenewCertificate(); err != nil {
                log.Error("Certificate renewal failed: %v", err)
            } else {
                log.Info("Certificate renewed successfully")
            }
        }
    }
}
```

### Certificate Revocation

**CRL (Certificate Revocation List)**:
```yaml
certificates:
  revocation:
    crl_url: "https://certs.aegisray.com/crl.pem"
    crl_check_interval: "4h"
    crl_cache_timeout: "24h" 
    enforce_crl_check: true
```

**OCSP (Online Certificate Status Protocol)**:
```yaml  
certificates:
  ocsp:
    responder_url: "https://ocsp.aegisray.com"
    timeout: "10s"
    max_age: "168h"  # 7 days
    fallback_to_crl: true
```

---

## 🔒 Security Best Practices

### Deployment Security

**1. Key Management**
```bash
# Generate keys offline
openssl genpkey -algorithm RSA -out ca.key -pkcs8 -aes256

# Store CA key on air-gapped system
cp ca.key /media/secure-usb/
shred -vfz ca.key  # Securely delete from online system

# Use hardware security modules (HSM) for production
pkcs11-tool --module /usr/lib/libsofthsm2.so --init-token
```

**2. Network Hardening** 
```yaml
# Disable unnecessary services
security:
  disable_services:
    - "ssh"          # Use console access only
    - "telnet"       # Plaintext protocols  
    - "ftp"
    - "snmp"
    
  # Enable security features
  kernel_hardening:
    - "net.ipv4.ip_forward=1"
    - "net.ipv4.conf.all.send_redirects=0"
    - "net.ipv4.conf.all.accept_redirects=0"
```

**3. File System Security**
```bash
# Secure certificate permissions
chmod 600 /etc/aegisray/certs/*.key
chmod 644 /etc/aegisray/certs/*.crt
chown aegisray:aegisray /etc/aegisray/certs/*

# Enable file system encryption
cryptsetup luksFormat /dev/sdb1
mount /dev/mapper/aegis-certs /etc/aegisray/certs
```

### Operational Security

**1. Logging & Monitoring**
```yaml
security:
  audit_logging:
    enabled: true
    events:
      - "peer_connect"      # Log all peer connections
      - "cert_validation"   # Certificate validation events  
      - "config_change"     # Configuration modifications
      - "admin_action"      # Administrative operations
    
  siem_integration:
    syslog_server: "192.168.1.100:514"
    format: "cef"          # Common Event Format
```

**2. Incident Response**
```yaml
security:
  incident_response:
    auto_quarantine:
      enabled: true
      triggers:
        - "cert_validation_failed"
        - "suspicious_traffic_pattern" 
        - "repeated_auth_failures"
      actions:
        - "disconnect_peer"
        - "alert_admin"
        - "log_incident"
```

**3. Regular Security Updates**
```bash
# Automated security updates
cat > /etc/cron.daily/aegisray-update << 'EOF'
#!/bin/bash
cd /opt/aegisray
git pull origin main
make build
systemctl restart aegisray
logger "AegisRay security update completed"
EOF
```

### Configuration Security

**Secure Defaults**:
```yaml
# Security-focused configuration template
security:
  # Encryption
  use_tls: true
  tls_version: "1.3"
  cipher_suites: ["TLS_AES_256_GCM_SHA384"]
  
  # Authentication  
  verify_client_certs: true
  certificate_pinning: true
  
  # Stealth
  stealth_mode: true
  stealth_domains: ["cloudflare.com"]
  
  # Network
  disable_plain_http: true
  enforce_perfect_forward_secrecy: true
  
  # Logging (security vs privacy balance)
  log_level: "warn"        # Minimize log data
  log_retention: "7d"      # Short retention
  log_encryption: true     # Encrypt log files
```

---

## 📋 Auditing & Compliance

### Security Auditing

**Automated Security Scanning**:
```bash  
# Vulnerability scanning
nmap -sV --script vuln localhost:443

# Certificate validation
openssl s_client -connect localhost:443 -verify_return_error

# Configuration audit  
aegisray-mesh --audit-config /etc/aegisray/node.yaml
```

**Penetration Testing Checklist**:
- [ ] TLS configuration and cipher suite validation
- [ ] Certificate chain verification and pinning  
- [ ] Protocol downgrade attack resistance
- [ ] Traffic analysis and correlation attacks
- [ ] Side-channel attack resistance (timing, power)
- [ ] Denial of service attack mitigation
- [ ] Key management security audit
- [ ] Authentication bypass attempts

### Compliance Standards

**SOC 2 Type II Compliance**:
```yaml
compliance:
  soc2:
    security_controls:
      - "CC6.1"  # Logical access security  
      - "CC6.2"  # Authentication controls
      - "CC6.3"  # Network security
      - "CC6.6"  # Data encryption
      - "CC7.1"  # System availability
```

**GDPR Compliance**:
```yaml
privacy:
  gdpr:
    data_minimization: true
    purpose_limitation: true  
    retention_periods:
      connection_logs: "30d"
      audit_logs: "1y"  
      user_data: "as_required"
    
    user_rights:
      - "data_portability"
      - "right_to_erasure"  
      - "right_to_rectification"
```

### Security Metrics

**Key Performance Indicators**:
```yaml
metrics:
  security_kpis:
    - name: "certificate_validation_success_rate"
      target: "> 99.9%"
      
    - name: "tls_handshake_failure_rate"  
      target: "< 0.1%"
      
    - name: "authentication_failure_rate"
      target: "< 1%"
      
    - name: "security_incident_count"
      target: "0 per month"
      
    - name: "certificate_expiry_warnings"
      target: "> 30 days notice"
```

---

This security model provides comprehensive protection against a wide range of threats while maintaining usability and performance. Regular security audits and updates are essential to maintain the effectiveness of these security measures.
