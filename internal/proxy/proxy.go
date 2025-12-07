package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// HTTPProxy provides HTTP proxy functionality for AegisRay
type HTTPProxy struct {
	port   int
	logger *logrus.Logger
	server *http.Server
}

// NewHTTPProxy creates a new HTTP proxy server
func NewHTTPProxy(port int, logger *logrus.Logger) *HTTPProxy {
	return &HTTPProxy{
		port:   port,
		logger: logger,
	}
}

// Start starts the HTTP proxy server
func (p *HTTPProxy) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.handleHTTP)

	p.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", p.port),
		Handler: mux,
		// Configure timeouts
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	p.logger.WithField("port", p.port).Info("Starting HTTP proxy server")

	// Handle CONNECT method for HTTPS tunneling
	p.server.Handler = http.HandlerFunc(p.handleRequest)

	return p.server.ListenAndServe()
}

// Stop stops the HTTP proxy server
func (p *HTTPProxy) Stop() error {
	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.server.Shutdown(ctx)
	}
	return nil
}

// handleRequest handles both HTTP and HTTPS (CONNECT) requests
func (p *HTTPProxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	p.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"host":   r.Host,
		"url":    r.URL.String(),
	}).Debug("Proxy request")

	if r.Method == http.MethodConnect {
		p.handleHTTPS(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleHTTP handles regular HTTP requests
func (p *HTTPProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Parse the request URL
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	p.logger.WithFields(logrus.Fields{
		"url":    r.URL.String(),
		"method": r.Method,
	}).Info("Forwarding HTTP request")

	// Create a new request to forward
	req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating request: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for name, values := range r.Header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	// Remove hop-by-hop headers
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Proxy-Authorization")

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	// Forward the request
	resp, err := client.Do(req)
	if err != nil {
		p.logger.WithError(err).Error("Error forwarding request")
		http.Error(w, fmt.Sprintf("Error forwarding request: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		p.logger.WithError(err).Error("Error copying response body")
	}
}

// handleHTTPS handles HTTPS CONNECT requests for tunneling
func (p *HTTPProxy) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	p.logger.WithField("host", r.Host).Info("Establishing HTTPS tunnel")

	// Connect to the target server
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error connecting to %s: %v", r.Host, err), http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	// Send 200 Connection Established
	w.WriteHeader(http.StatusOK)

	// Hijack the connection to handle raw TCP
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error hijacking connection: %v", err), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Start copying data between client and destination
	go p.copyData(clientConn, destConn, "client->dest")
	p.copyData(destConn, clientConn, "dest->client")
}

// copyData copies data between two connections
func (p *HTTPProxy) copyData(src, dst net.Conn, direction string) {
	bytes, err := io.Copy(dst, src)
	if err != nil {
		p.logger.WithFields(logrus.Fields{
			"direction": direction,
			"bytes":     bytes,
			"error":     err,
		}).Debug("Connection copy finished")
	}
}

// SOCKSProxy provides SOCKS5 proxy functionality
type SOCKSProxy struct {
	port   int
	logger *logrus.Logger
}

// NewSOCKSProxy creates a new SOCKS5 proxy
func NewSOCKSProxy(port int, logger *logrus.Logger) *SOCKSProxy {
	return &SOCKSProxy{
		port:   port,
		logger: logger,
	}
}

// Start starts the SOCKS5 proxy server
func (s *SOCKSProxy) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to start SOCKS proxy: %w", err)
	}
	defer listener.Close()

	s.logger.WithField("port", s.port).Info("Starting SOCKS5 proxy server")

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.logger.WithError(err).Error("Error accepting connection")
			continue
		}

		go s.handleSOCKSConnection(conn)
	}
}

// handleSOCKSConnection handles a SOCKS5 connection
func (s *SOCKSProxy) handleSOCKSConnection(conn net.Conn) {
	defer conn.Close()

	// Read SOCKS5 greeting
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		s.logger.WithError(err).Error("Error reading SOCKS greeting")
		return
	}

	if n < 3 || buf[0] != 0x05 {
		s.logger.Error("Invalid SOCKS version")
		return
	}

	// Send no authentication required
	_, err = conn.Write([]byte{0x05, 0x00})
	if err != nil {
		s.logger.WithError(err).Error("Error sending SOCKS auth response")
		return
	}

	// Read connection request
	n, err = conn.Read(buf)
	if err != nil {
		s.logger.WithError(err).Error("Error reading SOCKS request")
		return
	}

	if n < 10 || buf[0] != 0x05 || buf[1] != 0x01 {
		s.logger.Error("Invalid SOCKS request")
		return
	}

	// Parse destination address
	var destAddr string
	switch buf[3] {
	case 0x01: // IPv4
		destAddr = fmt.Sprintf("%d.%d.%d.%d:%d",
			buf[4], buf[5], buf[6], buf[7],
			int(buf[8])<<8+int(buf[9]))
	case 0x03: // Domain name
		domainLen := int(buf[4])
		domain := string(buf[5 : 5+domainLen])
		port := int(buf[5+domainLen])<<8 + int(buf[5+domainLen+1])
		destAddr = fmt.Sprintf("%s:%d", domain, port)
	default:
		s.logger.Error("Unsupported address type")
		return
	}

	s.logger.WithField("dest", destAddr).Info("SOCKS connection request")

	// Connect to destination
	destConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		s.logger.WithError(err).Error("Error connecting to destination")
		// Send connection failed response
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer destConn.Close()

	// Send success response
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		s.logger.WithError(err).Error("Error sending SOCKS success response")
		return
	}

	// Start data relay
	go s.copyData(conn, destConn, "client->dest")
	s.copyData(destConn, conn, "dest->client")
}

// copyData copies data between connections
func (s *SOCKSProxy) copyData(src, dst net.Conn, direction string) {
	bytes, err := io.Copy(dst, src)
	if err != nil {
		s.logger.WithFields(logrus.Fields{
			"direction": direction,
			"bytes":     bytes,
			"error":     err,
		}).Debug("SOCKS copy finished")
	}
}
