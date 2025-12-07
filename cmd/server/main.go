package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/aegisray/vpn-tunnel/internal/certs"
	"github.com/aegisray/vpn-tunnel/internal/config"
	"github.com/aegisray/vpn-tunnel/internal/crypto"
	"github.com/aegisray/vpn-tunnel/internal/proxy"
	pb "github.com/aegisray/vpn-tunnel/proto/tunnel"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

var (
	configFile = flag.String("config", "configs/server.yaml", "Configuration file path")
)

// TunnelServer implements the gRPC tunnel service
type TunnelServer struct {
	pb.UnimplementedTunnelServiceServer
	
	config     *config.ServerConfig
	encryption *crypto.EncryptionManager
	certMgr    *certs.CertificateManager
	httpProxy  *proxy.HTTPProxy
	socksProxy *proxy.SOCKSProxy
	sessions   map[string]*Session
	mu         sync.RWMutex
	logger     *logrus.Logger
}

// Session represents a client tunnel session
type Session struct {
	ID         string
	ClientID   string
	Encryption *crypto.EncryptionManager
	Created    time.Time
	LastSeen   time.Time
	Stream     pb.TunnelService_TunnelPacketsServer
}

// NewTunnelServer creates a new tunnel server
func NewTunnelServer(cfg *config.ServerConfig) (*TunnelServer, error) {
	encryption, err := crypto.NewEncryptionManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption manager: %w", err)
	}

	logger := logrus.New()
	level, err := logrus.ParseLevel(cfg.Server.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Initialize certificate manager if TLS is enabled
	var certMgr *certs.CertificateManager
	if cfg.Server.UseTLS {
		certMgr = certs.NewCertificateManager(cfg.Server.CertFile, cfg.Server.KeyFile)
		
		// Generate or load certificates
		hosts := []string{cfg.Server.Host}
		if cfg.Server.Host == "0.0.0.0" {
			hosts = []string{"localhost", "127.0.0.1"}
		}
		
		_, err := certMgr.LoadOrGenerateCertificate(hosts)
		if err != nil {
			return nil, fmt.Errorf("failed to setup certificates: %w", err)
		}

		// Log certificate information
		certInfo, err := certMgr.GetCertificateInfo()
		if err != nil {
			logger.WithError(err).Warn("Failed to get certificate info")
		} else {
			logger.WithFields(logrus.Fields{
				"dns_names":    certInfo.DNSNames,
				"ip_addresses": certInfo.IPAddresses,
				"valid_until":  certInfo.NotAfter,
			}).Info("TLS certificate loaded")
		}
	}

	// Initialize HTTP and SOCKS proxies
	httpProxy := proxy.NewHTTPProxy(8080, logger)
	socksProxy := proxy.NewSOCKSProxy(1080, logger)

	return &TunnelServer{
		config:     cfg,
		encryption: encryption,
		certMgr:    certMgr,
		httpProxy:  httpProxy,
		socksProxy: socksProxy,
		sessions:   make(map[string]*Session),
		logger:     logger,
	}, nil
}

// EstablishTunnel establishes a new tunnel session
func (s *TunnelServer) EstablishTunnel(ctx context.Context, req *pb.TunnelRequest) (*pb.TunnelResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"client_id": req.ClientId,
		"fake_sni":  req.FakeSni,
	}).Info("Establishing tunnel")

	// Create new session
	sessionID := fmt.Sprintf("session_%d", time.Now().UnixNano())
	
	// Create encryption for this session
	sessionEncryption, err := crypto.NewEncryptionManager()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create session encryption: %v", err)
	}

	session := &Session{
		ID:         sessionID,
		ClientID:   req.ClientId,
		Encryption: sessionEncryption,
		Created:    time.Now(),
		LastSeen:   time.Now(),
	}

	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()

	// Get server public key
	pubKey, err := sessionEncryption.GetPublicKeyPEM()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get public key: %v", err)
	}

	s.logger.WithField("session_id", sessionID).Info("Tunnel established")

	return &pb.TunnelResponse{
		SessionId:       sessionID,
		ServerPublicKey: pubKey,
		Success:         true,
		AssignedIp:      "10.8.0.1", // VPS tunnel IP
	}, nil
}

// TunnelPackets handles bidirectional packet streaming
func (s *TunnelServer) TunnelPackets(stream pb.TunnelService_TunnelPacketsServer) error {
	var session *Session
	
	for {
		req, err := stream.Recv()
		if err != nil {
			s.logger.WithError(err).Error("Failed to receive packet")
			return err
		}

		// Get session
		if session == nil {
			s.mu.RLock()
			session = s.sessions[req.SessionId]
			s.mu.RUnlock()
			
			if session == nil {
				return status.Errorf(codes.NotFound, "session not found: %s", req.SessionId)
			}
			session.Stream = stream
		}

		// Update last seen
		session.LastSeen = time.Now()

		// Process packet in goroutine
		go s.processPacket(session, req)
	}
}

// processPacket decrypts and forwards a packet
func (s *TunnelServer) processPacket(session *Session, req *pb.PacketRequest) {
	s.logger.WithFields(logrus.Fields{
		"session_id": req.SessionId,
		"packet_id":  req.PacketId,
		"fake_sni":   req.FakeSni,
		"host":       req.HostHeader,
	}).Debug("Processing packet")

	// Decrypt packet data
	decryptedData, err := session.Encryption.Decrypt(req.EncryptedData)
	if err != nil {
		s.logger.WithError(err).Error("Failed to decrypt packet")
		s.sendErrorResponse(session, req.PacketId, "decryption failed")
		return
	}

	// Forward packet to destination and get response
	responseData, err := s.forwardPacket(decryptedData)
	if err != nil {
		s.logger.WithError(err).Error("Failed to forward packet")
		s.sendErrorResponse(session, req.PacketId, "forwarding failed")
		return
	}

	// Encrypt response
	encryptedResponse, err := session.Encryption.Encrypt(responseData)
	if err != nil {
		s.logger.WithError(err).Error("Failed to encrypt response")
		s.sendErrorResponse(session, req.PacketId, "encryption failed")
		return
	}

	// Send response back to client
	response := &pb.PacketResponse{
		SessionId:     req.SessionId,
		EncryptedData: encryptedResponse,
		Timestamp:     time.Now().Unix(),
		PacketId:      req.PacketId,
		Success:       true,
	}

	if err := session.Stream.Send(response); err != nil {
		s.logger.WithError(err).Error("Failed to send response")
	}
}

// forwardPacket forwards decrypted packet to destination
func (s *TunnelServer) forwardPacket(packet []byte) ([]byte, error) {
	// Parse packet and extract destination
	// This is a simplified implementation
	// In reality, you'd parse IP headers and route accordingly
	
	// For now, simulate forwarding to internet
	// In a real implementation, you'd:
	// 1. Parse the IP packet
	// 2. Create a raw socket or use a TUN interface
	// 3. Forward to the actual destination
	// 4. Capture the response
	
	// Simulate network delay and response
	time.Sleep(10 * time.Millisecond)
	
	// Return a mock response (in real implementation, this would be the actual response)
	response := make([]byte, len(packet))
	copy(response, packet)
	
	return response, nil
}

// sendErrorResponse sends an error response to the client
func (s *TunnelServer) sendErrorResponse(session *Session, packetID uint32, errorMsg string) {
	response := &pb.PacketResponse{
		SessionId: session.ID,
		Timestamp: time.Now().Unix(),
		PacketId:  packetID,
		Success:   false,
		Error:     errorMsg,
	}

	if err := session.Stream.Send(response); err != nil {
		s.logger.WithError(err).Error("Failed to send error response")
	}
}

// Heartbeat handles heartbeat requests
func (s *TunnelServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	s.mu.RLock()
	session, exists := s.sessions[req.SessionId]
	s.mu.RUnlock()

	if !exists {
		return nil, status.Errorf(codes.NotFound, "session not found")
	}

	session.LastSeen = time.Now()

	return &pb.HeartbeatResponse{
		Alive:     true,
		Timestamp: time.Now().Unix(),
	}, nil
}

// cleanupSessions removes expired sessions
func (s *TunnelServer) cleanupSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for sessionID, session := range s.sessions {
			if now.Sub(session.LastSeen) > 5*time.Minute {
				s.logger.WithField("session_id", sessionID).Info("Cleaning up expired session")
				delete(s.sessions, sessionID)
			}
		}
		s.mu.Unlock()
	}
}

func main() {
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadServerConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create tunnel server
	server, err := NewTunnelServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start cleanup routine
	go server.cleanupSessions()

	// Start HTTP proxy server
	go func() {
		if err := server.httpProxy.Start(); err != nil {
			server.logger.WithError(err).Error("HTTP proxy server failed")
		}
	}()

	// Start SOCKS proxy server
	go func() {
		if err := server.socksProxy.Start(); err != nil {
			server.logger.WithError(err).Error("SOCKS proxy server failed")
		}
	}()

	// Create gRPC server with TLS if enabled
	var grpcServer *grpc.Server
	if cfg.Server.UseTLS && server.certMgr != nil {
		// Create TLS credentials
		tlsConfig := server.certMgr.GetServerTLSConfig()
		creds := credentials.NewTLS(tlsConfig)
		
		grpcServer = grpc.NewServer(grpc.Creds(creds))
		server.logger.Info("gRPC server configured with TLS")
	} else {
		grpcServer = grpc.NewServer()
		server.logger.Warn("gRPC server running without TLS (insecure)")
	}
	
	pb.RegisterTunnelServiceServer(grpcServer, server)

	// Listen on address
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}

	server.logger.WithField("address", addr).Info("Starting AegisRay tunnel server")

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		server.logger.Info("Shutting down server...")
		grpcServer.GracefulStop()
	}()

	// Start server
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
