package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/aegisray/vpn-tunnel/internal/certs"
	"github.com/aegisray/vpn-tunnel/internal/config"
	"github.com/aegisray/vpn-tunnel/internal/crypto"
	"github.com/aegisray/vpn-tunnel/internal/network"
	"github.com/aegisray/vpn-tunnel/internal/sni"
	pb "github.com/aegisray/vpn-tunnel/proto/tunnel"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var (
	configFile = flag.String("config", "configs/client.yaml", "Configuration file path")
)

// TunnelClient manages the VPN tunnel connection
type TunnelClient struct {
	config     *config.ClientConfig
	encryption *crypto.EncryptionManager
	sniFaker   *sni.SNIFaker
	certMgr    *certs.CertificateManager
	tunIface   *network.TUNInterface
	grpcClient pb.TunnelServiceClient
	grpcConn   *grpc.ClientConn
	stream     pb.TunnelService_TunnelPacketsClient
	sessionID  string
	logger     *logrus.Logger
	mu         sync.RWMutex
	packetID   uint32
}

// NewTunnelClient creates a new tunnel client
func NewTunnelClient(cfg *config.ClientConfig) (*TunnelClient, error) {
	encryption, err := crypto.NewEncryptionManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption manager: %w", err)
	}

	sniFaker := sni.NewSNIFaker(cfg.Server.FakeSNI)

	logger := logrus.New()
	level, err := logrus.ParseLevel(cfg.Server.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Initialize certificate manager for TLS
	var certMgr *certs.CertificateManager
	if cfg.Server.UseTLS {
		certMgr = certs.NewCertificateManager("", "") // Client doesn't need cert files
		logger.Info("TLS enabled for client connections")
	}

	return &TunnelClient{
		config:     cfg,
		encryption: encryption,
		sniFaker:   sniFaker,
		certMgr:    certMgr,
		logger:     logger,
	}, nil
}

// Connect establishes connection to the tunnel server
func (c *TunnelClient) Connect() error {
	// Create gRPC connection with fake SNI
	serverAddr := fmt.Sprintf("%s:%d", c.config.Server.Host, c.config.Server.Port)
	
	var opts []grpc.DialOption
	
	if c.config.Server.UseTLS && c.certMgr != nil {
		// Use TLS with SNI masquerading
		c.logger.WithFields(logrus.Fields{
			"server":   serverAddr,
			"fake_sni": c.config.Server.FakeSNI,
		}).Info("Connecting with TLS and fake SNI")

		// Create TLS credentials with fake SNI
		tlsConfig := c.certMgr.GetClientTLSConfig(serverAddr, c.config.Server.FakeSNI)
		creds := credentials.NewTLS(tlsConfig)
		
		opts = []grpc.DialOption{
			grpc.WithTransportCredentials(creds),
			grpc.WithDefaultCallOptions(grpc.Header(&metadata.MD{
				"host":       []string{c.config.Server.Host}, // Real VPS address
				"sni":        []string{c.config.Server.FakeSNI}, // Fake SNI
				":authority": []string{c.config.Server.FakeSNI},
			})),
		}
	} else {
		// Use insecure connection (fallback)
		c.logger.Warn("Using insecure connection (no TLS)")
		opts = []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(grpc.Header(&metadata.MD{
				"host":       []string{c.config.Server.Host}, // Real VPS address
				"sni":        []string{c.config.Server.FakeSNI}, // Fake SNI
				":authority": []string{c.config.Server.FakeSNI},
			})),
		}
	}

	conn, err := grpc.Dial(serverAddr, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}

	c.grpcConn = conn
	c.grpcClient = pb.NewTunnelServiceClient(conn)

	// Establish tunnel
	if err := c.establishTunnel(); err != nil {
		return fmt.Errorf("failed to establish tunnel: %w", err)
	}

	// Create TUN interface
	tunIface, err := network.NewTUNInterface(c.config.Tunnel.InterfaceName, c.config.Tunnel.LocalIP)
	if err != nil {
		return fmt.Errorf("failed to create TUN interface: %w", err)
	}
	c.tunIface = tunIface

	// Register packet handler
	c.tunIface.RegisterHandler("default", c.handleOutgoingPacket)

	c.logger.Info("Tunnel client connected successfully")
	return nil
}

// establishTunnel establishes a tunnel session with the server
func (c *TunnelClient) establishTunnel() error {
	pubKey, err := c.encryption.GetPublicKeyPEM()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Add fake SNI metadata
	ctx = metadata.AppendToOutgoingContext(ctx,
		"sni", c.config.Server.FakeSNI,
		"host", c.config.Server.Host,
	)

	req := &pb.TunnelRequest{
		ClientId:   c.config.Client.ID,
		PublicKey:  pubKey,
		FakeSni:    c.config.Server.FakeSNI,
		DnsServers: c.config.Tunnel.DNSServers,
	}

	resp, err := c.grpcClient.EstablishTunnel(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to establish tunnel: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("tunnel establishment failed: %s", resp.Error)
	}

	c.sessionID = resp.SessionId
	c.logger.WithField("session_id", c.sessionID).Info("Tunnel session established")

	// Start packet streaming
	return c.startPacketStream()
}

// startPacketStream starts the bidirectional packet stream
func (c *TunnelClient) startPacketStream() error {
	ctx := context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx,
		"sni", c.config.Server.FakeSNI,
		"host", c.config.Server.Host,
	)

	stream, err := c.grpcClient.TunnelPackets(ctx)
	if err != nil {
		return fmt.Errorf("failed to create packet stream: %w", err)
	}

	c.stream = stream

	// Start response handler
	go c.handleIncomingPackets()

	return nil
}

// handleOutgoingPacket handles packets from TUN interface
func (c *TunnelClient) handleOutgoingPacket(packet []byte) error {
	c.mu.Lock()
	c.packetID++
	packetID := c.packetID
	c.mu.Unlock()

	// Encrypt packet
	encryptedData, err := c.encryption.Encrypt(packet)
	if err != nil {
		c.logger.WithError(err).Error("Failed to encrypt packet")
		return err
	}

	// Create packet request with fake SNI
	req := &pb.PacketRequest{
		SessionId:     c.sessionID,
		EncryptedData: encryptedData,
		FakeSni:       c.sniFaker.GetRandomFakeSNI(),
		HostHeader:    c.config.Server.Host, // Real VPS address
		Timestamp:     time.Now().Unix(),
		PacketId:      packetID,
	}

	c.logger.WithFields(logrus.Fields{
		"packet_id": packetID,
		"fake_sni":  req.FakeSni,
		"host":      req.HostHeader,
		"size":      len(packet),
	}).Debug("Sending packet")

	// Send to server
	if err := c.stream.Send(req); err != nil {
		c.logger.WithError(err).Error("Failed to send packet")
		return err
	}

	return nil
}

// handleIncomingPackets handles response packets from server
func (c *TunnelClient) handleIncomingPackets() {
	for {
		resp, err := c.stream.Recv()
		if err != nil {
			c.logger.WithError(err).Error("Failed to receive packet")
			// Attempt reconnection
			go c.reconnect()
			return
		}

		if !resp.Success {
			c.logger.WithFields(logrus.Fields{
				"packet_id": resp.PacketId,
				"error":     resp.Error,
			}).Error("Received error response")
			continue
		}

		// Decrypt response
		decryptedData, err := c.encryption.Decrypt(resp.EncryptedData)
		if err != nil {
			c.logger.WithError(err).Error("Failed to decrypt response")
			continue
		}

		// Write to TUN interface
		if err := c.tunIface.WritePacket(decryptedData); err != nil {
			c.logger.WithError(err).Error("Failed to write packet to TUN")
			continue
		}

		c.logger.WithFields(logrus.Fields{
			"packet_id": resp.PacketId,
			"size":      len(decryptedData),
		}).Debug("Received and forwarded packet")
	}
}

// startTunnel starts reading packets from TUN interface
func (c *TunnelClient) startTunnel() error {
	c.logger.Info("Starting packet capture from TUN interface")
	
	// This will block and continuously read packets
	return c.tunIface.ReadPackets()
}

// startHeartbeat sends periodic heartbeat messages
func (c *TunnelClient) startHeartbeat() {
	ticker := time.NewTicker(time.Duration(c.config.Client.HeartbeatInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		
		req := &pb.HeartbeatRequest{
			SessionId: c.sessionID,
			Timestamp: time.Now().Unix(),
		}

		_, err := c.grpcClient.Heartbeat(ctx, req)
		if err != nil {
			c.logger.WithError(err).Error("Heartbeat failed")
			// Attempt reconnection
			go c.reconnect()
		}
		
		cancel()
	}
}

// reconnect attempts to reconnect to the server
func (c *TunnelClient) reconnect() {
	c.logger.Info("Attempting to reconnect...")
	
	// Close existing connection
	if c.grpcConn != nil {
		c.grpcConn.Close()
	}

	// Wait before reconnecting
	time.Sleep(time.Duration(c.config.Client.ReconnectInterval) * time.Second)

	// Attempt to reconnect
	if err := c.Connect(); err != nil {
		c.logger.WithError(err).Error("Failed to reconnect")
		// Try again later
		go func() {
			time.Sleep(time.Duration(c.config.Client.ReconnectInterval) * time.Second)
			c.reconnect()
		}()
	}
}

// Close closes the tunnel client
func (c *TunnelClient) Close() error {
	if c.tunIface != nil {
		c.tunIface.Close()
	}
	if c.grpcConn != nil {
		c.grpcConn.Close()
	}
	return nil
}

func main() {
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadClientConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create tunnel client
	client, err := NewTunnelClient(cfg)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Connect to server
	if err := client.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	// Start heartbeat
	go client.startHeartbeat()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		client.logger.Info("Shutting down client...")
		client.Close()
		os.Exit(0)
	}()

	// Start tunnel (this blocks)
	client.logger.Info("Starting AegisRay tunnel client")
	if err := client.startTunnel(); err != nil {
		log.Fatalf("Tunnel failed: %v", err)
	}
}
