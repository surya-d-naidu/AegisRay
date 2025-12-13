package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aegisray/vpn-tunnel/internal/config"
	"github.com/aegisray/vpn-tunnel/internal/mesh"
	"github.com/sirupsen/logrus"
)

var (
	configFile = flag.String("config", "configs/mesh.yaml", "Mesh configuration file")
	nodeID     = flag.String("node-id", "", "Override node ID")
	meshIP     = flag.String("mesh-ip", "", "Override mesh IP")
	exitNode   = flag.Bool("exit-node", false, "Run as exit node")
	daemon     = flag.Bool("daemon", false, "Run as daemon")
	version    = flag.Bool("version", false, "Show version")
)

const (
	AppName    = "AegisRay Mesh"
	AppVersion = "1.0.0"
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("%s v%s\n", AppName, AppVersion)
		fmt.Println("Ultra-stealth mesh VPN with SNI masquerading")
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.LoadMeshConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Apply command line overrides
	if *nodeID != "" {
		// Node ID override would require config modification
		logrus.WithField("node_id", *nodeID).Info("Node ID override not implemented yet")
	}

	if *meshIP != "" {
		cfg.MeshIP = *meshIP
	}

	if *exitNode {
		cfg.ExitNode = true
		cfg.DefaultRoute = true
		cfg.AllowedIPs = []string{"0.0.0.0/0"}
		cfg.AdvertiseRoutes = []string{"0.0.0.0/0"}
	}

	// Setup logging
	setupLogging(cfg.LogLevel, *daemon)

	logrus.WithFields(logrus.Fields{
		"app":       AppName,
		"version":   AppVersion,
		"config":    *configFile,
		"mesh_ip":   cfg.MeshIP,
		"network":   cfg.NetworkName,
		"exit_node": cfg.ExitNode,
		"stealth":   cfg.StealthMode,
	}).Info("Starting AegisRay Mesh Network")

	// Create mesh node
	node, err := mesh.NewMeshNode(cfg)
	if err != nil {
		log.Fatalf("Failed to create mesh node: %v", err)
	}

	// Start the mesh network
	if err := node.Start(); err != nil {
		log.Fatalf("Failed to start mesh node: %v", err)
	}

	// Print connection information
	printNodeInfo(node, cfg)

	// Handle graceful shutdown
	handleShutdown(node)
}

func setupLogging(level string, isDaemon bool) {
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		DisableColors: isDaemon,
	})

	if parsedLevel, err := logrus.ParseLevel(level); err == nil {
		logrus.SetLevel(parsedLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	if isDaemon {
		// In daemon mode, log to syslog or file
		logrus.SetOutput(os.Stdout)
	}
}

func printNodeInfo(node *mesh.MeshNode, cfg *config.MeshConfig) {
	nodeInfo := node.GetNodeInfo()

	fmt.Printf("\n🕸️  AegisRay Mesh Network Node\n")
	fmt.Printf("=====================================\n")
	fmt.Printf("Node ID:      %s\n", nodeInfo.ID[:16]+"...")
	fmt.Printf("Mesh IP:      %s\n", nodeInfo.MeshIP)
	fmt.Printf("Listen Port:  %d\n", nodeInfo.ListenPort)
	fmt.Printf("Network:      %s (%s)\n", cfg.NetworkName, cfg.NetworkCIDR)

	if cfg.ExitNode {
		fmt.Printf("Role:         Exit Node 🚪\n")
	} else {
		fmt.Printf("Role:         Client Node 💻\n")
	}

	if cfg.StealthMode {
		fmt.Printf("Stealth:      Enabled 🥷 (SNI Masquerading)\n")
	}

	fmt.Printf("TLS:          %v\n", cfg.UseTLS)
	fmt.Printf("Auto Discovery: %v\n", cfg.AutoDiscovery)

	if len(cfg.Coordinators) > 0 {
		fmt.Printf("Coordinators: %d configured\n", len(cfg.Coordinators))
	}

	fmt.Printf("\n📊 Status\n")
	fmt.Printf("Connected Peers: %d\n", nodeInfo.PeerCount)
	fmt.Printf("\n")

	// Show routing information
	if cfg.DefaultRoute {
		fmt.Printf("🌐 Routing all internet traffic through mesh\n")
	}

	if len(cfg.AdvertiseRoutes) > 0 {
		fmt.Printf("📢 Advertising routes: %v\n", cfg.AdvertiseRoutes)
	}

	fmt.Printf("\n💡 Tips:\n")
	fmt.Printf("• Check status: curl http://localhost:8080/status\n")
	fmt.Printf("• View peers:   curl http://localhost:8080/peers\n")
	fmt.Printf("• Monitor logs: tail -f /var/log/aegisray-mesh.log\n")
	fmt.Printf("\n")
}

func handleShutdown(node *mesh.MeshNode) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	sig := <-sigChan
	logrus.WithField("signal", sig.String()).Info("Received shutdown signal")

	fmt.Println("\n🛑 Shutting down AegisRay Mesh...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	shutdownCh := make(chan error, 1)
	go func() {
		shutdownCh <- node.Stop()
	}()

	select {
	case err := <-shutdownCh:
		if err != nil {
			logrus.WithError(err).Error("Error during shutdown")
		} else {
			logrus.Info("Mesh node stopped successfully")
		}
	case <-ctx.Done():
		logrus.Warn("Shutdown timeout exceeded, forcing exit")
	}

	fmt.Println("✅ AegisRay Mesh stopped")
}
