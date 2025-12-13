package config

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// MeshConfig holds mesh network configuration
type MeshConfig struct {
	// Node Configuration
	NodeName   string `yaml:"node_name"`
	MeshIP     string `yaml:"mesh_ip"`
	ListenPort int    `yaml:"listen_port"`
	LogLevel   string `yaml:"log_level"`

	// Network Configuration
	NetworkName string   `yaml:"network_name"`
	NetworkCIDR string   `yaml:"network_cidr"`
	DNSServers  []string `yaml:"dns_servers"`

	// Security Configuration
	UseTLS   bool   `yaml:"use_tls"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`

	// Stealth Configuration
	StealthMode    bool     `yaml:"stealth_mode"`
	StealthDomains []string `yaml:"stealth_domains"`

	// Peer Discovery
	Coordinators  []string `yaml:"coordinators"`
	StaticPeers   []string `yaml:"static_peers"`
	AutoDiscovery bool     `yaml:"auto_discovery"`

	// NAT Traversal
	STUNServers []string `yaml:"stun_servers"`
	TURNServers []string `yaml:"turn_servers"`
	UPnPEnabled bool     `yaml:"upnp_enabled"`

	// Routing
	AllowedIPs     []string `yaml:"allowed_ips"`
	ExcludedRoutes []string `yaml:"excluded_routes"`
	DefaultRoute   bool     `yaml:"default_route"`

	// Performance
	MTU                 int `yaml:"mtu"`
	KeepAlive           int `yaml:"keepalive"`
	PersistentKeepalive int `yaml:"persistent_keepalive"`

	// Advanced
	ExitNode        bool     `yaml:"exit_node"`
	AcceptRoutes    bool     `yaml:"accept_routes"`
	AdvertiseRoutes []string `yaml:"advertise_routes"`

	// Experimental
	MeshRouting   bool `yaml:"mesh_routing"`
	LoadBalancing bool `yaml:"load_balancing"`
}

// LoadMeshConfig loads mesh configuration from YAML file
func LoadMeshConfig(filename string) (*MeshConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config MeshConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	if err := setMeshConfigDefaults(&config); err != nil {
		return nil, fmt.Errorf("failed to set defaults: %w", err)
	}

	// Validate configuration
	if err := validateMeshConfig(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

// setMeshConfigDefaults sets default values for mesh configuration
func setMeshConfigDefaults(config *MeshConfig) error {
	if config.NodeName == "" {
		hostname, _ := os.Hostname()
		if hostname != "" {
			config.NodeName = hostname
		} else {
			config.NodeName = "aegisray-node"
		}
	}

	if config.ListenPort == 0 {
		config.ListenPort = 51820 // WireGuard's default port for stealth
	}

	if config.LogLevel == "" {
		config.LogLevel = "info"
	}

	if config.NetworkName == "" {
		config.NetworkName = "aegisray-mesh"
	}

	if config.NetworkCIDR == "" {
		config.NetworkCIDR = "100.64.0.0/16" // Use CGNAT range like Tailscale
	}

	if len(config.DNSServers) == 0 {
		config.DNSServers = []string{"1.1.1.1", "8.8.8.8"}
	}

	if len(config.StealthDomains) == 0 {
		config.StealthDomains = []string{
			"cloudflare.com",
			"google.com",
			"microsoft.com",
			"amazon.com",
		}
	}

	if len(config.STUNServers) == 0 {
		config.STUNServers = []string{
			"stun:stun.l.google.com:19302",
			"stun:stun1.l.google.com:19302",
			"stun:stun.cloudflare.com:3478",
		}
	}

	if config.MTU == 0 {
		config.MTU = 1420 // Safe MTU for tunneled traffic
	}

	if config.KeepAlive == 0 {
		config.KeepAlive = 25 // Default keepalive
	}

	// Enable TLS by default for security
	config.UseTLS = true

	// Enable auto-discovery by default
	config.AutoDiscovery = true

	// Accept routes by default
	config.AcceptRoutes = true

	return nil
}

// validateMeshConfig validates the mesh configuration
func validateMeshConfig(config *MeshConfig) error {
	// Validate mesh IP
	if config.MeshIP != "" {
		if net.ParseIP(config.MeshIP) == nil {
			return fmt.Errorf("invalid mesh IP: %s", config.MeshIP)
		}
	}

	// Validate network CIDR
	if config.NetworkCIDR != "" {
		if _, _, err := net.ParseCIDR(config.NetworkCIDR); err != nil {
			return fmt.Errorf("invalid network CIDR: %s", config.NetworkCIDR)
		}
	}

	// Validate port range
	if config.ListenPort < 1 || config.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port: %d", config.ListenPort)
	}

	// Validate allowed IPs
	for _, allowedIP := range config.AllowedIPs {
		if _, _, err := net.ParseCIDR(allowedIP); err != nil {
			return fmt.Errorf("invalid allowed IP: %s", allowedIP)
		}
	}

	// Validate excluded routes
	for _, route := range config.ExcludedRoutes {
		if _, _, err := net.ParseCIDR(route); err != nil {
			return fmt.Errorf("invalid excluded route: %s", route)
		}
	}

	// Validate advertise routes
	for _, route := range config.AdvertiseRoutes {
		if _, _, err := net.ParseCIDR(route); err != nil {
			return fmt.Errorf("invalid advertise route: %s", route)
		}
	}

	// Validate MTU
	if config.MTU < 576 || config.MTU > 9000 {
		return fmt.Errorf("invalid MTU: %d (must be between 576 and 9000)", config.MTU)
	}

	return nil
}

// GenerateDefaultMeshConfig generates a default mesh configuration
func GenerateDefaultMeshConfig() *MeshConfig {
	config := &MeshConfig{}
	setMeshConfigDefaults(config)
	return config
}

// GetNodeMeshIP assigns a mesh IP to this node based on the network CIDR
func (c *MeshConfig) GetNodeMeshIP() (string, error) {
	if c.MeshIP != "" {
		return c.MeshIP, nil
	}

	// Auto-assign IP from network CIDR
	_, network, err := net.ParseCIDR(c.NetworkCIDR)
	if err != nil {
		return "", fmt.Errorf("invalid network CIDR: %w", err)
	}

	// Simple IP assignment (in a real implementation, this would be coordinated)
	ip := network.IP
	// Increment the last octet by 1 for this node
	ip[len(ip)-1] += 1

	c.MeshIP = ip.String()
	return c.MeshIP, nil
}

// IsExitNode returns true if this node should act as an exit node
func (c *MeshConfig) IsExitNode() bool {
	return c.ExitNode
}

// ShouldAcceptRoutes returns true if this node should accept routes from peers
func (c *MeshConfig) ShouldAcceptRoutes() bool {
	return c.AcceptRoutes
}

// GetAdvertisedRoutes returns the routes this node advertises
func (c *MeshConfig) GetAdvertisedRoutes() []*net.IPNet {
	routes := make([]*net.IPNet, 0, len(c.AdvertiseRoutes))

	for _, routeStr := range c.AdvertiseRoutes {
		if _, route, err := net.ParseCIDR(routeStr); err == nil {
			routes = append(routes, route)
		}
	}

	return routes
}

// GetAllowedIPs returns the allowed IP ranges for peers
func (c *MeshConfig) GetAllowedIPs() []*net.IPNet {
	allowed := make([]*net.IPNet, 0, len(c.AllowedIPs))

	for _, allowedStr := range c.AllowedIPs {
		if _, allowedNet, err := net.ParseCIDR(allowedStr); err == nil {
			allowed = append(allowed, allowedNet)
		}
	}

	// If no allowed IPs specified, allow the entire mesh network
	if len(allowed) == 0 {
		if _, network, err := net.ParseCIDR(c.NetworkCIDR); err == nil {
			allowed = append(allowed, network)
		}
	}

	return allowed
}

// IsStealthModeEnabled returns true if stealth mode is enabled
func (c *MeshConfig) IsStealthModeEnabled() bool {
	return c.StealthMode
}

// GetCoordinators returns the list of coordinator servers
func (c *MeshConfig) GetCoordinators() []string {
	return c.Coordinators
}

// String returns a string representation of the config
func (c *MeshConfig) String() string {
	return fmt.Sprintf("MeshConfig{NodeName: %s, MeshIP: %s, NetworkCIDR: %s, Port: %d}",
		c.NodeName, c.MeshIP, c.NetworkCIDR, c.ListenPort)
}
