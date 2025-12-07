package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ServerConfig holds server configuration
type ServerConfig struct {
	Server struct {
		Host        string `yaml:"host"`
		Port        int    `yaml:"port"`
		CertFile    string `yaml:"cert_file"`
		KeyFile     string `yaml:"key_file"`
		LogLevel    string `yaml:"log_level"`
		MaxClients  int    `yaml:"max_clients"`
		UseTLS      bool   `yaml:"use_tls"`
		AutoCert    bool   `yaml:"auto_cert"`
	} `yaml:"server"`
	
	Network struct {
		InterfaceName string   `yaml:"interface_name"`
		DNSServers    []string `yaml:"dns_servers"`
		AllowedIPs    []string `yaml:"allowed_ips"`
	} `yaml:"network"`
}

// ClientConfig holds client configuration
type ClientConfig struct {
	Server struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		FakeSNI  string `yaml:"fake_sni"`
		UseTLS   bool   `yaml:"use_tls"`
		LogLevel string `yaml:"log_level"`
	} `yaml:"server"`
	
	Tunnel struct {
		InterfaceName string   `yaml:"interface_name"`
		LocalIP       string   `yaml:"local_ip"`
		DNSServers    []string `yaml:"dns_servers"`
		Routes        []string `yaml:"routes"`
	} `yaml:"tunnel"`
	
	Client struct {
		ID                string `yaml:"id"`
		ReconnectInterval int    `yaml:"reconnect_interval"`
		HeartbeatInterval int    `yaml:"heartbeat_interval"`
	} `yaml:"client"`
}

// LoadServerConfig loads server configuration from YAML file
func LoadServerConfig(filename string) (*ServerConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config ServerConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	if config.Server.Host == "" {
		config.Server.Host = "0.0.0.0"
	}
	if config.Server.Port == 0 {
		config.Server.Port = 8443
	}
	if config.Server.LogLevel == "" {
		config.Server.LogLevel = "info"
	}
	if config.Server.MaxClients == 0 {
		config.Server.MaxClients = 100
	}
	if config.Server.CertFile == "" {
		config.Server.CertFile = "certs/server.crt"
	}
	if config.Server.KeyFile == "" {
		config.Server.KeyFile = "certs/server.key"
	}
	// Default to TLS enabled for security
	config.Server.UseTLS = true
	config.Server.AutoCert = true

	return &config, nil
}

// LoadClientConfig loads client configuration from YAML file
func LoadClientConfig(filename string) (*ClientConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config ClientConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	if config.Server.Port == 0 {
		config.Server.Port = 8443
	}
	if config.Server.FakeSNI == "" {
		config.Server.FakeSNI = "cloudflare.com"
	}
	if config.Server.LogLevel == "" {
		config.Server.LogLevel = "info"
	}
	if config.Tunnel.InterfaceName == "" {
		config.Tunnel.InterfaceName = "aegis0"
	}
	if config.Tunnel.LocalIP == "" {
		config.Tunnel.LocalIP = "10.8.0.2/24"
	}
	if config.Client.ReconnectInterval == 0 {
		config.Client.ReconnectInterval = 5
	}
	if config.Client.HeartbeatInterval == 0 {
		config.Client.HeartbeatInterval = 30
	}
	// Default to TLS enabled for security
	config.Server.UseTLS = true

	return &config, nil
}
