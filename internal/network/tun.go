package network

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
)

// TUNInterface manages TUN interface for packet capture
type TUNInterface struct {
	iface    *water.Interface
	ip       net.IP
	subnet   *net.IPNet
	mu       sync.RWMutex
	handlers map[string]PacketHandler
}

// PacketHandler handles incoming packets
type PacketHandler func(packet []byte) error

// NewTUNInterface creates a new TUN interface
func NewTUNInterface(name, cidr string) (*TUNInterface, error) {
	config := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: name,
		},
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %w", err)
	}

	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	tun := &TUNInterface{
		iface:    iface,
		ip:       ip,
		subnet:   subnet,
		handlers: make(map[string]PacketHandler),
	}

	// Configure interface
	if err := tun.configure(); err != nil {
		return nil, fmt.Errorf("failed to configure interface: %w", err)
	}

	return tun, nil
}

// configure sets up the TUN interface
func (t *TUNInterface) configure() error {
	// This would typically use system calls to configure the interface
	// For now, we'll assume it's configured externally
	return nil
}

// ReadPackets continuously reads packets from TUN interface
func (t *TUNInterface) ReadPackets() error {
	buffer := make([]byte, 1500) // MTU size

	for {
		n, err := t.iface.Read(buffer)
		if err != nil {
			return fmt.Errorf("failed to read packet: %w", err)
		}

		packet := make([]byte, n)
		copy(packet, buffer[:n])

		// Parse packet
		go t.handlePacket(packet)
	}
}

// WritePacket writes a packet to the TUN interface
func (t *TUNInterface) WritePacket(packet []byte) error {
	_, err := t.iface.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to write packet: %w", err)
	}
	return nil
}

// handlePacket processes incoming packets
func (t *TUNInterface) handlePacket(data []byte) {
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	
	// Extract destination info for routing
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		dest := ip.DstIP.String()
		
		t.mu.RLock()
		handler, exists := t.handlers[dest]
		if !exists {
			// Use default handler
			handler = t.handlers["default"]
		}
		t.mu.RUnlock()
		
		if handler != nil {
			handler(data)
		}
	}
}

// RegisterHandler registers a packet handler for a destination
func (t *TUNInterface) RegisterHandler(dest string, handler PacketHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.handlers[dest] = handler
}

// Close closes the TUN interface
func (t *TUNInterface) Close() error {
	return t.iface.Close()
}

// GetName returns the interface name
func (t *TUNInterface) GetName() string {
	return t.iface.Name()
}
