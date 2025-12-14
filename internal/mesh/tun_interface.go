package mesh

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

// TUNInterface manages the TUN virtual network interface
type TUNInterface struct {
	iface  *water.Interface
	meshIP net.IP
	cidr   *net.IPNet
	logger *logrus.Logger

	// Packet handling
	incomingPackets chan []byte
	outgoingPackets chan []byte
	stopCh          chan struct{}
}

// NewTUNInterface creates a new TUN interface
func NewTUNInterface(meshIP net.IP, networkCIDR string, logger *logrus.Logger) (*TUNInterface, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	// Platform-specific interface name
	switch runtime.GOOS {
	case "linux":
		config.Name = "aegis0"
	case "darwin":
		config.Name = "utun"
	case "windows":
		config.Name = "AegisRay"
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %w", err)
	}

	_, cidr, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid network CIDR: %w", err)
	}

	tun := &TUNInterface{
		iface:           iface,
		meshIP:          meshIP,
		cidr:            cidr,
		logger:          logger,
		incomingPackets: make(chan []byte, 1000),
		outgoingPackets: make(chan []byte, 1000),
		stopCh:          make(chan struct{}),
	}

	return tun, nil
}

// Start initializes and starts the TUN interface
func (t *TUNInterface) Start() error {
	t.logger.WithFields(logrus.Fields{
		"interface": t.iface.Name(),
		"mesh_ip":   t.meshIP.String(),
		"cidr":      t.cidr.String(),
	}).Info("Starting TUN interface")

	// Configure the interface
	if err := t.configureInterface(); err != nil {
		return fmt.Errorf("failed to configure TUN interface: %w", err)
	}

	// Start packet handling goroutines
	go t.readPackets()
	go t.writePackets()

	t.logger.Info("TUN interface started successfully")
	return nil
}

// Stop stops the TUN interface
func (t *TUNInterface) Stop() error {
	t.logger.Info("Stopping TUN interface")

	close(t.stopCh)

	if t.iface != nil {
		return t.iface.Close()
	}

	return nil
}

// SendPacket sends a packet through the TUN interface
func (t *TUNInterface) SendPacket(packet []byte) {
	select {
	case t.outgoingPackets <- packet:
	default:
		t.logger.Warn("Outgoing packet buffer full, dropping packet")
	}
}

// ReceivePacket receives a packet from the TUN interface
func (t *TUNInterface) ReceivePacket() <-chan []byte {
	return t.incomingPackets
}

// configureInterface configures the TUN interface with IP and routes
func (t *TUNInterface) configureInterface() error {
	ifaceName := t.iface.Name()

	switch runtime.GOOS {
	case "linux":
		return t.configureLinux(ifaceName)
	case "darwin":
		return t.configureDarwin(ifaceName)
	case "windows":
		return t.configureWindows(ifaceName)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// configureLinux configures the interface on Linux
func (t *TUNInterface) configureLinux(ifaceName string) error {
	commands := [][]string{
		// Set IP address
		{"ip", "addr", "add", fmt.Sprintf("%s/%d", t.meshIP.String(), 16), "dev", ifaceName},
		// Bring interface up
		{"ip", "link", "set", "dev", ifaceName, "up"},
		// Add route for mesh network
		{"ip", "route", "add", t.cidr.String(), "dev", ifaceName},
	}

	for _, cmd := range commands {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			t.logger.WithError(err).WithField("command", cmd).Error("Failed to execute command")
			return err
		}
	}

	return nil
}

// configureDarwin configures the interface on macOS
func (t *TUNInterface) configureDarwin(ifaceName string) error {
	commands := [][]string{
		// Configure interface
		{"ifconfig", ifaceName, t.meshIP.String(), t.meshIP.String(), "up"},
		// Add route
		{"route", "add", "-net", t.cidr.String(), "-interface", ifaceName},
	}

	for _, cmd := range commands {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			t.logger.WithError(err).WithField("command", cmd).Error("Failed to execute command")
			return err
		}
	}

	return nil
}

// configureWindows configures the interface on Windows
func (t *TUNInterface) configureWindows(ifaceName string) error {
	commands := [][]string{
		// Set IP address (Windows netsh)
		{"netsh", "interface", "ip", "set", "address", ifaceName, "static", t.meshIP.String(), "255.255.0.0"},
		// Add route
		{"route", "add", t.cidr.String(), "mask", "255.255.0.0", t.meshIP.String()},
	}

	for _, cmd := range commands {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			t.logger.WithError(err).WithField("command", cmd).Error("Failed to execute command")
			return err
		}
	}

	return nil
}

// readPackets reads packets from the TUN interface
func (t *TUNInterface) readPackets() {
	buffer := make([]byte, 1500) // MTU size

	for {
		select {
		case <-t.stopCh:
			return
		default:
			n, err := t.iface.Read(buffer)
			if err != nil {
				if !isErrClosed(err) {
					t.logger.WithError(err).Error("Failed to read from TUN interface")
				}
				continue
			}

			// Copy packet data
			packet := make([]byte, n)
			copy(packet, buffer[:n])

			// Send to processing channel
			select {
			case t.incomingPackets <- packet:
			default:
				t.logger.Warn("Incoming packet buffer full, dropping packet")
			}
		}
	}
}

// writePackets writes packets to the TUN interface
func (t *TUNInterface) writePackets() {
	for {
		select {
		case <-t.stopCh:
			return
		case packet := <-t.outgoingPackets:
			if _, err := t.iface.Write(packet); err != nil {
				if !isErrClosed(err) {
					t.logger.WithError(err).Error("Failed to write to TUN interface")
				}
			}
		}
	}
}

// isErrClosed checks if error is due to closed interface
func isErrClosed(err error) bool {
	return err != nil && err.Error() == "use of closed file"
}

// GetInterfaceName returns the interface name
func (t *TUNInterface) GetInterfaceName() string {
	if t.iface != nil {
		return t.iface.Name()
	}
	return ""
}

// GetStats returns interface statistics
func (t *TUNInterface) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"interface_name":  t.GetInterfaceName(),
		"mesh_ip":         t.meshIP.String(),
		"network_cidr":    t.cidr.String(),
		"incoming_buffer": len(t.incomingPackets),
		"outgoing_buffer": len(t.outgoingPackets),
	}
}
