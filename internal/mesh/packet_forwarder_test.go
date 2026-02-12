package mesh

import (
	"encoding/hex"
	"net"
	"testing"
)

func TestParseIPPacket_IPv4(t *testing.T) {
	// Construct a minimal valid IPv4 packet
	// Version 4, IHL 5, TOS 0, Total Length 20
	// ID 0, Flags 0, Fragment Offset 0
	// TTL 64, Protocol 17 (UDP), Checksum 0 (ignored)
	// Source IP 10.0.0.1
	// Dest IP 10.0.0.2

	packetHex := "4500001400000000401100000a0000010a000002"
	data, _ := hex.DecodeString(packetHex)

	pf := &PacketForwarder{}

	pkt, err := pf.parseIPPacket(data)
	if err != nil {
		t.Fatalf("Failed to parse valid IPv4 packet: %v", err)
	}

	if !pkt.Source.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("Source IP mismatch. Got %s, want 10.0.0.1", pkt.Source.String())
	}

	if !pkt.Destination.Equal(net.ParseIP("10.0.0.2")) {
		t.Errorf("Dest IP mismatch. Got %s, want 10.0.0.2", pkt.Destination.String())
	}

	if pkt.Protocol != 17 {
		t.Errorf("Protocol mismatch. Got %d, want 17", pkt.Protocol)
	}
}

func TestParseIPPacket_IPv6(t *testing.T) {
	// Version 6
	packetHex := "60000000000000000000000000000000000000000000000000000000000000000000000000000000"
	data, _ := hex.DecodeString(packetHex)

	pf := &PacketForwarder{}

	_, err := pf.parseIPPacket(data)
	if err == nil {
		t.Error("Should return error for IPv6 packet")
	}

	if err.Error() != "ignored ipv6" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestParseIPPacket_TooShort(t *testing.T) {
	data := []byte{0x45}

	pf := &PacketForwarder{}

	_, err := pf.parseIPPacket(data)
	if err == nil {
		t.Error("Should return error for short packet")
	}
}
