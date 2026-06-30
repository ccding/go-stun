package stun

import (
	"testing"
)

func TestAttributeSafetyRawAddr(t *testing.T) {
	// Test case 1: attribute too short (< 4 bytes)
	att1 := &attribute{
		types:  attributeMappedAddress,
		length: 2,
		value:  []byte{0x00, 0x01},
	}
	_, err := att1.rawAddr()
	if err == nil {
		t.Error("expected error for attribute value too short (< 4 bytes)")
	}

	// Test case 2: IPv4 family but too short (< 8 bytes)
	att2 := &attribute{
		types:  attributeMappedAddress,
		length: 6,
		value:  []byte{0x00, 0x01, 0x12, 0x34, 0x01, 0x02},
	}
	_, err = att2.rawAddr()
	if err == nil {
		t.Error("expected error for IPv4 attribute length mismatch (< 8 bytes)")
	}

	// Test case 3: IPv6 family but too short (< 20 bytes)
	att3 := &attribute{
		types:  attributeMappedAddress,
		length: 12,
		value:  []byte{0x00, 0x02, 0x12, 0x34, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}
	_, err = att3.rawAddr()
	if err == nil {
		t.Error("expected error for IPv6 attribute length mismatch (< 20 bytes)")
	}

	// Test case 4: unknown family type
	att4 := &attribute{
		types:  attributeMappedAddress,
		length: 8,
		value:  []byte{0x00, 0x03, 0x12, 0x34, 0x01, 0x02, 0x03, 0x04},
	}
	_, err = att4.rawAddr()
	if err == nil {
		t.Error("expected error for unknown address family")
	}

	// Test case 5: valid IPv4
	att5 := &attribute{
		types:  attributeMappedAddress,
		length: 8,
		value:  []byte{0x00, 0x01, 0x12, 0x34, 127, 0, 0, 1},
	}
	host, err := att5.rawAddr()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if host.ip != "127.0.0.1" || host.port != 0x1234 {
		t.Errorf("invalid host: %v", host)
	}
}

func TestAttributeSafetyXorAddr(t *testing.T) {
	transID := make([]byte, 16)

	// Test case 1: attribute too short (< 4 bytes)
	att1 := &attribute{
		types:  attributeXorMappedAddress,
		length: 2,
		value:  []byte{0x00, 0x01},
	}
	_, err := att1.xorAddr(transID)
	if err == nil {
		t.Error("expected error for attribute value too short (< 4 bytes)")
	}

	// Test case 2: IPv4 family but too short (< 8 bytes)
	att2 := &attribute{
		types:  attributeXorMappedAddress,
		length: 6,
		value:  []byte{0x00, 0x01, 0x12, 0x34, 0x01, 0x02},
	}
	_, err = att2.xorAddr(transID)
	if err == nil {
		t.Error("expected error for IPv4 attribute length mismatch (< 8 bytes)")
	}

	// Test case 3: IPv6 family but too short (< 20 bytes)
	att3 := &attribute{
		types:  attributeXorMappedAddress,
		length: 12,
		value:  []byte{0x00, 0x02, 0x12, 0x34, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}
	_, err = att3.xorAddr(transID)
	if err == nil {
		t.Error("expected error for IPv6 attribute length mismatch (< 20 bytes)")
	}

	// Test case 4: transaction ID too short
	att4 := &attribute{
		types:  attributeXorMappedAddress,
		length: 8,
		value:  []byte{0x00, 0x01, 0x12, 0x34, 0x01, 0x02, 0x03, 0x04},
	}
	_, err = att4.xorAddr(transID[:2]) // transID too short
	if err == nil {
		t.Error("expected error for transaction ID too short")
	}
}
