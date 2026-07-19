// Copyright 2016 Cong Ding
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stun

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"net"
	"testing"
)

func TestNewPacketFromBytes(t *testing.T) {
	b := make([]byte, 19)
	_, err := newPacketFromBytes(b)
	if err == nil {
		t.Errorf("newPacketFromBytes error")
	}
	b = make([]byte, 20)
	_, err = newPacketFromBytes(b)
	if err != nil {
		t.Errorf("newPacketFromBytes error")
	}
}

func TestNewPacket(t *testing.T) {
	p, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.transID) != 16 || binary.BigEndian.Uint32(p.transID[:4]) != magicCookie {
		t.Fatalf("transaction ID = %x", p.transID)
	}
}

func TestPacketAll(t *testing.T) {
	p, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	mustAddAttribute(t, p, mustChangeReqAttribute(t, true, true))
	mustAddAttribute(t, p, mustSoftwareAttribute(t, "aaa"))
	mustAddAttribute(t, p, mustFingerprintAttribute(t, p))
	pkt, err := newPacketFromBytes(p.bytes())
	if err != nil {
		t.Fatal(err)
	}
	if pkt.types != 0 || pkt.length != 24 || len(pkt.attributes) != 3 {
		t.Fatalf("unexpected packet: type=%#x length=%d attributes=%d", pkt.types, pkt.length, len(pkt.attributes))
	}
	if got := pkt.bytes(); !bytes.Equal(got, p.bytes()) {
		t.Fatalf("packet did not round trip\ngot  %x\nwant %x", got, p.bytes())
	}
}

func TestPacketAcceptsRFC3489TransactionID(t *testing.T) {
	wire := []byte{
		0x01, 0x01, 0x00, 0x00,
		0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
		0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
	}
	p, err := newPacketFromBytes(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.bytes(); !bytes.Equal(got, wire) {
		t.Fatalf("RFC 3489 packet did not round trip\ngot  %x\nwant %x", got, wire)
	}
}

func TestAttributeLengthExcludesPadding(t *testing.T) {
	p, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	mustAddAttribute(t, p, mustSoftwareAttribute(t, "abc"))
	wire := p.bytes()
	if got := binary.BigEndian.Uint16(wire[22:24]); got != 3 {
		t.Fatalf("attribute length = %d, want 3", got)
	}
	if got := binary.BigEndian.Uint16(wire[2:4]); got != 8 {
		t.Fatalf("message length = %d, want 8", got)
	}
	if len(wire) != 28 || wire[27] != 0 {
		t.Fatalf("attribute was not padded to a 4-byte boundary: %x", wire)
	}
}

func TestPacketRejectsInvalidFraming(t *testing.T) {
	tests := [][]byte{
		append([]byte{0x40}, make([]byte, 19)...),
		append([]byte{0, 1, 0, 4}, make([]byte, 16)...),
		append([]byte{0, 1, 0, 2}, make([]byte, 18)...),
	}
	for _, wire := range tests {
		if _, err := newPacketFromBytes(wire); err == nil {
			t.Fatalf("accepted malformed packet: %x", wire)
		}
	}
}

func TestPacketRejectsInvalidFingerprint(t *testing.T) {
	p, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	mustAddAttribute(t, p, mustFingerprintAttribute(t, p))
	wire := p.bytes()
	wire[len(wire)-1] ^= 1
	if _, err := newPacketFromBytes(wire); err == nil {
		t.Fatal("accepted packet with invalid fingerprint")
	}
}

func TestRFC5769SampleRequest(t *testing.T) {
	// RFC 5769 section 2.1. Parsing the MESSAGE-INTEGRITY attribute does not
	// require the password that would be needed to validate it.
	wire, err := hex.DecodeString(
		"000100582112a442b7e7a701bc34d686fa87dfae" +
			"802200105354554e207465737420636c69656e74" +
			"002400046e0001ff" +
			"80290008932ff9b151263b36" +
			"000600096576746a3a68367659202020" +
			"000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2" +
			"80280004e57a3bcf")
	if err != nil {
		t.Fatal(err)
	}
	p, err := newPacketFromBytes(wire)
	if err != nil {
		t.Fatalf("RFC sample did not parse: %v", err)
	}
	if p.types != typeBindingRequest || p.length != 88 || len(p.attributes) != 6 {
		t.Fatalf("unexpected packet: type=%#x length=%d attributes=%d", p.types, p.length, len(p.attributes))
	}
	if !bytes.Equal(p.transID, wire[4:20]) {
		t.Fatalf("transaction ID = %x, want %x", p.transID, wire[4:20])
	}
	if got := p.attributes[3]; got.types != attributeUsername || got.length != 9 || string(got.value) != "evtj:h6vY" {
		t.Fatalf("USERNAME = %#v", got)
	}
	if got := p.bytes(); !bytes.Equal(got, wire) {
		t.Fatalf("re-encoded sample differs\ngot  %x\nwant %x", got, wire)
	}

	p.attributes = p.attributes[:len(p.attributes)-1]
	p.length -= 8
	generated := mustFingerprintAttribute(t, p)
	if !bytes.Equal(generated.value, wire[len(wire)-4:]) {
		t.Fatalf("generated fingerprint = %x, want %x", generated.value, wire[len(wire)-4:])
	}
}

func TestRFC5769XorMappedResponses(t *testing.T) {
	tests := []struct {
		name string
		hex  string
		ip   string
		port uint16
	}{
		{
			name: "IPv4",
			hex: "0101003c2112a442b7e7a701bc34d686fa87dfae" +
				"8022000b7465737420766563746f7220" +
				"002000080001a147e112a643" +
				"000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7" +
				"80280004c07d4c96",
			ip:   "192.0.2.1",
			port: 32853,
		},
		{
			name: "IPv6",
			hex: "010100482112a442b7e7a701bc34d686fa87dfae" +
				"8022000b7465737420766563746f7220" +
				"002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d9" +
				"00080014a382954e4be67bf11784c97c8292c275bfe3ed41" +
				"80280004c8fb0b4c",
			ip:   "2001:db8:1234:5678:11:2233:4455:6677",
			port: 32853,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := hex.DecodeString(tt.hex)
			if err != nil {
				t.Fatal(err)
			}
			p, err := newPacketFromBytes(wire)
			if err != nil {
				t.Fatal(err)
			}
			h, present := p.getXorMappedAddr()
			if !present {
				t.Fatal("XOR-MAPPED-ADDRESS was not found")
			}
			if h == nil || !net.ParseIP(h.IP()).Equal(net.ParseIP(tt.ip)) || h.Port() != tt.port {
				t.Fatalf("XOR-MAPPED-ADDRESS = %#v, want %s:%d", h, tt.ip, tt.port)
			}
			if got := p.bytes(); !bytes.Equal(got, wire) {
				t.Fatalf("response did not round trip\ngot  %x\nwant %x", got, wire)
			}
		})
	}
}

func TestExperimentalXorMappedAddressCompatibility(t *testing.T) {
	transactionID := make([]byte, 16)
	binary.BigEndian.PutUint32(transactionID[:4], magicCookie)
	port := uint16(54321)
	ip := net.ParseIP("192.0.2.25").To4()
	value := []byte{0, attributeFamilyIPv4, byte((port ^ uint16(magicCookie>>16)) >> 8), byte(port ^ uint16(magicCookie>>16))}
	for i := range ip {
		value = append(value, ip[i]^transactionID[i])
	}
	p := &packet{
		transID: transactionID,
		attributes: []attribute{
			*mustNewAttribute(t, attributeXorMappedAddressExp, value),
		},
	}

	host, present := p.getXorMappedAddr()
	if !present || host == nil || host.IP() != "192.0.2.25" || host.Port() != port {
		t.Fatalf("experimental XOR-MAPPED-ADDRESS = %#v, present %v", host, present)
	}
}

func TestServerErrorString(t *testing.T) {
	tests := []struct {
		err  *ServerError
		want string
	}{
		{err: &ServerError{Code: 420}, want: "stun server returned error 420"},
		{err: &ServerError{Code: 500, Reason: "Server Error"}, want: "stun server returned error 500: Server Error"},
	}
	for _, tt := range tests {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("ServerError.Error() = %q, want %q", got, tt.want)
		}
	}
}

func TestPacketPaddingLengths(t *testing.T) {
	for length := 0; length <= 12; length++ {
		t.Run(string(rune('A'+length)), func(t *testing.T) {
			p, err := newPacket()
			if err != nil {
				t.Fatal(err)
			}
			value := bytes.Repeat([]byte{0xa5}, length)
			mustAddAttribute(t, p, mustNewAttribute(t, attributeSoftware, value))
			wire := p.bytes()
			wantBody := 4 + align(length)
			if len(wire) != 20+wantBody || int(p.length) != wantBody {
				t.Fatalf("value length %d: wire=%d body=%d", length, len(wire), p.length)
			}
			parsed, err := newPacketFromBytes(wire)
			if err != nil {
				t.Fatal(err)
			}
			if len(parsed.attributes) != 1 || !bytes.Equal(parsed.attributes[0].value, value) || int(parsed.attributes[0].length) != length {
				t.Fatalf("value length %d did not round trip", length)
			}
		})
	}
}

func TestPacketRejectsMalformedAttributes(t *testing.T) {
	tests := map[string][]byte{
		"padding exceeds message": {0, 1, 0, 4, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1},
		"value exceeds message":   {0, 1, 0, 4, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 4},
	}
	for name, wire := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := newPacketFromBytes(wire); err == nil {
				t.Fatalf("accepted malformed packet: %x", wire)
			}
		})
	}

	p, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	mustAddAttribute(t, p, mustFingerprintAttribute(t, p))
	mustAddAttribute(t, p, mustSoftwareAttribute(t, "after fingerprint"))
	if _, err := newPacketFromBytes(p.bytes()); err == nil {
		t.Fatal("accepted FINGERPRINT that was not the final attribute")
	}
}

func TestPacketOwnsParsedBytes(t *testing.T) {
	p, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	mustAddAttribute(t, p, mustSoftwareAttribute(t, "client"))
	wire := p.bytes()
	parsed, err := newPacketFromBytes(wire)
	if err != nil {
		t.Fatal(err)
	}
	for i := range wire {
		wire[i] = 0
	}
	if string(parsed.attributes[0].value) != "client" || bytes.Equal(parsed.transID, make([]byte, 16)) {
		t.Fatal("parsed packet retained aliases into the caller's buffer")
	}
}

func TestPacketPreservesNonzeroPadding(t *testing.T) {
	p, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	a := mustSoftwareAttribute(t, "x")
	a.padding = []byte{0xaa, 0xbb, 0xcc}
	mustAddAttribute(t, p, a)
	mustAddAttribute(t, p, mustFingerprintAttribute(t, p))
	wire := p.bytes()

	parsed, err := newPacketFromBytes(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.bytes(); !bytes.Equal(got, wire) {
		t.Fatalf("nonzero padding did not round trip\ngot  %x\nwant %x", got, wire)
	}
}

func TestPacketParserRandomInputs(t *testing.T) {
	random := rand.New(rand.NewSource(1))

	// Arbitrary input primarily exercises rejection paths and verifies that no
	// byte sequence can panic the parser.
	for i := 0; i < 50000; i++ {
		wire := make([]byte, random.Intn(512))
		if _, err := random.Read(wire); err != nil {
			t.Fatal(err)
		}
		p, err := newPacketFromBytes(wire)
		if err != nil {
			continue
		}
		if _, err := newPacketFromBytes(p.bytes()); err != nil {
			t.Fatalf("accepted packet did not round trip: %v", err)
		}
	}

	// Structurally valid randomized packets exercise deep parsing paths,
	// arbitrary attribute types, boundary lengths, and nonzero padding.
	for i := 0; i < 10000; i++ {
		p := &packet{
			types:      uint16(random.Intn(1 << 14)),
			transID:    make([]byte, 16),
			attributes: make([]attribute, 0, 7),
		}
		if _, err := random.Read(p.transID); err != nil {
			t.Fatal(err)
		}
		for j, count := 0, random.Intn(7); j < count; j++ {
			types := uint16(random.Intn(1 << 16))
			if types == attributeFingerprint {
				types++
			}
			value := make([]byte, random.Intn(65))
			if _, err := random.Read(value); err != nil {
				t.Fatal(err)
			}
			a := mustNewAttribute(t, types, value)
			if _, err := random.Read(a.padding); err != nil {
				t.Fatal(err)
			}
			mustAddAttribute(t, p, a)
		}
		if random.Intn(2) == 0 {
			mustAddAttribute(t, p, mustFingerprintAttribute(t, p))
		}

		wire := p.bytes()
		parsed, err := newPacketFromBytes(wire)
		if err != nil {
			t.Fatalf("valid randomized packet was rejected: %v", err)
		}
		if got := parsed.bytes(); !bytes.Equal(got, wire) {
			t.Fatalf("valid randomized packet did not round trip\ngot  %x\nwant %x", got, wire)
		}
	}
}

func TestKnownRequiredAttributeScope(t *testing.T) {
	comprehended := []uint16{
		attributeMappedAddress,
		attributeResponseAddress,
		attributeChangeRequest,
		attributeSourceAddress,
		attributeChangedAddress,
		attributeUsername,
		attributePassword,
		attributeMessageIntegrity,
		attributeErrorCode,
		attributeUnknownAttributes,
		attributeReflectedFrom,
		attributeRealm,
		attributeNonce,
		attributeXorMappedAddress,
		attributePadding,
		attributeResponsePort,
	}
	for _, attributeType := range comprehended {
		if !isKnownRequiredAttribute(attributeType) {
			t.Errorf("attribute %#04x is not recognized", attributeType)
		}
	}

	uncomprehended := []uint16{
		attributeChannelNumber,
		attributeLifetime,
		attributeBandwidth,
		attributeXorPeerAddress,
		attributeData,
		attributeXorRelayedAddress,
		attributeRequestedAddressFamily,
		attributeEvenPort,
		attributeRequestedTransport,
		attributeDontFragment,
		attributeTimerVal,
		attributeReservationToken,
		attributePriority,
		attributeUseCandidate,
		attributeConnectionID,
	}
	for _, attributeType := range uncomprehended {
		if isKnownRequiredAttribute(attributeType) {
			t.Errorf("uncomprehended attribute %#04x is recognized", attributeType)
		}
	}
}
