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
	"fmt"
	"net"
	"testing"
)

func TestNewAttributeLengthBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		length      int
		wantPadding int
	}{
		{name: "empty", length: 0, wantPadding: 0},
		{name: "one byte", length: 1, wantPadding: 3},
		{name: "already aligned", length: 4, wantPadding: 0},
		{name: "maximum minus one", length: maxAttributeValueLength - 1, wantPadding: 1},
		{name: "maximum", length: maxAttributeValueLength, wantPadding: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := bytes.Repeat([]byte{0xa5}, tt.length)
			a := newAttribute(attributeSoftware, value)
			if int(a.length) != tt.length {
				t.Fatalf("length = %d, want %d", a.length, tt.length)
			}
			if !bytes.Equal(a.value, value) {
				t.Fatal("attribute value was not preserved")
			}
			if len(a.padding) != tt.wantPadding {
				t.Fatalf("padding length = %d, want %d", len(a.padding), tt.wantPadding)
			}
			if len(value) > 0 {
				value[0] ^= 0xff
				if a.value[0] == value[0] {
					t.Fatal("attribute retained the caller's value buffer")
				}
			}
		})
	}
}

func TestNewAttributeRejectsValuesTooLargeForSTUNMessage(t *testing.T) {
	for _, length := range []int{
		maxAttributeValueLength + 1,
		1<<16 - 1,
		1 << 16,
		1<<16 + 1,
	} {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			defer func() {
				got := recover()
				if got != "stun: attribute value exceeds maximum STUN message size" {
					t.Fatalf("panic = %#v, want oversized-attribute error", got)
				}
			}()
			newAttribute(attributeSoftware, make([]byte, length))
		})
	}
}

func TestAddAttributeRejectsPacketLengthOverflow(t *testing.T) {
	p, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	p.addAttribute(*newAttribute(attributeSoftware, make([]byte, maxAttributeValueLength)))
	if p.length != 65532 || len(p.attributes) != 1 {
		t.Fatalf("maximum packet body: length=%d attributes=%d", p.length, len(p.attributes))
	}
	wire := p.bytes()
	if len(wire) != 20+65532 {
		t.Fatalf("maximum packet wire length = %d, want %d", len(wire), 20+65532)
	}
	parsed, err := newPacketFromBytes(wire)
	if err != nil {
		t.Fatalf("maximum packet did not round trip: %v", err)
	}
	if parsed.length != p.length || len(parsed.attributes) != 1 ||
		len(parsed.attributes[0].value) != maxAttributeValueLength {
		t.Fatalf("round trip: length=%d attributes=%d value=%d", parsed.length,
			len(parsed.attributes), len(parsed.attributes[0].value))
	}

	func() {
		defer func() {
			got := recover()
			if got != "stun: packet attributes exceed maximum STUN message size" {
				t.Fatalf("panic = %#v, want packet-size error", got)
			}
		}()
		p.addAttribute(*newAttribute(attributeSoftware, nil))
	}()

	if p.length != 65532 || len(p.attributes) != 1 {
		t.Fatalf("failed add mutated packet: length=%d attributes=%d", p.length, len(p.attributes))
	}
}

func TestOversizedWireAttributeIsRejectedWithoutPanic(t *testing.T) {
	for _, declaredLength := range []uint16{65533, 65534, 65535} {
		t.Run(fmt.Sprintf("length_%d", declaredLength), func(t *testing.T) {
			wire := make([]byte, 20+65532)
			binary.BigEndian.PutUint16(wire[2:4], 65532)
			binary.BigEndian.PutUint16(wire[20:22], attributeSoftware)
			binary.BigEndian.PutUint16(wire[22:24], declaredLength)

			if _, err := newPacketFromBytes(wire); err == nil || err.Error() != "received data format mismatch" {
				t.Fatalf("newPacketFromBytes error = %v, want format mismatch", err)
			}
		})
	}
}

func TestChangeRequestAttribute(t *testing.T) {
	tests := []struct {
		name       string
		changeIP   bool
		changePort bool
		want       byte
	}{
		{"neither", false, false, 0x00},
		{"port", false, true, 0x02},
		{"ip", true, false, 0x04},
		{"both", true, true, 0x06},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newChangeReqAttribute(tt.changeIP, tt.changePort)
			if a.types != attributeChangeRequest || a.length != 4 {
				t.Fatalf("unexpected header: type=%#x length=%d", a.types, a.length)
			}
			if got := a.value[3]; got != tt.want {
				t.Fatalf("flags = %#x, want %#x", got, tt.want)
			}
		})
	}
}

func TestRawAddress(t *testing.T) {
	tests := []struct {
		name   string
		family byte
		ip     net.IP
		port   uint16
	}{
		{"IPv4", attributeFamilyIPv4, net.ParseIP("192.0.2.1").To4(), 3478},
		{"IPv6", attributeFamilyIPV6, net.ParseIP("2001:db8::1234").To16(), 65535},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := make([]byte, 4+len(tt.ip))
			value[1] = tt.family
			binary.BigEndian.PutUint16(value[2:4], tt.port)
			copy(value[4:], tt.ip)
			h := newAttribute(attributeMappedAddress, value).rawAddr()
			if h == nil || h.Family() != uint16(tt.family) || h.Port() != tt.port || !net.ParseIP(h.IP()).Equal(tt.ip) {
				t.Fatalf("decoded host = %#v", h)
			}
		})
	}
}

func TestXorAddress(t *testing.T) {
	transaction := []byte{0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae}
	tests := []struct {
		name   string
		family byte
		ip     net.IP
		port   uint16
	}{
		{"IPv4", attributeFamilyIPv4, net.ParseIP("192.0.2.1").To4(), 32853},
		{"IPv6", attributeFamilyIPV6, net.ParseIP("2001:db8:1234:5678:90ab:cdef:1020:3040").To16(), 49152},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := make([]byte, 4+len(tt.ip))
			value[1] = tt.family
			binary.BigEndian.PutUint16(value[2:4], tt.port^binary.BigEndian.Uint16(transaction[:2]))
			for i := range tt.ip {
				value[4+i] = tt.ip[i] ^ transaction[i]
			}
			h := newAttribute(attributeXorMappedAddress, value).xorAddr(transaction)
			if h == nil || h.Port() != tt.port || !net.ParseIP(h.IP()).Equal(tt.ip) {
				t.Fatalf("decoded host = %#v", h)
			}
		})
	}
}

func TestAddressAttributesRejectMalformedValues(t *testing.T) {
	transaction := make([]byte, 16)
	for _, length := range []int{0, 1, 3, 7, 9, 19, 21} {
		value := make([]byte, length)
		if newAttribute(attributeMappedAddress, value).rawAddr() != nil {
			t.Fatalf("raw address accepted length %d", length)
		}
		if newAttribute(attributeXorMappedAddress, value).xorAddr(transaction) != nil {
			t.Fatalf("XOR address accepted length %d", length)
		}
	}
	for _, family := range []byte{0, 3, 255} {
		value := make([]byte, 8)
		value[1] = family
		if newAttribute(attributeMappedAddress, value).rawAddr() != nil {
			t.Fatalf("raw address accepted family %d", family)
		}
	}
	if newAttribute(attributeXorMappedAddress, make([]byte, 8)).xorAddr(make([]byte, 15)) != nil {
		t.Fatal("XOR address accepted a short transaction ID")
	}
}
