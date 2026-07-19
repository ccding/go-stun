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
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math"
	"net"
)

type attribute struct {
	types   uint16
	length  uint16
	value   []byte
	padding []byte
}

// A STUN message body has a uint16 length and must be a multiple of four, so
// its largest representable size is 65,532 bytes. An attribute value must
// leave four of those bytes for its type and length fields.
const maxAttributeValueLength = 1<<16 - 8

var (
	errAttributeTooLarge = errors.New("stun: attribute value exceeds maximum STUN message size")
	errPacketTooLarge    = errors.New("stun: packet attributes exceed maximum STUN message size")
)

// newAttribute copies value into a wire-representable STUN attribute.
func newAttribute(types uint16, value []byte) (*attribute, error) {
	if len(value) > maxAttributeValueLength {
		return nil, errAttributeTooLarge
	}
	att := new(attribute)
	att.types = types
	att.value = append([]byte(nil), value...)
	att.length = uint16(len(value))
	att.padding = make([]byte, align(len(value))-len(value))
	return att, nil
}

func newFingerprintAttribute(packet *packet) (*attribute, error) {
	if int(packet.length)+8 > math.MaxUint16 {
		return nil, errPacketTooLarge
	}
	packetBytes := packet.bytes()
	binary.BigEndian.PutUint16(packetBytes[2:4], packet.length+8)
	crc := crc32.ChecksumIEEE(packetBytes) ^ fingerprint
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, crc)
	return newAttribute(attributeFingerprint, buf)
}

func newSoftwareAttribute(name string) (*attribute, error) {
	return newAttribute(attributeSoftware, []byte(name))
}

func newChangeReqAttribute(changeIP bool, changePort bool) (*attribute, error) {
	value := make([]byte, 4)
	if changeIP {
		value[3] |= 0x04
	}
	if changePort {
		value[3] |= 0x02
	}
	return newAttribute(attributeChangeRequest, value)
}

//	0                   1                   2                   3
//	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |x x x x x x x x|    Family     |         X-Port                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                X-Address (Variable)
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//	Figure 6: Format of XOR-MAPPED-ADDRESS Attribute
func (v *attribute) xorAddr(transID []byte) *Host {
	if len(transID) != 16 || (len(v.value) != 8 && len(v.value) != 20) {
		return nil
	}
	family := uint16(v.value[1])
	switch family {
	case attributeFamilyIPv4:
		if len(v.value) != 8 {
			return nil
		}
	case attributeFamilyIPV6:
		if len(v.value) != 20 {
			return nil
		}
	default:
		return nil
	}
	xorIP := make([]byte, 16)
	for i := 0; i < len(v.value)-4; i++ {
		xorIP[i] = v.value[i+4] ^ transID[i]
	}
	port := binary.BigEndian.Uint16(v.value[2:4])
	// Truncate if IPv4, otherwise net.IP sometimes renders it as an IPv6 address.
	if family == attributeFamilyIPv4 {
		xorIP = xorIP[:4]
	}
	x := binary.BigEndian.Uint16(transID[:2])
	return &Host{family, net.IP(xorIP).String(), port ^ x}
}

//	0                   1                   2                   3
//	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0 0 0 0 0 0 0 0|    Family     |           Port                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                 Address (32 bits or 128 bits)                 |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//	Figure 5: Format of MAPPED-ADDRESS Attribute
func (v *attribute) rawAddr() *Host {
	if len(v.value) != 8 && len(v.value) != 20 {
		return nil
	}
	host := new(Host)
	host.family = uint16(v.value[1])
	switch host.family {
	case attributeFamilyIPv4:
		if len(v.value) != 8 {
			return nil
		}
	case attributeFamilyIPV6:
		if len(v.value) != 20 {
			return nil
		}
	default:
		return nil
	}
	host.port = binary.BigEndian.Uint16(v.value[2:4])
	// Truncate if IPv4, otherwise net.IP sometimes renders it as an IPv6 address.
	if host.family == attributeFamilyIPv4 {
		host.ip = net.IP(v.value[4:8]).String()
	} else {
		host.ip = net.IP(v.value[4:20]).String()
	}
	return host
}
