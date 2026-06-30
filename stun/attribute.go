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
	"net"
)

type attribute struct {
	types  uint16
	length uint16
	value  []byte
}

func newAttribute(types uint16, value []byte) *attribute {
	att := new(attribute)
	att.types = types
	att.value = padding(value)
	att.length = uint16(len(att.value))
	return att
}

func newFingerprintAttribute(packet *packet) *attribute {
	crc := crc32.ChecksumIEEE(packet.bytes()) ^ fingerprint
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, crc)
	return newAttribute(attributeFingerprint, buf)
}

func newSoftwareAttribute(name string) *attribute {
	return newAttribute(attributeSoftware, []byte(name))
}

func newChangeReqAttribute(changeIP bool, changePort bool) *attribute {
	value := make([]byte, 4)
	if changeIP {
		value[3] |= 0x04
	}
	if changePort {
		value[3] |= 0x02
	}
	return newAttribute(attributeChangeRequest, value)
}

//      0                   1                   2                   3
//      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |x x x x x x x x|    Family     |         X-Port                |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                X-Address (Variable)
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//             Figure 6: Format of XOR-MAPPED-ADDRESS Attribute
func (v *attribute) xorAddr(transID []byte) (*Host, error) {
	if len(v.value) < 4 {
		return nil, errors.New("attribute value too short")
	}
	family := uint16(v.value[1])
	port := binary.BigEndian.Uint16(v.value[2:4])
	
	xorIP := make([]byte, 16)
	limit := len(v.value) - 4
	if limit > 16 {
		limit = 16
	}
	if len(transID) < limit {
		return nil, errors.New("transaction ID too short")
	}
	for i := 0; i < limit; i++ {
		xorIP[i] = v.value[i+4] ^ transID[i]
	}
	
	if family == attributeFamilyIPv4 {
		if len(v.value) < 8 {
			return nil, errors.New("IPv4 attribute length mismatch")
		}
		xorIP = xorIP[:4]
	} else if family == attributeFamilyIPV6 {
		if len(v.value) < 20 {
			return nil, errors.New("IPv6 attribute length mismatch")
		}
	} else {
		return nil, errors.New("unknown address family")
	}
	
	if len(transID) < 2 {
		return nil, errors.New("transaction ID too short for port XOR")
	}
	x := binary.BigEndian.Uint16(transID[:2])
	return &Host{family, net.IP(xorIP).String(), port ^ x}, nil
}

//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |0 0 0 0 0 0 0 0|    Family     |           Port                |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      |                 Address (32 bits or 128 bits)                 |
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//               Figure 5: Format of MAPPED-ADDRESS Attribute
func (v *attribute) rawAddr() (*Host, error) {
	if len(v.value) < 4 {
		return nil, errors.New("attribute value too short")
	}
	family := uint16(v.value[1])
	port := binary.BigEndian.Uint16(v.value[2:4])
	
	var ip string
	if family == attributeFamilyIPv4 {
		if len(v.value) < 8 {
			return nil, errors.New("IPv4 attribute length mismatch")
		}
		ip = net.IP(v.value[4:8]).String()
	} else if family == attributeFamilyIPV6 {
		if len(v.value) < 20 {
			return nil, errors.New("IPv6 attribute length mismatch")
		}
		ip = net.IP(v.value[4:20]).String()
	} else {
		return nil, errors.New("unknown address family")
	}
	
	return &Host{family, ip, port}, nil
}
