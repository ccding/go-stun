// Copyright 2013, Cong Ding. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: Cong Ding <dinggnu@gmail.com>

package stun

import (
	"encoding/binary"
	"hash/crc32"
	"net"
)

type attribute struct {
	types  uint16
	length uint16
	value  []byte
}

func newAttribute(types uint16, value []byte) *attribute {
	a := new(attribute)
	a.types = types
	a.value = padding(value)
	a.length = uint16(len(a.value))
	return a
}

func newFingerprintAttribute(packet *packet) *attribute {
	crc := crc32.ChecksumIEEE(packet.bytes()) ^ fingerprint
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, crc)
	return newAttribute(attribute_fingerprint, buf)
}

func newSoftwareAttribute(packet *packet, name string) *attribute {
	return newAttribute(attribute_SOFTWARE, []byte(name))
}

func newChangeReqAttribute(packet *packet, changeIp bool, changePort bool) *attribute {
	value := make([]byte, 4)
	if changeIp {
		value[3] |= 0x04
	}
	if changePort {
		value[3] |= 0x02
	}
	return newAttribute(attribute_CHANGE_REQUEST, value)
}

func (v *attribute) xorMappedAddr() *Host {
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, magicCookie)
	xorIp := make([]byte, 16)
	for i := 0; i < len(v.value)-4; i++ {
		xorIp[i] = v.value[i+4] ^ cookie[i]
	}
	port := binary.BigEndian.Uint16(v.value[2:4])
	return &Host{binary.BigEndian.Uint16(v.value[0:2]),
		net.IP(xorIp).String(), port ^ (magicCookie >> 32)}
}

func (v *attribute) address() *Host {
	h := new(Host)
	h.family = binary.BigEndian.Uint16(v.value[0:2])
	h.port = binary.BigEndian.Uint16(v.value[2:4])
	h.ip = net.IP(v.value[4:]).String()
	return h
}
