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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
)

type packet struct {
	types      uint16
	length     uint16
	transID    []byte // 4 bytes magic cookie + 12 bytes transaction id
	attributes []attribute
}

func newPacket() (*packet, error) {
	v := new(packet)
	v.transID = make([]byte, 16)
	binary.BigEndian.PutUint32(v.transID[:4], magicCookie)
	_, err := rand.Read(v.transID[4:])
	if err != nil {
		return nil, err
	}
	v.attributes = make([]attribute, 0, 10)
	v.length = 0
	return v, nil
}

func newPacketFromBytes(packetBytes []byte) (*packet, error) {
	if len(packetBytes) < 20 {
		return nil, errors.New("Received data length too short")
	}
	if len(packetBytes) > math.MaxUint16+20 {
		return nil, errors.New("Received data length too long")
	}
	pkt := new(packet)
	pkt.types = binary.BigEndian.Uint16(packetBytes[0:2])
	pkt.length = binary.BigEndian.Uint16(packetBytes[2:4])
	
	pkt.transID = make([]byte, 16)
	copy(pkt.transID, packetBytes[4:20])
	
	pkt.attributes = make([]attribute, 0, 10)
	packetBytes = packetBytes[20:]
	for pos := uint16(0); pos+4 < uint16(len(packetBytes)); {
		types := binary.BigEndian.Uint16(packetBytes[pos : pos+2])
		length := binary.BigEndian.Uint16(packetBytes[pos+2 : pos+4])
		end := pos + 4 + length
		if end < pos+4 || end > uint16(len(packetBytes)) {
			return nil, errors.New("Received data format mismatch")
		}
		value := make([]byte, length)
		copy(value, packetBytes[pos+4 : end])
		attribute := newAttribute(types, value)
		pkt.addAttribute(*attribute)
		pos += align(length) + 4
	}
	return pkt, nil
}

func (v *packet) addAttribute(a attribute) {
	v.attributes = append(v.attributes, a)
	v.length += align(a.length) + 4
}

func (v *packet) bytes() []byte {
	size := 20 + int(v.length)
	buf := make([]byte, size)
	binary.BigEndian.PutUint16(buf[0:2], v.types)
	binary.BigEndian.PutUint16(buf[2:4], v.length)
	copy(buf[4:20], v.transID)
	offset := 20
	for _, a := range v.attributes {
		binary.BigEndian.PutUint16(buf[offset:offset+2], a.types)
		binary.BigEndian.PutUint16(buf[offset+2:offset+4], a.length)
		copy(buf[offset+4:offset+4+len(a.value)], a.value)
		offset += 4 + len(a.value)
	}
	return buf
}

func (v *packet) getSourceAddr() (*Host, error) {
	return v.getRawAddr(attributeSourceAddress)
}

func (v *packet) getMappedAddr() (*Host, error) {
	return v.getRawAddr(attributeMappedAddress)
}

func (v *packet) getChangedAddr() (*Host, error) {
	return v.getRawAddr(attributeChangedAddress)
}

func (v *packet) getOtherAddr() (*Host, error) {
	return v.getRawAddr(attributeOtherAddress)
}

func (v *packet) getRawAddr(attribute uint16) (*Host, error) {
	for _, a := range v.attributes {
		if a.types == attribute {
			return a.rawAddr()
		}
	}
	return nil, nil
}

func (v *packet) getXorMappedAddr() (*Host, error) {
	addr, err := v.getXorAddr(attributeXorMappedAddress)
	if err != nil {
		return nil, err
	}
	if addr == nil {
		addr, err = v.getXorAddr(attributeXorMappedAddressExp)
		if err != nil {
			return nil, err
		}
	}
	return addr, nil
}

func (v *packet) getXorAddr(attribute uint16) (*Host, error) {
	for _, a := range v.attributes {
		if a.types == attribute {
			return a.xorAddr(v.transID)
		}
	}
	return nil, nil
}
