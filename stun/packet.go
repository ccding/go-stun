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
	"net"
	"time"
)

type packet struct {
	types      uint16
	length     uint16
	cookie     uint32
	id         []byte // 12 bytes
	attributes []attribute
}

func newPacket() *packet {
	v := new(packet)
	v.id = make([]byte, 12)
	v.attributes = make([]attribute, 0, 10)
	v.cookie = magicCookie
	v.length = 0
	return v
}

func newPacketFromBytes(b []byte) *packet {
	packet := newPacket()
	packet.types = binary.BigEndian.Uint16(b[0:2])
	packet.length = binary.BigEndian.Uint16(b[2:4])
	packet.cookie = binary.BigEndian.Uint32(b[4:8])
	packet.id = b[8:20]

	for pos := uint16(20); pos < uint16(len(b)); {
		types := binary.BigEndian.Uint16(b[pos : pos+2])
		length := binary.BigEndian.Uint16(b[pos+2 : pos+4])
		value := b[pos+4 : pos+4+length]
		attribute := newAttribute(types, value)
		packet.addAttribute(*attribute)
		pos += align(length) + 4
	}

	return packet
}

func (v *packet) addAttribute(a attribute) {
	v.attributes = append(v.attributes, a)
	v.length += align(a.length) + 4
}

func (v *packet) bytes() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], v.types)
	binary.BigEndian.PutUint16(b[2:4], v.length)
	binary.BigEndian.PutUint32(b[4:8], v.cookie)
	b = append(b, v.id...)

	for _, a := range v.attributes {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, a.types)
		b = append(b, buf...)
		binary.BigEndian.PutUint16(buf, a.length)
		b = append(b, buf...)
		b = append(b, a.value...)
	}
	return b
}

func (v *packet) mappedAddr() *Host {
	for _, a := range v.attributes {
		if a.types == attribute_MAPPED_ADDRESS {
			h := a.address()
			return h
		}
	}
	return nil
}

func (v *packet) changedAddr() *Host {
	for _, a := range v.attributes {
		if a.types == attribute_CHANGED_ADDRESS {
			h := a.address()
			return h
		}
	}
	return nil
}

func (v *packet) xorMappedAddr() *Host {
	for _, a := range v.attributes {
		if (a.types == attribute_XOR_MAPPED_ADDRESS) || (a.types == attribute_XOR_MAPPED_ADDRESS_EXP) {
			h := a.xorMappedAddr()
			return h
		}
	}
	return nil
}

// RFC 3489: Clients SHOULD retransmit the request starting with an interval
// of 100ms, doubling every retransmit until the interval reaches 1.6s.
// Retransmissions continue with intervals of 1.6s until a response is
// received, or a total of 9 requests have been sent.
func (packet *packet) send(conn net.Conn) (*packet, error) {
	timeout := 100

	for i := 0; i < 9; i++ {
		l, err := conn.Write(packet.bytes())
		if err != nil {
			return nil, err
		}

		conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))
		if timeout < 1600 {
			timeout *= 2
		}

		b := make([]byte, 1024)
		l, err = conn.Read(b)
		if err == nil {
			return newPacketFromBytes(b[0:l]), nil
		} else {
			if !err.(net.Error).Timeout() {
				return nil, err
			}
		}
	}

	return nil, nil
}
