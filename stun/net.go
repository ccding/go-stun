// Copyright 2016, Cong Ding. All rights reserved.
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
// Author: Cong Ding <dinggnu@gmail.com>

package stun

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	numRetransmit  = 9
	defaultTimeout = 100
)

func (c *Client) sendBindingReq(conn net.PacketConn, addr net.Addr, softwareName string, changeIP bool, changePort bool) (*packet, error) {
	// Construct packet.
	packet, err := newPacket()
	if err != nil {
		return nil, err
	}
	packet.types = typeBindingRequest
	attribute := newSoftwareAttribute(softwareName)
	packet.addAttribute(*attribute)
	if changeIP || changePort {
		attribute = newChangeReqAttribute(changeIP, changePort)
		packet.addAttribute(*attribute)
	}
	attribute = newFingerprintAttribute(packet)
	packet.addAttribute(*attribute)
	// Send packet.
	packet, err = c.send(packet, conn, addr)
	if err != nil {
		return nil, err
	}
	return packet, nil
}

// RFC 3489: Clients SHOULD retransmit the request starting with an interval
// of 100ms, doubling every retransmit until the interval reaches 1.6s.
// Retransmissions continue with intervals of 1.6s until a response is
// received, or a total of 9 requests have been sent.
func (c *Client) send(pkt *packet, conn net.PacketConn, addr net.Addr) (*packet, error) {
	if debug {
		fmt.Print(hex.Dump(pkt.bytes()))
	}
	timeout := defaultTimeout
	for i := 0; i < numRetransmit; i++ {
		length, err := conn.WriteTo(pkt.bytes(), addr)
		if err != nil {
			return nil, err
		}
		if length != len(pkt.bytes()) {
			return nil, errors.New("Error in sending data.")
		}
		err = conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))
		if err != nil {
			return nil, err
		}
		if timeout < 1600 {
			timeout *= 2
		}
		for {
			packetBytes := make([]byte, 1024)
			length, raddr, err := conn.ReadFrom(packetBytes)
			if err != nil {
				if err.(net.Error).Timeout() {
					break
				}
				return nil, err
			}
			p, err := newPacketFromBytes(packetBytes[0:length])
			if !bytes.Equal(pkt.transID, p.transID) {
				continue
			}
			if debug {
				fmt.Print(hex.Dump(pkt.bytes()))
			}
			p.raddr = raddr
			return p, err
		}
	}
	return nil, nil
}
