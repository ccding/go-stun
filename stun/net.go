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
	"encoding/hex"
	"errors"
	"net"
	"time"
	"unicode/utf8"
)

const (
	numRetransmit  = 9
	defaultTimeout = 100
	maxTimeout     = 1600
	maxPacketSize  = 64 * 1024
)

func (c *Client) sendBindingReq(conn net.PacketConn, addr net.Addr, changeIP bool, changePort bool) (*response, error) {
	pkt, err := c.newBindingRequest(changeIP, changePort)
	if err != nil {
		return nil, err
	}
	return c.send(pkt, conn, addr)
}

func (c *Client) newBindingRequest(changeIP bool, changePort bool) (*packet, error) {
	pkt, err := newPacket()
	if err != nil {
		return nil, err
	}
	pkt.types = typeBindingRequest
	if !c.rfc3489Mode {
		if !utf8.ValidString(c.softwareName) || utf8.RuneCountInString(c.softwareName) >= 128 {
			return nil, errors.New("software name must be valid UTF-8 and shorter than 128 characters")
		}
		attribute, err := newSoftwareAttribute(c.softwareName)
		if err != nil {
			return nil, err
		}
		if err := pkt.addAttribute(*attribute); err != nil {
			return nil, err
		}
	}
	if changeIP || changePort {
		attribute, err := newChangeReqAttribute(changeIP, changePort)
		if err != nil {
			return nil, err
		}
		if err := pkt.addAttribute(*attribute); err != nil {
			return nil, err
		}
	}
	if !c.rfc3489Mode {
		attribute, err := newFingerprintAttribute(pkt)
		if err != nil {
			return nil, err
		}
		if err := pkt.addAttribute(*attribute); err != nil {
			return nil, err
		}
	}
	return pkt, nil
}

// RFC 3489: Clients SHOULD retransmit the request starting with an interval
// of 100ms, doubling every retransmit until the interval reaches 1.6s.
// Retransmissions continue with intervals of 1.6s until a response is
// received, or a total of 9 requests have been sent.
func (c *Client) send(pkt *packet, conn net.PacketConn, addr net.Addr) (*response, error) {
	wire := pkt.bytes()
	c.logger.Info("\n" + hex.Dump(wire))
	timeout := defaultTimeout
	packetBytes := make([]byte, maxPacketSize)
	for i := 0; i < numRetransmit; i++ {
		// Send packet to the server.
		length, err := conn.WriteTo(wire, addr)
		if err != nil {
			return nil, err
		}
		if length != len(wire) {
			return nil, errors.New("error in sending data")
		}
		err = conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))
		if err != nil {
			return nil, err
		}
		if timeout < maxTimeout {
			timeout *= 2
		}
		for {
			// Read from the port.
			length, raddr, err := conn.ReadFrom(packetBytes)
			if err != nil {
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					break
				}
				return nil, err
			}
			if length < 0 || length > len(packetBytes) {
				return nil, errors.New("invalid packet length returned by connection")
			}
			p, err := newPacketFromBytes(packetBytes[0:length])
			if err != nil {
				// A UDP socket can receive unrelated or malformed traffic. RFC 5389
				// requires invalid STUN messages to be silently discarded.
				c.logger.Debugf("Discard response from %v: %v", raddr, err)
				continue
			}
			// If transId mismatches, keep reading until get a
			// matched packet or timeout.
			if !bytes.Equal(pkt.transID, p.transID) {
				c.logger.Debugf("Discard response from %v: transaction ID mismatch", raddr)
				continue
			}
			if p.types != typeBindingResponse && p.types != typeBindingErrorResponse {
				c.logger.Debugf("Discard response from %v: unexpected message type %#06x", raddr, p.types)
				continue
			}
			c.logger.Info("\n" + hex.Dump(packetBytes[0:length]))
			return processBindingResponse(p, conn, raddr)
		}
	}
	return nil, nil
}

func processBindingResponse(p *packet, conn localAddrProvider, source net.Addr) (*response, error) {
	if err := p.validateBindingResponseAttributes(); err != nil {
		return nil, err
	}
	if p.types == typeBindingErrorResponse {
		return nil, p.bindingError()
	}
	resp := newResponse(p, conn)
	if resp.mappedAddr == nil {
		return nil, errors.New("binding success response has no valid mapped address")
	}
	if source == nil {
		return nil, errors.New("binding response has no source address")
	}
	resp.serverAddr = newHostFromStr(source.String())
	if resp.serverAddr == nil {
		return nil, errors.New("binding response has an invalid source address")
	}
	return resp, nil
}
