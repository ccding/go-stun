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
	"net"
)

func (c *Client) test1(conn net.PacketConn, addr net.Addr) (*response, error) {
	return c.sendBindingReq(conn, addr, false, false)
}

func (c *Client) test2(conn net.PacketConn, addr net.Addr) (*response, error) {
	return c.sendBindingReq(conn, addr, true, true)
}

func (c *Client) test3(conn net.PacketConn, addr net.Addr) (*response, error) {
	return c.sendBindingReq(conn, addr, false, true)
}
func (c *Client) keepalivetest(conn net.PacketConn, addr net.Addr) error {
	return c.sendKeepAliveTest(conn, addr)
}
func (c *Client) sendKeepAliveTest(conn net.PacketConn, addr net.Addr) error {
	// Construct packet.
	pkt, err := newPacket()
	if err != nil {
		return err
	}
	pkt.types = typeBindingRequest
	attribute := newSoftwareAttribute(c.softwareName)
	pkt.addAttribute(*attribute)

	attribute = newFingerprintAttribute(pkt)
	pkt.addAttribute(*attribute)
	// Send packet.
	_, err = conn.WriteTo(pkt.bytes(), addr)
	if err != nil {
		return err
	}
	return nil
}
