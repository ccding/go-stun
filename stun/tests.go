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
	"errors"
	"net"
)

func (c *Client) test1(conn net.PacketConn, addr net.Addr, softwareName string) (*packet, net.Addr, bool, *Host, error) {
	packet, err := c.sendBindingReq(conn, addr, softwareName, false, false)
	if err != nil {
		return nil, nil, false, nil, err
	}
	if packet == nil {
		return nil, nil, false, nil, nil
	}
	// RFC 3489 doesn't require the server return XOR mapped address.
	hostMappedAddr := packet.xorMappedAddr()
	if hostMappedAddr == nil {
		hostMappedAddr = packet.getMappedAddr()
		if hostMappedAddr == nil {
			return nil, nil, false, nil, errors.New("No mapped address.")
		}
	}

	identical := isLocalAddress(conn.LocalAddr().String(), hostMappedAddr.TransportAddr())

	hostChangedAddr := packet.getChangedAddr()
	if hostChangedAddr == nil {
		return packet, nil, identical, hostMappedAddr, nil
	}
	changedAddrStr := hostChangedAddr.TransportAddr()
	changedAddr, err := net.ResolveUDPAddr("udp", changedAddrStr)
	if err != nil {
		return nil, nil, false, nil, errors.New("Failed to resolve changed address.")
	}
	return packet, changedAddr, identical, hostMappedAddr, nil
}

func (c *Client) test2(conn net.PacketConn, addr net.Addr, softwareName string) (*packet, error) {
	return c.sendBindingReq(conn, addr, softwareName, true, true)
}

func (c *Client) test3(conn net.PacketConn, addr net.Addr, softwareName string) (*packet, error) {
	return c.sendBindingReq(conn, addr, softwareName, false, true)
}
