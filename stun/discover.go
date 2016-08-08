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
// Author: Cong Ding <dinggnu@gmail.com>

package stun

import (
	"errors"
	"net"
	"strconv"
)

// Follow RFC 3489 and RFC 5389.
// Figure 2: Flow for type discovery process (from RFC 3489).
//                        +--------+
//                        |  Test  |
//                        |   I    |
//                        +--------+
//                             |
//                             |
//                             V
//                            /\              /\
//                         N /  \ Y          /  \ Y             +--------+
//          UDP     <-------/Resp\--------->/ IP \------------->|  Test  |
//          Blocked         \ ?  /          \Same/              |   II   |
//                           \  /            \? /               +--------+
//                            \/              \/                    |
//                                             | N                  |
//                                             |                    V
//                                             V                    /\
//                                         +--------+  Sym.      N /  \
//                                         |  Test  |  UDP    <---/Resp\
//                                         |   II   |  Firewall   \ ?  /
//                                         +--------+              \  /
//                                             |                    \/
//                                             V                     |Y
//                  /\                         /\                    |
//   Symmetric  N  /  \       +--------+   N  /  \                   V
//      NAT  <--- / IP \<-----|  Test  |<--- /Resp\               Open
//                \Same/      |   I    |     \ ?  /               Internet
//                 \? /       +--------+      \  /
//                  \/                         \/
//                  |Y                          |Y
//                  |                           |
//                  |                           V
//                  |                           Full
//                  |                           Cone
//                  V              /\
//              +--------+        /  \ Y
//              |  Test  |------>/Resp\---->Restricted
//              |   III  |       \ ?  /
//              +--------+        \  /
//                                 \/
//                                  |N
//                                  |       Port
//                                  +------>Restricted
func (c *Client) discover(conn net.PacketConn, addr net.Addr, softwareName string, logger *Logger) (NATType, *Host, error) {
	logger.Debugln("Do Test1")
	logger.Debugln("Send To:", addr)
	packet, changedAddr, identical, host, err := c.test1(conn, addr, softwareName)
	if err != nil {
		return NATError, nil, err
	}
	logger.Debugln("Received from:", packet.raddr)
	logger.Debugln("Received: isNil:", packet == nil)
	if packet == nil {
		return NATBlocked, nil, nil
	}
	exHostIP := host.IP()
	logger.Debugln("Received: extAddr:", host.TransportAddr())
	logger.Debugln("Received: changedAddr:", changedAddr)
	logger.Debugln("Received: identical:", identical)
	logger.Debugln("Do Test2")
	logger.Debugln("Send To:", addr)
	packet, err = c.test2(conn, addr, softwareName)
	if err != nil {
		return NATError, host, err
	}
	if packet != nil {
		logger.Debugln("Received from:", packet.raddr)
	}
	logger.Debugln("Received: isNil:", packet == nil)
	if identical {
		if packet == nil {
			return NATSymetricUDPFirewall, host, nil
		}
		return NATNone, host, nil
	}
	if packet != nil {
		return NATFull, host, nil
	}
	if changedAddr == nil {
		return NATError, host, errors.New("No changed address.")
	}
	logger.Debugln("Do Test1")
	logger.Debugln("Send To:", changedAddr)
	packet, _, _, host, err = c.test1(conn, changedAddr, softwareName)
	if err != nil {
		return NATError, host, err
	}
	logger.Debugln("Received from:", packet.raddr)
	logger.Debugln("Received: isNil:", packet == nil)
	if packet == nil {
		// It should be NAT_BLOCKED, but will be detected in the first
		// step. So this will never happen.
		return NATUnknown, host, nil
	}
	logger.Debugln("Received: extAddr:", host.TransportAddr())
	if exHostIP == host.IP() {
		tmpAddr, err := net.ResolveUDPAddr("udp", changedAddr.String())
		if err != nil {
			return NATError, host, err
		}
		ip := tmpAddr.IP
		tmpAddr, err = net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			return NATError, host, err
		}
		port := tmpAddr.Port
		changePortAddrStr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		changePortAddr, err := net.ResolveUDPAddr("udp", changePortAddrStr)
		if err != nil {
			return NATError, host, err
		}
		logger.Debugln("Do Test3")
		logger.Debugln("Send To:", addr)
		packet, err = c.test3(conn, changePortAddr, softwareName)
		if err != nil {
			return NATError, host, err
		}
		logger.Debugln("Received from:", packet.raddr)
		logger.Debugln("Received: isNil:", packet == nil)
		if packet == nil {
			return NATPortRestricted, host, nil
		}
		return NATRestricted, host, nil
	}
	return NATSymetric, host, nil
}
