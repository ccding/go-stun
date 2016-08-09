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
func (c *Client) discover(conn net.PacketConn, addr *net.UDPAddr, softwareName string, logger *Logger) (NATType, *Host, error) {
	logger.Debugln("Do Test1")
	logger.Debugln("Send To:", addr)
	resp, err := c.test1(conn, addr, softwareName)
	if err != nil {
		return NATError, nil, err
	}
	logger.Debugln("Received:", resp)
	if resp == nil {
		return NATBlocked, nil, nil
	}
	// identical used to check if it is open Internet or not.
	identical := resp.identical
	// changedAddr is used to perform second time test1 and test3.
	changedAddr := resp.changedAddr
	// mappedAddr is used as the return value, its IP is used for tests
	mappedAddr := resp.mappedAddr
	if changedAddr == nil {
		return NATError, mappedAddr, errors.New("No changed address.")
	}
	logger.Debugln("Do Test2")
	logger.Debugln("Send To:", addr)
	resp, err = c.test2(conn, addr, softwareName)
	if err != nil {
		return NATError, mappedAddr, err
	}
	logger.Debugln("Received:", resp)
	if identical {
		if resp == nil {
			return NATSymetricUDPFirewall, mappedAddr, nil
		}
		return NATNone, mappedAddr, nil
	}
	if resp != nil {
		return NATFull, mappedAddr, nil
	}
	logger.Debugln("Do Test1")
	logger.Debugln("Send To:", changedAddr)
	caddr, err := net.ResolveUDPAddr("udp", changedAddr.String())
	resp, err = c.test1(conn, caddr, softwareName)
	if err != nil {
		return NATError, mappedAddr, err
	}
	logger.Debugln("Received:", resp)
	if resp == nil {
		// It should be NAT_BLOCKED, but will be detected in the first
		// step. So this will never happen.
		return NATUnknown, mappedAddr, nil
	}
	if mappedAddr.IP() == resp.mappedAddr.IP() {
		caddr.Port = addr.Port
		logger.Debugln("Do Test3")
		logger.Debugln("Send To:", caddr)
		resp, err = c.test3(conn, caddr, softwareName)
		if err != nil {
			return NATError, mappedAddr, err
		}
		logger.Debugln("Received:", resp)
		if resp == nil {
			return NATPortRestricted, mappedAddr, nil
		}
		return NATRestricted, mappedAddr, nil
	}
	return NATSymetric, mappedAddr, nil
}
