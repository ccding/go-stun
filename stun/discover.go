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
	resp, err := c.test1(conn, addr, softwareName)
	if err != nil {
		return NATError, nil, err
	}
	logger.Debugln("Received from:", resp.serverAddr)
	logger.Debugln("Received: isNil:", resp.packet == nil)
	if resp.packet == nil {
		return NATBlocked, nil, nil
	}
	logger.Debugln("Received: extAddr:", resp.mappedAddr)
	logger.Debugln("Received: changedAddr:", resp.changedAddr)
	logger.Debugln("Received: identical:", resp.identical)
	exHostIP := resp.mappedAddr.IP()
	changedAddrHost := resp.changedAddr
	if changedAddrHost == nil {
		return NATError, resp.mappedAddr, errors.New("No changed address.")
	}
	logger.Debugln("Do Test2")
	logger.Debugln("Send To:", addr)
	resp, err = c.test2(conn, addr, softwareName)
	if err != nil {
		return NATError, resp.mappedAddr, err
	}
	if resp.packet != nil {
		logger.Debugln("Received from:", resp.serverAddr)
	}
	logger.Debugln("Received: isNil:", resp.packet == nil)
	if resp.identical {
		if resp.packet == nil {
			return NATSymetricUDPFirewall, resp.mappedAddr, nil
		}
		return NATNone, resp.mappedAddr, nil
	}
	if resp.packet != nil {
		return NATFull, resp.mappedAddr, nil
	}
	logger.Debugln("Do Test1")
	logger.Debugln("Send To:", changedAddrHost)
	changedAddr, err := net.ResolveUDPAddr("udp", changedAddrHost.String())
	resp, err = c.test1(conn, changedAddr, softwareName)
	if err != nil {
		return NATError, resp.mappedAddr, err
	}
	logger.Debugln("Received from:", resp.serverAddr)
	logger.Debugln("Received: isNil:", resp.packet == nil)
	if resp.packet == nil {
		// It should be NAT_BLOCKED, but will be detected in the first
		// step. So this will never happen.
		return NATUnknown, resp.mappedAddr, nil
	}
	logger.Debugln("Received: extAddr:", resp.mappedAddr)
	if exHostIP == resp.mappedAddr.IP() {
		tmpAddr, err := net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			return NATError, resp.mappedAddr, err
		}
		port := tmpAddr.Port
		changePortAddrStr := net.JoinHostPort(changedAddr.IP.String(), strconv.Itoa(port))
		changePortAddr, err := net.ResolveUDPAddr("udp", changePortAddrStr)
		if err != nil {
			return NATError, resp.mappedAddr, err
		}
		logger.Debugln("Do Test3")
		logger.Debugln("Send To:", addr)
		resp, err = c.test3(conn, changePortAddr, softwareName)
		if err != nil {
			return NATError, resp.mappedAddr, err
		}
		logger.Debugln("Received from:", resp.mappedAddr)
		logger.Debugln("Received: isNil:", resp.packet == nil)
		if resp.packet == nil {
			return NATPortRestricted, resp.mappedAddr, nil
		}
		return NATRestricted, resp.mappedAddr, nil
	}
	return NATSymetric, resp.mappedAddr, nil
}
