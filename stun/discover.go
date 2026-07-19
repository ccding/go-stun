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
	"errors"
	"fmt"
	"net"
)

// ErrBehaviorDiscoveryUnsupported indicates that the server answered a
// Binding request but did not advertise a usable alternate address, which is
// required for RFC 5780 mapping and filtering behavior discovery.
var ErrBehaviorDiscoveryUnsupported = errors.New("server does not support RFC 5780 behavior discovery")

// Follow RFC 3489 and RFC 5389.
// Figure 2: Flow for type discovery process (from RFC 3489).
//
//	                     +--------+
//	                     |  Test  |
//	                     |   I    |
//	                     +--------+
//	                          |
//	                          |
//	                          V
//	                         /\              /\
//	                      N /  \ Y          /  \ Y             +--------+
//	       UDP     <-------/Resp\--------->/ IP \------------->|  Test  |
//	       Blocked         \ ?  /          \Same/              |   II   |
//	                        \  /            \? /               +--------+
//	                         \/              \/                    |
//	                                          | N                  |
//	                                          |                    V
//	                                          V                    /\
//	                                      +--------+  Sym.      N /  \
//	                                      |  Test  |  UDP    <---/Resp\
//	                                      |   II   |  Firewall   \ ?  /
//	                                      +--------+              \  /
//	                                          |                    \/
//	                                          V                     |Y
//	               /\                         /\                    |
//	Symmetric  N  /  \       +--------+   N  /  \                   V
//	   NAT  <--- / IP \<-----|  Test  |<--- /Resp\               Open
//	             \Same/      |   I    |     \ ?  /               Internet
//	              \? /       +--------+      \  /
//	               \/                         \/
//	               |Y                          |Y
//	               |                           |
//	               |                           V
//	               |                           Full
//	               |                           Cone
//	               V              /\
//	           +--------+        /  \ Y
//	           |  Test  |------>/Resp\---->Restricted
//	           |   III  |       \ ?  /
//	           +--------+        \  /
//	                              \/
//	                               |N
//	                               |       Port
//	                               +------>Restricted
func (c *Client) discover(conn net.PacketConn, addr *net.UDPAddr) (NATType, *Host, error) {
	// Perform test1 to check if it is under NAT.
	c.logger.Debugln("Do Test1")
	c.logger.Debugln("Send To:", addr)
	resp, err := c.test1(conn, addr)
	if err != nil {
		return NATError, nil, err
	}
	c.logger.Debugln("Received:", resp)
	if resp == nil {
		return NATBlocked, nil, nil
	}
	// identical used to check if it is open Internet or not.
	identical := resp.identical
	// changedAddr is used to perform second time test1 and test3.
	changedAddr := resp.changedAddr
	// mappedAddr is used as the return value, its IP is used for tests
	mappedAddr := resp.mappedAddr
	// send currently rejects mapped-address-less success responses. Keep this
	// guard as defense in depth if response construction changes later.
	if mappedAddr == nil {
		return NATError, nil, errors.New("server response has no mapped address")
	}
	// Make sure IP and port are not changed.
	if resp.serverAddr.IP() != addr.IP.String() ||
		resp.serverAddr.Port() != uint16(addr.Port) {
		return NATError, mappedAddr, errors.New("server error: response IP/port")
	}
	// if changedAddr is not available, use otherAddr as changedAddr,
	// which is updated in RFC 5780
	if changedAddr == nil {
		changedAddr = resp.otherAddr
	}
	// changedAddr shall not be nil
	if changedAddr == nil {
		return NATUnknown, mappedAddr, nil
	}
	// RFC 3489 CHANGED-ADDRESS and RFC 5780 OTHER-ADDRESS identify an
	// alternate IP and port. A primary endpoint advertised as its own
	// alternate cannot support the remaining classification probes.
	if !isUsableAlternate(addr, changedAddr) {
		return NATUnknown, mappedAddr, nil
	}
	// Perform test2 to see if the client can receive packet sent from
	// another IP and port.
	c.logger.Debugln("Do Test2")
	c.logger.Debugln("Send To:", addr)
	resp, err = c.test2(conn, addr)
	if err != nil {
		return NATError, mappedAddr, err
	}
	c.logger.Debugln("Received:", resp)
	// Make sure IP and port are changed.
	if resp != nil &&
		(resp.serverAddr.IP() == addr.IP.String() ||
			resp.serverAddr.Port() == uint16(addr.Port)) {
		return NATError, mappedAddr, errors.New("server error: response IP/port")
	}
	if identical {
		if resp == nil {
			return SymmetricUDPFirewall, mappedAddr, nil
		}
		return NATNone, mappedAddr, nil
	}
	if resp != nil {
		return NATFull, mappedAddr, nil
	}
	// Perform test1 to another IP and port to see if the NAT use the same
	// external IP.
	c.logger.Debugln("Do Test1")
	c.logger.Debugln("Send To:", changedAddr)
	caddr, err := net.ResolveUDPAddr("udp", changedAddr.String())
	if err != nil {
		return NATError, mappedAddr, fmt.Errorf("resolve server alternate address %q: %w", changedAddr, err)
	}
	resp, err = c.test1(conn, caddr)
	if err != nil {
		return NATError, mappedAddr, err
	}
	c.logger.Debugln("Received:", resp)
	if resp == nil {
		// The primary address worked, but the alternate address is
		// unreachable, so classification cannot continue.
		return NATUnknown, mappedAddr, nil
	}
	// Make sure IP/port is not changed.
	if resp.serverAddr.IP() != caddr.IP.String() ||
		resp.serverAddr.Port() != uint16(caddr.Port) {
		return NATError, mappedAddr, errors.New("server error: response IP/port")
	}
	if mappedAddr.IP() == resp.mappedAddr.IP() && mappedAddr.Port() == resp.mappedAddr.Port() {
		// Perform test3 to see if the client can receive packet sent
		// from another port.
		c.logger.Debugln("Do Test3")
		c.logger.Debugln("Send To:", caddr)
		resp, err = c.test3(conn, caddr)
		if err != nil {
			return NATError, mappedAddr, err
		}
		c.logger.Debugln("Received:", resp)
		if resp == nil {
			return NATPortRestricted, mappedAddr, nil
		}
		// Make sure IP is not changed, and port is changed.
		if resp.serverAddr.IP() != caddr.IP.String() ||
			resp.serverAddr.Port() == uint16(caddr.Port) {
			return NATError, mappedAddr, errors.New("server error: response IP/port")
		}
		return NATRestricted, mappedAddr, nil
	}
	return NATSymmetric, mappedAddr, nil
}

func (c *Client) behaviorTest(conn net.PacketConn, addr *net.UDPAddr) (*NATBehavior, error) {
	natBehavior := &NATBehavior{}

	// Test1   ->(IP1,port1)
	// Perform test to check if it is under NAT.
	c.logger.Debugln("Do Test1")
	resp1, err := c.test(conn, addr)
	if err != nil {
		return nil, err
	}
	natBehavior.NoTranslation = resp1.identical
	// use otherAddr or changedAddr
	otherAddr := resp1.otherAddr
	if otherAddr == nil {
		if resp1.changedAddr != nil {
			otherAddr = resp1.changedAddr
		} else {
			return natBehavior, ErrBehaviorDiscoveryUnsupported
		}
	}
	if !isUsableAlternate(addr, otherAddr) {
		return natBehavior, fmt.Errorf("%w: alternate address %s must use a different IP and port from primary %s",
			ErrBehaviorDiscoveryUnsupported, otherAddr, addr)
	}
	alternateAddr, err := net.ResolveUDPAddr("udp", otherAddr.String())
	if err != nil {
		return natBehavior, fmt.Errorf("resolve server alternate address %q: %w", otherAddr, err)
	}

	// Filtering Test II ->(IP1,port1)   (IP2,port2)->
	// Filtering has to be tested before sending mapping probes to the
	// alternate endpoint; those probes would otherwise create NAT state and
	// could make filtering appear less restrictive than it is.
	// Perform test to see if the client can receive packet sent from
	// another IP and port.
	c.logger.Debugln("Do Filtering Test II")
	resp4, err := c.testChangeBoth(conn, addr)
	if err != nil {
		return natBehavior, err
	}
	if resp4 != nil {
		natBehavior.FilteringType = BehaviorTypeEndpoint
	}

	// Filtering Test III ->(IP1,port1)   (IP1,port2)->
	// Perform test to see if the client can receive packet sent from
	// another port.
	if natBehavior.FilteringType == BehaviorTypeUnknown {
		c.logger.Debugln("Do Filtering Test III")
		resp5, err := c.testChangePort(conn, addr)
		if err != nil {
			return natBehavior, err
		}
		if resp5 != nil {
			natBehavior.FilteringType = BehaviorTypeAddr
		} else {
			natBehavior.FilteringType = BehaviorTypeAddrAndPort
		}
	}

	// A matching local and mapped transport address means there is no
	// translation. Its mapping behavior is effectively endpoint-independent;
	// the filtering tests above still describe any firewall behavior.
	if resp1.identical {
		natBehavior.MappingType = BehaviorTypeEndpoint
		return natBehavior, nil
	}

	// Mapping Test II ->(IP2,port1)
	// Perform test to see if mapping to the same IP and port when sending to
	// another IP.
	c.logger.Debugln("Do Mapping Test II")
	tmpAddr := &net.UDPAddr{IP: alternateAddr.IP, Port: addr.Port}
	resp2, err := c.testBehaviorAlternate(conn, tmpAddr)
	if err != nil {
		return natBehavior, err
	}
	if resp2.mappedAddr.IP() == resp1.mappedAddr.IP() &&
		resp2.mappedAddr.Port() == resp1.mappedAddr.Port() {
		natBehavior.MappingType = BehaviorTypeEndpoint
	}

	// Mapping Test III ->(IP2,port2)
	// Perform test to see if mapping to the same IP and port when sending to
	// another port.
	if natBehavior.MappingType == BehaviorTypeUnknown {
		c.logger.Debugln("Do Mapping Test III")
		tmpAddr.Port = alternateAddr.Port
		resp3, err := c.testBehaviorAlternate(conn, tmpAddr)
		if err != nil {
			return natBehavior, err
		}
		if resp3.mappedAddr.IP() == resp2.mappedAddr.IP() &&
			resp3.mappedAddr.Port() == resp2.mappedAddr.Port() {
			natBehavior.MappingType = BehaviorTypeAddr
		} else {
			natBehavior.MappingType = BehaviorTypeAddrAndPort
		}
	}

	return natBehavior, nil
}

// isUsableAlternate reports whether alternate can exercise both the alternate
// IP and alternate port paths required by RFC 3489/RFC 5780 discovery.
func isUsableAlternate(primary *net.UDPAddr, alternate *Host) bool {
	if primary == nil || primary.IP == nil || alternate == nil || alternate.Port() == 0 {
		return false
	}
	alternateIP := net.ParseIP(alternate.IP())
	return alternateIP != nil && !primary.IP.Equal(alternateIP) && primary.Port != int(alternate.Port())
}

// testBehaviorAlternate sends a mapping probe without treating a timeout as
// generic NAT blocking. The primary endpoint already answered, so a timeout
// here specifically means that the advertised alternate endpoint failed.
func (c *Client) testBehaviorAlternate(conn net.PacketConn, addr *net.UDPAddr) (*response, error) {
	c.logger.Debugln("Send To:", addr)
	resp, err := c.test1(conn, addr)
	if err != nil {
		return nil, err
	}
	c.logger.Debugln("Received:", resp)
	if resp == nil {
		return nil, fmt.Errorf("no response from server alternate address %s", addr)
	}
	if !addrCompare(resp.serverAddr, addr, false, false) {
		return nil, errors.New("server error: response IP/port")
	}
	return resp, nil
}
