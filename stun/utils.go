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
	"net"
)

var interfaceAddrs = net.InterfaceAddrs

// align rounds a STUN field length up to the smallest multiple of four that
// is greater than or equal to n. It uses int arithmetic so every uint16 wire
// length, including 65,533 through 65,535, aligns without wrapping.
func align(n int) int {
	return (n + 3) &^ 3
}

// isLocalAddress check if localRemote is a local address.
func isLocalAddress(local, localRemote string) bool {
	// Resolve the IP returned by the STUN server first.
	localRemoteAddr, err := net.ResolveUDPAddr("udp", localRemote)
	if err != nil || localRemoteAddr.IP == nil {
		return false
	}
	// Try comparing with the local address on the socket first, but only if
	// it's actually specified.
	addr, err := net.ResolveUDPAddr("udp", local)
	if err != nil || addr.Port != localRemoteAddr.Port {
		return false
	}
	if addr.IP != nil && !addr.IP.IsUnspecified() {
		return addr.IP.Equal(localRemoteAddr.IP)
	}
	// Fallback to checking IPs of all interfaces
	addrs, err := interfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}
		if ip.Equal(localRemoteAddr.IP) {
			return true
		}
	}
	return false
}
