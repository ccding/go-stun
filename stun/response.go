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

type response struct {
	packet      *packet // the original packet from the server
	serverAddr  *Host   // the address received packet
	changedAddr *Host   // parsed from packet
	mappedAddr  *Host   // parsed from packet, external addr of client NAT
	identical   bool    // if mappedAddr is in local addr list
}

func newNilResponse() *response {
	return &response{nil, nil, nil, nil, false}
}

func newResponse(pkt *packet, conn net.PacketConn) *response {
	resp := &response{pkt, nil, nil, nil, false}
	if pkt == nil {
		return resp
	}
	// RFC 3489 doesn't require the server return XOR mapped address.
	mappedAddr := pkt.xorMappedAddr()
	if mappedAddr == nil {
		mappedAddr = pkt.getMappedAddr()
	}
	resp.mappedAddr = mappedAddr
	// compute identical
	localAddrStr := conn.LocalAddr().String()
	if mappedAddr != nil {
		mappedAddrStr := mappedAddr.String()
		resp.identical = isLocalAddress(localAddrStr, mappedAddrStr)
	}
	// compute changedAddr
	changedAddr := pkt.getChangedAddr()
	changedAddrHost := newHostFromStr(changedAddr.String())
	resp.changedAddr = changedAddrHost

	return resp
}
