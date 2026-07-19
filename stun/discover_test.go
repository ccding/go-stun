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
	"testing"
	"time"
)

func TestDiscoverReturnsMappedAddressWhenNATTypeUnavailable(t *testing.T) {
	conn := &bindingResponseConn{scriptedPacketConn: scriptedPacketConn{
		local: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
	}}
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	nat, host, err := NewClient().discover(conn, server)
	if err != nil {
		t.Fatal(err)
	}
	if nat != NATUnknown {
		t.Fatalf("NAT type = %v, want %v", nat, NATUnknown)
	}
	if host == nil || host.String() != "192.0.2.20:40000" {
		t.Fatalf("mapped address = %#v", host)
	}
}

func TestNATUnknownString(t *testing.T) {
	if got := NATUnknown.String(); got != "NAT type unavailable" {
		t.Fatalf("NATUnknown.String() = %q", got)
	}
}

func TestDiscoverRejectsResponseWithoutMappedAddress(t *testing.T) {
	conn := &bindingResponseConn{
		scriptedPacketConn: scriptedPacketConn{
			local: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
		},
		omitMapped: true,
	}
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	nat, host, err := NewClient().discover(conn, server)
	if err == nil || nat != NATError || host != nil {
		t.Fatalf("discover returned NAT=%v host=%#v error=%v", nat, host, err)
	}
}

type behaviorProbe struct {
	destination string
	change      byte
}

type behaviorPacketConn struct {
	local              *net.UDPAddr
	pending            []packetRead
	seen               map[string]bool
	probes             []behaviorProbe
	omitMappedAt       int
	initialMappedLocal bool
}

func newBehaviorPacketConn() *behaviorPacketConn {
	return &behaviorPacketConn{
		local: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
		seen:  make(map[string]bool),
	}
}

func (c *behaviorPacketConn) ReadFrom(dst []byte) (int, net.Addr, error) {
	if len(c.pending) == 0 {
		return 0, nil, timeoutError{}
	}
	read := c.pending[0]
	c.pending = c.pending[1:]
	return copy(dst, read.data), read.addr, read.err
}

func (c *behaviorPacketConn) WriteTo(wire []byte, destination net.Addr) (int, error) {
	request, err := newPacketFromBytes(wire)
	if err != nil {
		return 0, err
	}
	key := string(request.transID)
	if c.seen[key] {
		return len(wire), nil
	}
	c.seen[key] = true

	change := byte(0)
	if a := request.getAttributeBeforeIntegrity(attributeChangeRequest); a != nil {
		change = a.value[3]
	}
	c.probes = append(c.probes, behaviorProbe{destination: destination.String(), change: change})
	probeNumber := len(c.probes)

	// Filtering Test II deliberately receives no response. Retransmissions
	// use the same transaction ID and therefore do not create extra probes.
	if change == 0x06 {
		return len(wire), nil
	}

	destinationAddr, err := net.ResolveUDPAddr("udp", destination.String())
	if err != nil {
		return 0, err
	}
	responseAddr := &net.UDPAddr{IP: append(net.IP(nil), destinationAddr.IP...), Port: destinationAddr.Port}
	if change == 0x02 {
		responseAddr.Port = 3479
	}

	response := bindingPacket(typeBindingResponse, request.transID)
	mappedIP := net.ParseIP("192.0.2.20")
	mappedPort := uint16(40000)
	if destinationAddr.IP.Equal(net.ParseIP("203.0.113.2")) {
		mappedPort = 40001
	}
	if c.initialMappedLocal && probeNumber == 1 {
		mappedIP = c.local.IP
		mappedPort = uint16(c.local.Port)
	}
	if c.omitMappedAt != probeNumber {
		response.addAttribute(*mappedAddressAttribute(mappedIP, mappedPort))
	}
	if probeNumber == 1 {
		other := mappedAddressAttribute(net.ParseIP("203.0.113.2"), 3479)
		other.types = attributeOtherAddress
		response.addAttribute(*other)
	}
	c.pending = append(c.pending, packetRead{data: response.bytes(), addr: responseAddr})
	return len(wire), nil
}

func (c *behaviorPacketConn) Close() error                     { return nil }
func (c *behaviorPacketConn) LocalAddr() net.Addr              { return c.local }
func (c *behaviorPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *behaviorPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *behaviorPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestBehaviorTestRunsFilteringBeforeMapping(t *testing.T) {
	conn := newBehaviorPacketConn()
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	behavior, err := NewClient().behaviorTest(conn, server)
	if err != nil {
		t.Fatal(err)
	}
	if behavior.MappingType != BehaviorTypeAddr || behavior.FilteringType != BehaviorTypeAddr {
		t.Fatalf("behavior = %#v", behavior)
	}

	want := []behaviorProbe{
		{destination: "198.51.100.1:3478", change: 0x00},
		{destination: "198.51.100.1:3478", change: 0x06},
		{destination: "198.51.100.1:3478", change: 0x02},
		{destination: "203.0.113.2:3478", change: 0x00},
		{destination: "203.0.113.2:3479", change: 0x00},
	}
	if len(conn.probes) != len(want) {
		t.Fatalf("probes = %#v, want %#v", conn.probes, want)
	}
	for i := range want {
		if conn.probes[i] != want[i] {
			t.Fatalf("probe %d = %#v, want %#v", i, conn.probes[i], want[i])
		}
	}
}

func TestBehaviorTestValidatesMappedAddressAtEveryStage(t *testing.T) {
	for _, probeNumber := range []int{3, 4, 5} {
		t.Run(string(rune('0'+probeNumber)), func(t *testing.T) {
			conn := newBehaviorPacketConn()
			conn.omitMappedAt = probeNumber
			server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
			if _, err := NewClient().behaviorTest(conn, server); err == nil {
				t.Fatalf("behavior test accepted probe %d without a mapped address", probeNumber)
			}
		})
	}
}

func TestBehaviorTestHandlesOpenInternet(t *testing.T) {
	conn := newBehaviorPacketConn()
	conn.initialMappedLocal = true
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	behavior, err := NewClient().behaviorTest(conn, server)
	if err != nil {
		t.Fatal(err)
	}
	if behavior.MappingType != BehaviorTypeEndpoint || behavior.FilteringType != BehaviorTypeAddr {
		t.Fatalf("behavior = %#v", behavior)
	}
	if len(conn.probes) != 3 {
		t.Fatalf("open-internet test sent mapping probes: %#v", conn.probes)
	}
}

func TestResolveLocalAddrSupportsIPv6(t *testing.T) {
	client := NewClient()
	client.SetLocalIP("2001:db8::1")
	client.SetLocalPort(5000)
	addr, err := client.resolveLocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if addr == nil || !addr.IP.Equal(net.ParseIP("2001:db8::1")) || addr.Port != 5000 {
		t.Fatalf("local address = %#v", addr)
	}
}
