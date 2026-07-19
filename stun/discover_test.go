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
	"net"
	"strconv"
	"strings"
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

	respondToChangeBoth       bool
	changeBothFromSameAddr    bool
	silentChangePort          bool
	changePortFromOtherIP     bool
	mappingProbeFromWrongAddr bool
	uniformMapping            bool
	portSensitiveMapping      bool
	omitOtherAddress          bool
	alternateUnreachable      bool
	alternateSameIP           bool
	alternateSamePort         bool
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

	// Filtering Test II deliberately receives no response by default.
	// Retransmissions use the same transaction ID and therefore do not create
	// extra probes.
	if change == 0x06 && !c.respondToChangeBoth && !c.changeBothFromSameAddr {
		return len(wire), nil
	}
	if change == 0x02 && c.silentChangePort {
		return len(wire), nil
	}

	destinationAddr, err := net.ResolveUDPAddr("udp", destination.String())
	if err != nil {
		return 0, err
	}
	responseAddr := &net.UDPAddr{IP: append(net.IP(nil), destinationAddr.IP...), Port: destinationAddr.Port}
	if change == 0x02 {
		responseAddr.Port = destinationAddr.Port + 1
		if c.changePortFromOtherIP {
			responseAddr.IP = net.ParseIP("203.0.113.2")
		}
	}
	if change == 0x06 && !c.changeBothFromSameAddr {
		responseAddr = &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 3479}
	}
	if c.mappingProbeFromWrongAddr && change == 0 && destinationAddr.IP.Equal(net.ParseIP("203.0.113.2")) {
		responseAddr.IP = net.ParseIP("203.0.113.3")
	}
	if c.alternateUnreachable && change == 0 && destinationAddr.IP.Equal(net.ParseIP("203.0.113.2")) {
		return len(wire), nil
	}

	response := bindingPacket(typeBindingResponse, request.transID)
	mappedIP := net.ParseIP("192.0.2.20")
	mappedPort := uint16(40000)
	if !c.uniformMapping && destinationAddr.IP.Equal(net.ParseIP("203.0.113.2")) {
		mappedPort = 40001
		if c.portSensitiveMapping && destinationAddr.Port == 3479 {
			mappedPort = 40002
		}
	}
	if c.initialMappedLocal && probeNumber == 1 {
		mappedIP = c.local.IP
		mappedPort = uint16(c.local.Port)
	}
	if c.omitMappedAt != probeNumber {
		response.addAttribute(*mappedAddressAttribute(mappedIP, mappedPort))
	}
	if probeNumber == 1 && !c.omitOtherAddress {
		otherIP := net.ParseIP("203.0.113.2")
		otherPort := uint16(3479)
		if c.alternateSameIP {
			otherIP = net.ParseIP("198.51.100.1")
		}
		if c.alternateSamePort {
			otherPort = 3478
		}
		other := mappedAddressAttribute(otherIP, otherPort)
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
		t.Run(strconv.Itoa(probeNumber), func(t *testing.T) {
			conn := newBehaviorPacketConn()
			conn.omitMappedAt = probeNumber
			server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
			behavior, err := NewClient().behaviorTest(conn, server)
			if err == nil {
				t.Fatalf("behavior test accepted probe %d without a mapped address", probeNumber)
			}
			if behavior == nil {
				t.Fatalf("behavior test discarded partial result at probe %d", probeNumber)
			}
			if probeNumber >= 4 && behavior.FilteringType != BehaviorTypeAddr {
				t.Fatalf("partial behavior at probe %d = %#v", probeNumber, behavior)
			}
		})
	}
}

func TestBehaviorTestHandlesFilteredNoTranslation(t *testing.T) {
	conn := newBehaviorPacketConn()
	conn.initialMappedLocal = true
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	behavior, err := NewClient().behaviorTest(conn, server)
	if err != nil {
		t.Fatal(err)
	}
	if behavior.MappingType != BehaviorTypeEndpoint || behavior.FilteringType != BehaviorTypeAddr || !behavior.NoTranslation {
		t.Fatalf("behavior = %#v", behavior)
	}
	if got := behavior.NormalType(); got != "Symmetric UDP firewall" {
		t.Fatalf("NormalType() = %q", got)
	}
	if len(conn.probes) != 3 {
		t.Fatalf("open-internet test sent mapping probes: %#v", conn.probes)
	}
}

func TestBehaviorTestHandlesOpenInternet(t *testing.T) {
	conn := newBehaviorPacketConn()
	conn.initialMappedLocal = true
	conn.respondToChangeBoth = true
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	behavior, err := NewClient().behaviorTest(conn, server)
	if err != nil {
		t.Fatal(err)
	}
	if behavior.MappingType != BehaviorTypeEndpoint || behavior.FilteringType != BehaviorTypeEndpoint || !behavior.NoTranslation {
		t.Fatalf("behavior = %#v", behavior)
	}
	if got := behavior.NormalType(); got != "Open Internet (no NAT)" {
		t.Fatalf("NormalType() = %q", got)
	}
	if len(conn.probes) != 2 {
		t.Fatalf("open-internet test sent unexpected probes: %#v", conn.probes)
	}
}

func TestBehaviorTestReportsUnsupportedServer(t *testing.T) {
	conn := newBehaviorPacketConn()
	conn.omitOtherAddress = true
	behavior, err := NewClient().behaviorTest(conn, &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478})
	if !errors.Is(err, ErrBehaviorDiscoveryUnsupported) {
		t.Fatalf("behaviorTest error = %v", err)
	}
	if behavior == nil {
		t.Fatal("behaviorTest discarded the partial result")
	}
}

func TestBehaviorTestRejectsUnusableAlternateAddress(t *testing.T) {
	for _, tt := range []struct {
		name      string
		configure func(*behaviorPacketConn)
	}{
		{"same IP", func(c *behaviorPacketConn) { c.alternateSameIP = true }},
		{"same port", func(c *behaviorPacketConn) { c.alternateSamePort = true }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn := newBehaviorPacketConn()
			tt.configure(conn)
			behavior, err := NewClient().behaviorTest(conn, &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478})
			if !errors.Is(err, ErrBehaviorDiscoveryUnsupported) || behavior == nil {
				t.Fatalf("behaviorTest = %#v, %v", behavior, err)
			}
		})
	}
}

func TestBehaviorTestReturnsPartialWhenAlternateIsUnreachable(t *testing.T) {
	conn := newBehaviorPacketConn()
	conn.alternateUnreachable = true
	behavior, err := NewClient().behaviorTest(conn, &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478})
	if err == nil || !strings.Contains(err.Error(), "no response from server alternate address 203.0.113.2:3478") {
		t.Fatalf("behaviorTest error = %v", err)
	}
	if behavior == nil || behavior.MappingType != BehaviorTypeUnknown || behavior.FilteringType != BehaviorTypeAddr {
		t.Fatalf("partial behavior = %#v", behavior)
	}
}

func TestBehaviorTestRejectsChangePortResponseFromWrongIP(t *testing.T) {
	conn := newBehaviorPacketConn()
	conn.changePortFromOtherIP = true
	behavior, err := NewClient().behaviorTest(conn, &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478})
	if err == nil || err.Error() != "server error: response IP/port" {
		t.Fatalf("behaviorTest error = %v", err)
	}
	if behavior == nil {
		t.Fatal("behaviorTest discarded the partial result")
	}
}

func TestBehaviorTestRejectsChangeBothResponseFromSameAddress(t *testing.T) {
	conn := newBehaviorPacketConn()
	conn.changeBothFromSameAddr = true
	behavior, err := NewClient().behaviorTest(conn, &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478})
	if err == nil || err.Error() != "server error: response IP/port" {
		t.Fatalf("behaviorTest error = %v", err)
	}
	if behavior == nil {
		t.Fatal("behaviorTest discarded the partial result")
	}
}

func TestBehaviorTestRejectsMappingResponseFromWrongAddress(t *testing.T) {
	conn := newBehaviorPacketConn()
	conn.mappingProbeFromWrongAddr = true
	behavior, err := NewClient().behaviorTest(conn, &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478})
	if err == nil || err.Error() != "server error: response IP/port" {
		t.Fatalf("behaviorTest error = %v", err)
	}
	if behavior == nil || behavior.MappingType != BehaviorTypeUnknown || behavior.FilteringType != BehaviorTypeAddr {
		t.Fatalf("partial behavior = %#v", behavior)
	}
}

func TestBehaviorTestClassificationMatrix(t *testing.T) {
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	tests := []struct {
		name      string
		configure func(*behaviorPacketConn)
		want      NATBehavior
	}{
		{"address dependent", func(*behaviorPacketConn) {}, NATBehavior{MappingType: BehaviorTypeAddr, FilteringType: BehaviorTypeAddr}},
		{"endpoint filtering", func(c *behaviorPacketConn) { c.respondToChangeBoth = true }, NATBehavior{MappingType: BehaviorTypeAddr, FilteringType: BehaviorTypeEndpoint}},
		{"address and port filtering", func(c *behaviorPacketConn) { c.silentChangePort = true }, NATBehavior{MappingType: BehaviorTypeAddr, FilteringType: BehaviorTypeAddrAndPort}},
		{"endpoint mapping", func(c *behaviorPacketConn) { c.uniformMapping = true }, NATBehavior{MappingType: BehaviorTypeEndpoint, FilteringType: BehaviorTypeAddr}},
		{"address and port mapping", func(c *behaviorPacketConn) { c.portSensitiveMapping = true }, NATBehavior{MappingType: BehaviorTypeAddrAndPort, FilteringType: BehaviorTypeAddr}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newBehaviorPacketConn()
			tt.configure(conn)
			behavior, err := NewClient().behaviorTest(conn, server)
			if err != nil {
				t.Fatal(err)
			}
			if *behavior != tt.want {
				t.Fatalf("behavior = %#v, want %#v", *behavior, tt.want)
			}
		})
	}
}

func TestDiscoverClassificationMatrix(t *testing.T) {
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	tests := []struct {
		name      string
		configure func(*behaviorPacketConn)
		want      NATType
	}{
		{"symmetric", func(*behaviorPacketConn) {}, NATSymmetric},
		{"full cone", func(c *behaviorPacketConn) { c.respondToChangeBoth = true }, NATFull},
		{"open internet", func(c *behaviorPacketConn) { c.respondToChangeBoth = true; c.initialMappedLocal = true }, NATNone},
		{"symmetric UDP firewall", func(c *behaviorPacketConn) { c.initialMappedLocal = true }, SymmetricUDPFirewall},
		{"restricted", func(c *behaviorPacketConn) { c.uniformMapping = true }, NATRestricted},
		{"port restricted", func(c *behaviorPacketConn) { c.uniformMapping = true; c.silentChangePort = true }, NATPortRestricted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newBehaviorPacketConn()
			tt.configure(conn)
			nat, host, err := NewClient().discover(conn, server)
			if err != nil || nat != tt.want || host == nil {
				t.Fatalf("discover = %v, %#v, %v; want %v and mapped host", nat, host, err, tt.want)
			}
		})
	}
}

func TestDiscoverTreatsUnusableAlternateAddressAsUnavailable(t *testing.T) {
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	for _, tt := range []struct {
		name      string
		configure func(*behaviorPacketConn)
	}{
		{"same IP", func(c *behaviorPacketConn) { c.alternateSameIP = true }},
		{"same port", func(c *behaviorPacketConn) { c.alternateSamePort = true }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn := newBehaviorPacketConn()
			tt.configure(conn)
			nat, host, err := NewClient().discover(conn, server)
			if err != nil || nat != NATUnknown || host == nil || host.String() != "192.0.2.20:40000" {
				t.Fatalf("discover = %v, %#v, %v; want NATUnknown and mapped host", nat, host, err)
			}
			if len(conn.probes) != 1 {
				t.Fatalf("discover sent probes to unusable alternate: %#v", conn.probes)
			}
		})
	}
}

func TestDiscoverRejectsChangeBothResponseFromSameAddress(t *testing.T) {
	conn := newBehaviorPacketConn()
	conn.changeBothFromSameAddr = true
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	nat, host, err := NewClient().discover(conn, server)
	if err == nil || err.Error() != "server error: response IP/port" {
		t.Fatalf("discover error = %v", err)
	}
	if nat != NATError || host == nil || host.String() != "192.0.2.20:40000" {
		t.Fatalf("discover = %v, %#v, %v", nat, host, err)
	}
}

func TestDiscoverClassifiesBlockedAndRejectsSpoofedServer(t *testing.T) {
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	blocked := &scriptedPacketConn{local: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000}}
	if nat, host, err := NewClient().discover(blocked, server); err != nil || nat != NATBlocked || host != nil {
		t.Fatalf("blocked discover = %v, %#v, %v", nat, host, err)
	}

	spoofed := &bindingResponseConn{scriptedPacketConn: scriptedPacketConn{
		local: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
	}}
	wrongPort := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 9999}
	if nat, host, err := NewClient().discover(spoofed, wrongPort); err == nil || nat != NATError || host == nil {
		t.Fatalf("spoofed discover = %v, %#v, %v", nat, host, err)
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
