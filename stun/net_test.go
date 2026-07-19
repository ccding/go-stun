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
	"testing"
	"time"
)

type packetRead struct {
	data []byte
	addr net.Addr
	err  error
}

type scriptedPacketConn struct {
	reads    []packetRead
	writes   [][]byte
	local    net.Addr
	deadline time.Time
	writeErr error
	short    bool
}

func (c *scriptedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(c.reads) == 0 {
		return 0, nil, timeoutError{}
	}
	read := c.reads[0]
	c.reads = c.reads[1:]
	if read.err != nil {
		return 0, read.addr, read.err
	}
	return copy(p, read.data), read.addr, nil
}

func (c *scriptedPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.writes = append(c.writes, append([]byte(nil), p...))
	if c.short {
		return len(p) - 1, nil
	}
	return len(p), nil
}

func (c *scriptedPacketConn) Close() error                      { return nil }
func (c *scriptedPacketConn) LocalAddr() net.Addr               { return c.local }
func (c *scriptedPacketConn) SetDeadline(t time.Time) error     { c.deadline = t; return nil }
func (c *scriptedPacketConn) SetReadDeadline(t time.Time) error { c.deadline = t; return nil }
func (c *scriptedPacketConn) SetWriteDeadline(time.Time) error  { return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type bindingResponseConn struct {
	scriptedPacketConn
	responded  bool
	omitMapped bool
	mappedIP   net.IP
	mappedPort uint16
	legacy     bool
}

func (c *bindingResponseConn) ReadFrom(dst []byte) (int, net.Addr, error) {
	if c.responded || len(c.writes) == 0 {
		return 0, nil, timeoutError{}
	}
	request, err := newPacketFromBytes(c.writes[len(c.writes)-1])
	if err != nil {
		return 0, nil, err
	}
	response := bindingPacket(typeBindingResponse, request.transID)
	if !c.omitMapped {
		mappedIP := c.mappedIP
		if mappedIP == nil {
			mappedIP = net.ParseIP("192.0.2.20")
		}
		mappedPort := c.mappedPort
		if mappedPort == 0 {
			mappedPort = 40000
		}
		response.addAttribute(*mappedAddressAttribute(mappedIP, mappedPort))
	}
	if c.legacy {
		source := mappedAddressAttribute(net.ParseIP("198.51.100.1"), 3478)
		source.types = attributeSourceAddress
		response.addAttribute(*source)
		changed := mappedAddressAttribute(net.ParseIP("203.0.113.2"), 3479)
		changed.types = attributeChangedAddress
		response.addAttribute(*changed)
	}
	wire := response.bytes()
	c.responded = true
	return copy(dst, wire), &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}, nil
}

func bindingPacket(messageType uint16, transactionID []byte) *packet {
	p := &packet{
		types:      messageType,
		transID:    append([]byte(nil), transactionID...),
		attributes: make([]attribute, 0, 1),
	}
	return p
}

func mappedAddressAttribute(ip net.IP, port uint16) *attribute {
	ip = ip.To4()
	value := []byte{0, attributeFamilyIPv4, byte(port >> 8), byte(port)}
	value = append(value, ip...)
	return newAttribute(attributeMappedAddress, value)
}

func errorCodeAttribute(code int, reason string) *attribute {
	value := []byte{0, 0, byte(code / 100), byte(code % 100)}
	value = append(value, []byte(reason)...)
	return newAttribute(attributeErrorCode, value)
}

func TestSendDiscardsMalformedAndUnrelatedPackets(t *testing.T) {
	request, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	request.types = typeBindingRequest

	mismatch := bindingPacket(typeBindingResponse, request.transID)
	mismatch.transID[len(mismatch.transID)-1] ^= 1
	wrongClass := bindingPacket(typeBindingRequest, request.transID)
	valid := bindingPacket(typeBindingResponse, request.transID)
	valid.addAttribute(*mappedAddressAttribute(net.ParseIP("192.0.2.10"), 54321))
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	conn := &scriptedPacketConn{
		local: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
		reads: []packetRead{
			{data: []byte{0, 1, 2}, addr: server},
			{data: mismatch.bytes(), addr: server},
			{data: wrongClass.bytes(), addr: server},
			{data: valid.bytes(), addr: server},
		},
	}

	resp, err := NewClient().send(request, conn, server)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.mappedAddr == nil || resp.mappedAddr.IP() != "192.0.2.10" || resp.mappedAddr.Port() != 54321 {
		t.Fatalf("unexpected response: %#v", resp)
	}
	if len(conn.writes) != 1 {
		t.Fatalf("writes = %d, want 1", len(conn.writes))
	}
}

func TestSendBindingRequestWireFormat(t *testing.T) {
	client := NewClient()
	client.SetSoftwareName("abc")
	conn := &bindingResponseConn{scriptedPacketConn: scriptedPacketConn{
		local: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
	}}
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	resp, err := client.sendBindingReq(conn, server, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.mappedAddr == nil || resp.mappedAddr.String() != "192.0.2.20:40000" {
		t.Fatalf("unexpected response: %#v", resp)
	}
	if len(conn.writes) != 1 {
		t.Fatalf("writes = %d, want 1", len(conn.writes))
	}
	request, err := newPacketFromBytes(conn.writes[0])
	if err != nil {
		t.Fatal(err)
	}
	if request.types != typeBindingRequest || len(request.attributes) != 1 {
		t.Fatalf("unexpected request: type=%#x attributes=%d", request.types, len(request.attributes))
	}
	if got := request.attributes[0]; got.types != attributeChangeRequest || len(got.value) != 4 || got.value[3] != 0x06 {
		t.Fatalf("unexpected CHANGE-REQUEST attribute: %#v", got)
	}
}

func TestSendRetransmitsAfterTimeout(t *testing.T) {
	p, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	conn := &scriptedPacketConn{local: &net.UDPAddr{IP: net.IPv4zero, Port: 5000}}
	resp, err := NewClient().send(p, conn, &net.UDPAddr{IP: net.IPv4zero, Port: 3478})
	if err != nil || resp != nil {
		t.Fatalf("send returned response=%#v error=%v", resp, err)
	}
	if len(conn.writes) != numRetransmit {
		t.Fatalf("writes = %d, want %d", len(conn.writes), numRetransmit)
	}
}

func TestSendReportsWriteFailures(t *testing.T) {
	p, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		conn *scriptedPacketConn
	}{
		{"error", &scriptedPacketConn{writeErr: errors.New("write failed")}},
		{"short write", &scriptedPacketConn{short: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewClient().send(p, tt.conn, &net.UDPAddr{}); err == nil {
				t.Fatal("send succeeded")
			}
		})
	}
}

func TestRFC3489BindingInteroperability(t *testing.T) {
	client := NewClient()
	client.SetSoftwareName("not sent on the wire")
	conn := &bindingResponseConn{
		scriptedPacketConn: scriptedPacketConn{
			local: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
		},
		legacy: true,
	}
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	resp, err := client.sendBindingReq(conn, server, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(conn.writes) != 1 {
		t.Fatalf("writes = %d, want 1", len(conn.writes))
	}
	request, err := newPacketFromBytes(conn.writes[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(request.attributes) != 0 {
		t.Fatalf("RFC 3489-compatible request has attributes: %#v", request.attributes)
	}
	if resp == nil || resp.mappedAddr.String() != "192.0.2.20:40000" ||
		resp.changedAddr == nil || resp.changedAddr.String() != "203.0.113.2:3479" {
		t.Fatalf("legacy response = %#v", resp)
	}
}

func TestMappedIdentityIncludesPort(t *testing.T) {
	conn := &bindingResponseConn{
		scriptedPacketConn: scriptedPacketConn{
			local: &net.UDPAddr{IP: net.ParseIP("192.0.2.20"), Port: 5000},
		},
		mappedIP:   net.ParseIP("192.0.2.20"),
		mappedPort: 40000,
	}
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	resp, err := NewClient().sendBindingReq(conn, server, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if resp.identical {
		t.Fatal("same IP with a translated port was treated as an identical transport address")
	}
}

func TestSendReturnsBindingErrors(t *testing.T) {
	for _, code := range []int{300, 400, 420, 500} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			request, err := newPacket()
			if err != nil {
				t.Fatal(err)
			}
			request.types = typeBindingRequest
			response := bindingPacket(typeBindingErrorResponse, request.transID)
			response.addAttribute(*errorCodeAttribute(code, "failure"))
			// An error response must never become a success, even if a broken
			// server also includes a mapped address.
			response.addAttribute(*mappedAddressAttribute(net.ParseIP("192.0.2.20"), 40000))
			server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
			conn := &scriptedPacketConn{reads: []packetRead{{data: response.bytes(), addr: server}}}
			resp, err := NewClient().send(request, conn, server)
			if resp != nil {
				t.Fatalf("error response returned success: %#v", resp)
			}
			var stunErr *stunError
			if !errors.As(err, &stunErr) || stunErr.Code != code || stunErr.Reason != "failure" {
				t.Fatalf("error = %#v", err)
			}
		})
	}
}

func TestSendRejectsMalformedBindingErrors(t *testing.T) {
	tests := []struct {
		name string
		attr *attribute
	}{
		{name: "missing"},
		{name: "short", attr: newAttribute(attributeErrorCode, []byte{0, 0, 4})},
		{name: "class", attr: errorCodeAttribute(200, "bad")},
		{name: "number", attr: newAttribute(attributeErrorCode, []byte{0, 0, 4, 100})},
		{name: "utf8", attr: newAttribute(attributeErrorCode, []byte{0, 0, 4, 0, 0xff})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, err := newPacket()
			if err != nil {
				t.Fatal(err)
			}
			response := bindingPacket(typeBindingErrorResponse, request.transID)
			if tt.attr != nil {
				response.addAttribute(*tt.attr)
			}
			server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
			conn := &scriptedPacketConn{reads: []packetRead{{data: response.bytes(), addr: server}}}
			if resp, err := NewClient().send(request, conn, server); err == nil || resp != nil {
				t.Fatalf("send returned response=%#v error=%v", resp, err)
			}
		})
	}
}

func TestSendRejectsUnknownRequiredResponseAttribute(t *testing.T) {
	request, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	response := bindingPacket(typeBindingResponse, request.transID)
	response.addAttribute(*mappedAddressAttribute(net.ParseIP("192.0.2.20"), 40000))
	response.addAttribute(*newAttribute(0x1234, nil))
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	conn := &scriptedPacketConn{reads: []packetRead{{data: response.bytes(), addr: server}}}
	if resp, err := NewClient().send(request, conn, server); err == nil || resp != nil {
		t.Fatalf("send returned response=%#v error=%v", resp, err)
	}
}

func TestResponseIgnoresAttributesAfterMessageIntegrity(t *testing.T) {
	t.Run("unknown required", func(t *testing.T) {
		request, err := newPacket()
		if err != nil {
			t.Fatal(err)
		}
		response := bindingPacket(typeBindingResponse, request.transID)
		response.addAttribute(*mappedAddressAttribute(net.ParseIP("192.0.2.20"), 40000))
		response.addAttribute(*newAttribute(attributeMessageIntegrity, make([]byte, 20)))
		response.addAttribute(*newAttribute(0x1234, nil))
		server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
		conn := &scriptedPacketConn{reads: []packetRead{{data: response.bytes(), addr: server}}}
		resp, err := NewClient().send(request, conn, server)
		if err != nil || resp == nil {
			t.Fatalf("send returned response=%#v error=%v", resp, err)
		}
	})

	t.Run("mapped address", func(t *testing.T) {
		request, err := newPacket()
		if err != nil {
			t.Fatal(err)
		}
		response := bindingPacket(typeBindingResponse, request.transID)
		response.addAttribute(*newAttribute(attributeMessageIntegrity, make([]byte, 20)))
		response.addAttribute(*mappedAddressAttribute(net.ParseIP("192.0.2.20"), 40000))
		server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
		conn := &scriptedPacketConn{reads: []packetRead{{data: response.bytes(), addr: server}}}
		if resp, err := NewClient().send(request, conn, server); err == nil || resp != nil {
			t.Fatalf("send returned response=%#v error=%v", resp, err)
		}
	})
}
