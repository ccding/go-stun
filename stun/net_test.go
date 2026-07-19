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
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
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

type invalidReadLengthPacketConn struct {
	scriptedPacketConn
	length int
}

func (c *invalidReadLengthPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return c.length, &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}, nil
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
		mapped, err := newMappedAddressAttribute(mappedIP, mappedPort)
		if err != nil {
			return 0, nil, err
		}
		if err := response.addAttribute(*mapped); err != nil {
			return 0, nil, err
		}
	}
	if c.legacy {
		source, err := newMappedAddressAttribute(net.ParseIP("198.51.100.1"), 3478)
		if err != nil {
			return 0, nil, err
		}
		source.types = attributeSourceAddress
		if err := response.addAttribute(*source); err != nil {
			return 0, nil, err
		}
		changed, err := newMappedAddressAttribute(net.ParseIP("203.0.113.2"), 3479)
		if err != nil {
			return 0, nil, err
		}
		changed.types = attributeChangedAddress
		if err := response.addAttribute(*changed); err != nil {
			return 0, nil, err
		}
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

func newMappedAddressAttribute(ip net.IP, port uint16) (*attribute, error) {
	ip = ip.To4()
	value := []byte{0, attributeFamilyIPv4, byte(port >> 8), byte(port)}
	value = append(value, ip...)
	return newAttribute(attributeMappedAddress, value)
}

func mappedAddressAttribute(t testing.TB, ip net.IP, port uint16) *attribute {
	t.Helper()
	a, err := newMappedAddressAttribute(ip, port)
	return mustAttribute(t, a, err)
}

func xorMappedAddressAttribute(t testing.TB, types uint16, transactionID []byte, ip net.IP, port uint16) *attribute {
	t.Helper()
	ip = ip.To4()
	xorPort := port ^ binary.BigEndian.Uint16(transactionID[:2])
	value := []byte{0, attributeFamilyIPv4, byte(xorPort >> 8), byte(xorPort)}
	for i := range ip {
		value = append(value, ip[i]^transactionID[i])
	}
	a, err := newAttribute(types, value)
	return mustAttribute(t, a, err)
}

func errorCodeAttribute(t testing.TB, code int, reason string) *attribute {
	t.Helper()
	value := []byte{0, 0, byte(code / 100), byte(code % 100)}
	value = append(value, []byte(reason)...)
	a, err := newAttribute(attributeErrorCode, value)
	return mustAttribute(t, a, err)
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
	mustAddAttribute(t, valid, mappedAddressAttribute(t, net.ParseIP("192.0.2.10"), 54321))
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
	if request.types != typeBindingRequest || len(request.attributes) != 3 {
		t.Fatalf("unexpected request: type=%#x attributes=%d", request.types, len(request.attributes))
	}
	if got := request.attributes[0]; got.types != attributeSoftware || string(got.value) != "abc" {
		t.Fatalf("unexpected SOFTWARE attribute: %#v", got)
	}
	if got := request.attributes[1]; got.types != attributeChangeRequest || len(got.value) != 4 || got.value[3] != 0x06 {
		t.Fatalf("unexpected CHANGE-REQUEST attribute: %#v", got)
	}
	if got := request.attributes[2]; got.types != attributeFingerprint || len(got.value) != 4 {
		t.Fatalf("unexpected FINGERPRINT attribute: %#v", got)
	}
}

func TestSendBindingRequestValidatesSoftwareName(t *testing.T) {
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	tests := []struct {
		name     string
		software string
	}{
		{name: "invalid UTF-8", software: string([]byte{0xff})},
		{name: "128 characters", software: strings.Repeat("x", 128)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient()
			client.SetSoftwareName(tt.software)
			conn := &scriptedPacketConn{}
			if resp, err := client.sendBindingReq(conn, server, false, false); err == nil || resp != nil {
				t.Fatalf("sendBindingReq() = %#v, %v", resp, err)
			}
			if len(conn.writes) != 0 {
				t.Fatalf("invalid SOFTWARE value produced %d writes", len(conn.writes))
			}
		})
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

func TestSendReturnsNonTimeoutReadError(t *testing.T) {
	p, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("read failed")
	conn := &scriptedPacketConn{reads: []packetRead{{err: want}}}
	resp, err := NewClient().send(p, conn, &net.UDPAddr{})
	if resp != nil || !errors.Is(err, want) {
		t.Fatalf("send returned response=%#v error=%v, want %v", resp, err, want)
	}
}

func TestSendRejectsInvalidPacketConnReadLengths(t *testing.T) {
	request, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	request.types = typeBindingRequest
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}

	for _, tt := range []struct {
		name   string
		length int
	}{
		{name: "negative", length: -1},
		{name: "larger than receive buffer", length: maxPacketSize + 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn := &invalidReadLengthPacketConn{length: tt.length}
			resp, err := NewClient().send(request, conn, server)
			if resp != nil {
				t.Fatalf("send returned response %#v", resp)
			}
			if err == nil || err.Error() != "invalid packet length returned by connection" {
				t.Fatalf("send error = %v, want invalid packet length", err)
			}
			if len(conn.writes) != 1 {
				t.Fatalf("writes = %d, want 1", len(conn.writes))
			}
		})
	}
}

func TestRFC3489BindingInteroperability(t *testing.T) {
	client := NewClient()
	client.SetSoftwareName("not sent on the wire")
	client.SetRFC3489Compatibility(true)
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

func TestRFC3489CompatibilitySendsOnlyRequiredClassicAttributes(t *testing.T) {
	client := NewClient()
	client.SetSoftwareName(string([]byte{0xff})) // Omitted in compatibility mode.
	client.SetRFC3489Compatibility(true)
	conn := &bindingResponseConn{scriptedPacketConn: scriptedPacketConn{
		local: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
	}}
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	if _, err := client.sendBindingReq(conn, server, false, true); err != nil {
		t.Fatal(err)
	}
	request, err := newPacketFromBytes(conn.writes[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(request.attributes) != 1 || request.attributes[0].types != attributeChangeRequest ||
		len(request.attributes[0].value) != 4 || request.attributes[0].value[3] != 0x02 {
		t.Fatalf("RFC 3489-compatible request attributes = %#v", request.attributes)
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
			mustAddAttribute(t, response, errorCodeAttribute(t, code, "failure"))
			// An error response must never become a success, even if a broken
			// server also includes a mapped address.
			mustAddAttribute(t, response, mappedAddressAttribute(t, net.ParseIP("192.0.2.20"), 40000))
			server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
			conn := &scriptedPacketConn{reads: []packetRead{{data: response.bytes(), addr: server}}}
			resp, err := NewClient().send(request, conn, server)
			if resp != nil {
				t.Fatalf("error response returned success: %#v", resp)
			}
			var serverErr *ServerError
			if !errors.As(err, &serverErr) || serverErr.Code != code || serverErr.Reason != "failure" {
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
		{name: "short", attr: mustNewAttribute(t, attributeErrorCode, []byte{0, 0, 4})},
		{name: "class", attr: errorCodeAttribute(t, 200, "bad")},
		{name: "number", attr: mustNewAttribute(t, attributeErrorCode, []byte{0, 0, 4, 100})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, err := newPacket()
			if err != nil {
				t.Fatal(err)
			}
			response := bindingPacket(typeBindingErrorResponse, request.transID)
			if tt.attr != nil {
				mustAddAttribute(t, response, tt.attr)
			}
			server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
			conn := &scriptedPacketConn{reads: []packetRead{{data: response.bytes(), addr: server}}}
			resp, err := NewClient().send(request, conn, server)
			if err == nil || resp != nil {
				t.Fatalf("send returned response=%#v error=%v", resp, err)
			}
			var serverErr *ServerError
			if errors.As(err, &serverErr) {
				t.Fatalf("structurally invalid ERROR-CODE returned ServerError: %#v", serverErr)
			}
		})
	}
}

func TestSendSanitizesBindingErrorReasons(t *testing.T) {
	tests := []struct {
		name   string
		reason []byte
		want   string
	}{
		{name: "RFC 3489 space padding", reason: []byte("Unknown Attribute   "), want: "Unknown Attribute"},
		{name: "invalid UTF-8", reason: []byte{'b', 'a', 'd', 0xff, 'r', 'e', 'a', 's', 'o', 'n'}, want: "bad\uFFFDreason"},
		{name: "terminal controls", reason: []byte("\x1b[31mforged\nline\u009b"), want: "\uFFFD[31mforged\uFFFDline\uFFFD"},
		{name: "truncate by rune", reason: []byte(strings.Repeat("界", 130)), want: strings.Repeat("界", 127)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, err := newPacket()
			if err != nil {
				t.Fatal(err)
			}
			response := bindingPacket(typeBindingErrorResponse, request.transID)
			value := []byte{0, 0, 4, 20}
			value = append(value, tt.reason...)
			mustAddAttribute(t, response, mustNewAttribute(t, attributeErrorCode, value))
			server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
			conn := &scriptedPacketConn{reads: []packetRead{{data: response.bytes(), addr: server}}}

			resp, err := NewClient().send(request, conn, server)
			if resp != nil {
				t.Fatalf("error response returned success: %#v", resp)
			}
			var serverErr *ServerError
			if !errors.As(err, &serverErr) {
				t.Fatalf("error type = %T, want *ServerError: %v", err, err)
			}
			if serverErr.Code != 420 || serverErr.Reason != tt.want {
				t.Fatalf("ServerError = %#v, want code 420 reason %q", serverErr, tt.want)
			}
			for _, value := range []string{serverErr.Reason, serverErr.Error()} {
				for _, r := range value {
					if unicode.IsControl(r) {
						t.Fatalf("sanitized error contains control rune %U: %q", r, value)
					}
				}
			}
		})
	}
}

func TestSendRejectsMalformedXorMappedAddressInsteadOfFallingBack(t *testing.T) {
	for _, tt := range []struct {
		name  string
		types uint16
	}{
		{name: "standard", types: attributeXorMappedAddress},
		{name: "experimental", types: attributeXorMappedAddressExp},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request, err := newPacket()
			if err != nil {
				t.Fatal(err)
			}
			request.types = typeBindingRequest
			response := bindingPacket(typeBindingResponse, request.transID)
			mustAddAttribute(t, response, mustNewAttribute(t, tt.types, make([]byte, 7)))
			mustAddAttribute(t, response, mappedAddressAttribute(t, net.ParseIP("192.0.2.20"), 40000))
			server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
			conn := &scriptedPacketConn{reads: []packetRead{{data: response.bytes(), addr: server}}}

			resp, err := NewClient().send(request, conn, server)
			if err == nil || resp != nil {
				t.Fatalf("send returned response=%#v error=%v", resp, err)
			}
			if !strings.Contains(err.Error(), "invalid XOR-MAPPED-ADDRESS") {
				t.Fatalf("send error = %q", err)
			}
		})
	}
}

func TestNewResponseDoesNotFallbackFromMalformedXorMappedAddress(t *testing.T) {
	pkt := bindingPacket(typeBindingResponse, make([]byte, 16))
	mustAddAttribute(t, pkt, mustNewAttribute(t, attributeXorMappedAddress, make([]byte, 7)))
	mustAddAttribute(t, pkt, mappedAddressAttribute(t, net.ParseIP("192.0.2.20"), 40000))
	resp := newResponse(pkt, &scriptedPacketConn{})
	if resp.mappedAddr != nil {
		t.Fatalf("newResponse fell back to MAPPED-ADDRESS: %#v", resp.mappedAddr)
	}
}

func TestSendIgnoresMalformedExperimentalXorWhenStandardIsValid(t *testing.T) {
	for _, experimentalFirst := range []bool{false, true} {
		name := "standard first"
		if experimentalFirst {
			name = "experimental first"
		}
		t.Run(name, func(t *testing.T) {
			request, err := newPacket()
			if err != nil {
				t.Fatal(err)
			}
			request.types = typeBindingRequest
			response := bindingPacket(typeBindingResponse, request.transID)
			standard := xorMappedAddressAttribute(t, attributeXorMappedAddress, request.transID, net.ParseIP("192.0.2.20"), 40000)
			experimental := mustNewAttribute(t, attributeXorMappedAddressExp, make([]byte, 7))
			if experimentalFirst {
				mustAddAttribute(t, response, experimental)
				mustAddAttribute(t, response, standard)
			} else {
				mustAddAttribute(t, response, standard)
				mustAddAttribute(t, response, experimental)
			}
			server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
			conn := &scriptedPacketConn{reads: []packetRead{{data: response.bytes(), addr: server}}}

			resp, err := NewClient().send(request, conn, server)
			if err != nil || resp == nil || resp.mappedAddr == nil || resp.mappedAddr.String() != "192.0.2.20:40000" {
				t.Fatalf("send returned response=%#v error=%v", resp, err)
			}
		})
	}
}

func TestSendReturnsServerErrorDespiteMalformedXorMappedAddress(t *testing.T) {
	request, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	request.types = typeBindingRequest
	response := bindingPacket(typeBindingErrorResponse, request.transID)
	mustAddAttribute(t, response, mustNewAttribute(t, attributeXorMappedAddress, make([]byte, 7)))
	mustAddAttribute(t, response, errorCodeAttribute(t, 500, "Server Error"))
	server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
	conn := &scriptedPacketConn{reads: []packetRead{{data: response.bytes(), addr: server}}}

	resp, err := NewClient().send(request, conn, server)
	var serverErr *ServerError
	if resp != nil || !errors.As(err, &serverErr) || serverErr.Code != 500 || serverErr.Reason != "Server Error" {
		t.Fatalf("send returned response=%#v error=%#v", resp, err)
	}
}

func TestSendRejectsUnknownRequiredResponseAttribute(t *testing.T) {
	request, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	response := bindingPacket(typeBindingResponse, request.transID)
	mustAddAttribute(t, response, mappedAddressAttribute(t, net.ParseIP("192.0.2.20"), 40000))
	mustAddAttribute(t, response, mustNewAttribute(t, 0x1234, nil))
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
		mustAddAttribute(t, response, mappedAddressAttribute(t, net.ParseIP("192.0.2.20"), 40000))
		mustAddAttribute(t, response, mustNewAttribute(t, attributeMessageIntegrity, make([]byte, 20)))
		mustAddAttribute(t, response, mustNewAttribute(t, 0x1234, nil))
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
		mustAddAttribute(t, response, mustNewAttribute(t, attributeMessageIntegrity, make([]byte, 20)))
		mustAddAttribute(t, response, mappedAddressAttribute(t, net.ParseIP("192.0.2.20"), 40000))
		server := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}
		conn := &scriptedPacketConn{reads: []packetRead{{data: response.bytes(), addr: server}}}
		if resp, err := NewClient().send(request, conn, server); err == nil || resp != nil {
			t.Fatalf("send returned response=%#v error=%v", resp, err)
		}
	})
}
