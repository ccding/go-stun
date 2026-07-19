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
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type addressedTCPConn struct {
	net.Conn
	local  net.Addr
	remote net.Addr
}

func (c *addressedTCPConn) LocalAddr() net.Addr  { return c.local }
func (c *addressedTCPConn) RemoteAddr() net.Addr { return c.remote }

func tcpPipe() (*addressedTCPConn, net.Conn) {
	client, server := net.Pipe()
	return &addressedTCPConn{
		Conn:   client,
		local:  &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
		remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478},
	}, server
}

func tcpSuccessResponse(request *packet, ip net.IP, port uint16) (*packet, error) {
	response := bindingPacket(typeBindingResponse, request.transID)
	xorPort := port ^ binary.BigEndian.Uint16(request.transID[:2])
	value := []byte{0, attributeFamilyIPv4, byte(xorPort >> 8), byte(xorPort)}
	ip = ip.To4()
	for i := range ip {
		value = append(value, ip[i]^request.transID[i])
	}
	mapped, err := newAttribute(attributeXorMappedAddress, value)
	if err != nil {
		return nil, err
	}
	if err := response.addAttribute(*mapped); err != nil {
		return nil, err
	}
	return response, nil
}

func TestDiscoverTCPReusesCallerConnection(t *testing.T) {
	clientConn, serverConn := tcpPipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	serverErr := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
			wire, err := readTCPFrame(serverConn)
			if err != nil {
				serverErr <- err
				return
			}
			request, err := newPacketFromBytes(wire)
			if err != nil {
				serverErr <- err
				return
			}
			if request.types != typeBindingRequest || len(request.attributes) != 2 ||
				request.attributes[0].types != attributeSoftware ||
				request.attributes[1].types != attributeFingerprint {
				serverErr <- errors.New("unexpected TCP Binding request")
				return
			}
			response, err := tcpSuccessResponse(request, net.ParseIP("192.0.2.20"), uint16(40000+i))
			if err != nil {
				serverErr <- err
				return
			}
			responseWire := response.bytes()
			if i == 0 {
				if err := writeAll(serverConn, responseWire[:7]); err != nil {
					serverErr <- err
					return
				}
				responseWire = responseWire[7:]
			}
			if err := writeAll(serverConn, responseWire); err != nil {
				serverErr <- err
				return
			}
		}
		serverErr <- nil
	}()

	client := NewClientWithTCPConnection(clientConn)
	if err := client.SetTCPTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		host, err := client.DiscoverTCP()
		if err != nil {
			t.Fatal(err)
		}
		if got, want := host.String(), net.JoinHostPort("192.0.2.20", strconv.Itoa(40000+i)); got != want {
			t.Fatalf("DiscoverTCP() = %s, want %s", got, want)
		}
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverTCPDialsAndClosesConnection(t *testing.T) {
	clientConn, serverConn := tcpPipe()
	defer func() { _ = serverConn.Close() }()

	serverErr := make(chan error, 1)
	go func() {
		wire, err := readTCPFrame(serverConn)
		if err != nil {
			serverErr <- err
			return
		}
		request, err := newPacketFromBytes(wire)
		if err != nil {
			serverErr <- err
			return
		}
		response, err := tcpSuccessResponse(request, net.ParseIP("203.0.113.10"), 45000)
		if err != nil {
			serverErr <- err
			return
		}
		if err := serverConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			serverErr <- err
			return
		}
		if err := writeAll(serverConn, response.bytes()); err != nil {
			serverErr <- err
			return
		}
		var one [1]byte
		if _, err := serverConn.Read(one[:]); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			serverErr <- errors.New("client did not close internally dialed TCP connection")
			return
		}
		serverErr <- nil
	}()

	client := NewClient()
	client.SetServerAddr("198.51.100.1:3478")
	client.SetLocalIP("127.0.0.1")
	client.tcpDial = func(dialer *net.Dialer, address string) (net.Conn, error) {
		if address != "198.51.100.1:3478" {
			t.Fatalf("dial address = %q", address)
		}
		local, ok := dialer.LocalAddr.(*net.TCPAddr)
		if !ok || !local.IP.Equal(net.ParseIP("127.0.0.1")) {
			t.Fatalf("dial local address = %#v", dialer.LocalAddr)
		}
		return clientConn, nil
	}
	if err := client.SetTCPTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	host, err := client.DiscoverTCP()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := host.String(), "203.0.113.10:45000"; got != want {
		t.Fatalf("DiscoverTCP() = %s, want %s", got, want)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestSendTCPDiscardsUnrelatedFrames(t *testing.T) {
	clientConn, serverConn := tcpPipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	serverErr := make(chan error, 1)
	go func() {
		wire, err := readTCPFrame(serverConn)
		if err != nil {
			serverErr <- err
			return
		}
		request, err := newPacketFromBytes(wire)
		if err != nil {
			serverErr <- err
			return
		}
		mismatch, err := tcpSuccessResponse(request, net.ParseIP("192.0.2.1"), 40000)
		if err != nil {
			serverErr <- err
			return
		}
		mismatch.transID[len(mismatch.transID)-1] ^= 1
		wrongType := bindingPacket(typeBindingRequest, request.transID)
		valid, err := tcpSuccessResponse(request, net.ParseIP("192.0.2.2"), 40001)
		if err != nil {
			serverErr <- err
			return
		}
		frames := append(mismatch.bytes(), wrongType.bytes()...)
		frames = append(frames, valid.bytes()...)
		serverErr <- writeAll(serverConn, frames)
	}()

	client := NewClientWithTCPConnection(clientConn)
	if err := client.SetTCPTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	host, err := client.DiscoverTCP()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := host.String(), "192.0.2.2:40001"; got != want {
		t.Fatalf("DiscoverTCP() = %s, want %s", got, want)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

type timeoutTCPConn struct {
	writes    int
	deadlines []time.Time
}

func (c *timeoutTCPConn) Read([]byte) (int, error)    { return 0, timeoutError{} }
func (c *timeoutTCPConn) Write(p []byte) (int, error) { c.writes++; return len(p), nil }
func (c *timeoutTCPConn) Close() error                { return nil }
func (c *timeoutTCPConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *timeoutTCPConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (c *timeoutTCPConn) SetDeadline(t time.Time) error {
	c.deadlines = append(c.deadlines, t)
	return nil
}
func (c *timeoutTCPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *timeoutTCPConn) SetWriteDeadline(time.Time) error { return nil }

func TestSendTCPUsesOneRequestAndTransactionTimeout(t *testing.T) {
	pkt, err := NewClient().newBindingRequest(false, false)
	if err != nil {
		t.Fatal(err)
	}
	conn := &timeoutTCPConn{}
	client := NewClient()
	if err := client.SetTCPTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	resp, err := client.sendTCP(pkt, conn)
	if resp != nil || err == nil || !strings.Contains(err.Error(), "TCP STUN transaction timed out") {
		t.Fatalf("sendTCP() = %#v, %v", resp, err)
	}
	if conn.writes != 1 {
		t.Fatalf("TCP writes = %d, want 1", conn.writes)
	}
	if len(conn.deadlines) != 2 || conn.deadlines[0].IsZero() || !conn.deadlines[1].IsZero() {
		t.Fatalf("deadlines = %#v", conn.deadlines)
	}
}

func TestTCPBindingReturnsServerError(t *testing.T) {
	clientConn, serverConn := tcpPipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	errorAttr := errorCodeAttribute(t, 420, "Unknown Attribute")
	serverResult := make(chan error, 1)
	go func() {
		wire, err := readTCPFrame(serverConn)
		if err != nil {
			serverResult <- err
			return
		}
		request, err := newPacketFromBytes(wire)
		if err != nil {
			serverResult <- err
			return
		}
		response := bindingPacket(typeBindingErrorResponse, request.transID)
		if err := response.addAttribute(*errorAttr); err != nil {
			serverResult <- err
			return
		}
		serverResult <- writeAll(serverConn, response.bytes())
	}()

	client := NewClientWithTCPConnection(clientConn)
	if err := client.SetTCPTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	host, err := client.DiscoverTCP()
	var serverErr *ServerError
	if host != nil || !errors.As(err, &serverErr) || serverErr.Code != 420 {
		t.Fatalf("DiscoverTCP() = %#v, %#v", host, err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestTCPConfigurationValidation(t *testing.T) {
	client := NewClient()
	if client.tcpTransactionTimeout() != DefaultTCPTimeout {
		t.Fatalf("default timeout = %v", client.tcpTransactionTimeout())
	}
	for _, timeout := range []time.Duration{0, -time.Second} {
		if err := client.SetTCPTimeout(timeout); err == nil {
			t.Fatalf("SetTCPTimeout(%v) succeeded", timeout)
		}
	}
	if host, err := NewClientWithTCPConnection(nil).DiscoverTCP(); host != nil || err == nil || err.Error() != "TCP connection is nil" {
		t.Fatalf("nil TCP connection returned %#v, %v", host, err)
	}
	packetClient := NewClientWithConnection(&scriptedPacketConn{})
	if host, err := packetClient.DiscoverTCP(); host != nil || err == nil {
		t.Fatalf("packet connection returned %#v, %v", host, err)
	}
	client.SetServerAddr(":")
	if host, err := client.DiscoverTCP(); host != nil || err == nil {
		t.Fatalf("invalid server returned %#v, %v", host, err)
	}
}

type chunkWriter struct {
	max       int
	writes    int
	zeroWrite bool
	buf       bytes.Buffer
	mu        sync.Mutex
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	if w.zeroWrite {
		return 0, nil
	}
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.buf.Write(p)
}

func TestTCPFrameHelpers(t *testing.T) {
	frame := make([]byte, 24)
	binary.BigEndian.PutUint16(frame[2:4], 4)
	copy(frame[20:], []byte("body"))
	got, err := readTCPFrame(bytes.NewReader(frame))
	if err != nil || !bytes.Equal(got, frame) {
		t.Fatalf("readTCPFrame() = %x, %v", got, err)
	}
	if _, err := readTCPFrame(bytes.NewReader(frame[:22])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated frame error = %v", err)
	}

	w := &chunkWriter{max: 2}
	if err := writeAll(w, []byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	if got := w.buf.String(); got != "abcdef" || w.writes != 3 {
		t.Fatalf("writeAll result = %q in %d writes", got, w.writes)
	}
	if err := writeAll(&chunkWriter{max: 1, zeroWrite: true}, []byte("x")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero write error = %v", err)
	}
}
