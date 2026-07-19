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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// DefaultTCPTimeout is the RFC 8489 default time to wait for a STUN response
// after sending a request over TCP. TCP provides reliability, so requests are
// not retransmitted at the STUN layer. When the client opens the connection,
// the same duration independently bounds connection establishment.
const DefaultTCPTimeout = 39500 * time.Millisecond

// NewClientWithTCPConnection returns a client that performs TCP Binding
// transactions over conn. The caller owns conn and remains responsible for
// closing it. Keeping the connection open also keeps its TCP NAT mapping
// available for subsequent use.
func NewClientWithTCPConnection(conn net.Conn) *Client {
	c := NewClient()
	c.tcpConn = conn
	c.tcpConnSet = true
	return c
}

// SetTCPTimeout sets how long a TCP Binding transaction waits for a response.
// When DiscoverTCP opens the connection, the same duration independently
// bounds connection establishment. The RFC 8489 default response timeout is
// DefaultTCPTimeout.
func (c *Client) SetTCPTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return errors.New("TCP timeout must be positive")
	}
	c.tcpTimeout = timeout
	return nil
}

// DiscoverTCP performs a basic STUN Binding transaction over TCP and returns
// the reflexive TCP transport address reported by the server.
//
// When the client was created with NewClientWithTCPConnection, DiscoverTCP
// reuses that caller-owned connection and leaves it open. Otherwise it opens a
// connection using the configured server and local address, then closes it
// after the transaction. A TCP mapping remains useful only while its
// connection stays open, so callers that need the mapping after this method
// returns should provide their own connection.
func (c *Client) DiscoverTCP() (*Host, error) {
	c.ensureLogger()
	if c.tcpConnSet {
		return c.discoverTCP(c.tcpConn)
	}
	if c.conn != nil {
		return nil, errors.New("TCP discovery cannot use a packet connection")
	}
	if c.serverAddr == "" {
		c.SetServerAddr(DefaultServerAddr)
	}
	serverAddr, err := net.ResolveTCPAddr("tcp", c.serverAddr)
	if err != nil {
		return nil, err
	}
	localAddr, err := c.resolveLocalTCPAddr()
	if err != nil {
		return nil, err
	}
	if localAddr != nil {
		c.logger.Debugln("Local TCP address:", localAddr)
	}
	dialer := net.Dialer{
		LocalAddr: localAddr,
		Timeout:   c.tcpTransactionTimeout(),
	}
	var conn net.Conn
	if c.tcpDial != nil {
		conn, err = c.tcpDial(&dialer, serverAddr.String())
	} else {
		conn, err = dialer.Dial("tcp", serverAddr.String())
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return c.discoverTCP(conn)
}

func (c *Client) discoverTCP(conn net.Conn) (*Host, error) {
	if conn == nil {
		return nil, errors.New("TCP connection is nil")
	}
	pkt, err := c.newBindingRequest(false, false)
	if err != nil {
		return nil, err
	}
	resp, err := c.sendTCP(pkt, conn)
	if err != nil {
		return nil, err
	}
	return resp.mappedAddr, nil
}

func (c *Client) sendTCP(pkt *packet, conn net.Conn) (*response, error) {
	deadline := time.Now().Add(c.tcpTransactionTimeout())
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	wire := pkt.bytes()
	c.logger.Info("\n" + hex.Dump(wire))
	if err := writeAll(conn, wire); err != nil {
		return nil, err
	}

	for {
		frame, err := readTCPFrame(conn)
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				return nil, fmt.Errorf("TCP STUN transaction timed out: %w", err)
			}
			return nil, err
		}
		p, err := newPacketFromBytes(frame)
		if err != nil {
			c.logger.Debugf("Discard TCP response: %v", err)
			continue
		}
		if !bytes.Equal(pkt.transID, p.transID) {
			c.logger.Debugln("Discard TCP response: transaction ID mismatch")
			continue
		}
		if p.types != typeBindingResponse && p.types != typeBindingErrorResponse {
			c.logger.Debugf("Discard TCP response: unexpected message type %#06x", p.types)
			continue
		}
		c.logger.Info("\n" + hex.Dump(frame))
		return processBindingResponse(p, conn, conn.RemoteAddr())
	}
}

func readTCPFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, 20)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	body := make([]byte, int(binary.BigEndian.Uint16(header[2:4])))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return errors.New("invalid write length")
		}
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (c *Client) tcpTransactionTimeout() time.Duration {
	if c.tcpTimeout > 0 {
		return c.tcpTimeout
	}
	return DefaultTCPTimeout
}

func (c *Client) resolveLocalTCPAddr() (*net.TCPAddr, error) {
	if c.localPort == 0 && c.localIP == "" {
		return nil, nil
	}
	address := net.JoinHostPort(c.localIP, strconv.Itoa(c.localPort))
	return net.ResolveTCPAddr("tcp", address)
}
