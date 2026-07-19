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
	"time"
)

// Client performs STUN Binding transactions and UDP NAT behavior discovery.
type Client struct {
	serverAddr   string
	localIP      string
	localPort    int
	softwareName string
	rfc3489Mode  bool
	conn         net.PacketConn
	tcpConn      net.Conn
	tcpConnSet   bool
	tcpTimeout   time.Duration
	tcpDial      func(*net.Dialer, string) (net.Conn, error)
	logger       *Logger
}

// NewClient returns a client that creates its network connection when a
// discovery method is called.
func NewClient() *Client {
	c := new(Client)
	c.SetSoftwareName(DefaultSoftwareName)
	c.logger = NewLogger()
	return c
}

// NewClientWithConnection returns a client which uses the given connection.
// Please note the connection should be acquired via net.Listen* method.
func NewClientWithConnection(conn net.PacketConn) *Client {
	c := new(Client)
	c.conn = conn
	c.SetSoftwareName(DefaultSoftwareName)
	c.logger = NewLogger()
	return c
}

// ensureLogger makes the Client zero value safe to use. Constructors install
// the same logger eagerly, while a directly allocated Client gets it on first
// use.
func (c *Client) ensureLogger() *Logger {
	if c.logger == nil {
		c.logger = NewLogger()
	}
	return c.logger
}

// SetVerbose sets the client to be in the verbose mode, which prints
// information in the discover process.
func (c *Client) SetVerbose(v bool) {
	c.ensureLogger().SetDebug(v)
}

// SetVVerbose sets the client to be in the double verbose mode, which prints
// information and packet in the discover process.
func (c *Client) SetVVerbose(v bool) {
	c.ensureLogger().SetInfo(v)
}

// SetServerHost allows user to set the STUN hostname and port.
func (c *Client) SetServerHost(host string, port int) {
	c.serverAddr = net.JoinHostPort(host, strconv.Itoa(port))
}

// SetServerAddr allows user to set the transport layer STUN server address.
func (c *Client) SetServerAddr(address string) {
	c.serverAddr = address
}

// SetLocalPort allows user to set the local port to send request.
func (c *Client) SetLocalPort(port int) {
	c.localPort = port
}

// SetLocalIP allows user to set the local ip address to send request.
func (c *Client) SetLocalIP(ip string) {
	c.localIP = ip
}

// SetSoftwareName sets the value sent in the SOFTWARE attribute. The value
// must be valid UTF-8 and shorter than 128 characters. It is omitted when
// RFC 3489 compatibility mode is enabled.
func (c *Client) SetSoftwareName(name string) {
	c.softwareName = name
}

// SetRFC3489Compatibility controls interoperability with RFC 3489-only
// servers. When enabled, Binding requests omit the optional SOFTWARE and
// FINGERPRINT attributes as recommended by RFC 5389 section 12.1. Requests
// used for classic NAT discovery still include CHANGE-REQUEST when needed.
// Compatibility mode is disabled by default to preserve the wire behavior of
// earlier go-stun releases.
func (c *Client) SetRFC3489Compatibility(enabled bool) {
	c.rfc3489Mode = enabled
}

// Discover contacts the STUN server and returns the NAT type and mapped host.
// If Binding succeeds but the server cannot classify NAT behavior, Discover
// returns NATUnknown together with the mapped host and a nil error.
func (c *Client) Discover() (NATType, *Host, error) {
	c.ensureLogger()
	if c.serverAddr == "" {
		c.SetServerAddr(DefaultServerAddr)
	}
	serverUDPAddr, err := net.ResolveUDPAddr("udp", c.serverAddr)
	if err != nil {
		return NATError, nil, err
	}
	// Use the connection passed to the client if it is not nil, otherwise
	// create a connection and close it at the end.
	conn := c.conn
	if conn == nil {
		laddr, err := c.resolveLocalAddr()
		if err != nil {
			return NATError, nil, err
		}
		if laddr != nil {
			c.logger.Debugln("Local listen address: " + laddr.String())
		}

		conn, err = net.ListenUDP("udp", laddr)
		if err != nil {
			return NATError, nil, err
		}
		defer func() { _ = conn.Close() }()
	}
	return c.discover(conn, serverUDPAddr)
}

// BehaviorTest performs RFC 5780 mapping and filtering behavior tests. If a
// later probe fails, it returns the behavior fields already determined along
// with the error. Servers without a usable alternate address return
// ErrBehaviorDiscoveryUnsupported.
func (c *Client) BehaviorTest() (*NATBehavior, error) {
	c.ensureLogger()
	if c.serverAddr == "" {
		c.SetServerAddr(DefaultServerAddr)
	}
	serverUDPAddr, err := net.ResolveUDPAddr("udp", c.serverAddr)
	if err != nil {
		return nil, err
	}
	// Use the connection passed to the client if it is not nil, otherwise
	// create a connection and close it at the end.
	conn := c.conn
	if conn == nil {
		laddr, err := c.resolveLocalAddr()
		if err != nil {
			return nil, err
		}
		if laddr != nil {
			c.logger.Debugln("Local listen address: " + laddr.String())
		}
		conn, err = net.ListenUDP("udp", laddr)
		if err != nil {
			return nil, err
		}
		defer func() { _ = conn.Close() }()
	}
	return c.behaviorTest(conn, serverUDPAddr)
}

// Keepalive sends and receives a bind request, which ensures the mapping stays open
// Only applicable when client was created with a connection.
func (c *Client) Keepalive() (*Host, error) {
	c.ensureLogger()
	if c.conn == nil {
		return nil, errors.New("no connection available")
	}
	if c.serverAddr == "" {
		c.SetServerAddr(DefaultServerAddr)
	}
	serverUDPAddr, err := net.ResolveUDPAddr("udp", c.serverAddr)
	if err != nil {
		return nil, err
	}

	resp, err := c.test1(c.conn, serverUDPAddr)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.packet == nil {
		return nil, errors.New("failed to contact")
	}
	return resp.mappedAddr, nil
}

func (c *Client) resolveLocalAddr() (*net.UDPAddr, error) {
	if c.localPort == 0 && c.localIP == "" {
		return nil, nil
	}
	address := net.JoinHostPort(c.localIP, strconv.Itoa(c.localPort))
	return net.ResolveUDPAddr("udp", address)
}
