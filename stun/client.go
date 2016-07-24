// Copyright 2013, Cong Ding. All rights reserved.
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
	"errors"
	"net"
	"strconv"
)

type Client struct {
	serverAddr    string
	softwareName  string
	conn          net.PacketConn
	serverUDPAddr *net.UDPAddr
}

// NewClient returns a client without network connection. The network
// connection will be build when calling Discover function.
func NewClient() *Client {
	c := new(Client)
	c.SetSoftwareName(DefaultSoftwareName)
	return c
}

// NewClientWithConnection returns a client which uses the given connection.
// Please note the connection should be acquired via net.Listen* method.
func NewClientWithConnection(conn net.PacketConn) *Client {
	c := new(Client)
	c.conn = conn
	c.SetSoftwareName(DefaultSoftwareName)
	return c
}

// SetServerHost allows user to set the STUN hostname and port.
func (c *Client) SetServerHost(host string, port int) error {
	ips, err := net.LookupHost(host)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return errors.New("Failed to get IP address of " + host + ".")
	}
	c.serverAddr = net.JoinHostPort(ips[0], strconv.Itoa(port))
	return nil
}

// SetServerAddr allows user to set the transport layer STUN server address.
func (c *Client) SetServerAddr(address string) {
	c.serverAddr = address
}

// SetSoftwareName allows user to set the name of the software, which is used
// for logging purpose (NOT used in the current implementation).
func (c *Client) SetSoftwareName(name string) {
	c.softwareName = name
}

// Reset cleans the network connections in the client. If error occurs when
// calling Discover, users can call Reset then retry Discover.
func (c *Client) Reset() {
	c.serverUDPAddr = nil
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// Discover contacts the STUN server and gets the response of NAT type, host
// for UDP punching.
func (c *Client) Discover() (NATType, *Host, error) {
	if c.serverAddr == "" {
		err := c.SetServerHost(DefaultServerHost, DefaultServerPort)
		if err != nil {
			return NAT_ERROR, nil, err
		}
	}
	if c.serverUDPAddr == nil {
		addr, err := net.ResolveUDPAddr("udp", c.serverAddr)
		if err != nil {
			return NAT_ERROR, nil, err
		}
		c.serverUDPAddr = addr
	}
	if c.conn == nil {
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return NAT_ERROR, nil, err
		}
		c.conn = conn
	}
	return discover(c.conn, c.serverUDPAddr, c.softwareName)
}
