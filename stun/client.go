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
// author: Cong Ding <dinggnu@gmail.com>

package stun

import (
	"errors"
	"net"
	"strconv"
)

var (
	serverAddr   string
	softwareName string
)

func init() {
	SetSoftwareName(DefaultSoftwareName)
}

// SetServerHost allows user to set the STUN hostname and port
func SetServerHost(host string, port int) error {
	ips, err := net.LookupHost(host)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return errors.New("Failed to get IP address of " + host)
	}
	serverAddr = net.JoinHostPort(ips[0], strconv.Itoa(port))
	return nil
}

// SetServerAddr allows user to set the transport layer STUN server address
func SetServerAddr(address string) {
	serverAddr = address
}

// SetSoftwareName allows user to set the name of her software
func SetSoftwareName(name string) {
	softwareName = name
}

// Discover contacts the STUN server and gets the response of NAT type, host
// for UDP punching
func Discover() (int, *Host, error) {
	if serverAddr == "" {
		err := SetServerHost(DefaultServerHost, DefaultServerPort)
		if err != nil {
			return NAT_ERROR, nil, err
		}
	}
	return discover()
}
