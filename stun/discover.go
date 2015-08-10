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
)

// Padding the length of the byte slice to multiple of 4.
func padding(bytes []byte) []byte {
	length := uint16(len(bytes))
	return append(bytes, make([]byte, align(length)-length)...)
}

// Align the uint16 number to the smallest multiple of 4, which is larger than
// or equal to the uint16 number.
func align(n uint16) uint16 {
	return (n + 3) & 0xfffc
}

func sendBindingReq(destAddr string) (*packet, string, error) {
	conn, err := net.Dial("udp", destAddr)
	if err != nil {
		return nil, "", err
	}
	// Construct packet.
	packet := newPacket()
	packet.types = type_BINDING_REQUEST
	attribute := newSoftwareAttribute(packet, DefaultSoftwareName)
	packet.addAttribute(*attribute)
	attribute = newFingerprintAttribute(packet)
	packet.addAttribute(*attribute)
	// Send packet.
	localAddr := conn.LocalAddr().String()
	packet, err = packet.send(conn)
	if err != nil {
		return nil, "", err
	}
	err = conn.Close()
	return packet, localAddr, err
}

func sendChangeReq(changeIP bool, changePort bool) (*packet, error) {
	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		return nil, err
	}
	// Construct packet.
	packet := newPacket()
	packet.types = type_BINDING_REQUEST
	attribute := newSoftwareAttribute(packet, DefaultSoftwareName)
	packet.addAttribute(*attribute)
	attribute = newChangeReqAttribute(packet, changeIP, changePort)
	packet.addAttribute(*attribute)
	attribute = newFingerprintAttribute(packet)
	packet.addAttribute(*attribute)
	// Send packet.
	packet, err = packet.send(conn)
	if err != nil {
		return nil, err
	}
	err = conn.Close()
	return packet, err
}

func test1(destAddr string) (*packet, string, bool, *Host, error) {
	packet, localAddr, err := sendBindingReq(destAddr)
	if err != nil {
		return nil, "", false, nil, err
	}
	if packet == nil {
		return nil, "", false, nil, nil
	}

	// RFC 3489 doesn't require the server return XOR mapped address.
	hostMappedAddr := packet.xorMappedAddr()
	if hostMappedAddr == nil {
		hostMappedAddr = packet.mappedAddr()
		if hostMappedAddr == nil {
			return nil, "", false, nil, errors.New("No mapped address.")
		}
	}

	hostChangedAddr := packet.changedAddr()
	if hostChangedAddr == nil {
		return nil, "", false, nil, errors.New("No changed address.")
	}
	changeAddr := hostChangedAddr.TransportAddr()
	identical := localAddr == hostMappedAddr.TransportAddr()
	return packet, changeAddr, identical, hostMappedAddr, nil
}

func test2() (*packet, error) {
	return sendChangeReq(true, true)
}

func test3() (*packet, error) {
	return sendChangeReq(false, true)
}

// follow rfc 3489 and 5389
func discover() (NATType, *Host, error) {
	packet, changeAddr, identical, host, err := test1(serverAddr)
	if err != nil {
		return NAT_ERROR, nil, err
	}
	if packet == nil {
		return NAT_BLOCKED, nil, err
	}
	if identical {
		packet, err = test2()
		if err != nil {
			return NAT_ERROR, host, err
		}
		if packet != nil {
			return NAT_NONE, host, nil
		}
		return NAT_SYMETRIC_UDP_FIREWALL, host, nil
	} else {
		packet, err = test2()
		if err != nil {
			return NAT_ERROR, host, err
		}
		if packet != nil {
			return NAT_FULL, host, nil
		} else {
			packet, _, identical, _, err := test1(changeAddr)
			if err != nil {
				return NAT_ERROR, host, err
			}
			if packet == nil {
				// It should be NAT_BLOCKED, but will be
				// detected in the first step. So this will
				// never happen.
				return NAT_UNKNOWN, host, nil
			}
			if identical {
				packet, err = test3()
				if err != nil {
					return NAT_ERROR, host, err
				}
				if packet == nil {
					return NAT_PORT_RESTRICTED, host, nil
				} else {
					return NAT_RESTRICTED, host, nil
				}
			} else {
				return NAT_SYMETRIC, host, nil
			}
		}
	}
}
