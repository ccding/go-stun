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

package main

import (
	"fmt"
	"github.com/ccding/go-stun/stun"
)

func main() {
	nat, host, err := stun.Discover()
	if err != nil {
		fmt.Println(err)
	}

	switch nat {
	case stun.NAT_ERROR:
		fmt.Println("Test failed")
	case stun.NAT_UNKNOWN:
		fmt.Println("Unexpected response from the STUN server")
	case stun.NAT_BLOCKED:
		fmt.Println("UDP is blocked")
	case stun.NAT_FULL:
		fmt.Println("Full cone NAT")
	case stun.NAT_SYMETRIC:
		fmt.Println("Symetric NAT")
	case stun.NAT_RESTRICTED:
		fmt.Println("Restricted NAT")
	case stun.NAT_PORT_RESTRICTED:
		fmt.Println("Port restricted NAT")
	case stun.NAT_NONE:
		fmt.Println("Not behind a NAT")
	case stun.NAT_SYMETRIC_UDP_FIREWALL:
		fmt.Println("Symetric UDP firewall")
	}

	if host != nil {
		fmt.Println(host.Family())
		fmt.Println(host.Ip())
		fmt.Println(host.Port())
	}
}
