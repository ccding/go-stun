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
	"testing"
)

func TestAlign(t *testing.T) {
	tests := []struct {
		input int
		want  int
	}{
		{0, 0},
		{1, 4},
		{4, 4},
		{5, 8},
		{6, 8},
		{7, 8},
		{8, 8},
		{65528, 65528},
		{65529, 65532},
		{65531, 65532},
		{65532, 65532},
		{65533, 65536},
		{65534, 65536},
		{65535, 65536},
	}
	for _, tt := range tests {
		if got := align(tt.input); got != tt.want {
			t.Errorf("align(%d) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestIsLocalAddress(t *testing.T) {
	originalInterfaceAddrs := interfaceAddrs
	t.Cleanup(func() { interfaceAddrs = originalInterfaceAddrs })

	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			textAddr("not-a-cidr"),
			textAddr("192.0.2.10/24"),
			textAddr("2001:db8::10/64"),
		}, nil
	}

	tests := []struct {
		name        string
		local       string
		localRemote string
		want        bool
	}{
		{"wildcard IPv4", ":1234", "192.0.2.10:1234", true},
		{"wildcard IPv6", "[::]:1234", "[2001:db8::10]:1234", true},
		{"wildcard address mismatch", ":1234", "198.51.100.10:1234", false},
		{"specified address match", "192.0.2.20:1234", "192.0.2.20:1234", true},
		{"specified address mismatch", "192.0.2.20:1234", "192.0.2.21:1234", false},
		{"port mismatch", "192.0.2.20:1234", "192.0.2.20:8888", false},
		{"invalid local address", "[2001:db8::1", "[2001:db8::1]:1234", false},
		{"invalid remote address", "192.0.2.20:1234", "missing-port", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLocalAddress(tt.local, tt.localRemote); got != tt.want {
				t.Fatalf("isLocalAddress(%q, %q) = %v, want %v", tt.local, tt.localRemote, got, tt.want)
			}
		})
	}

	interfaceAddrs = func() ([]net.Addr, error) {
		return nil, errors.New("interface lookup failed")
	}
	if isLocalAddress(":1234", "192.0.2.10:1234") {
		t.Fatal("interface lookup failure was treated as a local address match")
	}
}

type textAddr string

func (a textAddr) Network() string { return "test" }
func (a textAddr) String() string  { return string(a) }
