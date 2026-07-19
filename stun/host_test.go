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

import "testing"

func TestHostParsingAndFormatting(t *testing.T) {
	tests := []struct {
		input  string
		family uint16
		ip     string
		port   uint16
		text   string
	}{
		{"192.0.2.1:3478", attributeFamilyIPv4, "192.0.2.1", 3478, "192.0.2.1:3478"},
		{"[2001:db8::1]:65535", attributeFamilyIPV6, "2001:db8::1", 65535, "[2001:db8::1]:65535"},
	}
	for _, tt := range tests {
		h := newHostFromStr(tt.input)
		if h == nil || h.Family() != tt.family || h.IP() != tt.ip || h.Port() != tt.port || h.String() != tt.text || h.TransportAddr() != tt.text {
			t.Fatalf("newHostFromStr(%q) = %#v", tt.input, h)
		}
	}
}

func TestHostRejectsInvalidAddress(t *testing.T) {
	for _, input := range []string{"", "192.0.2.1", "bad:address:3478", "127.0.0.1:notaport"} {
		if got := newHostFromStr(input); got != nil {
			t.Fatalf("newHostFromStr(%q) = %#v, want nil", input, got)
		}
	}
}
