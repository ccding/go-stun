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
	"net"
	"strings"
	"testing"
)

func TestUtilityCoverageClientConfiguration(t *testing.T) {
	conn := &scriptedPacketConn{}
	client := NewClientWithConnection(conn)
	if client.conn != net.PacketConn(conn) || client.softwareName != DefaultSoftwareName || client.logger == nil {
		t.Fatalf("NewClientWithConnection() = %#v", client)
	}
	if client.rfc3489Mode {
		t.Fatal("RFC 3489 compatibility must be opt-in to preserve the default wire format")
	}

	client.SetVerbose(true)
	client.SetVVerbose(true)
	client.SetServerHost("2001:db8::1", 3478)
	client.SetSoftwareName("custom client")
	client.SetRFC3489Compatibility(true)
	if !client.logger.debug || !client.logger.info {
		t.Fatal("verbose settings were not applied to the logger")
	}
	if client.serverAddr != "[2001:db8::1]:3478" {
		t.Fatalf("server address = %q", client.serverAddr)
	}
	if client.softwareName != "custom client" || !client.rfc3489Mode {
		t.Fatalf("client compatibility settings = %#v", client)
	}

	client.SetServerAddr("192.0.2.1:1234")
	if client.serverAddr != "192.0.2.1:1234" {
		t.Fatalf("server address = %q", client.serverAddr)
	}
}

func TestUtilityCoverageResolveLocalAddrDefaultsToNil(t *testing.T) {
	addr, err := NewClient().resolveLocalAddr()
	if err != nil || addr != nil {
		t.Fatalf("resolveLocalAddr() = %#v, %v", addr, err)
	}
}

func TestUtilityCoverageLoggerLevels(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger()
	logger.SetOutput(&output)

	logger.Debug("quiet debug")
	logger.Debugf("quiet %s", "debugf")
	logger.Debugln("quiet debugln")
	logger.Info("quiet info")
	logger.Infof("quiet %s", "infof")
	logger.Infoln("quiet infoln")
	if output.Len() != 0 {
		t.Fatalf("disabled logger wrote %q", output.String())
	}

	logger.SetDebug(true)
	logger.SetInfo(true)
	logger.Debug("loud-debug")
	logger.Debugf("loud-%s", "debugf")
	logger.Debugln("loud-debugln")
	logger.Info("loud-info")
	logger.Infof("loud-%s", "infof")
	logger.Infoln("loud-infoln")
	for _, want := range []string{
		"loud-debug", "loud-debugf", "loud-debugln",
		"loud-info", "loud-infof", "loud-infoln",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("logger output %q does not contain %q", output.String(), want)
		}
	}
}

func TestUtilityCoverageStringMethods(t *testing.T) {
	if got := NATType(999).String(); got != "Unknown" {
		t.Fatalf("NATType(999).String() = %q", got)
	}
	if got := BehaviorTypeEndpoint.String(); got != "EndpointIndependent" {
		t.Fatalf("BehaviorTypeEndpoint.String() = %q", got)
	}
	if got := BehaviorType(999).String(); got != "Unknown" {
		t.Fatalf("BehaviorType(999).String() = %q", got)
	}

	known := NATBehavior{MappingType: BehaviorTypeEndpoint, FilteringType: BehaviorTypeEndpoint}
	if got := known.NormalType(); got != "Full cone NAT" {
		t.Fatalf("known NormalType() = %q", got)
	}
	unknown := NATBehavior{MappingType: BehaviorTypeAddr, FilteringType: BehaviorTypeEndpoint}
	if got := unknown.NormalType(); got != "Undefined" {
		t.Fatalf("unknown NormalType() = %q", got)
	}

	if got := (*response)(nil).String(); got != "Nil" {
		t.Fatalf("nil response String() = %q", got)
	}
	if got := (&response{}).String(); !strings.Contains(got, "packet nil: true") {
		t.Fatalf("empty response String() = %q", got)
	}
}

func TestNormalTypeWithoutTranslation(t *testing.T) {
	tests := []struct {
		name      string
		filtering BehaviorType
		want      string
	}{
		{name: "unknown filtering", filtering: BehaviorTypeUnknown, want: "Open Internet (no NAT)"},
		{name: "endpoint-independent filtering", filtering: BehaviorTypeEndpoint, want: "Open Internet (no NAT)"},
		{name: "address-dependent filtering", filtering: BehaviorTypeAddr, want: "Symmetric UDP firewall"},
		{name: "address-and-port-dependent filtering", filtering: BehaviorTypeAddrAndPort, want: "Symmetric UDP firewall"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			behavior := NATBehavior{
				MappingType:   BehaviorTypeEndpoint,
				FilteringType: tt.filtering,
				NoTranslation: true,
			}
			if got := behavior.NormalType(); got != tt.want {
				t.Fatalf("NormalType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUtilityCoverageExportedWrapperInputErrors(t *testing.T) {
	if host, err := NewClient().Keepalive(); err == nil || host != nil {
		t.Fatalf("Keepalive() without a connection = %#v, %v", host, err)
	}

	client := NewClientWithConnection(&scriptedPacketConn{})
	client.SetServerAddr("bad:addr:3478")
	if nat, host, err := client.Discover(); err == nil || nat != NATError || host != nil {
		t.Fatalf("Discover() = %v, %#v, %v", nat, host, err)
	}
	if behavior, err := client.BehaviorTest(); err == nil || behavior != nil {
		t.Fatalf("BehaviorTest() = %#v, %v", behavior, err)
	}
	if host, err := client.Keepalive(); err == nil || host != nil {
		t.Fatalf("Keepalive() = %#v, %v", host, err)
	}
}

func TestUtilityCoverageKeepaliveWithInjectedConnection(t *testing.T) {
	conn := &bindingResponseConn{scriptedPacketConn: scriptedPacketConn{
		local: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
	}}
	client := NewClientWithConnection(conn)
	client.SetServerAddr("198.51.100.1:3478")
	host, err := client.Keepalive()
	if err != nil {
		t.Fatal(err)
	}
	if host == nil || host.String() != "192.0.2.20:40000" {
		t.Fatalf("Keepalive() mapped host = %#v", host)
	}
}

func TestUtilityCoverageDiscoverWithInjectedConnection(t *testing.T) {
	conn := &bindingResponseConn{scriptedPacketConn: scriptedPacketConn{
		local: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
	}}
	client := NewClientWithConnection(conn)
	client.SetServerAddr("198.51.100.1:3478")
	nat, host, err := client.Discover()
	if err != nil {
		t.Fatal(err)
	}
	if nat != NATUnknown || host == nil || host.String() != "192.0.2.20:40000" {
		t.Fatalf("Discover() = %v, %#v", nat, host)
	}
}

func TestUtilityCoverageBehaviorTestWithInjectedConnection(t *testing.T) {
	client := NewClientWithConnection(newBehaviorPacketConn())
	client.SetServerAddr("198.51.100.1:3478")
	behavior, err := client.BehaviorTest()
	if err != nil {
		t.Fatal(err)
	}
	if behavior == nil || behavior.MappingType != BehaviorTypeAddr || behavior.FilteringType != BehaviorTypeAddr {
		t.Fatalf("BehaviorTest() = %#v", behavior)
	}
}
