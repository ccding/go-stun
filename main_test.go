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

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ccding/go-stun/stun"
)

func TestWriteBehaviorTestResultTreatsUnsupportedServerAsSuccess(t *testing.T) {
	var output bytes.Buffer
	if err := writeBehaviorTestResult(&output, &stun.NATBehaviorResult{}, stun.ErrBehaviorDiscoveryUnsupported); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(output.String()); got != stun.ErrBehaviorDiscoveryUnsupported.Error() {
		t.Fatalf("output = %q", got)
	}
}

func TestRunDiscoveryRejectsUnknownTransport(t *testing.T) {
	nat, host, hasNATType, err := runDiscovery(stun.NewClient(), "sctp")
	if nat != stun.NATError || host != nil || hasNATType || err == nil {
		t.Fatalf("runDiscovery() = %v, %#v, %v, %v", nat, host, hasNATType, err)
	}
}

type discoveryClientStub struct {
	udpCalls int
	tcpCalls int
	udpErr   error
	tcpErr   error
}

func (c *discoveryClientStub) Discover() (stun.NATType, *stun.Host, error) {
	c.udpCalls++
	return stun.NATFull, nil, c.udpErr
}

func (c *discoveryClientStub) DiscoverTCP() (*stun.Host, error) {
	c.tcpCalls++
	return nil, c.tcpErr
}

func TestRunDiscoveryDispatchesUDP(t *testing.T) {
	wantErr := errors.New("UDP failed")
	client := &discoveryClientStub{udpErr: wantErr}
	nat, host, hasNATType, err := runDiscovery(client, "udp")
	if nat != stun.NATFull || host != nil || !hasNATType || !errors.Is(err, wantErr) {
		t.Fatalf("runDiscovery() = %v, %#v, %v, %v", nat, host, hasNATType, err)
	}
	if client.udpCalls != 1 || client.tcpCalls != 0 {
		t.Fatalf("calls = UDP %d, TCP %d", client.udpCalls, client.tcpCalls)
	}
}

func TestRunDiscoveryDispatchesTCP(t *testing.T) {
	wantErr := errors.New("TCP failed")
	client := &discoveryClientStub{tcpErr: wantErr}
	nat, host, hasNATType, err := runDiscovery(client, "tcp")
	if nat != stun.NATUnknown || host != nil || hasNATType || !errors.Is(err, wantErr) {
		t.Fatalf("runDiscovery() = %v, %#v, %v, %v", nat, host, hasNATType, err)
	}
	if client.udpCalls != 0 || client.tcpCalls != 1 {
		t.Fatalf("calls = UDP %d, TCP %d", client.udpCalls, client.tcpCalls)
	}
}

func TestWriteBehaviorTestResultPreservesUnsupportedNoTranslation(t *testing.T) {
	var output bytes.Buffer
	behavior := &stun.NATBehaviorResult{NATBehavior: stun.NATBehavior{NoTranslation: true}}
	if err := writeBehaviorTestResult(&output, behavior, stun.ErrBehaviorDiscoveryUnsupported); err != nil {
		t.Fatal(err)
	}
	want := "   Normal NAT Type: Open Internet (no NAT)\n" +
		stun.ErrBehaviorDiscoveryUnsupported.Error() + "\n"
	if got := output.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestWriteBehaviorTestResultReportsOpenInternet(t *testing.T) {
	var output bytes.Buffer
	behavior := &stun.NATBehaviorResult{NATBehavior: stun.NATBehavior{
		MappingType:   stun.BehaviorTypeEndpoint,
		FilteringType: stun.BehaviorTypeEndpoint,
		NoTranslation: true,
	}}
	if err := writeBehaviorTestResult(&output, behavior, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Open Internet (no NAT)") {
		t.Fatalf("output = %q", output.String())
	}
}

func TestWriteBehaviorTestResultReturnsOperationalErrors(t *testing.T) {
	want := errors.New("network failed")
	if got := writeBehaviorTestResult(&bytes.Buffer{}, nil, want); !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}

func TestWriteBehaviorTestResultPreservesPartialBehavior(t *testing.T) {
	var output bytes.Buffer
	want := errors.New("alternate server timed out")
	behavior := &stun.NATBehaviorResult{NATBehavior: stun.NATBehavior{FilteringType: stun.BehaviorTypeAddr}}
	if got := writeBehaviorTestResult(&output, behavior, want); !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
	if got := output.String(); !strings.Contains(got, "Filtering Behavior: AddressDependent") ||
		strings.Contains(got, "Mapping Behavior:") {
		t.Fatalf("partial output = %q", got)
	}
}

func TestWriteBehaviorTestResultClassifiesCompletePartialBehavior(t *testing.T) {
	var output bytes.Buffer
	wantErr := errors.New("later behavior probe failed")
	behavior := &stun.NATBehaviorResult{NATBehavior: stun.NATBehavior{
		MappingType:   stun.BehaviorTypeEndpoint,
		FilteringType: stun.BehaviorTypeAddrAndPort,
	}}
	if got := writeBehaviorTestResult(&output, behavior, wantErr); !errors.Is(got, wantErr) {
		t.Fatalf("error = %v, want %v", got, wantErr)
	}
	wantOutput := "  Mapping Behavior: EndpointIndependent\n" +
		"Filtering Behavior: AddressAndPortDependent\n" +
		"   Normal NAT Type: Port Restricted cone NAT\n"
	if got := output.String(); got != wantOutput {
		t.Fatalf("output = %q, want %q", got, wantOutput)
	}
}

type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestWriteBehaviorTestResultReturnsPartialWriteError(t *testing.T) {
	want := errors.New("write failed")
	behavior := &stun.NATBehaviorResult{NATBehavior: stun.NATBehavior{NoTranslation: true}}
	got := writeBehaviorTestResult(failingWriter{err: want}, behavior, stun.ErrBehaviorDiscoveryUnsupported)
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}

func TestWritePartialBehaviorTestResultReportsKnownMapping(t *testing.T) {
	var output bytes.Buffer
	behavior := &stun.NATBehavior{MappingType: stun.BehaviorTypeEndpoint}
	if err := writePartialBehaviorTestResult(&output, behavior); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "  Mapping Behavior: EndpointIndependent\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestWritePartialBehaviorTestResultReportsCompleteClassification(t *testing.T) {
	var output bytes.Buffer
	behavior := &stun.NATBehavior{
		MappingType:   stun.BehaviorTypeEndpoint,
		FilteringType: stun.BehaviorTypeAddr,
	}
	if err := writePartialBehaviorTestResult(&output, behavior); err != nil {
		t.Fatal(err)
	}
	want := "  Mapping Behavior: EndpointIndependent\n" +
		"Filtering Behavior: AddressDependent\n" +
		"   Normal NAT Type: Restricted cone NAT\n"
	if got := output.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestWritePartialBehaviorTestResultReportsUndefinedCompleteClassification(t *testing.T) {
	var output bytes.Buffer
	behavior := &stun.NATBehavior{
		MappingType:   stun.BehaviorTypeAddr,
		FilteringType: stun.BehaviorTypeEndpoint,
	}
	if err := writePartialBehaviorTestResult(&output, behavior); err != nil {
		t.Fatal(err)
	}
	want := "  Mapping Behavior: AddressDependent\n" +
		"Filtering Behavior: EndpointIndependent\n" +
		"   Normal NAT Type: Undefined\n"
	if got := output.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestWritePartialBehaviorTestResultSuppressesIncompleteClassification(t *testing.T) {
	tests := []struct {
		name     string
		behavior *stun.NATBehavior
		want     string
	}{
		{
			name:     "neither behavior known",
			behavior: &stun.NATBehavior{},
		},
		{
			name:     "only mapping known",
			behavior: &stun.NATBehavior{MappingType: stun.BehaviorTypeEndpoint},
			want:     "  Mapping Behavior: EndpointIndependent\n",
		},
		{
			name:     "only filtering known",
			behavior: &stun.NATBehavior{FilteringType: stun.BehaviorTypeAddrAndPort},
			want:     "Filtering Behavior: AddressAndPortDependent\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := writePartialBehaviorTestResult(&output, tt.behavior); err != nil {
				t.Fatal(err)
			}
			if got := output.String(); got != tt.want {
				t.Fatalf("output = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWritePartialBehaviorTestResultReportsNoTranslationClassification(t *testing.T) {
	var output bytes.Buffer
	behavior := &stun.NATBehavior{NoTranslation: true}
	if err := writePartialBehaviorTestResult(&output, behavior); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "   Normal NAT Type: Open Internet (no NAT)\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

// mappedAddressConn answers a Binding request without using a network socket.
type mappedAddressConn struct {
	ip       net.IP
	response []byte
}

func (c *mappedAddressConn) WriteTo(request []byte, _ net.Addr) (int, error) {
	family := byte(2)
	ip := c.ip.To16()
	if ipv4 := c.ip.To4(); ipv4 != nil {
		family, ip = 1, ipv4
	}
	c.response = make([]byte, 28+len(ip))
	binary.BigEndian.PutUint16(c.response[:2], 0x0101)
	binary.BigEndian.PutUint16(c.response[2:4], uint16(8+len(ip)))
	copy(c.response[4:20], request[4:20])
	binary.BigEndian.PutUint16(c.response[20:22], 1)
	binary.BigEndian.PutUint16(c.response[22:24], uint16(4+len(ip)))
	c.response[25] = family
	binary.BigEndian.PutUint16(c.response[26:28], 40000)
	copy(c.response[28:], ip)
	return len(request), nil
}

func (c *mappedAddressConn) ReadFrom(dst []byte) (int, net.Addr, error) {
	if c.response == nil {
		return 0, nil, errors.New("no pending Binding response")
	}
	length := copy(dst, c.response)
	c.response = nil
	return length, &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3478}, nil
}

func (c *mappedAddressConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000}
}

func (c *mappedAddressConn) Close() error                     { return nil }
func (c *mappedAddressConn) SetDeadline(time.Time) error      { return nil }
func (c *mappedAddressConn) SetReadDeadline(time.Time) error  { return nil }
func (c *mappedAddressConn) SetWriteDeadline(time.Time) error { return nil }

func mappedHostForTest(t *testing.T, ip string) *stun.Host {
	t.Helper()
	client := stun.NewClientWithConnection(&mappedAddressConn{ip: net.ParseIP(ip)})
	client.SetServerAddr("198.51.100.1:3478")
	host, err := client.Keepalive()
	if err != nil {
		t.Fatal(err)
	}
	return host
}

func TestWriteBehaviorTestResult_ReportsMappedAddressAndPortPreservation(t *testing.T) {
	wantErr := errors.New("later probe failed")
	tests := []struct {
		name      string
		ip        string
		family    int
		preserved bool
		err       error
	}{
		{"success", "192.0.2.20", 1, false, nil},
		{"IPv6 preserved", "2001:db8::20", 2, true, nil},
		{"unsupported", "192.0.2.20", 1, true, stun.ErrBehaviorDiscoveryUnsupported},
		{"later failure", "192.0.2.20", 1, false, wantErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			host := mappedHostForTest(t, tt.ip)
			behavior := &stun.NATBehaviorResult{
				MappedAddress: host, PortPreservation: &tt.preserved,
				NATBehavior: stun.NATBehavior{MappingType: stun.BehaviorTypeEndpoint, FilteringType: stun.BehaviorTypeAddr},
			}
			if errors.Is(tt.err, stun.ErrBehaviorDiscoveryUnsupported) {
				behavior.MappingType, behavior.FilteringType = stun.BehaviorTypeUnknown, stun.BehaviorTypeUnknown
			} else if tt.err != nil {
				behavior.MappingType = stun.BehaviorTypeUnknown
			}
			err := writeBehaviorTestResult(&output, behavior, tt.err)
			if tt.err == wantErr {
				if !errors.Is(err, wantErr) {
					t.Fatalf("error = %v, want %v", err, wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			want := "External IP Family: " + strconv.Itoa(tt.family) + "\n" +
				"External IP: " + tt.ip + "\nExternal Port: 40000\n" +
				"Port Preservation: " + strconv.FormatBool(tt.preserved) + "\n"
			if errors.Is(tt.err, stun.ErrBehaviorDiscoveryUnsupported) {
				want += stun.ErrBehaviorDiscoveryUnsupported.Error() + "\n"
			} else if tt.err != nil {
				want += "Filtering Behavior: AddressDependent\n"
			} else {
				want += "  Mapping Behavior: EndpointIndependent\nFiltering Behavior: AddressDependent\n" +
					"   Normal NAT Type: Restricted cone NAT\n"
			}
			if got := output.String(); got != want {
				t.Fatalf("output = %q, want %q", got, want)
			}
		})
	}
}

func TestWriteBehaviorTestResult_UnsupportedServerRetainsBindingOutput(t *testing.T) {
	client := stun.NewClientWithConnection(&mappedAddressConn{ip: net.ParseIP("192.0.2.20")})
	client.SetServerAddr("198.51.100.1:3478")
	behavior, err := client.BehaviorTestWithDetails()
	if !errors.Is(err, stun.ErrBehaviorDiscoveryUnsupported) {
		t.Fatalf("BehaviorTestWithDetails() error = %v", err)
	}
	var output bytes.Buffer
	if err := writeBehaviorTestResult(&output, behavior, err); err != nil {
		t.Fatal(err)
	}
	want := "External IP Family: 1\nExternal IP: 192.0.2.20\nExternal Port: 40000\nPort Preservation: false\n" +
		stun.ErrBehaviorDiscoveryUnsupported.Error() + "\n"
	if got := output.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestWriteBehaviorTestResult_ReportsMappedAddressWhenPreservationUnknown(t *testing.T) {
	var output bytes.Buffer
	behavior := &stun.NATBehaviorResult{MappedAddress: mappedHostForTest(t, "192.0.2.20")}
	if err := writeBehaviorTestResult(&output, behavior, stun.ErrBehaviorDiscoveryUnsupported); err != nil {
		t.Fatal(err)
	}
	want := "External IP Family: 1\nExternal IP: 192.0.2.20\nExternal Port: 40000\n" +
		stun.ErrBehaviorDiscoveryUnsupported.Error() + "\n"
	if got := output.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestWriteBehaviorTestResult_InitialBindingFailurePrintsNoObservations(t *testing.T) {
	wantErr := errors.New("initial Binding failed")
	for _, behavior := range []*stun.NATBehaviorResult{nil, {}} {
		var output bytes.Buffer
		if err := writeBehaviorTestResult(&output, behavior, wantErr); !errors.Is(err, wantErr) {
			t.Fatalf("error = %v, want %v", err, wantErr)
		}
		if output.Len() != 0 {
			t.Fatalf("fabricated output after initial failure: %q", output.String())
		}
	}
}

type failAfterWriter struct {
	remaining int
	err       error
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.remaining == 0 {
		return 0, w.err
	}
	w.remaining--
	return len(p), nil
}

func TestWriteBehaviorTestResult_ReturnsMappedOutputWriteErrors(t *testing.T) {
	host := mappedHostForTest(t, "192.0.2.20")
	preserved := false
	behavior := &stun.NATBehaviorResult{MappedAddress: host, PortPreservation: &preserved}
	wantErr := errors.New("write failed")
	for _, probeErr := range []error{nil, stun.ErrBehaviorDiscoveryUnsupported, errors.New("later failure")} {
		for remaining := 0; remaining < 4; remaining++ {
			writer := &failAfterWriter{remaining: remaining, err: wantErr}
			if err := writeBehaviorTestResult(writer, behavior, probeErr); !errors.Is(err, wantErr) {
				t.Fatalf("write %d with probe error %v returned %v, want %v", remaining+1, probeErr, err, wantErr)
			}
		}
	}
}
