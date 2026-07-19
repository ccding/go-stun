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
	"errors"
	"strings"
	"testing"

	"github.com/ccding/go-stun/stun"
)

func TestWriteBehaviorTestResultTreatsUnsupportedServerAsSuccess(t *testing.T) {
	var output bytes.Buffer
	if err := writeBehaviorTestResult(&output, &stun.NATBehavior{}, stun.ErrBehaviorDiscoveryUnsupported); err != nil {
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
	behavior := &stun.NATBehavior{NoTranslation: true}
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
	behavior := &stun.NATBehavior{
		MappingType:   stun.BehaviorTypeEndpoint,
		FilteringType: stun.BehaviorTypeEndpoint,
		NoTranslation: true,
	}
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
	behavior := &stun.NATBehavior{FilteringType: stun.BehaviorTypeAddr}
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
	behavior := &stun.NATBehavior{
		MappingType:   stun.BehaviorTypeEndpoint,
		FilteringType: stun.BehaviorTypeAddrAndPort,
	}
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
	behavior := &stun.NATBehavior{NoTranslation: true}
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
