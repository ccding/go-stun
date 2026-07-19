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
