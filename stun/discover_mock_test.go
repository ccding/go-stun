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
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func mockResponse(t *testing.T, transID []byte, mappedIP string, mappedPort uint16, changedIP string, changedPort uint16) []byte {
	p, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	p.types = typeBindingResponse
	p.transID = transID

	// Add MAPPED-ADDRESS
	mappedVal := make([]byte, 8)
	mappedVal[1] = 0x01 // IPv4
	binary.BigEndian.PutUint16(mappedVal[2:4], mappedPort)
	copy(mappedVal[4:8], net.ParseIP(mappedIP).To4())
	p.addAttribute(*newAttribute(attributeMappedAddress, mappedVal))

	// Add CHANGED-ADDRESS
	changedVal := make([]byte, 8)
	changedVal[1] = 0x01 // IPv4
	binary.BigEndian.PutUint16(changedVal[2:4], changedPort)
	copy(changedVal[4:8], net.ParseIP(changedIP).To4())
	p.addAttribute(*newAttribute(attributeChangedAddress, changedVal))

	return p.bytes()
}

func TestDiscoverMockNone(t *testing.T) {
	localAddr, _ := net.ResolveUDPAddr("udp", "1.2.3.4:12345")
	conn := newMockPacketConn(localAddr)
	client := NewClientWithConnection(conn)
	client.SetServerAddr("9.9.9.9:3478")

	// Run Discover in a goroutine
	type result struct {
		nat NATType
		host *Host
		err  error
	}
	resChan := make(chan result, 1)
	go func() {
		nat, host, err := client.Discover()
		resChan <- result{nat, host, err}
	}()

	// 1. Wait for Test I request to be written
	select {
	case <-conn.writeSignal:
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for Test I request")
	}

	if len(conn.writeCalls) != 1 {
		t.Fatalf("expected 1 write call, got %d", len(conn.writeCalls))
	}
	rec1 := conn.writeCalls[0]
	transID1 := rec1.data[4:20]

	// Send Test I response (Mapped Address matches local IP/port)
	server1Addr, _ := net.ResolveUDPAddr("udp", "9.9.9.9:3478")
	resp1 := mockResponse(t, transID1, "1.2.3.4", 12345, "8.8.8.8", 3479)
	conn.readBuf <- resp1
	conn.readAddr <- server1Addr

	// 2. Wait for Test II request to be written (because mapping identical == true and we test for open internet)
	select {
	case <-conn.writeSignal:
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for Test II request")
	}

	if len(conn.writeCalls) != 2 {
		t.Fatalf("expected 2 write calls, got %d", len(conn.writeCalls))
	}
	rec2 := conn.writeCalls[1]
	transID2 := rec2.data[4:20]

	// Send Test II response
	server2Addr, _ := net.ResolveUDPAddr("udp", "8.8.8.8:3479")
	resp2 := mockResponse(t, transID2, "1.2.3.4", 12345, "8.8.8.8", 3479)
	conn.readBuf <- resp2
	conn.readAddr <- server2Addr

	// Verify discover results
	select {
	case res := <-resChan:
		if res.err != nil {
			t.Fatalf("unexpected Discover error: %v", res.err)
		}
		if res.nat != NATNone {
			t.Errorf("expected NAT type NATNone, got %v", res.nat)
		}
		if res.host == nil || res.host.IP() != "1.2.3.4" || res.host.Port() != 12345 {
			t.Errorf("unexpected host returned: %v", res.host)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for Discover to complete")
	}
}

func TestDiscoverMockBlocked(t *testing.T) {
	localAddr, _ := net.ResolveUDPAddr("udp", "1.2.3.4:12345")
	conn := newMockPacketConn(localAddr)
	conn.instantTimeout = true
	// Set read deadline to fire instantly to avoid waiting 9 retransmits * timeout
	client := NewClientWithConnection(conn)
	client.SetServerAddr("9.9.9.9:3478")

	// We let the client send packets, but we never respond.
	// Since there are 9 retransmits, we can let it run. But wait, retransmits double timeout.
	// To make the test run fast, let's inject a read error or timeout immediately, or just speed up the mock.
	// Actually, mock timeout error is returned when deadline is exceeded.
	// Since client.send loops 9 times, and each read times out after `timeout` milliseconds (which defaults to 100ms),
	// the total timeout would be around 1.6s. That's fine for a unit test.
	
	type result struct {
		nat NATType
		host *Host
		err  error
	}
	resChan := make(chan result, 1)
	go func() {
		nat, host, err := client.Discover()
		resChan <- result{nat, host, err}
	}()

	// Just let it time out and verify it returns NATBlocked
	select {
	case res := <-resChan:
		if res.err != nil {
			t.Fatalf("unexpected Discover error: %v", res.err)
		}
		if res.nat != NATBlocked {
			t.Errorf("expected NAT type NATBlocked, got %v", res.nat)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for Discover to complete under NATBlocked test")
	}
}
