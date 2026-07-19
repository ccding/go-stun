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
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ccding/go-stun/stun"
)

func main() {
	var serverAddr = flag.String("s", stun.DefaultServerAddr, "STUN server address")
	var localPort = flag.Int("p", 0, "The port on which to bind requests, set to 0 to pick a random port")
	var localIP = flag.String("i", "", "The ip on which to bind requests, set to empty will use default")
	var behaviorTestMode = flag.Bool("b", false, "Enable NAT behavior test mode")
	var legacyMode = flag.Bool("legacy", false, "Enable compatibility with RFC 3489-only STUN servers")
	var transport = flag.String("t", "udp", "STUN transport (udp or tcp)")
	var verboseLevel = flag.Int("v", 0, "Verbose level (0: none, 1: verbose, 2: double verbose, 3: triple verbose)")
	flag.Parse()

	// Validate verbose level
	if *verboseLevel < 0 || *verboseLevel > 3 {
		fmt.Fprintln(os.Stderr, "Error: Invalid verbose level. Use -v with values 0, 1, 2, or 3.")
		os.Exit(1)
	}

	// Create a STUN client
	client := stun.NewClient()
	client.SetServerAddr(*serverAddr)
	client.SetLocalPort(*localPort)
	client.SetLocalIP(*localIP)
	client.SetRFC3489Compatibility(*legacyMode)
	client.SetVerbose(*verboseLevel >= 1)
	client.SetVVerbose(*verboseLevel >= 2)
	network := strings.ToLower(*transport)

	// Run behavior test if specified
	if *behaviorTestMode {
		if network != "udp" {
			fmt.Fprintln(os.Stderr, "Error: NAT behavior tests require UDP transport")
			os.Exit(1)
		}
		err := runBehaviorTest(client)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		return
	}

	// Discover the mapped transport address and, for UDP, the NAT type.
	nat, host, hasNATType, err := runDiscovery(client, network)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if hasNATType {
		fmt.Println("NAT Type:", nat)
	} else {
		fmt.Println("Transport: TCP")
	}
	if host != nil {
		fmt.Println("External IP Family:", host.Family())
		fmt.Println("External IP:", host.IP())
		fmt.Println("External Port:", host.Port())
	}
}

type discoveryClient interface {
	Discover() (stun.NATType, *stun.Host, error)
	DiscoverTCP() (*stun.Host, error)
}

func runDiscovery(client discoveryClient, transport string) (stun.NATType, *stun.Host, bool, error) {
	switch transport {
	case "udp":
		nat, host, err := client.Discover()
		return nat, host, true, err
	case "tcp":
		host, err := client.DiscoverTCP()
		return stun.NATUnknown, host, false, err
	default:
		return stun.NATError, nil, false, fmt.Errorf("unsupported STUN transport %q; use udp or tcp", transport)
	}
}

func runBehaviorTest(c *stun.Client) error {
	natBehavior, err := c.BehaviorTest()
	return writeBehaviorTestResult(os.Stdout, natBehavior, err)
}

func writeBehaviorTestResult(w io.Writer, natBehavior *stun.NATBehavior, err error) error {
	if err != nil {
		if errors.Is(err, stun.ErrBehaviorDiscoveryUnsupported) {
			if writeErr := writePartialBehaviorTestResult(w, natBehavior); writeErr != nil {
				return writeErr
			}
			_, writeErr := fmt.Fprintln(w, err)
			return writeErr
		}
		if writeErr := writePartialBehaviorTestResult(w, natBehavior); writeErr != nil {
			return writeErr
		}
		return err
	}

	if natBehavior != nil {
		if _, err := fmt.Fprintln(w, "  Mapping Behavior:", natBehavior.MappingType); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "Filtering Behavior:", natBehavior.FilteringType); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "   Normal NAT Type:", natBehavior.NormalType()); err != nil {
			return err
		}
	}
	return nil
}

func writePartialBehaviorTestResult(w io.Writer, natBehavior *stun.NATBehavior) error {
	if natBehavior == nil {
		return nil
	}
	if natBehavior.MappingType != stun.BehaviorTypeUnknown {
		if _, err := fmt.Fprintln(w, "  Mapping Behavior:", natBehavior.MappingType); err != nil {
			return err
		}
	}
	if natBehavior.FilteringType != stun.BehaviorTypeUnknown {
		if _, err := fmt.Fprintln(w, "Filtering Behavior:", natBehavior.FilteringType); err != nil {
			return err
		}
	}
	if natBehavior.NoTranslation ||
		(natBehavior.MappingType != stun.BehaviorTypeUnknown &&
			natBehavior.FilteringType != stun.BehaviorTypeUnknown) {
		if _, err := fmt.Fprintln(w, "   Normal NAT Type:", natBehavior.NormalType()); err != nil {
			return err
		}
	}
	return nil
}
