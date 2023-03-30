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
	"flag"
	"fmt"
	"os"

	"github.com/ccding/go-stun/stun"
)

func main() {
	var serverAddr = flag.String("s", stun.DefaultServerAddr, "STUN server address")
	var behaviorTestMode = flag.Bool("b", false, "Enable NAT behavior test mode")
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
	client.SetVerbose(*verboseLevel >= 1)
	client.SetVVerbose(*verboseLevel >= 2)

	// Run behavior test if specified
	if *behaviorTestMode {
		err := runBehaviorTest(client)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		return
	}

	// Discover the NAT
	nat, host, err := client.Discover()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	fmt.Println("NAT Type:", nat)
	if host != nil {
		fmt.Println("External IP Family:", host.Family())
		fmt.Println("External IP:", host.IP())
		fmt.Println("External Port:", host.Port())
	}
}

func runBehaviorTest(c *stun.Client) error {
	natBehavior, err := c.BehaviorTest()
	if err != nil {
		return err
	}

	if natBehavior != nil {
		fmt.Println("  Mapping Behavior:", natBehavior.MappingType)
		fmt.Println("Filtering Behavior:", natBehavior.FilteringType)
		fmt.Println("   Normal NAT Type:", natBehavior.NormalType())
	}
	return nil
}
