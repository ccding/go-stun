# go-stun

[![Go Reference (latest release)](https://pkg.go.dev/badge/github.com/ccding/go-stun/stun.svg)](https://pkg.go.dev/github.com/ccding/go-stun/stun)
[![Tests](https://github.com/ccding/go-stun/actions/workflows/go.yml/badge.svg)](https://github.com/ccding/go-stun/actions/workflows/go.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-red.svg)](LICENSE)

`go-stun` is a Go library and command-line client for STUN over UDP and TCP. It
can discover the public IP address and port assigned to a socket and, for UDP
when the server supports the required probes, classify the client's NAT
behavior.

STUN is one building block for NAT traversal. This project does not implement a
complete UDP hole-punching, ICE, or TURN solution.

## Features

- Discover a socket's public (server-reflexive) IP address and port.
- Perform basic STUN Binding transactions over UDP or TCP.
- Send [RFC 5389] Binding requests with `SOFTWARE` and `FINGERPRINT`
  attributes.
- Perform classic NAT type discovery based on [RFC 3489].
- Test NAT mapping and filtering behavior as described by [RFC 5780].
- Select the STUN server and local IP address or port.
- Reuse an existing `net.PacketConn` from library code.
- Communicate with RFC 3489-only servers through an explicit compatibility
  mode.

## Install the command

This README documents the current `master` branch. With Go 1.16 or newer,
install that branch explicitly until the next release is tagged:

```console
go install github.com/ccding/go-stun@master
```

The newest tag, `v0.1.5`, predates RFC 3489 compatibility mode, the `-legacy`
flag, and `ErrBehaviorDiscoveryUnsupported`. Use `@latest` only if you need the
older released interface.

Ensure your Go binary directory (usually `$GOBIN` or `$GOPATH/bin`) is on
`PATH`, then run:

```console
go-stun
```

To build from a source checkout instead:

```console
git clone https://github.com/ccding/go-stun.git
cd go-stun
go build .
./go-stun
```

## Command-line usage

Running `go-stun` with no options uses the default server and an automatically
selected local address. Example output:

```text
NAT Type: Full cone NAT
External IP Family: 1
External IP: 203.0.113.10
External Port: 54321
```

The values depend on the network and server. Address family `1` denotes IPv4;
`2` denotes IPv6.

Available options:

| Option | Description |
| --- | --- |
| `-s host:port` | Use a specific STUN server. |
| `-i ip` | Bind requests to a local IP address. |
| `-p port` | Bind requests to a local port; `0` selects an available port. |
| `-b` | Run RFC 5780 mapping and filtering behavior tests. |
| `-legacy` | Omit modern optional attributes for RFC 3489-only servers. |
| `-t transport` | Select `udp` (the default) or `tcp`. TCP performs basic Binding only. |
| `-v level` | Set verbosity to `0` (quiet), `1` (protocol trace), or `2`/`3` (also dump packets in hex); values above `3` are rejected. |

Use `go-stun -h` to see the current defaults. For example:

```console
go-stun -s stun.example.com:3478
go-stun -s stun.example.com:3478 -t tcp
go-stun -s stun.example.com:3478 -b
go-stun -v 1
```

## Use the library

Add the package to a Go module:

```console
go get github.com/ccding/go-stun/stun@master
```

Then create a client and call `Discover`:

```go
package main

import (
	"fmt"
	"log"

	"github.com/ccding/go-stun/stun"
)

func main() {
	client := stun.NewClient()

	natType, mappedAddr, err := client.Discover()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("NAT type:", natType)
	if mappedAddr != nil {
		fmt.Println("Mapped address:", mappedAddr)
	}
}
```

If no server is configured, the client uses `stun.DefaultServerAddr`. Other
configuration methods include `SetServerHost`, `SetLocalIP`, `SetLocalPort`,
`SetSoftwareName`, and the verbosity setters. For an existing socket, use
`stun.NewClientWithConnection(conn)` with a `net.PacketConn` created by an
applicable `net.Listen*` function; the caller remains responsible for closing
the connection, and `Keepalive` can refresh its mapping.

For a basic Binding transaction over TCP, call `DiscoverTCP`:

```go
mappedAddr, err := client.DiscoverTCP()
```

`DiscoverTCP` opens a TCP connection for the transaction and closes it before
returning. Because a reflexive TCP address remains useful only while its
connection is open, applications that need to retain the mapping should dial
the server themselves and use `NewClientWithTCPConnection`. The caller owns
that connection and can call `DiscoverTCP` again to refresh the mapping. Use
`SetTCPTimeout` to replace the [RFC 8489] default response timeout of 39.5
seconds. When `DiscoverTCP` opens the connection itself, the same duration
also bounds connection establishment independently.

Run `go doc github.com/ccding/go-stun/stun` for documentation matching the
version in your module. The linked [package reference] shows the latest tagged
release and will not include `master`-only symbols until a new release is
published.

### NAT behavior discovery

`Discover` first performs a standard Binding request. If that succeeds but the
server does not provide a usable alternate address, it returns
`stun.NATUnknown`, the mapped address, and a `nil` error. The mapped address is
still valid even though the NAT type could not be determined.

Add `"errors"` to the import block, then call `BehaviorTest` (or use the CLI's
`-b` option) for RFC 5780 mapping and filtering tests:

```go
behavior, err := client.BehaviorTest()
if errors.Is(err, stun.ErrBehaviorDiscoveryUnsupported) {
	fmt.Println("The server does not support behavior discovery")
} else if err != nil {
	fmt.Println("Behavior test failed:", err)
}

if behavior != nil && behavior.MappingType != stun.BehaviorTypeUnknown {
	fmt.Println("Mapping behavior:", behavior.MappingType)
}
if behavior != nil && behavior.FilteringType != stun.BehaviorTypeUnknown {
	fmt.Println("Filtering behavior:", behavior.FilteringType)
}
```

A non-nil behavior result may contain partial results when a later probe fails.

### RFC 3489 compatibility

Normal requests include `SOFTWARE` and `FINGERPRINT` attributes. Some legacy
RFC 3489 servers reject those attributes; enable compatibility mode for such a
server:

```go
client := stun.NewClient()
client.SetRFC3489Compatibility(true)
```

The equivalent command-line option is `-legacy`.

## Server requirements and limitations

A successful STUN Binding request only requires the server to return a mapped
address. NAT classification additionally requires an alternate IP address and
port, advertised through RFC 3489's `CHANGED-ADDRESS` or RFC 5780's
`OTHER-ADDRESS` attribute. Many public STUN servers support Binding but do not
support these discovery probes; `NAT type unavailable` is therefore an expected
result with those servers.

UDP requests use the RFC 3489 retransmission schedule: nine sends beginning at
100 ms, doubling up to a 1.6-second interval. A timed-out probe can consequently
take several seconds. TCP requests rely on TCP reliability and are not
retransmitted at the STUN layer.

## Security

Report suspected vulnerabilities privately by following the
[security policy](SECURITY.md). Please do not publish vulnerability details in
a GitHub issue.

## Development

Run the checks used by CI before submitting changes:

```console
git ls-files -z -- '*.go' | xargs -0 gofmt -l
go mod tidy
go mod verify
go vet -mod=readonly ./...
staticcheck -checks=all ./...
go test -mod=readonly -race -shuffle=on -covermode=atomic -coverprofile=coverage.out ./...
govulncheck -test ./...
```

The formatting command should produce no output, and `go mod tidy` should not
change `go.mod` or `go.sum`. CI also requires at least 84% statement coverage.
See the [Go CI workflow] for the pinned Go and tool versions and the exact
checks.

## License

`go-stun` is available under the [Apache License 2.0](LICENSE).

[package reference]: https://pkg.go.dev/github.com/ccding/go-stun/stun
[Go CI workflow]: .github/workflows/go.yml
[RFC 3489]: https://www.rfc-editor.org/rfc/rfc3489.html
[RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389.html
[RFC 5780]: https://www.rfc-editor.org/rfc/rfc5780.html
[RFC 8489]: https://www.rfc-editor.org/rfc/rfc8489.html
