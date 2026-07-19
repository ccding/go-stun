go-stun
=======

[![License](https://img.shields.io/badge/License-Apache%202.0-red.svg)](https://opensource.org/licenses/Apache-2.0)
[![GoDoc](https://godoc.org/github.com/ccding/go-stun?status.svg)](http://godoc.org/github.com/ccding/go-stun/stun)
[![Go Report Card](https://goreportcard.com/badge/github.com/ccding/go-stun)](https://goreportcard.com/report/github.com/ccding/go-stun)

go-stun is a STUN (RFC 3489, 5389) client implementation in golang
(a.k.a. UDP hole punching).

[RFC 3489](https://tools.ietf.org/html/rfc3489):
STUN - Simple Traversal of User Datagram Protocol (UDP)
Through Network Address Translators (NATs)

[RFC 5389](https://tools.ietf.org/html/rfc5389):
Session Traversal Utilities for NAT (STUN)

### Use the Command Line Tool

Simply run these commands (if you have installed golang and set `$GOPATH`)
```
go get github.com/ccding/go-stun
go-stun
```
or clone this repo and run these commands
```
go build
./go-stun
```
You will get the output like
```
NAT Type: Full cone NAT
External IP Family: 1
External IP: 166.111.4.100
External Port: 23009
```
You can use `-s` flag to use another STUN server, and use `-v` to work on
verbose mode.

Most public STUN servers, including Google's and Cloudflare's, support basic
Binding requests but not the alternate-address tests needed to classify NAT
behavior. With those servers the client returns `NATUnknown`, a non-nil mapped
address, and a nil error. Full NAT classification requires a server with
RFC 3489 classic NAT-discovery support or RFC 5780 behavior discovery.
```bash
> ./go-stun --help
Usage of ./go-stun:
  -b    Enable NAT behavior test mode
  -i string
        The ip on which to bind requests, set to empty will use default
  -legacy
        Enable compatibility with RFC 3489-only STUN servers
  -p int
        The port on which to bind requests, set to 0 to pick a random port
  -s string
        STUN server address (default "stunserver2025.stunprotocol.org:3478")
  -v int
        Verbose level (0: none, 1: verbose, 2: double verbose, 3: triple verbose)
```

### Use the Library

The library `github.com/ccding/go-stun/stun` is extremely easy to use -- just
one line of code.

```go
import "github.com/ccding/go-stun/stun"

func main() {
	nat, host, err := stun.NewClient().Discover()
}
```

Modern Binding requests include SOFTWARE and FINGERPRINT attributes. For an
RFC 3489-only server, enable compatibility mode before discovery. Compatibility
mode is disabled by default, preserving the request format used by earlier
go-stun releases:

```go
client := stun.NewClient()
client.SetRFC3489Compatibility(true)
nat, host, err := client.Discover()
```

UDP requests retain the RFC 3489 retransmission schedule used by the classic
NAT-discovery algorithm: nine sends starting at 100 ms, doubling to a 1.6 s
cap. This favors legacy behavior over RFC 5389's newer recommended defaults.

More details please go to `main.go` and [GoDoc](http://godoc.org/github.com/ccding/go-stun/stun)
