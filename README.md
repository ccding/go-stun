go-stun
=======

Forked from <https://github.com/ccding/go-stun> to make it work for me:
- added quick stun test 
- removed magic cookies because it's not working for the stun server I tested

## Original README

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
```bash
> ./go-stun --help
Usage of ./go-stun:
  -s string
        server address (default "stun1.l.google.com:19302")
  -v    verbose mode
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

More details please go to `main.go` and [GoDoc](http://godoc.org/github.com/ccding/go-stun/stun)
