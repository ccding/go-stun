go-stun
=======

[![Build Status](https://travis-ci.org/ccding/go-stun.svg?branch=master)]
(https://travis-ci.org/ccding/go-stun)
[![GoDoc](https://godoc.org/github.com/ccding/go-stun?status.svg)]
(http://godoc.org/github.com/ccding/go-stun/stun)

go-stun is a STUN (RFC 3489, 5389) client implementation in golang.

It is extremely easy to use -- just one line of code.

```go
import "github.com/ccding/go-stun/stun"

func main() {
	nat, host, err := stun.NewClient().Discover()
}
```

More details please go to `example.go` and [GoDoc]
(http://godoc.org/github.com/ccding/go-stun/stun)
