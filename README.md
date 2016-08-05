go-stun
=======

[![Build Status](https://travis-ci.org/ccding/go-stun.svg?branch=master)]
(https://travis-ci.org/ccding/go-stun)
[![License](https://img.shields.io/badge/License-Apache%202.0-red.svg)]
(https://opensource.org/licenses/Apache-2.0)
[![GoDoc](https://godoc.org/github.com/ccding/go-stun?status.svg)]
(http://godoc.org/github.com/ccding/go-stun/stun)
[![Go Report Card](https://goreportcard.com/badge/github.com/ccding/go-stun)]
(https://goreportcard.com/report/github.com/ccding/go-stun)

go-stun is a STUN (RFC 3489, 5389) client implementation in golang.

It is extremely easy to use -- just one line of code.

```go
import "github.com/ccding/go-stun/stun"

func main() {
	nat, host, err := stun.NewClient().Discover()
}
```

More details please go to `main.go` and [GoDoc]
(http://godoc.org/github.com/ccding/go-stun/stun)
