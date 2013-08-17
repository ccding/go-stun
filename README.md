go-stun
=======

go-stun is a STUN (RFC 3489, 5389) client implementation in golang.

It is extremely easy to use -- just one line of code.

```go
import "github.com/ccding/go-stun/stun"

func main() {
	nat, host, err := stun.Discover()
}
```

More details please go to `example.go`.
