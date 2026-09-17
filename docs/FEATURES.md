# Features

## F-001: Behavior mode address and port preservation

Status: implemented. Addresses [issue #65](https://github.com/ccding/go-stun/issues/65).

`Client.BehaviorTest` returns the initial Binding response's external address in
`NATBehavior.MappedAddress`. `NATBehavior.PortPreservation` compares that external
port with the actual local port of the socket used for the test. Its values are
`true` for a preserved port, `false` for a translated port, and `nil` when the
local port is unknown. This is an observation of one mapping, not a guarantee
for other destinations or future connections.

The CLI's `-b` mode prints `External IP Family`, `External IP`, `External Port`,
and, when known, `Port Preservation`. These observations survive unsupported
behavior discovery and failures in later probes. No additional Binding request
or socket is needed. An initial Binding failure produces no observations.

Implementation: [result fields and classification](../stun/const.go),
[behavior discovery](../stun/discover.go), and [CLI output](../main.go).
Regression coverage: [discovery tests](../stun/discover_test.go) and
[CLI tests](../main_test.go). See [DEC-001](DECISIONS.md#dec-001-retain-initial-binding-observations).
