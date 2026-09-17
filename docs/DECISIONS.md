# Decisions

## DEC-001: Retain initial Binding observations

For [F-001](FEATURES.md#f-001-behavior-mode-address-and-port-preservation), retain
the mapped address and port-preservation observation in `NATBehavior`, leaving
the `BehaviorTest` method signature unchanged. Both values come from the initial
Binding transaction and its socket. Calling `Discover` separately could allocate
a different local port and report a different NAT mapping.

Represent port preservation as `*bool` so an unavailable local port is distinct
from an observed port translation. Retain observations when subsequent discovery
is unsupported or fails. `NormalType` uses only mapping, filtering, and
no-translation information; the additional observations do not change NAT
classification.
