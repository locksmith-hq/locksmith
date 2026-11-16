# Design: M10c

## D1. Groups live in the binding, expanded by the daemon
A group is a named list of key names in `.locksmith.toml`. The client sends group names in
`RunSpec.groups`; the daemon expands them from the binding it pinned for the lease, never from
client-supplied key lists. Unknown group: BadRequest. Group with a key that is not in the vault:
BadRequest naming the key (no partial injection).

## D2. Names only
Groups carry key names. No value crosses any new path; the existing redactor covers injected values.

## D3. Combining
`--group` may repeat and combines with `--key`; the injected set is the union, de-duplicated.
