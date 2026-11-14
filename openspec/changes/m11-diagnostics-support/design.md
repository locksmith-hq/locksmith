# Design: M11 Diagnostics and Support

## Decisions

### D1. Defense in depth for bundles
Three layers: (1) the collector only reads allowlisted sources; (2) every file passes the redactor
with the full vault automaton when unlocked; (3) the generic scanner runs. If a layer-3 finding
remains, the bundle is aborted, not written partially. A unit test plants canaries in every source.

### D2. Telemetry data model
`{schema:"telemetry.v1", install_id(random, rotatable), day, version, os, arch, tier,
counters:{cmd.<name>, block.<rule_id>, doctor.fail.<check_id>, update.<outcome>}}`.
No project names, paths, hostnames, key names or IPs. The server truncates the IP before storage.
Retention is 13 months. This keeps us out of PII-processing scope.

### D3. Crash reports
`std::panic::set_hook` writes `crash-<ts>.json` with the panic message passed through the redactor
and a `backtrace` captured with addresses only. Symbolication happens server-side or with
`smith diag symbolicate` using published debug symbols. No minidumps, because core dumps are off
by design.

## Risks / Trade-offs
- Opt-in telemetry gives little data. To compensate, the in-app nudge after 7 days of use explains
  what is sent.
