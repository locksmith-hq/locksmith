## ADDED Requirements

### Requirement: Canary leak scan across the local stack
`just leak-scan` SHALL search Postgres, Loki logs, Tempo traces, a given directory and a given transcript for every supported encoding of every active canary, and SHALL never print a canary value.

#### Scenario: Planted leak in the database is found
- **WHEN** a test inserts a canary's base64 form into a table and runs `just leak-scan`
- **THEN** it exits non-zero and prints `LEAK <encoding> postgres:<table>.<column>`, where `<encoding>` is the oracle label of the matched encoding (for example `b64-offset0`)
- **AND** the output does not contain the canary in any encoding

#### Scenario: Planted leak in logs is found
- **WHEN** a test sends an OTLP log containing a canary's hex form
- **THEN** `just leak-scan` reports `LEAK hex-lower loki:<stream>`

#### Scenario: Clean stack passes
- **WHEN** no canary has been written anywhere
- **THEN** `just leak-scan` exits 0 and `--explain` shows non-zero coverage for every source

#### Scenario: Empty coverage fails
- **WHEN** a configured source is unreachable
- **THEN** `just leak-scan` exits non-zero with `SOURCE-UNREACHABLE <name>`
