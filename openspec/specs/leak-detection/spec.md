# leak-detection Specification

## Purpose
TBD - created by archiving change f1-test-kit. Update Purpose after archive.

## Requirements

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

### Requirement: Oracle scans extended encodings
The canary oracle SHALL also find a canary, and the canary text, as base32, UTF-16LE, UTF-16BE, `\u` JSON escapes, HTML numeric entities, quoted-printable and inside a gzip stream with or without a `Content-Encoding` label, reversed, and in a separator-stripped view of the scanned text (whitespace and header framing removed) that finds a canary split across headers or one character per line. Its self-test SHALL cover every form, and its output SHALL still never print the canary.

#### Scenario: Self-test covers new forms
- **WHEN** `run.sh selftest` runs
- **THEN** the oracle finds a planted canary in each new form and reports the form name

#### Scenario: Clean file stays clean
- **WHEN** the oracle scans a file of random bytes and text with no canary
- **THEN** it reports no hit for any new form
