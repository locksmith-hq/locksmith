# Spec Delta

## ADDED Requirements

### Requirement: Oracle scans extended encodings
The canary oracle SHALL also find a canary, and the canary text, as base32, UTF-16LE, UTF-16BE, `\u` JSON escapes, HTML numeric entities, quoted-printable and inside a gzip stream with or without a `Content-Encoding` label. Its self-test SHALL cover every form, and its output SHALL still never print the canary.

#### Scenario: Self-test covers new forms
- **WHEN** `run.sh selftest` runs
- **THEN** the oracle finds a planted canary in each new form and reports the form name

#### Scenario: Clean file stays clean
- **WHEN** the oracle scans a file of random bytes and text with no canary
- **THEN** it reports no hit for any new form
