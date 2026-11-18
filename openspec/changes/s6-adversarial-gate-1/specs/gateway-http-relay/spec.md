# Spec Delta

## ADDED Requirements

### Requirement: Relay redacts base32, UTF-16 and escaped forms
In addition to the plain, base64, URL, hex and JSON forms, the relay SHALL redact or refuse a response that carries the injected secret as base32, UTF-16LE, UTF-16BE or `\u` JSON escapes, in headers and body, including when the form is split across stream chunks.

#### Scenario: Base32 echo
- **WHEN** a bound upstream returns the injected secret base32-encoded in a header and in the body
- **THEN** the agent receives the redaction marker in both places and no oracle hit

#### Scenario: UTF-16 echo split across chunks
- **WHEN** a bound upstream streams the secret as UTF-16LE split byte by byte
- **THEN** the agent receives a redacted or refused response and no oracle hit
