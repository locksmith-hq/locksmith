# Spec Delta

## Purpose

Masks secret values in any output Locksmith relays, so agents and terminals never display them even when a program echoes them.

## ADDED Requirements

### Requirement: Multi-encoding detection
The redactor SHALL mask each active secret in plain form, standard and url-safe base64 at every byte alignment, lower and upper hex, percent-encoding and JSON-escaped form.

#### Scenario: Base64 at offset
- **WHEN** a command prints base64 of a prefix byte followed by the secret
- **THEN** the output contains no decodable copy of the secret

#### Scenario: Labelled replacement
- **WHEN** secret `STRIPE_KEY` appears in output
- **THEN** it is replaced by `[REDACTED:STRIPE_KEY]`

### Requirement: Chunk-boundary correctness
Detection SHALL be independent of how output is split into chunks.

#### Scenario: Split secret
- **WHEN** a secret is written one byte per write with 50 ms pauses
- **THEN** the secret does not appear in the relayed output

### Requirement: Interactive latency
Output that cannot be part of a secret SHALL be relayed within 50 ms of being produced.

#### Scenario: Prompt shows promptly
- **WHEN** a program prints a prompt without a trailing newline and waits for input
- **THEN** the prompt is visible to the user within 50 ms

### Requirement: Text integrity
The redactor SHALL never emit a partial UTF-8 code point and SHALL leave output without secrets byte-identical.

#### Scenario: Non-ASCII output
- **WHEN** a command prints mixed emoji and CJK text containing no secrets
- **THEN** relayed output is byte-identical to the original

### Requirement: Short secret warning
Secrets shorter than 8 bytes SHALL still be redacted in plain form, and adding them SHALL warn that encoded forms are not covered.

#### Scenario: Short value
- **WHEN** the user adds a 5-byte secret
- **THEN** the add succeeds with a warning about reduced redaction coverage
