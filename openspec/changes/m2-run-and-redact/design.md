# Design: M2 Run and Redact

## Context
v5 §6.3 and §7.1. v6 changes: an idle flush, a minimum secret length, and derived forms.

## Goals / Non-Goals
**Goals:** zero false negatives for the supported encodings, under 1 ms added latency per chunk,
and correct handling of interactive TUIs.
**Non-Goals:** catching arbitrary transformations (rot13, compression, encryption). Those are
documented as out of scope.

## Decisions

### D1. Pattern set per secret value `v` (minimum length 8 bytes, shorter values warn at `add`)
`v`, `base64(v)`, plus `base64(pad_k || v)` at offsets k=1,2 with the first and last unstable
characters trimmed, the url-safe variants of each, `hex(v)` upper and lower, `percent(v)`,
`json_escape(v)`, and `base64("user:" + v)` for Basic auth when the key is tagged `basic_auth`.
Each pattern maps to its key name for the replacement label `[REDACTED:<KEY>]`.
`LeftmostLongest` match semantics.

### D2. Streaming
Keep `carry = max_pattern_len - 1` bytes. On each chunk, scan `carry + chunk`, emit everything up
to `len - carry` with matches replaced, and keep the rest. If no new data arrives for 20 ms, emit
the held bytes that cannot begin a match: compute the longest suffix of the held bytes that is a
prefix of some pattern, and keep only that. Never split a UTF-8 code point when emitting. Back
up to a char boundary.

### D3. PTY vs pipes
PTY (`portable-pty`) when our stdout is a TTY, so TUIs like `claude` render correctly. The PTY
merges stdout and stderr, which is accepted. Pipes otherwise. Signals (SIGINT, SIGWINCH) are
forwarded, and the exit code passes through.

### D4. Env construction
Start from the parent environment. Remove `LOCKSMITH_*` variables. Add only the keys the binding
or `--only` lists. With no binding, all keys of the environment are added after a confirmation
prompt.

## Risks / Trade-offs
- A child can exfiltrate through channels that bypass stdout, such as the network or files. Mode C
  does not stop this, and `--explain` says so. Containment comes in M8.
- The idle flush can hold up to `max_len-1` bytes of a genuine partial prefix indefinitely until
  more output or EOF arrives. That is acceptable, because EOF flushes it.
