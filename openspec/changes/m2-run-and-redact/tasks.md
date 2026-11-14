# Tasks

## 1. Redactor (`ls-redact`)

- [ ] 1.1 Pattern generation per design D1, with `Redactor::new(secrets)` building a LeftmostLongest automaton. Verify: unit tests for each encoding and the Basic-auth form.
- [ ] 1.2 Streaming engine with carry, idle flush and UTF-8 boundary handling (design D2). Verify: `proptest`, where random output with secrets inserted at random positions, random chunking and random encodings yields zero leaks and identical secret-free output.
- [ ] 1.3 Benchmarks (`criterion`) for 100 secrets × 10 MB of output. Verify: throughput ≥ 200 MB/s and p99 chunk latency < 1 ms on CI hardware.

## 2. `smith run`

- [ ] 2.1 `.locksmith.toml` parser plus the secret-in-binding check, and `smith init --binding-only` to create the file. Verify: unit tests, and the secret-in-binding e2e exits 3.
- [ ] 2.2 Pipe mode with env construction (design D4) and exit-code passthrough. Verify: e2e for `exit 7`, `LOCKSMITH_SESSION` stripped, only bound keys injected.
- [ ] 2.3 PTY mode with signal and resize forwarding. Verify: an e2e using `expect` drives `python3 -c 'input("x> ")'` and the prompt appears within 50 ms.
- [ ] 2.4 `--explain` and `smith env-template`. Verify: snapshot tests.

## 3. Diagnostics and adversarial

- [ ] 3.1 Doctor checks `redact.selftest` (runs the KAT corpus) and `run.pty_available`. Verify: doctor snapshot.
- [ ] 3.2 Adversarial case A6a: under `smith run`, a script prints the canary in all encodings, slowly and split. Verify: `run.sh A6a` passes.

## 4. Milestone acceptance

- [ ] 4.1 Dogfood: run `smith run -- claude` in a real repo for a day, ask Claude to debug a failing API call that echoes the key, and check the transcript JSONL with the oracle. Verify: the oracle reports zero hits.
