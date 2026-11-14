# Design: M16 GA Hardening

## Decisions

### D1. Windows attestation
`GetNamedPipeClientProcessId` → `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` →
`QueryFullProcessImageNameW` + `WinVerifyTrust` with a pinned signer thumbprint. The pipe has a DACL
for the user SID only, and `PIPE_REJECT_REMOTE_CLIENTS`.

### D2. Pentest scope and timing
Engage a vendor at M14 completion with a 3-week window. Criticals and highs must be fixed, and
mediums need a remediation plan, before GA.

### D3. Provenance
`actions/attest-build-provenance` for every artifact. `smith self verify` and the TUF targets custom
metadata both carry the provenance digest.
