# Progress: B2 Rust core service

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-23 (PM, planning)
- Split out of `b1-nestjs-api` group 5 (tasks 5.2 and 5.3) so a second worker can build the Rust core while B1's NestJS foundation is in progress (#653, #670). B1 keeps 5.4 (the NestJS side calls `packages/core-client`) and 5.5. Nothing implemented.
