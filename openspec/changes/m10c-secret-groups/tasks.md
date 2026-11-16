# Tasks

## 1. Backend
- [ ] 1.1 `[groups.<name>] keys` in the binding parser (validate names, reject empty groups). Verify: parser unit tests.
- [ ] 1.2 `RunSpec.groups` and daemon expansion from the pinned binding. Verify: unit tests for known, unknown, missing-key, union, and a post-session edit being ignored.
- [ ] 1.3 `smith run --group` and `smith group ls`; groups in `smith ls`. Verify: CLI integration tests.
- [ ] 1.4 `locksmith_list_keys` returns each key's groups. Verify: MCP test, no value fields.

## 2. Desktop
- [ ] 2.1 Keys screen groups keys by group. Verify: Vitest component test.
