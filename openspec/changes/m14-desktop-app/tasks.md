# Tasks

## 1. Shell

- [ ] 1.1 Scaffold `apps/desktop` (Tauri v2, React 19, Vite, `packages/ui`), `api-types` codegen via ts-rs, and the Tauri capabilities and CSP (design D1). Verify: `npm run tauri build` in CI on macOS and Linux.
- [ ] 1.2 Native secure input plugin. Verify: a test that the value never enters JS (the mock daemon receives it, and the UI state snapshot has none).

## 2. Features

- [ ] 2.1 Tray with lock state, sessions and revoke. Verify: e2e via tauri-driver plus the mock daemon.
- [ ] 2.2 Approval center. Verify: e2e with simulated MCP requests.
- [ ] 2.3 Management screens (projects, envs, keys, tokens, relays, Git and AWS wizards). Verify: Vitest component tests plus e2e happy paths.
- [ ] 2.4 Audit viewer and diagnostics panel. Verify: e2e shows a tampered ledger as broken.
- [ ] 2.5 Account and updates panels. Verify: e2e against staging license server and nightly feed.
- [ ] 2.6 Onboarding. Verify: a manual usability test with 3 people new to Locksmith, with notes in the PR.

## 3. Packaging

- [ ] 3.1 Signed and notarized `Locksmith.app` bundling `locksmithd`, a DMG, a Homebrew cask, and a Linux AppImage. Verify: `spctl -a -vv` passes and the cask installs on a clean VM.
