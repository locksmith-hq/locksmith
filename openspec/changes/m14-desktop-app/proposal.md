# Proposal: M14 Desktop App

## Why

Approvals (biometric step-ups, MCP secret requests, ask decisions from hooks), session oversight and
audit review are hard in a terminal while an agent is driving it. Most paying users also expect a
GUI. v5 Phase 5 specifies Tauri v2 + React 19. v6 keeps that and makes the app a thin, attested
daemon client that never handles secret values except when the human types them.

## What Changes

- `apps/desktop`: Tauri v2 (Rust side in `src-tauri`, depending on `ls-ipc` / `ls-license`) and a
  React 19 + Vite UI using `packages/ui`.
- Menu-bar/tray: lock state, active sessions, revoke buttons, pending approvals badge.
- Approval center: MCP secret requests (secure input field), hook "ask" decisions, biometric step-up
  context, with agent text marked as untrusted (M10 D2).
- Management: projects, environments, keys (metadata, add/rotate with secure input), opaque tokens,
  relays, Git/AWS setup wizards, `smith init` for a chosen folder.
- Audit viewer: timeline, filters, chain verification status, anchors.
- Diagnostics panel: doctor results with Fix buttons, bundle creation.
- Account: license status, upgrade, devices. Updates: channel and release notes through the Tauri
  updater (feed from M12).
- Onboarding: create vault, recovery phrase (print or save to a password manager), Touch ID enroll,
  first project, install hooks.

## Usable outcome

A user installs `Locksmith.app`, onboards without the terminal, and approves agent requests from the
menu bar.

## Capabilities

### New Capabilities
- `desktop-app`: Graphical management, approvals and oversight.

### Modified Capabilities

## Out of scope

- A Windows build of the app (M16). A Linux build ships as an AppImage, best effort.

## Impact

`apps/desktop`, `packages/ui` components, `packages/api-types` (generated with `ts-rs` from
`ls-ipc` types). The macOS app bundle also carries `locksmithd` (M9 D1).
