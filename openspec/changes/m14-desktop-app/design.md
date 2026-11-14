# Design: M14 Desktop App

## Decisions

### D1. Webview never sees secrets
Secret input uses a native secure text field via a Tauri plugin (`NSSecureTextField` on macOS),
and the value is sent straight from the Rust side to the daemon. The React layer receives only "submitted".
Tauri `capabilities` restrict the webview to an explicit command list, with a CSP of `default-src 'self'`
and no remote content.

### D2. One IPC client
The app's Rust side is just another attested client (`locksmith-desktop` identity, M3 D2). There is
no separate API. Types for the UI come from `packages/api-types`, generated from Rust.

### D3. Tests
Rust command handlers are unit-tested. The UI is tested with Vitest plus Testing Library, and e2e
uses `tauri-driver` WebDriver on Linux CI with a macOS manual checklist.
