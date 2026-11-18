## Why
The desktop app (Tauri) and `ls-ipc` only run on Unix: IPC uses Unix domain sockets, and the manual `ci-platforms` Windows job excludes `ls-vault`, `smith-cli`, `ls-ipc`, `ls-broker` and `locksmithd` with a "rejoin later" shortcut. Every later phase would add more platform debt. X1 pays it once so that from here each phase ends green on macOS, Linux and Windows.

## What changes
- `ls-ipc` gets a Windows named-pipe transport behind the same API as the Unix socket one; peer-identity checks have a Windows implementation.
- `ls-vault`, `smith-cli`, `ls-broker` and `locksmithd` build and pass their tests on Windows; the exclusions in the Windows check are removed (SQLCipher built against a vendored OpenSSL, no system install).
- The desktop app builds, launches and answers a health IPC call on macOS, Linux and Windows; the web console builds.
- `just apps-build` builds web plus desktop on the host OS; a smoke script launches the built desktop binary headless and checks it.
- `ci-platforms` runs the Tauri bundle on all three OSes and the result is recorded in `progress.md`.

## Usable outcome
A user on macOS, Linux or Windows can install the desktop app, start it, and see it talk to the local daemon; every later change inherits a green three-OS gate.

## Out of scope
Code signing and notarisation, installers and auto-update (P2), new desktop features, Windows services, any change to the secret or crypto design.

## Depends on
`s4-agent-connector` (the desktop surface it adds must be what gets ported).

## Protected files
`.github/workflows/ci-platforms.yml` is protected. Workflow edits go in a separate PR the owner merges (needs-owner issue); agent tasks here never edit workflows.
