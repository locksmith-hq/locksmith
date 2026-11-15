# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

(The desktop app is a Tauri v2 webview on macOS and Linux; its UI is web technology inside a native
window, tray and system dialogs.)

## Users

- Developers who run AI coding agents (Claude Code, Cursor, Codex and others) on their own macOS or
  Linux machine. They open the desktop app between agent runs to see what agents did with
  credentials, revoke sessions, add or rotate keys, and check the audit trail.
- Security or platform leads on the same team who review audit trails, policy and revocations.

## Product Purpose

Locksmith is a credential broker for AI coding agents: agents perform authenticated operations
(Git, HTTP APIs, databases, AWS) without ever holding the real credential. Success is an agent that
gets its work done while no secret ever reaches its context, files, shell history or transcript, and
a human who can see and stop anything at once.

## Positioning

Delegation instead of handover: the key never leaves Locksmith. Requests are signed, relayed or
injected on the agent's behalf, bound to a session the human started, and revocable immediately.
Every protection is labelled honestly as prevention, containment or detection.

## Operating Context

- Local daemon `locksmithd` holds the unlocked vault; the CLI is `smith`; the desktop app is another
  attested client of the same daemon.
- Concepts users meet: vault, project and environment, keys (names only), sessions (leases) with
  scopes `run`, `git`, `http`, `db`, `aws`, opaque `lsk_` tokens, relays (Git forwarder, HTTP relay,
  AWS SigV4 relay, DB relay), tamper-evident audit ledger, revoke.
- Checked between agent runs, often glanced at from the tray; sometimes reviewed in depth after an
  incident.

## Capabilities and Constraints

- The UI never sees, renders or accepts a secret value. Passphrases and secret values go through a
  native secure prompt on the Rust side; the webview only learns "submitted" or "cancelled".
- Content Security Policy `default-src 'self'`: no remote fonts, scripts, images or analytics.
- Tray and menu-bar icons must work as single-colour template images at 16–22 px (macOS menu bar,
  Linux app indicators).
- Not yet available (later milestones): approval center (M9, M10), account and updates (M12, M13),
  Touch ID onboarding, signed packaging.

## Brand Commitments

- Name: Locksmith. CLI: `smith`.
- Feel: technical and clean; it must read as a trustworthy security company.
- The mark is built around a lock, but no generic padlock or shield clip-art.

## Evidence on Hand

- No logo, customers, testimonials, benchmarks or press exist yet. Do not invent them.

## Product Principles

1. Show what happened, not what might: every screen answers "what can agents do right now, and what
   did they do".
2. Stopping is always one action away: lock and revoke are never buried.
3. Names, never values: the interface handles key names, prefixes and events only.
4. Honest labels: prevention, containment and detection are named as such.

## Accessibility & Inclusion

- Keyboard-operable throughout; visible focus; status changes announced (`aria-live`).
