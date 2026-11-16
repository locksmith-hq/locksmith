---
version: 1
slug: "src-app-tsx"
primary_target: "src/App.tsx"
related_targets: ["src/screens.tsx","src/styles.css"]
---

# Surface: Locksmith desktop app (apps/desktop)

Mode: Operate. Users: developers running AI coding agents, and their security lead. Job: see what
agents can do right now and what they did; lock, revoke, add or rotate keys, verify the audit
ledger. Constraints: the webview never holds a secret (native secure prompts only); CSP
`default-src 'self'` (fonts bundled locally); macOS and Linux; keyboard-operable; dark and light
modes (follows the system, with a manual override).

## Direction contract

THESIS: Locksmith as a calm, premium security tool: the vault's state leads, every live session is
its own clearly-stated card, and stopping anything is one action away. It refuses the generic
blue-on-white admin table and the neon-on-black AI dashboard.

OWN-WORLD: Gatehouse. Warm stone neutrals (dark: bg #1b1a18, surface #242320, raised #2d2b28,
text #f1eee8, muted #aba69c; light: bg #f4f4f2, surface #fff, border #e4e2dc, text #1c1b19,
muted #66625a), spruce accent (#6cc3bd dark / #0e6e70 light), live green, amber warning, red
danger. Figtree for UI, JetBrains Mono for ids and payloads. Hairline borders and soft long
shadows, rounded cards; no glow.

STORY: The visitor sees at once whether the vault is open and which agents hold access, reads each
session's scopes and remaining time, sees what was blocked, and can revoke or lock instantly.

FIRST VIEWPORT: Left sidebar (vault-dial logo whose outer ring turns on lock/unlock, Unbounded
wordmark, Overview, Keys, Tokens, Relays, Audit with counts, appearance control, daemon status).
A sticky header line: "Vault ● Unlocked · N sessions · since HH:MM" with Revoke all (quiet) and one
primary Lock/Unlock. Main: "Sessions" as dense rows on a shared lease timeline (agent, session id,
project / env, scopes as text, lease bar from a "now" line, time left; ended sessions muted below a
hairline), then "Activity" as a one-line-per-event log with a decision marker and sentence-case
labels. Rules and alignment, not boxes; no avatars, chips or icon tiles.

FORM: Gatehouse (UI round 2, direction B), chosen by the founder with a sidebar instead of top
tabs; the banner toggle was later rejected ("I don't like this toggle showing again our logo").
seed: none (pinned) — "Gatehouse but with sidepanel".
Signature move: the shared lease timeline — who holds access, and until when, at a glance. The
vault-dial ring rotation lives on the sidebar mark only.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
