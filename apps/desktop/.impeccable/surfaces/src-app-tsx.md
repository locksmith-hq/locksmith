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
`default-src 'self'` (no remote fonts or assets); macOS and Linux; keyboard-operable.

## Direction contract

THESIS: Every session is a key cut for one job. The app is the locksmith's keying schedule:
what is cut, for whom, until when, and what was struck off. It refuses the category default of a
white admin console with blue buttons and coloured chips.

OWN-WORLD: Cool drafting-film off-white ground, cobalt technical ink for rules, headings and the
mark, graphite text, brass for granted pins, a single red for revoked and blocked. Hairline ruled
tables, generous but exact spacing, a neutral grotesk for UI and a mono only for ids and ledger
payloads. Shear-line mark in the rail.

STORY: The visitor sees at once whether the vault is open, which keys are cut and live, and what
was struck or blocked; stopping anything is one action away; nothing hides a secret.

FIRST VIEWPORT: Left rail (mark + wordmark, Overview, Keys, Tokens, Relays, Audit). Top band: vault
state large ("Unlocked"/"Locked") with Lock and Revoke all, plus a small cylinder-plug drawing
turned or not. Main: "Keying schedule" table (Session, Agent, Project/env, Key cut, Time left,
Revoke); below it "Struck from the schedule". Right column: latest ledger events.

FORM: Keying Schedule, position 1 on my ordered list (IMPECCABLE'S PICK). seed:f733efef24ab9253.
Signature move: the key-cut glyph, a key blade whose five pin positions (run, git, http, db, aws) are
cut deep when granted, shallow when not; reused in Keys/Tokens wherever scopes appear.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
