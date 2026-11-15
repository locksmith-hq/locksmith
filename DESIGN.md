---
name: Locksmith
description: The locksmith's keying schedule. What is cut, for whom, until when, and what was struck off.
colors:
  cobalt-ink: "#1f3fae"
  cobalt-ink-deep: "#17318a"
  brass: "#c8a044"
  brass-edge: "#8a6812"
  revoke-red: "#b3261e"
  revoke-wash: "#fbeceb"
  drafting-ground: "#f3f5f7"
  sheet: "#ffffff"
  cobalt-wash: "#e4e9f6"
  graphite: "#2b2f36"
  quiet-graphite: "#565e6d"
  hairline: "rgba(31, 63, 174, 0.24)"
typography:
  display:
    fontFamily: "IBM Plex Sans, -apple-system, BlinkMacSystemFont, Segoe UI, Helvetica Neue, system-ui, sans-serif"
    fontSize: "28px"
    fontWeight: 600
    lineHeight: "34px"
    letterSpacing: "-0.015em"
  headline:
    fontFamily: "IBM Plex Sans, system-ui, sans-serif"
    fontSize: "22px"
    fontWeight: 600
    lineHeight: "28px"
    letterSpacing: "-0.01em"
  title:
    fontFamily: "IBM Plex Sans, system-ui, sans-serif"
    fontSize: "16px"
    fontWeight: 600
    lineHeight: "22px"
  body:
    fontFamily: "IBM Plex Sans, system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: "20px"
    fontFeature: "\"tnum\" 1"
  label:
    fontFamily: "IBM Plex Sans, system-ui, sans-serif"
    fontSize: "12px"
    fontWeight: 600
    lineHeight: "16px"
    letterSpacing: "0.02em"
  mono:
    fontFamily: "IBM Plex Mono, ui-monospace, SF Mono, Menlo, DejaVu Sans Mono, monospace"
    fontSize: "12.5px"
    fontWeight: 400
    fontFeature: "\"liga\" 0, \"calt\" 0"
rounded:
  tag: "2px"
  code: "3px"
  control: "6px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
  xxl: "32px"
  section: "40px"
components:
  button:
    backgroundColor: "{colors.sheet}"
    textColor: "{colors.cobalt-ink}"
    rounded: "{rounded.control}"
    padding: "0 16px"
    height: "36px"
  button-hover:
    backgroundColor: "{colors.cobalt-wash}"
  button-primary:
    backgroundColor: "{colors.cobalt-ink}"
    textColor: "{colors.sheet}"
    rounded: "{rounded.control}"
    padding: "0 16px"
    height: "36px"
  button-primary-hover:
    backgroundColor: "{colors.cobalt-ink-deep}"
  button-danger:
    backgroundColor: "{colors.sheet}"
    textColor: "{colors.revoke-red}"
    rounded: "{rounded.control}"
    padding: "0 16px"
    height: "36px"
  button-danger-hover:
    backgroundColor: "{colors.revoke-wash}"
  link-danger:
    textColor: "{colors.revoke-red}"
    padding: "4px 2px"
  input:
    backgroundColor: "{colors.sheet}"
    textColor: "{colors.graphite}"
    rounded: "{rounded.control}"
    padding: "0 10px"
    height: "36px"
  nav-item:
    textColor: "{colors.graphite}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "36px"
  nav-item-current:
    backgroundColor: "{colors.cobalt-wash}"
    textColor: "{colors.cobalt-ink}"
  ruled-table-row:
    textColor: "{colors.graphite}"
    height: "56px"
  ruled-table-head:
    textColor: "{colors.cobalt-ink}"
    typography: "{typography.label}"
    height: "40px"
  code-inline:
    backgroundColor: "{colors.cobalt-wash}"
    textColor: "{colors.cobalt-ink-deep}"
    typography: "{typography.mono}"
    rounded: "{rounded.code}"
    padding: "1px 5px"
  alert:
    backgroundColor: "{colors.revoke-wash}"
    textColor: "{colors.revoke-red}"
    rounded: "{rounded.control}"
    padding: "10px 14px"
  note:
    backgroundColor: "{colors.cobalt-wash}"
    textColor: "{colors.cobalt-ink-deep}"
    rounded: "{rounded.control}"
    padding: "12px 16px"
  keycut:
    width: "136px"
    height: "30px"
---

# Design System: Locksmith

<!-- Recorded from the shipped build of apps/desktop (the first surface in this world). Brand marks live in packages/ui/brand and apply company-wide. -->

## Overview

**Creative North Star: "The Keying Schedule"**

Every session is a key cut for one job. The interface is the locksmith's keying schedule drawn on cool drafting film: cobalt technical ink for rules, headings and the mark, graphite for text, brass only where a pin sits in a cut, and a single red for anything revoked, blocked or about to run out. It reads as a technical drawing, not an admin console: hairline-ruled tables sit directly on the ground, nothing floats on a card, and the one large word on screen is the vault's state.

Density is exact rather than airy: a 36 px control height, 44 to 56 px ruled rows, a 4 px spacing base. Type is one neutral grotesk (IBM Plex Sans) for the interface and its mono sibling only for identifiers, commands and ledger payloads. Motion is mechanical and brief: a plug turns a quarter, a revoked row is struck through.

The desktop app (`apps/desktop`) is the first surface built in this world; the mark, palette and type are company-wide.

**Key Characteristics:**
- Drafting-film ground with cobalt hairline rules; flat, no shadows, no cards.
- Brass is a material, not an accent: it means "pin present in a cut".
- One red, reserved for revoke, blocked and time-low.
- The shear-line mark and the KeyCut blade are drawn parts, built on the pixel grid.
- Names, never values: no surface accepts or renders a secret.

## Colors

A cool, low-chroma ground carrying one saturated technical ink, one warm metal and one alarm.

### Primary
- **Cobalt Ink** (cobalt-ink): headings, table head rules, the mark and wordmark, outline-button borders and text, primary-button fill, focus ring, caret, the locked vault state.
- **Deep Cobalt** (cobalt-ink-deep): primary-button hover, inline code text, note and verdict-ok text.

### Secondary
- **Brass** (brass) with **Brass Edge** (brass-edge) as its 0.75 to 1 px stroke: the granted pin in a KeyCut, the plug's pins, the current nav item's dot, the app icon's pins. Never text, never a button.

### Tertiary
- **Revoke Red** (revoke-red) and **Revoke Wash** (revoke-wash): revoke buttons and links, blocked ledger events, time left under ten minutes, the revoked verdict in "Struck", error alerts, the broken-ledger verdict (solid red with white text).

### Neutral
- **Drafting Ground** (drafting-ground): the window background everywhere, including behind tables.
- **Sheet** (sheet): inside inputs, buttons, the plug core and the `pre` command block; also the text colour on cobalt and red fills.
- **Cobalt Wash** (cobalt-wash): current nav item, button hover, inline code, notes, the KeyCut blade fill, the plug slot.
- **Graphite** (graphite): body text.
- **Quiet Graphite** (quiet-graphite): secondary text, struck rows, timestamps, placeholders, disabled controls, empty pins.
- **Hairline** (hairline, cobalt at 24%): row rules, the rail border, input borders, dashed empty states. Selection uses cobalt at 18%, nav hover cobalt at 6%.

### Named Rules
**The One Red Rule.** Red appears only for revoke, blocked and time-low (under 600 s). No second warning hue, no amber, no green success.

**The Brass Is Metal Rule.** Brass marks a physical pin and nothing else. If it is not a pin in a drawing, it is not brass.

## Typography

**Body Font:** IBM Plex Sans 400/500/600, bundled via `@fontsource/ibm-plex-sans` (CSP forbids remote fonts), falling back to the system UI stack.
**Mono Font:** IBM Plex Mono 400/500 via `@fontsource/ibm-plex-mono`, for session ids, key names, hosts, commands and ledger payloads.

**Character:** One engineered grotesk family in two cuts; the mono is the sans's sibling, so ids sit in the same voice as labels. Tabular figures are on globally so times and counts align in columns.

### Hierarchy
- **Display** (600, 28px/34px, -0.015em): the vault state ("Unlocked", "Locked") in the top band only.
- **Headline** (600, 22px/28px, -0.01em, cobalt): screen titles and the daemon-down heading.
- **Title** (600, 16px/22px, cobalt): section heads such as "Keying schedule", with a 13px quiet count beside it.
- **Body** (400, 14px/20px, graphite): everything else; lede and notes cap at 64 to 72ch.
- **Label** (600, 12px/16px, +0.02em, cobalt): table column heads, sentence case. Ledger action names in the events list use 12px +0.04em as data, not as decoration.
- **Mono** (400, 12.5px; 14px inside the command `pre`).

### Named Rules
**The Two Hyphens Rule.** Mono has ligatures off (`font-variant-ligatures: none`): `--` in a copyable command must read as two hyphens.

**The Mono Is Data Rule.** Mono is for identifiers and payloads only, never for labels, headings or UI chrome.

## Layout

A fixed 208px left rail (mark and wordmark, five nav items, an active/struck count pinned to the foot) beside a scrolling work column. The work column opens with a top band (min 88px, 16px 32px padding, hairline below) holding the vault state, the band actions and the plug drawing. Main content pads 28px 32px 40px and caps at 1120px.

The Overview is a two-column grid (fluid table column, 296px events column, 28px gap) that collapses to one column below 1180px. Spacing steps are 4, 8, 12, 16, 24, 32 and 40px; sections separate by 36 to 40px, fields by 16px.

**The Stopping Is Adjacent Rule.** Lock and Revoke all live in the top band on every screen; per-row revoke sits at the row's end. Never move them into a menu.

## Elevation & Depth

Flat. There are no shadows anywhere. Depth is conveyed by ink weight alone: a full cobalt rule above a table and under its head, hairline rules between rows, a cobalt wash for the current or hovered thing.

**The Drafting Sheet Rule.** Tables and lists sit directly on the ground between rules; they are never wrapped in a card, a border box or a shadow.

## Shapes

Small, mechanical radii: 6px on every control, alert and note; 3px on inline code and the focus ring; 2px on host tags. Status dots in the rail are 7px circles. The drawn parts (mark, plug, KeyCut) use 1px strokes on half-pixel coordinates so every edge lands on the pixel grid.

### The shear-line mark
A rounded-square lock body (52 units, 16 radius, 6-unit stroke on a 64 grid) holding three pin stacks.
- **Unlocked** (`locksmith-mark.svg`, default): every pin stack splits on one straight shear line at y 27 to 32, and a 5-unit mask cuts the body along that same line. The body is split; the lock is turning.
- **Locked** (`locksmith-mark-locked.svg`): the same pins sit off the line at uneven heights and the body is whole. Used for the daemon-down screen.
- **Tray template glyphs** (`tray-unlocked.svg`, `tray-locked.svg`): redrawn, not scaled, on an 18px integer grid (2px pins, 1px shear gap, crisp edges), black on transparent, shipped at 18 and 36px and set as macOS template images.
- **App icon** (`app-icon.svg`): the unlocked mark at 10x on a cobalt rounded square (185 radius on 824), housing in drafting ground, pins in brass. Rasters are generated from the SVG, never edited.

**The Shear Line Rule.** Unlocked splits the body along the shear line; locked keeps the body whole and the pins off the line. Never show a generic padlock or shield.

## Components

### Buttons
- **Shape:** gently squared (6px), 36px high, 16px side padding, 600 weight.
- **Default:** sheet fill, cobalt 1px border and text; hover fills cobalt wash (120ms).
- **Primary:** cobalt fill, white text; hover deep cobalt. One per context (Unlock, Add or rotate key).
- **Danger:** red border and text on sheet; hover red wash. Revoke all.
- **Disabled:** hairline border, quiet text, transparent.
- **Link:** text-only, 600, underline appears on hover at 3px offset; the danger link is the per-row Revoke.

### Inputs / Fields
- **Style:** label above (13px, 600), 36px input, hairline border, sheet fill, 6px radius; widths 200, 280 or 320px.
- **Focus:** border turns cobalt with the 2px cobalt ring at 0 offset.

### Navigation
Rail buttons, 36px high, 12px gap to a 7px hollow quiet dot. Hover: cobalt at 6%. Current: cobalt wash, cobalt 600 text, dot filled brass with brass-edge ring.

### Ruled table
Column heads in label type, cobalt, bottom-aligned with a cobalt rule beneath; 56px body rows (44px in struck and audit tables) separated by hairlines; first and last columns flush to the rule ends; numbers right-aligned; ids in mono. Bad rows turn red. Struck rows go quiet with the id struck through at 1.5px.

### Notes, alerts and verdicts
Note: cobalt wash, deep cobalt text, hairline border. Alert: red border, red wash, red text, `role="alert"`. Verdict ok: wash; verdict broken: solid red with white text. Empty states: dashed hairline, quiet text, with the CLI command to fix it.

### Plug
A 48px cylinder face seen end-on: housing and core circles, four ticks, a keyway slot with three brass pins. When the vault is open the keyway group turns a quarter (420ms, expo-out).

### KeyCut (signature)
A 136 by 30px key blade drawn 1:1 on the pixel grid, tip to the right, with five pin positions at a 24px pitch for `run`, `git`, `http`, `db`, `aws`. A granted scope is cut deep with a brass pin sitting in it; a scope not granted is cut shallow with a hollow quiet pin. The column head is the KeyCut legend: "Key cut" with the five scope names centred over their pins. It carries an `aria-label` listing the granted scopes. Reuse it wherever scopes appear (Overview, Tokens).

### Motion
One easing, `cubic-bezier(0.16, 1, 0.3, 1)`. Plug quarter-turn 420ms. Revoke strike: a 1.5px red line draws across the row over 480ms while its text fades to quiet, then the row moves to "Struck". Button hover 120ms. Under `prefers-reduced-motion: reduce` all transitions and animations are off and the revoke skips its strike delay.

## Do's and Don'ts

### Do:
- **Do** keep tables on the ground between a cobalt top rule and hairline row rules.
- **Do** show scopes with the KeyCut blade, never as coloured chips.
- **Do** use the unlocked shear-line mark by default and the locked mark only for a closed or unreachable vault.
- **Do** redraw tray glyphs on the 18px integer grid as single-colour template images.
- **Do** bundle fonts locally and keep ligatures off in mono.
- **Do** honour reduced motion by removing the strike and the turn, not by shortening them.

### Don't:
- **Don't** add a text field, textarea or reveal toggle for any secret value or passphrase; secret entry goes through the native Locksmith prompt and the window only learns "submitted" or "cancelled".
- **Don't** introduce a second warning colour, a green success colour or coloured status chips.
- **Don't** use brass for text, buttons or decoration.
- **Don't** add shadows or wrap tables in cards.
- **Don't** use a generic padlock, shield or icon-font glyph for the brand.
