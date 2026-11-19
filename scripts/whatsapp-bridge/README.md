# WhatsApp bridge

Lets the lead text the owner on WhatsApp, and the owner text back.

The design is copied from OpenClaw's WhatsApp channel: one always-on process owns a
[Baileys](https://github.com/WhiskeySockets/Baileys) (WhatsApp Web) session, pinned to the same
version OpenClaw uses (`7.0.0-rc14`).

- **Lead → owner.** The lead ends a `needs-owner` issue, or a comment on it, with
  `<!-- wa: casual text -->` (rule in `docs/agents/common.md`). Every `POLL_SECONDS` the bridge
  reads open `needs-owner` issues and texts each new line once. It shows "typing…" for a few
  seconds first, so it reads like a person.
- **Owner → lead.** A text from the owner's number becomes an owner comment on that issue: the one
  whose message you quote-replied to, otherwise the one texted last. That comment wakes the agents
  through `.github/workflows/wake-agents.yml`, as a GitHub reply would. The bridge reacts 👍 once
  the comment is posted.
- **Ignored.** Every other number, groups, media, and messages older than 20 minutes.

The agents in cloud VMs never touch WhatsApp. They only write issue comments, so the cloud
environment needs no new domain or secret.

## Needs
- **A second WhatsApp number for the lead**, such as an eSIM or prepaid SIM in WhatsApp or WhatsApp
  Business. Give it the lead's name and avatar from `docs/agents/avatars/`.
- **An always-on host** with Node 20+ and a persistent disk: a small VPS, or Railway or Fly.io with
  a volume. A sleeping laptop drops the session.
- **A fine-grained GitHub token** from the owner account (`tomer555`), limited to
  `locksmith-hq/locksmith` with Issues read and write. Comments must come from the owner account,
  or `wake-agents.yml` won't fire. Keep the token in the host's secret store.

## Run
```bash
npm ci
WA_OWNER=+972... WA_BOT_NUMBER=+972... GH_TOKEN=... DATA_DIR=/data npm start
```
The first start prints a pairing code. On the lead's phone, open WhatsApp > Linked devices >
Link with phone number, and enter it. The session is saved in `$DATA_DIR/auth` and survives
restarts. If WhatsApp logs it out, delete that folder and link again.

| Variable | Default | Meaning |
|---|---|---|
| `WA_OWNER` | (required) | Owner's number. The only sender allowed in. |
| `WA_BOT_NUMBER` | (first link only) | The lead's number, used to get the pairing code. |
| `GH_TOKEN` | (required) | Owner's fine-grained token. |
| `GH_REPO` | `locksmith-hq/locksmith` | Repo to watch. |
| `DATA_DIR` | `./data` | Session and dedupe state. Must persist. |
| `POLL_SECONDS` | `60` | How often to check GitHub. |

## Risks
- **The session keys in `$DATA_DIR/auth` are a full login** to the lead's WhatsApp account. The
  directory is created with mode 700. Never copy it into the repo or an agent VM.
- **Baileys is unofficial and breaks WhatsApp's terms,** as OpenClaw's channel does. One contact at
  low volume is a low ban risk, not zero, which is why it uses a separate number.
- **The owner's WhatsApp texts count as owner instructions** (`common.md`). Only `WA_OWNER` gets
  through.

## Test
```bash
npm test
```
