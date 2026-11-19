// WhatsApp <-> GitHub relay for the lead, following OpenClaw's WhatsApp channel design:
// one long-running process owns a Baileys (WhatsApp Web) session, with an owner-only allowlist,
// a lock against a second owner, reconnects, and dedupe across restarts.
// Out: `<!-- wa: ... -->` lines on open needs-owner issues are texted to the owner.
// In: the owner's replies become owner comments on that issue, which wake the agents (wake-agents.yml).
import fs from 'node:fs';
import path from 'node:path';
import makeWASocket, { DisconnectReason, useMultiFileAuthState } from 'baileys';
import pino from 'pino';
import { isFromOwner, pendingTexts, phoneJid, pickIssue, quotedIdOf, textOf, trim, typingMs } from './lib.mjs';

const env = (k, d) => process.env[k] || d || (() => { throw new Error(`${k} is not set`); })();
const OWNER = phoneJid(env('WA_OWNER'));
const BOT_NUMBER = process.env.WA_BOT_NUMBER?.replace(/\D/g, '');
const GH_TOKEN = env('GH_TOKEN');
const REPO = env('GH_REPO', 'locksmith-hq/locksmith');
const DATA = path.resolve(env('DATA_DIR', './data'));
const POLL_MS = Number(env('POLL_SECONDS', '60')) * 1000;
const MAX_AGE_MS = 24 * 3600e3; // never text stale questions after downtime
const INBOUND_MAX_AGE_S = 20 * 60; // like OpenClaw: answer offline messages up to 20 minutes old

const AUTH = path.join(DATA, 'auth');
const STATE_FILE = path.join(DATA, 'state.json');
fs.mkdirSync(AUTH, { recursive: true, mode: 0o700 });

// Lock sidecar: two processes on one session knock each other off.
const LOCK = `${AUTH}.lock`;
try {
  const pid = Number(fs.readFileSync(LOCK, 'utf8'));
  if (pid && pid !== process.pid) {
    process.kill(pid, 0); // throws if that process is gone
    console.error(`another bridge (pid ${pid}) owns ${AUTH}`);
    process.exit(1);
  }
} catch {}
fs.writeFileSync(LOCK, String(process.pid));
process.on('exit', () => fs.rmSync(LOCK, { force: true }));
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => process.exit(0));

const state = fs.existsSync(STATE_FILE)
  ? JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'))
  : { seen: {}, sent: {}, handled: {}, lastIssue: null };
function save() {
  for (const k of ['seen', 'sent', 'handled']) trim(state[k]);
  fs.writeFileSync(`${STATE_FILE}.tmp`, JSON.stringify(state));
  fs.renameSync(`${STATE_FILE}.tmp`, STATE_FILE);
}

async function gh(route, init = {}) {
  const res = await fetch(`https://api.github.com/repos/${REPO}/${route}`, {
    ...init,
    headers: { Authorization: `Bearer ${GH_TOKEN}`, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json' },
  });
  if (!res.ok) throw new Error(`GitHub ${init.method ?? 'GET'} ${route}: ${res.status}`);
  return res.json();
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let sock = null;
let open = false;

async function textOwner(text) {
  await sock.presenceSubscribe(OWNER).catch(() => {});
  await sock.sendPresenceUpdate('composing', OWNER);
  await sleep(typingMs(text));
  await sock.sendPresenceUpdate('paused', OWNER);
  return sock.sendMessage(OWNER, { text });
}

async function pollGitHub() {
  if (!open) return;
  const issues = (await gh('issues?labels=needs-owner&state=open&per_page=50')).filter((i) => !i.pull_request);
  const comments = {};
  const since = new Date(Date.now() - MAX_AGE_MS).toISOString(); // else long threads return only the oldest 100
  for (const i of issues) comments[i.number] = await gh(`issues/${i.number}/comments?per_page=100&since=${since}`);
  for (const t of pendingTexts(issues, comments, state.seen, Date.now(), MAX_AGE_MS)) {
    const sent = await textOwner(t.text);
    state.seen[t.key] = true;
    state.sent[sent.key.id] = t.issue;
    state.lastIssue = t.issue;
    save();
    console.log(`texted owner for #${t.issue}`);
  }
}

async function onMessage(m) {
  if (!isFromOwner(m.key, OWNER) || state.handled[m.key.id]) return;
  if (Date.now() / 1000 - Number(m.messageTimestamp ?? 0) > INBOUND_MAX_AGE_S) return;
  const text = textOf(m.message);
  if (!text) return; // media, reactions, edits: text only for now
  state.handled[m.key.id] = true;
  save();
  await sock.readMessages([m.key]);
  const issue = pickIssue(state, quotedIdOf(m.message));
  if (!issue) {
    await textOwner('nothing open on my side right now, will ping you when something comes up');
    return;
  }
  // No agent marker: wake-agents.yml treats this as an owner reply and wakes the routine.
  await gh(`issues/${issue}/comments`, { method: 'POST', body: JSON.stringify({ body: `${text}\n\n<sub>via WhatsApp</sub>` }) });
  await sock.sendMessage(OWNER, { react: { text: '👍', key: m.key } });
  console.log(`owner reply posted to #${issue}`);
}

let backoff = 2000;
let pairingRequested = false;
async function connect() {
  const { state: auth, saveCreds } = await useMultiFileAuthState(AUTH);
  sock = makeWASocket({ auth, logger: pino({ level: 'warn' }), markOnlineOnConnect: false });
  sock.ev.on('creds.update', saveCreds);
  sock.ev.on('connection.update', async ({ connection, lastDisconnect, qr }) => {
    if (qr && !auth.creds.registered && !pairingRequested) {
      if (!BOT_NUMBER) { console.error('not linked: set WA_BOT_NUMBER to get a pairing code'); process.exit(1); }
      pairingRequested = true;
      const code = await sock.requestPairingCode(BOT_NUMBER);
      console.log(`On the lead's phone: WhatsApp > Linked devices > Link with phone number > ${code}`);
    }
    if (connection === 'open') { open = true; backoff = 2000; console.log('connected'); }
    if (connection === 'close') {
      open = false;
      if (lastDisconnect?.error?.output?.statusCode === DisconnectReason.loggedOut) {
        console.error(`logged out: delete ${AUTH} and link again`);
        process.exit(1);
      }
      pairingRequested = false;
      setTimeout(connect, backoff);
      backoff = Math.min(backoff * 2, 60_000);
    }
  });
  sock.ev.on('messages.upsert', ({ messages }) => {
    for (const m of messages) onMessage(m).catch((e) => console.error(`inbound: ${e.message}`));
  });
}

await connect();
for (;;) {
  await pollGitHub().catch((e) => console.error(`poll: ${e.message}`));
  await sleep(POLL_MS);
}
