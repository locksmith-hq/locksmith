// Pure helpers for bridge.mjs, kept separate so they are testable without a WhatsApp session.

const WA_LINE = /<!--\s*wa:\s*([\s\S]*?)\s*-->/;

/** The `<!-- wa: ... -->` text an agent left for the owner's WhatsApp, or null. */
export function extractWa(body) {
  const m = WA_LINE.exec(body ?? '');
  return m && m[1] ? m[1] : null;
}

/** "+972 50-123 4567" -> "972501234567@s.whatsapp.net" */
export function phoneJid(e164) {
  const digits = String(e164).replace(/\D/g, '');
  if (digits.length < 8) throw new Error(`not a phone number: ${e164}`);
  return `${digits}@s.whatsapp.net`;
}

/** Allowlist: only the owner's own DMs count. Newer WhatsApp may address by LID, with the number in remoteJidAlt. */
export function isFromOwner(key, ownerJid) {
  if (!key || key.fromMe) return false;
  return key.remoteJid === ownerJid || key.remoteJidAlt === ownerJid;
}

export function textOf(message) {
  return (message?.conversation ?? message?.extendedTextMessage?.text ?? '').trim();
}

export function quotedIdOf(message) {
  return message?.extendedTextMessage?.contextInfo?.stanzaId ?? null;
}

/** Which issue a reply belongs to: the one whose text was quoted, else the one texted last. */
export function pickIssue(state, quotedId) {
  return (quotedId && state.sent[quotedId]) || state.lastIssue || null;
}

/** How long to show "typing…" before a text, like a person would. */
export function typingMs(text) {
  return Math.min(8000, 1500 + 40 * text.length);
}

/**
 * New WhatsApp texts from open needs-owner issues: issue bodies and comments carrying a wa line,
 * not sent before and not older than maxAgeMs. Oldest first.
 */
export function pendingTexts(issues, commentsByIssue, seen, now, maxAgeMs) {
  const out = [];
  for (const issue of issues) {
    const items = [{ key: `i${issue.id}`, ...issue }, ...(commentsByIssue[issue.number] ?? []).map((c) => ({ key: `c${c.id}`, ...c }))];
    for (const it of items) {
      const text = extractWa(it.body);
      if (!text || seen[it.key] || now - Date.parse(it.created_at) > maxAgeMs) continue;
      out.push({ key: it.key, issue: issue.number, text, at: it.created_at });
    }
  }
  return out.sort((a, b) => a.at.localeCompare(b.at));
}

/** shortcut: keeps the newest n entries of an insertion-ordered map; enough for one owner's chat. */
export function trim(map, n = 500) {
  const keys = Object.keys(map);
  for (const k of keys.slice(0, Math.max(0, keys.length - n))) delete map[k];
  return map;
}
