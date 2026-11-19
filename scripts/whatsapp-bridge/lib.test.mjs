import assert from 'node:assert/strict';
import test from 'node:test';
import { extractWa, isFromOwner, pendingTexts, phoneJid, pickIssue, quotedIdOf, textOf, trim } from './lib.mjs';

test('extractWa reads the hidden line, multi-line too', () => {
  assert.equal(extractWa('<!-- agent -->\nDecision\n<!-- wa: hey, quick one\nok? -->'), 'hey, quick one\nok?');
  assert.equal(extractWa('<!-- agent --> no line'), null);
  assert.equal(extractWa('<!-- wa: -->'), null);
  assert.equal(extractWa(null), null);
});

test('phoneJid normalises and rejects junk', () => {
  assert.equal(phoneJid('+972 50-123 4567'), '972501234567@s.whatsapp.net');
  assert.throws(() => phoneJid('abc'));
});

test('only the owner, not us, gets through, by number or LID alt', () => {
  const owner = phoneJid('+972501234567');
  assert.ok(isFromOwner({ remoteJid: owner }, owner));
  assert.ok(isFromOwner({ remoteJid: '123@lid', remoteJidAlt: owner }, owner));
  assert.ok(!isFromOwner({ remoteJid: owner, fromMe: true }, owner));
  assert.ok(!isFromOwner({ remoteJid: '111@s.whatsapp.net' }, owner));
  assert.ok(!isFromOwner({ remoteJid: '120363@g.us', participant: owner }, owner));
});

test('reply text and quoted id', () => {
  assert.equal(textOf({ conversation: ' revert it ' }), 'revert it');
  const quoted = { extendedTextMessage: { text: 'yes', contextInfo: { stanzaId: 'ABC' } } };
  assert.equal(textOf(quoted), 'yes');
  assert.equal(quotedIdOf(quoted), 'ABC');
  assert.equal(textOf({ imageMessage: {} }), '');
});

test('pickIssue prefers the quoted text, then the last one sent', () => {
  const state = { sent: { ABC: 7 }, lastIssue: 9 };
  assert.equal(pickIssue(state, 'ABC'), 7);
  assert.equal(pickIssue(state, 'unknown'), 9);
  assert.equal(pickIssue({ sent: {}, lastIssue: null }, null), null);
});

test('pendingTexts: new, fresh, wa-bearing items only, oldest first', () => {
  const now = Date.parse('2026-11-19T12:00:00Z');
  const issues = [{ id: 1, number: 5, body: '<!-- wa: first -->', created_at: '2026-11-19T10:00:00Z' }];
  const comments = {
    5: [
      { id: 2, body: '<!-- wa: second -->', created_at: '2026-11-19T11:00:00Z' },
      { id: 3, body: 'owner reply, no line', created_at: '2026-11-19T11:30:00Z' },
      { id: 4, body: '<!-- wa: old -->', created_at: '2026-11-17T11:00:00Z' },
    ],
  };
  const day = 24 * 3600e3;
  assert.deepEqual(pendingTexts(issues, comments, {}, now, day).map((t) => [t.key, t.issue, t.text]), [
    ['i1', 5, 'first'],
    ['c2', 5, 'second'],
  ]);
  assert.deepEqual(pendingTexts(issues, comments, { i1: true }, now, day).map((t) => t.key), ['c2']);
});

test('trim keeps the newest entries', () => {
  assert.deepEqual(trim({ a: 1, b: 2, c: 3 }, 2), { b: 2, c: 3 });
});
