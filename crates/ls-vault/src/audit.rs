//! Forward-secure audit ledger (design: openspec/changes/m3-daemon-sessions/design.md D4,
//! docs/v6-review.md §2.1).
//!
//! Event `s` carries `prev_hash = SHA256(canonical(s-1) || mac(s-1))` and
//! `mac = HMAC(K_s, canonical(s))`, with `K_s = HMAC(K_{s-1}, "ratchet")` and
//! `K_root = HMAC(K_0, "ratchet")`, `K_0 = HKDF(recovery seed, audit root)`.
//! Only the newest key is stored (wrapped under VK, same transaction as the event), so code
//! holding VK can recompute the MAC of the newest event but not of any earlier one.
//!
//! Protection level (stated honestly): detection, not prevention. Daily `verify` detects edits,
//! reordering and deletions of stored events, including tail truncation; `verify --full` with the
//! recovery phrase additionally detects an attacker who held VK forging any event but the newest.

use crate::vault::{Error, Vault};
use hmac::{Hmac, Mac};
use ls_audit::{BreakKind, Encoder, Link};
use ls_crypto::SecretKey32;
use ls_crypto::aead::{self, Aad, Sealed};
use ls_crypto::recovery::RecoveryPhrase;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::Sha256;

type Result<T> = std::result::Result<T, Error>;

pub(crate) const SCHEMA_V2: &str = "
CREATE TABLE audit_events(
  seq INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  session_id TEXT,
  actor_pid INTEGER NOT NULL,
  actor_start INTEGER NOT NULL,
  actor_exe TEXT NOT NULL,
  actor_exe_hash TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  policy_rule TEXT NOT NULL,
  decision TEXT NOT NULL,
  prev_hash BLOB NOT NULL,
  mac BLOB NOT NULL);
CREATE TABLE audit_key(
  id INTEGER PRIMARY KEY CHECK (id = 1),
  seq INTEGER NOT NULL,
  root_seq INTEGER NOT NULL,
  anchored INTEGER NOT NULL,
  nonce BLOB NOT NULL,
  ct BLOB NOT NULL);
";

const DOMAIN: &[u8] = b"locksmith-audit-v1";

/// One decision to record. Identifiers only: never a secret value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuditRecord {
    pub ts: i64,
    pub session_id: Option<String>,
    pub actor_pid: u32,
    pub actor_start: u64,
    pub actor_exe: String,
    pub actor_exe_hash: String,
    /// ACCESS, CREATE, ROTATE, REVOKE, BLOCKED, UNLOCK, LOCK, SESSION_START, ...
    pub action: String,
    /// `project/env/NAME` or another identifier.
    pub target: Option<String>,
    pub policy_rule: String,
    /// ALLOW or DENY.
    pub decision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    pub seq: u64,
    pub record: AuditRecord,
    pub prev_hash: [u8; 32],
    pub mac: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub events: u64,
    /// First sequence number whose chain, order or MAC check failed.
    pub broken_at: Option<u64>,
    /// Human summary (coverage of the full check, legacy roots, etc.).
    pub detail: String,
}

fn hmac(k: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(k).expect("any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

fn ratchet(k: &SecretKey32) -> SecretKey32 {
    SecretKey32::from_bytes(hmac(k.expose(), b"ratchet"))
}

/// Deterministic encoding (`ls_audit::Encoder`): domain tag, then every field as u32 length +
/// bytes, in fixed order. Pinned by the golden vectors below.
pub(crate) fn canonical(seq: u64, r: &AuditRecord, prev: &[u8; 32]) -> Vec<u8> {
    let mut e = Encoder::new(DOMAIN);
    e.field(&seq.to_be_bytes())
        .field(&r.ts.to_be_bytes())
        .opt_field(r.session_id.as_deref().map(str::as_bytes))
        .field(&r.actor_pid.to_be_bytes())
        .field(&r.actor_start.to_be_bytes())
        .field(r.actor_exe.as_bytes())
        .field(r.actor_exe_hash.as_bytes())
        .field(r.action.as_bytes())
        .opt_field(r.target.as_deref().map(str::as_bytes))
        .field(r.policy_rule.as_bytes())
        .field(r.decision.as_bytes())
        .field(prev);
    e.finish()
}

/// `SHA256(canonical || mac)`: the vault ledger links over the MAC as well.
fn row_hash(e: &StoredEvent) -> [u8; 32] {
    ls_audit::row_hash(&canonical(e.seq, &e.record, &e.prev_hash), &e.mac)
}

struct KeyRow {
    key: SecretKey32,
    seq: u64,
    root_seq: u64,
    anchored: bool,
}

fn key_aad(seq: u64) -> Aad {
    Aad::new().field(b"audit-key").field(&seq.to_be_bytes())
}

fn store_key(c: &Connection, vk: &SecretKey32, k: &KeyRow) -> Result<()> {
    let s = aead::seal(vk, k.key.expose(), &key_aad(k.seq))?;
    c.execute(
        "INSERT INTO audit_key(id,seq,root_seq,anchored,nonce,ct) VALUES(1,?1,?2,?3,?4,?5)
         ON CONFLICT(id) DO UPDATE SET seq=?1, root_seq=?2, anchored=?3, nonce=?4, ct=?5",
        params![
            k.seq as i64,
            k.root_seq as i64,
            k.anchored,
            &s.nonce[..],
            s.ct
        ],
    )?;
    Ok(())
}

fn load_key(c: &Connection, vk: &SecretKey32) -> Result<Option<KeyRow>> {
    let row = c
        .query_row(
            "SELECT seq, root_seq, anchored, nonce, ct FROM audit_key WHERE id=1",
            [],
            |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, bool>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((seq, root_seq, anchored, nonce, ct)) = row else {
        return Ok(None);
    };
    let corrupt = || Error::Invalid("audit key row is corrupt".into());
    let sealed = Sealed {
        nonce: nonce.try_into().map_err(|_| corrupt())?,
        ct,
    };
    let b = aead::open(vk, &sealed, &key_aad(seq))?;
    let arr: [u8; 32] = b.expose().try_into().map_err(|_| corrupt())?;
    Ok(Some(KeyRow {
        key: SecretKey32::from_bytes(arr),
        seq,
        root_seq,
        anchored,
    }))
}

fn last_seq(c: &Connection) -> Result<u64> {
    Ok(
        c.query_row("SELECT COALESCE(MAX(seq),0) FROM audit_events", [], |r| {
            r.get::<_, i64>(0)
        })? as u64,
    )
}

fn event_from_row(r: &rusqlite::Row) -> rusqlite::Result<StoredEvent> {
    let b32 = |v: Vec<u8>| -> rusqlite::Result<[u8; 32]> {
        v.try_into().map_err(|_| {
            rusqlite::Error::InvalidColumnType(0, "hash".into(), rusqlite::types::Type::Blob)
        })
    };
    Ok(StoredEvent {
        seq: r.get::<_, i64>(0)? as u64,
        record: AuditRecord {
            ts: r.get(1)?,
            session_id: r.get(2)?,
            actor_pid: r.get(3)?,
            actor_start: r.get::<_, i64>(4)? as u64,
            actor_exe: r.get(5)?,
            actor_exe_hash: r.get(6)?,
            action: r.get(7)?,
            target: r.get(8)?,
            policy_rule: r.get(9)?,
            decision: r.get(10)?,
        },
        prev_hash: b32(r.get(11)?)?,
        mac: b32(r.get(12)?)?,
    })
}

const COLS: &str = "seq,ts,session_id,actor_pid,actor_start,actor_exe,actor_exe_hash,action,target,policy_rule,decision,prev_hash,mac";

/// (Re-)root the ratchet at `K_0` from the recovery phrase; the next event uses HMAC(K_0).
pub(crate) fn root_from_phrase(
    c: &Connection,
    vk: &SecretKey32,
    phrase: &RecoveryPhrase,
) -> Result<()> {
    let next = last_seq(c)? + 1;
    store_key(
        c,
        vk,
        &KeyRow {
            key: ratchet(&phrase.audit_root()),
            seq: next,
            root_seq: next,
            anchored: true,
        },
    )
}

/// Vaults created before M3 have no phrase-derived root and the phrase is not available at
/// open: start an unanchored ledger with a random root (`verify --full` says so).
pub(crate) fn ensure_key(c: &Connection, vk: &SecretKey32) -> Result<()> {
    if load_key(c, vk)?.is_some() {
        return Ok(());
    }
    let next = last_seq(c)? + 1;
    store_key(
        c,
        vk,
        &KeyRow {
            key: SecretKey32::random()?,
            seq: next,
            root_seq: next,
            anchored: false,
        },
    )
}

impl Vault {
    /// Append one event; the event and the ratcheted key commit in one transaction.
    pub fn audit_append(&self, rec: &AuditRecord) -> Result<u64> {
        let (c, vk) = self.audit_parts();
        let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
        let k =
            load_key(&tx, vk)?.ok_or_else(|| Error::Invalid("audit ledger has no key".into()))?;
        let last = last_seq(&tx)?;
        let s = last + 1;
        let key = if k.seq == s {
            k.key
        } else if k.seq == last {
            ratchet(&k.key)
        } else {
            return Err(Error::Invalid(format!(
                "audit ledger is inconsistent (key at {}, last event {last}); run `smith audit verify`",
                k.seq
            )));
        };
        let prev = match last {
            0 => [0u8; 32],
            _ => row_hash(&tx.query_row(
                &format!("SELECT {COLS} FROM audit_events WHERE seq=?1"),
                [last as i64],
                event_from_row,
            )?),
        };
        let mac = hmac(key.expose(), &canonical(s, rec, &prev));
        tx.execute(
            &format!(
                "INSERT INTO audit_events({COLS}) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)"
            ),
            params![
                s as i64,
                rec.ts,
                rec.session_id,
                rec.actor_pid,
                rec.actor_start as i64,
                rec.actor_exe,
                rec.actor_exe_hash,
                rec.action,
                rec.target,
                rec.policy_rule,
                rec.decision,
                &prev[..],
                &mac[..]
            ],
        )?;
        store_key(
            &tx,
            vk,
            &KeyRow {
                key,
                seq: s,
                root_seq: k.root_seq,
                anchored: k.anchored,
            },
        )?;
        tx.commit()?;
        // Old wrapped keys must not linger in the WAL; secure_delete scrubs freed pages.
        // shortcut: best effort; a concurrent reader can keep old frames until the next append.
        let _ = c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
        Ok(s)
    }

    /// Newest `limit` events, oldest first.
    pub fn audit_list(&self, limit: u32) -> Result<Vec<StoredEvent>> {
        let (c, _) = self.audit_parts();
        let mut st = c.prepare(&format!(
            "SELECT {COLS} FROM (SELECT * FROM audit_events ORDER BY seq DESC LIMIT ?1) ORDER BY seq"
        ))?;
        let rows = st.query_map([limit], event_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Daily check: contiguous sequence, hash chain, and the newest MAC under the stored key.
    /// With `phrase`, also every MAC from the phrase-derived root (`smith audit verify --full`).
    pub fn audit_verify(&self, phrase: Option<&RecoveryPhrase>) -> Result<VerifyReport> {
        let (c, vk) = self.audit_parts();
        let k = load_key(c, vk)?.ok_or_else(|| Error::Invalid("audit ledger has no key".into()))?;
        let mut st = c.prepare(&format!("SELECT {COLS} FROM audit_events ORDER BY seq"))?;
        let events: Vec<StoredEvent> = st
            .query_map([], event_from_row)?
            .collect::<rusqlite::Result<_>>()?;
        let n = events.len() as u64;
        let broken = |seq: u64, why: &str| VerifyReport {
            events: n,
            broken_at: Some(seq),
            detail: format!("event {seq}: {why}"),
        };
        // No stored hash and no checkpoints here: tail truncation is caught by the key position.
        let walk = ls_audit::verify(
            events.iter().map(|e| Link {
                seq: e.seq,
                prev_hash: e.prev_hash,
                hash: row_hash(e),
                stored_hash: None,
            }),
            &[],
        );
        if let Some(b) = walk.broken {
            return Ok(match b.kind {
                BreakKind::Sequence => broken(b.seq, "missing (deleted or reordered)"),
                _ => broken(b.seq, "hash chain broken (edited, deleted or reordered)"),
            });
        }
        // The stored key must sit exactly on the newest event, or just after it on a fresh root.
        match events.last() {
            Some(last) if k.seq == last.seq => {
                let mac = hmac(
                    k.key.expose(),
                    &canonical(last.seq, &last.record, &last.prev_hash),
                );
                if mac != last.mac {
                    return Ok(broken(last.seq, "authentication failed"));
                }
            }
            Some(last) if k.seq == k.root_seq && k.root_seq == last.seq + 1 => {}
            Some(last) => {
                return Ok(broken(
                    last.seq + 1,
                    "later events were removed (the ledger key is ahead of the newest event)",
                ));
            }
            None if k.seq == k.root_seq && k.seq == 1 => {}
            None => return Ok(broken(1, "events were removed")),
        }
        let mut detail = format!("{n} events; hash chain and newest MAC ok");
        if let Some(phrase) = phrase {
            if !k.anchored {
                detail = format!(
                    "{n} events; chain ok; full check unavailable: this ledger's root predates M3 \
                     and is not derived from the recovery phrase (run `smith vault recovery rotate` to anchor it)"
                );
            } else {
                let mut key = ratchet(&phrase.audit_root());
                for e in events.iter().filter(|e| e.seq >= k.root_seq) {
                    if hmac(key.expose(), &canonical(e.seq, &e.record, &e.prev_hash)) != e.mac {
                        return Ok(broken(
                            e.seq,
                            "authentication failed under the recovery-phrase root (forged, or wrong phrase)",
                        ));
                    }
                    key = ratchet(&key);
                }
                detail = format!("{n} events; every MAC verified from the recovery phrase");
                if k.root_seq > 1 {
                    detail.push_str(&format!(
                        "; events 1..{} predate the current recovery phrase and are chain-checked only",
                        k.root_seq - 1
                    ));
                }
            }
        }
        Ok(VerifyReport {
            events: n,
            broken_at: None,
            detail,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;
    use ls_crypto::kdf::KdfParams;

    const WEAK: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    fn rec(action: &str, target: &str) -> AuditRecord {
        AuditRecord {
            ts: 1_700_000_000,
            session_id: Some("s1".into()),
            actor_pid: 42,
            actor_start: 7,
            actor_exe: "/usr/local/bin/smith".into(),
            actor_exe_hash: "ab".into(),
            action: action.into(),
            target: Some(target.into()),
            policy_rule: "lease".into(),
            decision: "ALLOW".into(),
        }
    }

    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn vault() -> (Dir, Vault, RecoveryPhrase) {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let d = Dir(std::env::temp_dir().join(format!(
            "ls-audit-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        )));
        let phrase = RecoveryPhrase::generate().unwrap();
        let v = Vault::create(&d.0, b"pw", WEAK, true, &phrase).unwrap();
        (d, v, phrase)
    }

    fn append5(v: &Vault) {
        for i in 0..5u64 {
            assert_eq!(
                v.audit_append(&rec("ACCESS", &format!("p/e/K{i}")))
                    .unwrap(),
                i + 1
            );
        }
    }

    #[test]
    fn append_and_verify_daily_and_full() {
        let (_d, v, phrase) = vault();
        assert_eq!(v.audit_verify(None).unwrap().broken_at, None, "empty");
        append5(&v);
        let r = v.audit_verify(None).unwrap();
        assert_eq!((r.events, r.broken_at), (5, None), "{}", r.detail);
        let full = v.audit_verify(Some(&phrase)).unwrap();
        assert_eq!(full.broken_at, None, "{}", full.detail);
        assert!(full.detail.contains("every MAC"));
        let other = RecoveryPhrase::generate().unwrap();
        assert_eq!(v.audit_verify(Some(&other)).unwrap().broken_at, Some(1));
        let seqs: Vec<u64> = v.audit_list(2).unwrap().iter().map(|e| e.seq).collect();
        assert_eq!(seqs, [4, 5]);
    }

    #[test]
    fn tamper_delete_reorder_truncate_are_detected() {
        let cases: &[(&str, u64)] = &[
            ("UPDATE audit_events SET target='p/e/X' WHERE seq=2", 3),
            ("UPDATE audit_events SET decision='DENY' WHERE seq=5", 5),
            ("DELETE FROM audit_events WHERE seq=3", 3),
            (
                "UPDATE audit_events SET seq=-seq WHERE seq IN (2,3);
                 UPDATE audit_events SET seq=5+seq WHERE seq<0",
                2,
            ),
            ("DELETE FROM audit_events WHERE seq=5", 5),
            ("DELETE FROM audit_events", 1),
        ];
        for (q, at) in cases {
            let (_d, v, _) = vault();
            append5(&v);
            v.audit_parts().0.execute_batch(q).unwrap();
            let r = v.audit_verify(None).unwrap();
            assert_eq!(r.broken_at, Some(*at), "{q}: {}", r.detail);
        }
    }

    #[test]
    fn current_key_cannot_forge_an_earlier_event() {
        // An attacker with VK holds only the newest key: rewriting event 2 and re-chaining
        // everything with that key fools the daily check but not the full check.
        let (_d, v, phrase) = vault();
        append5(&v);
        let (c, vk) = v.audit_parts();
        let k = load_key(c, vk).unwrap().unwrap();
        let mut evs = v.audit_list(10).unwrap();
        evs[1].record.target = Some("p/e/FORGED".into());
        let mut prev = [0u8; 32];
        for e in evs.iter_mut() {
            e.prev_hash = prev;
            e.mac = hmac(k.key.expose(), &canonical(e.seq, &e.record, &e.prev_hash));
            prev = row_hash(e);
            c.execute(
                "UPDATE audit_events SET target=?1, prev_hash=?2, mac=?3 WHERE seq=?4",
                params![e.record.target, &e.prev_hash[..], &e.mac[..], e.seq as i64],
            )
            .unwrap();
        }
        assert_eq!(
            v.audit_verify(None).unwrap().broken_at,
            None,
            "daily is fooled"
        );
        assert_eq!(v.audit_verify(Some(&phrase)).unwrap().broken_at, Some(1));
    }

    #[test]
    fn key_ratchets_and_is_stored_once() {
        let (_d, v, _) = vault();
        let (c, vk) = v.audit_parts();
        let k1 = load_key(c, vk).unwrap().unwrap();
        assert_eq!((k1.seq, k1.root_seq, k1.anchored), (1, 1, true));
        v.audit_append(&rec("ACCESS", "p/e/A")).unwrap();
        v.audit_append(&rec("ACCESS", "p/e/B")).unwrap();
        let k2 = load_key(c, vk).unwrap().unwrap();
        assert_eq!(k2.seq, 2);
        assert_eq!(k2.key.expose(), ratchet(&k1.key).expose());
        let rows: i64 = c
            .query_row("SELECT COUNT(*) FROM audit_key", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[test]
    fn rotation_reanchors_and_reports_coverage() {
        let (_d, mut v, _) = vault();
        v.audit_append(&rec("ACCESS", "p/e/A")).unwrap();
        let new = RecoveryPhrase::generate().unwrap();
        v.rotate_recovery(&new).unwrap();
        v.audit_append(&rec("ACCESS", "p/e/B")).unwrap();
        assert_eq!(v.audit_verify(None).unwrap().broken_at, None);
        let r = v.audit_verify(Some(&new)).unwrap();
        assert_eq!(r.broken_at, None, "{}", r.detail);
        assert!(r.detail.contains("predate"), "{}", r.detail);
    }

    #[test]
    fn pre_m3_vault_gets_an_unanchored_ledger_and_says_so() {
        let (d, v, phrase) = vault();
        v.audit_parts()
            .0
            .execute_batch("DELETE FROM audit_key")
            .unwrap();
        drop(v);
        let v = Vault::open_passphrase(&d.0, b"pw", true).unwrap();
        v.audit_append(&rec("ACCESS", "p/e/A")).unwrap();
        assert_eq!(v.audit_verify(None).unwrap().broken_at, None);
        let r = v.audit_verify(Some(&phrase)).unwrap();
        assert_eq!(r.broken_at, None);
        assert!(r.detail.contains("unavailable"), "{}", r.detail);
    }

    #[test]
    fn ledger_columns_hold_no_values() {
        let (_d, v, _) = vault();
        let cols: Vec<String> = v
            .audit_parts()
            .0
            .prepare("SELECT name FROM pragma_table_info('audit_events')")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(cols.join(","), COLS);
    }

    // Golden vectors (s5-audit-ledger 1.2): recorded from the ls-vault implementation before
    // the chain core moved to ls-audit. They pin the canonical encoding, the row hash, the MAC
    // ratchet and the stored `prev_hash`/`mac` columns. Never update them to make a test pass:
    // a change here means existing ledgers no longer verify.

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn golden_canonical_row_hash_and_ratchet() {
        let some = rec("ACCESS", "p/e/K0");
        let prev = [0x11u8; 32];
        let none = AuditRecord {
            session_id: None,
            target: None,
            ..rec("UNLOCK", "")
        };
        let e = StoredEvent {
            seq: 3,
            record: some.clone(),
            prev_hash: prev,
            mac: [0x22u8; 32],
        };
        // Public test key, not a secret.
        let k0 = SecretKey32::from_bytes([7u8; 32]);
        let k1 = ratchet(&k0);
        let k2 = ratchet(&k1);
        let got = [
            ("canonical_some", hx(&canonical(3, &some, &prev))),
            ("canonical_none", hx(&canonical(1, &none, &[0u8; 32]))),
            ("row_hash", hx(&row_hash(&e))),
            ("ratchet_1", hx(k1.expose())),
            ("ratchet_2", hx(k2.expose())),
            ("mac", hx(&hmac(k2.expose(), &canonical(3, &some, &prev)))),
        ];
        let got: Vec<(&str, &str)> = got.iter().map(|(n, h)| (*n, h.as_str())).collect();
        assert_eq!(got, GOLDEN_VECTORS);
    }

    #[test]
    fn golden_stored_ledger_columns() {
        // BIP-39 all-zero-entropy test phrase (public vector), so the ratchet root is fixed.
        let phrase = RecoveryPhrase::parse(&format!("{}art", "abandon ".repeat(23))).unwrap();
        let d = Dir(std::env::temp_dir().join(format!("ls-audit-golden-{}", std::process::id())));
        let v = Vault::create(&d.0, b"pw", WEAK, true, &phrase).unwrap();
        v.audit_append(&rec("ACCESS", "p/e/A")).unwrap();
        v.audit_append(&AuditRecord {
            session_id: None,
            target: None,
            ..rec("LOCK", "")
        })
        .unwrap();
        v.audit_append(&rec("ROTATE", "p/e/B")).unwrap();
        let got: Vec<(u64, String, String)> = v
            .audit_list(10)
            .unwrap()
            .iter()
            .map(|e| (e.seq, hx(&e.prev_hash), hx(&e.mac)))
            .collect();
        let want: Vec<(u64, String, String)> = GOLDEN_LEDGER
            .iter()
            .map(|(s, p, m)| (*s, p.to_string(), m.to_string()))
            .collect();
        assert_eq!(got, want);
        assert_eq!(v.audit_verify(Some(&phrase)).unwrap().broken_at, None);
    }

    const GOLDEN_VECTORS: &[(&str, &str)] = &[
        (
            "canonical_some",
            "6c6f636b736d6974682d61756469742d7631\
             00000008000000000000000300000008000000006553f100\
             0000000301733100000004\
             0000002a000000080000000000000007\
             000000142f7573722f6c6f63616c2f62696e2f736d697468\
             000000026162000000064143434553530000000701702f652f4b30\
             000000056c6561736500000005414c4c4f57\
             000000201111111111111111111111111111111111111111111111111111111111111111",
        ),
        (
            "canonical_none",
            "6c6f636b736d6974682d61756469742d7631\
             00000008000000000000000100000008000000006553f100\
             000000010000000004\
             0000002a000000080000000000000007\
             000000142f7573722f6c6f63616c2f62696e2f736d697468\
             00000002616200000006554e4c4f434b0000000100\
             000000056c6561736500000005414c4c4f57\
             000000200000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "row_hash",
            "2e590baf529c1410a2adad7ef5b8431a76d86873ed1f1e5ed99cdda3aea9926e",
        ),
        (
            "ratchet_1",
            "ff4afd707212a9211a8df9e34ab936afeffc9f6483b9cbc71c7c0aede156abd3",
        ),
        (
            "ratchet_2",
            "42e44c47ce67e07a23710ba7056ab832dcd3d3ab32e76c404dc5e9868f407854",
        ),
        (
            "mac",
            "cf03054fb90bc7207b9f78f288dfda7aac6b7cdb429101898342142793c7cae1",
        ),
    ];
    const GOLDEN_LEDGER: &[(u64, &str, &str)] = &[
        (
            1,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "010212b6739e9d2c6c1d12b99c57d29c0080d9c53a38aad14e043ec729f0b3cc",
        ),
        (
            2,
            "021f3952e2bf78c646c59131eeabda14581a9c257f03aeb0feda3a2cf45a6064",
            "1c4cafd0c67284fd0d1fda427056464d8029ba39625531dfe65a2a00a2a9e141",
        ),
        (
            3,
            "9e7c43a763ba89c6071b7aac22ad416f87aaf2fea0c814312d4c288fed7dc88a",
            "18fb5dad7d9ca38214d8ba2e6a4d20899ffdb03fd8b5a1daf1ace1ddcc56f81f",
        ),
    ];
}
