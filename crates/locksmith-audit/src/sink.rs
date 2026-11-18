//! Export sinks (S5 design decision 7, task 5.2).
//!
//! [`AuditSink`] is what `locksmith-audit export` writes through; [`FileSink`] is the local
//! directory of JSON Lines that `verify --dir` reads ([`ls_audit::export`] defines the format).
//! The P1 S3 Object Lock sink implements the same trait.
//!
//! The cursor is the commit point. A batch is written in this order, each file to a temp file
//! in the same directory, fsynced, renamed over its name and the directory fsynced:
//! 1. the batch's event file `events-<first_seq>.jsonl`;
//! 2. `checkpoints.jsonl`, rewritten with the committed lines plus the new ones;
//! 3. `cursor.json`.
//!
//! A crash before step 3 leaves the cursor where it was. The next commit removes what the
//! interrupted one wrote above the cursor (event files whose first `seq` is above it and
//! checkpoint lines above its `checkpoint_seq`) before writing, so no event or checkpoint is
//! ever in the directory twice.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use ls_audit::export::{
    CHECKPOINTS_FILE, CURSOR_FILE, Cursor, checkpoint_line, cursor_line, event_line,
    events_file_first_seq, events_file_name, parse_cursor,
};
use ls_audit::{Record, SignedCheckpoint};
use serde_json::Value;
use uuid::Uuid;

use crate::Error;

/// Where an export goes.
pub trait AuditSink {
    /// The committed export position of `org`; `None` before its first export.
    fn cursor(&mut self, org: Uuid) -> Result<Option<Cursor>, Error>;

    /// Store `events` and `checkpoints`, which continue the chain at `from` (the caller checked
    /// them with [`ls_audit::export::check_batch`]), and commit the advanced cursor, which is
    /// returned. `from` must be the sink's committed cursor (or [`Cursor::start`] before the
    /// first export); otherwise nothing is written. Either the whole batch is committed or, after
    /// a crash, none of it counts and the next commit from the same cursor replaces it.
    fn commit(
        &mut self,
        from: &Cursor,
        events: &[Record],
        checkpoints: &[SignedCheckpoint],
    ) -> Result<Cursor, Error>;
}

/// Lock file at the top of the export directory: one export at a time.
pub const LOCK_FILE: &str = ".export.lock";
/// Prefix of the temp files a commit writes before renaming them.
const TMP_PREFIX: &str = ".tmp-export-";

/// The local file sink: `<dir>/<org_id>/{events-<first_seq>.jsonl, checkpoints.jsonl,
/// cursor.json}`. Holds an exclusive lock on `<dir>/.export.lock` while it exists.
pub struct FileSink {
    dir: PathBuf,
    _lock: File,
}

fn io_err(p: &Path) -> impl Fn(std::io::Error) -> Error + '_ {
    move |e| Error::Io(format!("{}: {e}", p.display()))
}

impl FileSink {
    /// Open (creating it if needed) the export directory and take its lock. Fails if another
    /// export holds the lock.
    pub fn open(dir: &Path) -> Result<Self, Error> {
        if !dir.exists() {
            fs::create_dir_all(dir).map_err(io_err(dir))?;
            if let Some(parent) = dir.parent() {
                sync_dir(parent)?;
            }
        }
        let lock_path = dir.join(LOCK_FILE);
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(io_err(&lock_path))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(Error::Io(format!(
                    "{}: another export is running",
                    dir.display()
                )));
            }
            Err(fs::TryLockError::Error(e)) => return Err(io_err(&lock_path)(e)),
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            _lock: lock,
        })
    }

    fn org_dir(&self, org: Uuid) -> PathBuf {
        self.dir.join(org.hyphenated().to_string())
    }

    /// `(first_seq, path)` of every event file in `org_dir`.
    fn event_files(org_dir: &Path) -> Result<Vec<(u64, PathBuf)>, Error> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(org_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(io_err(org_dir)(e)),
        };
        for entry in entries {
            let entry = entry.map_err(io_err(org_dir))?;
            if let Some(first) = entry.file_name().to_str().and_then(events_file_first_seq) {
                out.push((first, entry.path()));
            }
        }
        out.sort();
        Ok(out)
    }

    /// Remove what an interrupted commit left above `from`: temp files and event files whose
    /// first `seq` is above the cursor. Returns whether anything was removed.
    fn remove_uncommitted(org_dir: &Path, from: &Cursor) -> Result<bool, Error> {
        let mut removed = false;
        for (first, path) in Self::event_files(org_dir)? {
            if first > from.seq {
                fs::remove_file(&path).map_err(io_err(&path))?;
                removed = true;
            }
        }
        for entry in fs::read_dir(org_dir).map_err(io_err(org_dir))? {
            let entry = entry.map_err(io_err(org_dir))?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(TMP_PREFIX))
            {
                let path = entry.path();
                fs::remove_file(&path).map_err(io_err(&path))?;
                removed = true;
            }
        }
        Ok(removed)
    }

    /// The committed lines of `checkpoints.jsonl` (`seq <= from.checkpoint_seq`) and whether
    /// any uncommitted line was dropped.
    fn committed_checkpoint_lines(
        org_dir: &Path,
        from: &Cursor,
    ) -> Result<(Vec<String>, bool), Error> {
        let path = org_dir.join(CHECKPOINTS_FILE);
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok((Vec::new(), false)),
            Err(e) => return Err(io_err(&path)(e)),
        };
        let mut kept = Vec::new();
        let mut dropped = false;
        for (i, line) in text.lines().enumerate() {
            let seq = serde_json::from_str::<Value>(line)
                .ok()
                .and_then(|v| v.get("seq").and_then(Value::as_u64))
                .ok_or_else(|| {
                    Error::Io(format!(
                        "{}:{}: not a checkpoint line; refusing to rewrite the file",
                        path.display(),
                        i + 1
                    ))
                })?;
            if seq <= from.checkpoint_seq {
                kept.push(line.to_owned());
            } else {
                dropped = true;
            }
        }
        Ok((kept, dropped))
    }
}

impl AuditSink for FileSink {
    fn cursor(&mut self, org: Uuid) -> Result<Option<Cursor>, Error> {
        let org_dir = self.org_dir(org);
        let path = org_dir.join(CURSOR_FILE);
        let text = match fs::read(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // A commit writes the start cursor before any event file, so event files
                // without a cursor mean the cursor was removed. Starting over would replace
                // exported history with the database's current version: refuse.
                if !Self::event_files(&org_dir)?.is_empty() {
                    return Err(Error::Io(format!(
                        "{}: event files but no {CURSOR_FILE}; refusing to export into it",
                        org_dir.display()
                    )));
                }
                return Ok(None);
            }
            Err(e) => return Err(io_err(&path)(e)),
        };
        let cursor = serde_json::from_slice::<Value>(&text)
            .ok()
            .as_ref()
            .and_then(parse_cursor)
            .filter(|c| c.org_id == org)
            .ok_or_else(|| Error::Io(format!("{}: not a cursor for this org", path.display())))?;
        Ok(Some(cursor))
    }

    fn commit(
        &mut self,
        from: &Cursor,
        events: &[Record],
        checkpoints: &[SignedCheckpoint],
    ) -> Result<Cursor, Error> {
        let org = from.org_id;
        let stored = self.cursor(org)?.unwrap_or(Cursor::start(org));
        if stored != *from {
            return Err(Error::Io(format!(
                "org {}: the export cursor moved (at seq {}, batch starts after seq {})",
                org.hyphenated(),
                stored.seq,
                from.seq
            )));
        }
        if events.is_empty() && checkpoints.is_empty() {
            return Ok(stored);
        }
        let org_dir = self.org_dir(org);
        if !org_dir.exists() {
            fs::create_dir(&org_dir).map_err(io_err(&org_dir))?;
            sync_dir(&self.dir)?;
        }
        if !org_dir.join(CURSOR_FILE).exists() {
            // The start cursor goes first, so event files without a cursor never come from an
            // interrupted first export (see `cursor`).
            write_cursor(&org_dir, from)?;
        }
        // Read before writing anything, so an unreadable file stops the commit untouched.
        let (mut lines, dropped) = Self::committed_checkpoint_lines(&org_dir, from)?;
        if Self::remove_uncommitted(&org_dir, from)? {
            sync_dir(&org_dir)?;
        }

        if let Some(first) = events.first() {
            let mut text = String::new();
            for r in events {
                text.push_str(&event_line(r).to_string());
                text.push('\n');
            }
            write_atomic(&org_dir, &events_file_name(first.seq), text.as_bytes())?;
        }

        if dropped || !checkpoints.is_empty() {
            lines.extend(checkpoints.iter().map(|c| checkpoint_line(c).to_string()));
            let mut text = String::new();
            for l in &lines {
                text.push_str(l);
                text.push('\n');
            }
            write_atomic(&org_dir, CHECKPOINTS_FILE, text.as_bytes())?;
        }

        let next = from.advance(events, checkpoints);
        write_cursor(&org_dir, &next)?;
        Ok(next)
    }
}

fn write_cursor(org_dir: &Path, c: &Cursor) -> Result<(), Error> {
    write_atomic(
        org_dir,
        CURSOR_FILE,
        format!("{}\n", cursor_line(c)).as_bytes(),
    )
}

/// Write `bytes` to `dir/name` atomically: a temp file in `dir`, fsync, rename over the name,
/// fsync `dir`.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), Error> {
    let target = dir.join(name);
    let mut tmp = tempfile::Builder::new()
        .prefix(TMP_PREFIX)
        .tempfile_in(dir)
        .map_err(io_err(dir))?;
    tmp.write_all(bytes).map_err(io_err(tmp.path()))?;
    tmp.as_file().sync_all().map_err(io_err(&target))?;
    tmp.persist(&target).map_err(|e| io_err(&target)(e.error))?;
    sync_dir(dir)
}

/// Make a rename or create in `dir` durable (POSIX: fsync the directory). Windows has no
/// directory handle to fsync; its renames are durable once `MoveFileEx` returns.
fn sync_dir(dir: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(io_err(dir))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ls_audit::export::check_batch;
    use ls_audit::{Actor, Attrs, CheckpointBody, Code, Event, GENESIS, Target, kind, outcome};
    use tempfile::TempDir;

    const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000aa);

    fn chain(n: u64) -> Vec<Record> {
        let mut prev = GENESIS;
        (1..=n)
            .map(|seq| {
                let e = Event {
                    kind: kind::RELAY_ATTEMPT,
                    actor: Actor::Service(Code::new("gateway")),
                    target: Some(Target::Secret(Uuid::from_u128(7))),
                    outcome: outcome::PENDING,
                    attrs: Attrs::new(),
                };
                let r = Record::new(ORG, seq, Uuid::from_u128(seq.into()), 1, &e, prev);
                prev = r.hash;
                r
            })
            .collect()
    }

    fn cp(r: &Record) -> SignedCheckpoint {
        SignedCheckpoint {
            body: CheckpointBody {
                org_id: ORG,
                seq: r.seq,
                hash: r.hash,
                at_micros: 1,
            },
            key_id: "audit-checkpoint:1".into(),
            signature: [0; 64],
        }
    }

    fn org_dir(t: &TempDir) -> PathBuf {
        t.path().join(ORG.hyphenated().to_string())
    }

    /// Every exported event seq in file order, and every checkpoint seq.
    fn exported(t: &TempDir) -> (Vec<u64>, Vec<u64>) {
        let dir = org_dir(t);
        let mut seqs = Vec::new();
        for (_, p) in FileSink::event_files(&dir).unwrap() {
            for l in fs::read_to_string(p).unwrap().lines() {
                let v: Value = serde_json::from_str(l).unwrap();
                seqs.push(v["seq"].as_u64().unwrap());
            }
        }
        let cps = fs::read_to_string(dir.join(CHECKPOINTS_FILE))
            .unwrap_or_default()
            .lines()
            .map(|l| {
                serde_json::from_str::<Value>(l).unwrap()["seq"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        (seqs, cps)
    }

    fn names(t: &TempDir) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(org_dir(t))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn incremental_commits_write_each_event_once() {
        let t = TempDir::new().unwrap();
        let c = chain(7);
        let mut s = FileSink::open(t.path()).unwrap();
        assert_eq!(s.cursor(ORG).unwrap(), None);
        let start = Cursor::start(ORG);
        assert_eq!(s.commit(&start, &[], &[]).unwrap(), start);
        assert!(!org_dir(&t).exists(), "an empty batch writes nothing");

        let c1 = s.commit(&start, &c[..3], &[cp(&c[1])]).unwrap();
        assert_eq!((c1.seq, c1.hash, c1.checkpoint_seq), (3, c[2].hash, 2));
        assert_eq!(s.cursor(ORG).unwrap(), Some(c1));

        // Replaying the first batch from the old cursor is refused and changes nothing.
        assert!(s.commit(&start, &c[..3], &[cp(&c[1])]).is_err());

        check_batch(&c1, &c[3..], &[cp(&c[5])]).unwrap();
        let c2 = s.commit(&c1, &c[3..], &[cp(&c[5])]).unwrap();
        // A checkpoint-only batch.
        let c3 = s.commit(&c2, &[], &[cp(&c[6])]).unwrap();
        assert_eq!((c3.seq, c3.checkpoint_seq), (7, 7));
        assert_eq!(exported(&t), ((1..=7).collect(), vec![2, 6, 7]));
        assert_eq!(
            names(&t),
            [
                "checkpoints.jsonl",
                "cursor.json",
                "events-1.jsonl",
                "events-4.jsonl"
            ]
        );
        drop(s);
        // A new sink resumes from the cursor on disk.
        let mut s = FileSink::open(t.path()).unwrap();
        assert_eq!(s.cursor(ORG).unwrap(), Some(c3));
    }

    #[test]
    fn a_crash_before_the_cursor_moves_does_not_duplicate() {
        let t = TempDir::new().unwrap();
        let c = chain(6);
        let mut s = FileSink::open(t.path()).unwrap();
        let c1 = s
            .commit(&Cursor::start(ORG), &c[..2], &[cp(&c[1])])
            .unwrap();
        // Simulate a crash after steps 1 and 2 of a batch 3..=5 (cursor still at 2): its event
        // file, its checkpoint line, and a stray temp file are on disk.
        let dir = org_dir(&t);
        let orphan: String = c[2..5]
            .iter()
            .map(|r| format!("{}\n", event_line(r)))
            .collect();
        fs::write(dir.join(events_file_name(3)), orphan).unwrap();
        let mut cps = fs::read_to_string(dir.join(CHECKPOINTS_FILE)).unwrap();
        cps.push_str(&format!("{}\n", checkpoint_line(&cp(&c[4]))));
        fs::write(dir.join(CHECKPOINTS_FILE), cps).unwrap();
        fs::write(dir.join(format!("{TMP_PREFIX}x")), "partial").unwrap();
        assert_eq!(s.cursor(ORG).unwrap(), Some(c1));

        // The rerun reads from the cursor again, with a bigger batch.
        let c2 = s.commit(&c1, &c[2..], &[cp(&c[4])]).unwrap();
        assert_eq!(c2.seq, 6);
        assert_eq!(exported(&t), ((1..=6).collect(), vec![2, 5]));
        assert_eq!(
            names(&t),
            [
                "checkpoints.jsonl",
                "cursor.json",
                "events-1.jsonl",
                "events-3.jsonl"
            ]
        );

        // An orphan file from a crashed batch whose first seq differs is removed too.
        fs::write(dir.join(events_file_name(7)), "{}\n").unwrap();
        let c7 = chain(7);
        s.commit(&c2, &c7[6..], &[]).unwrap();
        assert_eq!(exported(&t).0, (1..=7).collect::<Vec<_>>());

        // An uncommitted checkpoint line is dropped even by a batch with no checkpoints.
        let mut cps = fs::read_to_string(dir.join(CHECKPOINTS_FILE)).unwrap();
        cps.push_str(&format!("{}\n", checkpoint_line(&cp(&c7[6]))));
        fs::write(dir.join(CHECKPOINTS_FILE), cps).unwrap();
        let c8 = chain(8);
        let cur = s.cursor(ORG).unwrap().unwrap();
        s.commit(&cur, &c8[7..], &[]).unwrap();
        assert_eq!(exported(&t), ((1..=8).collect(), vec![2, 5]));
    }

    #[test]
    fn a_crash_during_the_first_export_does_not_block_the_next() {
        let t = TempDir::new().unwrap();
        let c = chain(3);
        let mut s = FileSink::open(t.path()).unwrap();
        // The first commit writes the start cursor, then events-1; crash before the cursor moves.
        let dir = org_dir(&t);
        fs::create_dir(&dir).unwrap();
        write_cursor(&dir, &Cursor::start(ORG)).unwrap();
        fs::write(
            dir.join(events_file_name(1)),
            format!("{}\n", event_line(&c[0])),
        )
        .unwrap();
        assert_eq!(s.cursor(ORG).unwrap(), Some(Cursor::start(ORG)));
        s.commit(&Cursor::start(ORG), &c, &[]).unwrap();
        assert_eq!(exported(&t).0, vec![1, 2, 3]);
    }

    #[test]
    fn refuses_files_without_a_cursor_a_foreign_cursor_and_a_second_exporter() {
        let t = TempDir::new().unwrap();
        let c = chain(2);
        let mut s = FileSink::open(t.path()).unwrap();
        assert!(FileSink::open(t.path()).is_err(), "the lock is held");
        s.commit(&Cursor::start(ORG), &c, &[]).unwrap();
        let dir = org_dir(&t);

        let cursor = fs::read_to_string(dir.join(CURSOR_FILE)).unwrap();
        fs::write(
            dir.join(CURSOR_FILE),
            cursor.replace(&ORG.hyphenated().to_string(), &Uuid::nil().to_string()),
        )
        .unwrap();
        assert!(s.cursor(ORG).is_err());

        fs::remove_file(dir.join(CURSOR_FILE)).unwrap();
        assert!(s.cursor(ORG).is_err(), "events-1 without a cursor");

        fs::write(dir.join(CHECKPOINTS_FILE), "not json\n").unwrap();
        fs::remove_file(dir.join(events_file_name(1))).unwrap();
        assert_eq!(s.cursor(ORG).unwrap(), None);
        assert!(
            s.commit(&Cursor::start(ORG), &c, &[]).is_err(),
            "an unreadable checkpoints file is not rewritten"
        );
        assert!(
            FileSink::event_files(&dir).unwrap().is_empty(),
            "nothing written"
        );
    }
}
