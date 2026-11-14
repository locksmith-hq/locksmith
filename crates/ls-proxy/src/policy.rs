//! Push policy for `git-receive-pack` requests (design D4): parse the pkt-line command list and
//! refuse deletes (and stale updates, when the advertised value is known) of protected refs.

use crate::RefUpdate;
use std::collections::HashMap;

const ZERO: char = '0';

/// Walks pkt-lines from the start of `pkt`. Returns the offset just past the first flush-pkt
/// (`0000`), or `None` when more bytes are needed.
pub fn commands_end(pkt: &[u8]) -> Result<Option<usize>, String> {
    let mut i = 0;
    loop {
        match next_pkt(&pkt[i..])? {
            None => return Ok(None),
            Some((0, _)) => return Ok(Some(i + 4)),
            Some((len, _)) => i += len,
        }
    }
}

/// Returns `(total_len, payload)`; total_len 0 is a flush-pkt.
fn next_pkt(b: &[u8]) -> Result<Option<(usize, &[u8])>, String> {
    if b.len() < 4 {
        return Ok(None);
    }
    let hex = std::str::from_utf8(&b[..4]).map_err(|_| "bad pkt-line length")?;
    if !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("bad pkt-line length".into());
    }
    let len = usize::from_str_radix(hex, 16).map_err(|_| "bad pkt-line length")?;
    match len {
        0 => Ok(Some((0, &[]))),
        1..=3 => Err("bad pkt-line length".into()),
        _ if b.len() < len => Ok(None),
        _ => Ok(Some((len, &b[4..len]))),
    }
}

fn is_oid(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Parses the receive-pack command list (`<old> <new> <ref>[\0caps]` lines then `0000`).
pub fn parse_commands(pkt: &[u8]) -> Result<Vec<RefUpdate>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let (len, payload) = next_pkt(&pkt[i..])?.ok_or("incomplete command list")?;
        if len == 0 {
            return Ok(out);
        }
        i += len;
        let line = payload.strip_suffix(b"\n").unwrap_or(payload);
        let line = line.split(|&c| c == 0).next().unwrap_or_default();
        let line = std::str::from_utf8(line).map_err(|_| "non-UTF-8 command")?;
        if line.starts_with("push-cert") {
            return Err("signed pushes (push-cert) are not supported through locksmith".into());
        }
        if line.starts_with("shallow ") {
            continue;
        }
        let mut p = line.splitn(3, ' ');
        let (Some(old), Some(new), Some(name)) = (p.next(), p.next(), p.next()) else {
            return Err("malformed ref update command".into());
        };
        if !is_oid(old) || !is_oid(new) || old.len() != new.len() || name.is_empty() {
            return Err("malformed ref update command".into());
        }
        out.push(RefUpdate {
            old: old.into(),
            new: new.into(),
            name: name.into(),
        });
    }
}

fn matches(pattern: &str, name: &str) -> bool {
    [format!("refs/heads/{pattern}"), pattern.to_string()]
        .iter()
        .any(|c| match c.strip_suffix("/*") {
            Some(prefix) => name
                .strip_prefix(prefix)
                .is_some_and(|r| r.starts_with('/')),
            None => name == c,
        })
}

fn rule(name: &str, why: &str) -> String {
    format!("protected ref {name}: {why} by .locksmith.toml [git] protected")
}

/// Delete-only policy: refuse deleting a protected ref.
pub fn check(updates: &[RefUpdate], protected: &[String]) -> Result<(), String> {
    check_with_advertised(updates, protected, &HashMap::new())
}

/// Also refuses `old != advertised[ref]` on protected refs when the advertised value is known.
pub fn check_with_advertised(
    updates: &[RefUpdate],
    protected: &[String],
    advertised: &HashMap<String, String>,
) -> Result<(), String> {
    for u in updates {
        if !protected.iter().any(|p| matches(p, &u.name)) {
            continue;
        }
        if u.new.chars().all(|c| c == ZERO) {
            return Err(rule(&u.name, "deletion is not allowed"));
        }
        if advertised.get(&u.name).is_some_and(|a| *a != u.old) {
            return Err(rule(
                &u.name,
                "stale update (old value differs from the remote's current value) is not allowed",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "1111111111111111111111111111111111111111";
    const Z: &str = "0000000000000000000000000000000000000000";

    fn upd(old: &str, new: &str, name: &str) -> RefUpdate {
        RefUpdate {
            old: old.into(),
            new: new.into(),
            name: name.into(),
        }
    }

    fn pkt(s: &str) -> Vec<u8> {
        format!("{:04x}{s}", s.len() + 4).into_bytes()
    }

    #[test]
    fn delete_protected_denied() {
        let e = check(&[upd(A, Z, "refs/heads/main")], &["main".into()]).unwrap_err();
        assert_eq!(
            e,
            "protected ref refs/heads/main: deletion is not allowed by .locksmith.toml [git] protected"
        );
    }

    #[test]
    fn normal_push_and_unprotected_delete_allowed() {
        let p = ["main".to_string()];
        assert!(check(&[upd(A, A, "refs/heads/main")], &p).is_ok());
        assert!(check(&[upd(A, Z, "refs/heads/topic")], &p).is_ok());
    }

    #[test]
    fn pattern_matching() {
        let p = ["release/*".to_string(), "refs/tags/v1".to_string()];
        assert!(check(&[upd(A, Z, "refs/heads/release/1.0")], &p).is_err());
        assert!(check(&[upd(A, Z, "refs/heads/release")], &p).is_ok());
        assert!(check(&[upd(A, Z, "refs/tags/v1")], &p).is_err());
        assert!(check(&[upd(A, Z, "refs/heads/xrelease/1")], &p).is_ok());
    }

    #[test]
    fn stale_old_denied_when_advertised_known() {
        let adv = HashMap::from([("refs/heads/main".to_string(), A.to_string())]);
        let b = "2222222222222222222222222222222222222222";
        let p = ["main".to_string()];
        assert!(check_with_advertised(&[upd(b, A, "refs/heads/main")], &p, &adv).is_err());
        assert!(check_with_advertised(&[upd(A, b, "refs/heads/main")], &p, &adv).is_ok());
    }

    #[test]
    fn parses_commands_and_caps() {
        let mut b = pkt(&format!(
            "{A} {Z} refs/heads/x\0report-status side-band-64k\n"
        ));
        b.extend(pkt(&format!("{Z} {A} refs/heads/y")));
        b.extend(b"0000PACK...");
        let end = commands_end(&b).unwrap().unwrap();
        let u = parse_commands(&b[..end]).unwrap();
        assert_eq!(
            u,
            vec![upd(A, Z, "refs/heads/x"), upd(Z, A, "refs/heads/y")]
        );
        assert_eq!(commands_end(&b[..10]).unwrap(), None);
    }

    #[test]
    fn shallow_skipped_and_push_cert_refused() {
        let mut b = pkt(&format!("shallow {A}"));
        b.extend(pkt(&format!("{A} {A} refs/heads/x\0caps")));
        b.extend(b"0000");
        assert_eq!(parse_commands(&b).unwrap().len(), 1);
        let mut c = pkt("push-cert\0caps");
        c.extend(b"0000");
        assert!(parse_commands(&c).is_err());
        assert!(parse_commands(b"0000").unwrap().is_empty());
        assert!(parse_commands(b"zzzz").is_err());
    }
}
