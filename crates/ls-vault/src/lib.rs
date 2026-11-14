//! Encrypted vault storage: `vault.header` sidecar plus a SQLCipher `vault.db`.
use std::path::Path;

mod doctor;
mod header;
mod vault;
pub use vault::*;

use rusqlite::Connection;

/// Opens (or creates) a SQLCipher DB keyed with a raw 32-byte key (no KDF on a passphrase).
/// A wrong key fails here, not on first real query.
pub fn open_encrypted(path: &Path, key: &[u8; 32]) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    // Raw-key blob syntax; the pragma string holds key material, so don't log it.
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))?;
    // Best effort: unknown pragmas are ignored by SQLite.
    conn.execute_batch("PRAGMA cipher_memory_security = ON;")?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "CANARY_KEY_NAME_12345";

    #[test]
    fn encrypted_roundtrip_and_wrong_key() {
        let path = std::env::temp_dir().join(format!("ls-vault-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let (k, bad) = ([7u8; 32], [8u8; 32]);

        let c = open_encrypted(&path, &k).unwrap();
        c.execute_batch("CREATE TABLE t(name TEXT)").unwrap();
        c.execute("INSERT INTO t VALUES (?1)", [CANARY]).unwrap();
        drop(c);

        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()));

        let c = open_encrypted(&path, &k).unwrap();
        let got: String = c.query_row("SELECT name FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(got, CANARY);
        let mem: String = c
            .query_row("PRAGMA cipher_memory_security", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mem, "1");
        drop(c);

        assert!(open_encrypted(&path, &bad).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
