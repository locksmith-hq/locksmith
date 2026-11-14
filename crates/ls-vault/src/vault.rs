//! The vault: header + SQLCipher DB, unlock, schema migrations and the repository API.
//! Nothing here prints or formats a secret value.

use crate::header::{self, Body, FORMAT, HEADER_FILE, SealedDto};
use crate::open_encrypted;
use ls_crypto::aead::{self, Aad};
use ls_crypto::kdf::{KdfParams, hkdf, label};
use ls_crypto::recovery::RecoveryPhrase;
use ls_crypto::wrap::{self, WRAP_PASSPHRASE};
use ls_crypto::{CryptoError, SecretBytes, SecretKey32};
use rusqlite::{Connection, OptionalExtension, params};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const DB_FILE: &str = "vault.db";
const VK_VERSION: u32 = 1;

const SCHEMA_V1: &str = "
CREATE TABLE projects(id BLOB PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
CREATE TABLE environments(
  id BLOB PRIMARY KEY,
  project_id BLOB NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(project_id, name));
CREATE TABLE secrets(
  id BLOB PRIMARY KEY,
  environment_id BLOB NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  name TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(environment_id, name));
CREATE TABLE secret_versions(
  id BLOB PRIMARY KEY,
  secret_id BLOB NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  encrypted_dek BLOB NOT NULL, dek_nonce BLOB NOT NULL,
  payload BLOB NOT NULL, payload_nonce BLOB NOT NULL,
  created_at INTEGER NOT NULL, UNIQUE(secret_id, version));
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
";
/// Index + 1 is the `PRAGMA user_version` a migration leads to.
const MIGRATIONS: &[&str] = &[SCHEMA_V1, crate::audit::SCHEMA_V2];

#[derive(Debug)]
pub enum Error {
    NotInitialized,
    AlreadyExists(String),
    Perms(String),
    BadCredentials,
    HeaderTampered,
    Header(String),
    Schema(String),
    NotFound(String),
    Invalid(String),
    Crypto(CryptoError),
    Db(rusqlite::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotInitialized => f.write_str("no vault found; run `smith vault init`"),
            Error::AlreadyExists(w) => write!(f, "{w} already exists"),
            Error::Perms(m) => f.write_str(m),
            Error::BadCredentials => f.write_str(
                "wrong passphrase or recovery phrase (or the vault header was modified)",
            ),
            Error::HeaderTampered => {
                f.write_str("vault header failed its integrity check (tampering or corruption)")
            }
            Error::Header(m) | Error::Schema(m) | Error::Invalid(m) => f.write_str(m),
            Error::NotFound(w) => write!(f, "{w} not found"),
            Error::Crypto(e) => write!(f, "{e}"),
            Error::Db(e) => write!(f, "database error: {e}"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<CryptoError> for Error {
    fn from(e: CryptoError) -> Self {
        Error::Crypto(e)
    }
}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Db(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct SecretMeta {
    pub project: String,
    pub environment: String,
    pub name: String,
    pub version: u32,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct VersionMeta {
    pub version: u32,
    pub created_at: i64,
    pub current: bool,
}

pub struct Vault {
    conn: Connection,
    dir: PathBuf,
    vk: SecretKey32,
    header: Body,
}

enum Unlock<'a> {
    Passphrase(&'a [u8], bool),
    Recovery(&'a RecoveryPhrase),
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn rand<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|_| CryptoError::Rng)?;
    Ok(b)
}

/// UUID v4 as 16 raw bytes.
fn new_id() -> Result<[u8; 16]> {
    let mut b = rand::<16>()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Ok(b)
}

fn id16(v: Vec<u8>) -> rusqlite::Result<[u8; 16]> {
    v.try_into().map_err(|_| {
        rusqlite::Error::InvalidColumnType(0, "id".into(), rusqlite::types::Type::Blob)
    })
}

fn check_name(kind: &str, n: &str) -> Result<()> {
    let ok = !n.is_empty()
        && n.len() <= 128
        && n.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "invalid {kind} name (use 1-128 of A-Z a-z 0-9 _ . -)"
        )))
    }
}

/// Refuses when the vault dir or any file in it is accessible to group or other, is owned by
/// another user, or (for entries inside the dir) is a symlink that could redirect vault I/O.
pub fn check_perms(dir: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let uid = ls_platform::current_uid();
    let not_owned = |p: &Path, owner: u32| {
        Error::Perms(format!(
            "{} is owned by uid {owner}, not the current user (uid {uid})",
            p.display()
        ))
    };
    let bad = |p: &Path, mode: u32, fix: &str| {
        Error::Perms(format!(
            "{} is accessible to other users (mode {:o}); fix with: chmod {fix} '{}'",
            p.display(),
            mode & 0o777,
            p.display()
        ))
    };
    let md = match std::fs::metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if md.uid() != uid {
        return Err(not_owned(dir, md.uid()));
    }
    if md.permissions().mode() & 0o077 != 0 {
        return Err(bad(dir, md.permissions().mode(), "700"));
    }
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        let md = std::fs::symlink_metadata(&p)?;
        if md.file_type().is_symlink() {
            return Err(Error::Perms(format!(
                "{} is a symlink; vault files must be regular files",
                p.display()
            )));
        }
        if md.uid() != uid {
            return Err(not_owned(&p, md.uid()));
        }
        if md.is_file() && md.permissions().mode() & 0o077 != 0 {
            return Err(bad(&p, md.permissions().mode(), "600"));
        }
    }
    Ok(())
}

pub fn exists(dir: &Path) -> bool {
    dir.join(HEADER_FILE).exists()
}

fn private_file(p: &Path) -> Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(p)?;
    Ok(())
}

fn tune(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL; PRAGMA secure_delete = ON;",
    )?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
    Ok(())
}

fn migrate(conn: &mut Connection, db_path: &Path, migrations: &[&str]) -> Result<()> {
    let cur: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let latest = migrations.len() as u32;
    if cur > latest {
        return Err(Error::Schema(format!(
            "vault schema v{cur} is newer than this build supports (v{latest}); update Locksmith"
        )));
    }
    if cur > 0 && cur < latest {
        // Fold the WAL into the main file so the copy is complete, then back up before migrating.
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        let mut name = db_path.as_os_str().to_owned();
        name.push(format!(".bak-{}", now()));
        let bak = PathBuf::from(name);
        std::fs::copy(db_path, &bak)?;
        std::fs::set_permissions(&bak, std::fs::Permissions::from_mode(0o600))?;
    }
    for (i, sql) in migrations.iter().enumerate().skip(cur as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute_batch(&format!("PRAGMA user_version = {}", i + 1))?;
        tx.commit()?;
    }
    Ok(())
}

fn put_in(
    vk: &SecretKey32,
    vk_version: u32,
    conn: &Connection,
    env_id: &[u8; 16],
    name: &str,
    value: &[u8],
) -> Result<u32> {
    check_name("secret", name)?;
    let existing: Option<[u8; 16]> = conn
        .query_row(
            "SELECT id FROM secrets WHERE environment_id=?1 AND name=?2",
            params![&env_id[..], name],
            |r| id16(r.get(0)?),
        )
        .optional()?;
    let secret_id = match existing {
        Some(i) => i,
        None => {
            let i = new_id()?;
            conn.execute(
                "INSERT INTO secrets(id,environment_id,name,created_at) VALUES(?1,?2,?3,?4)",
                params![&i[..], &env_id[..], name, now()],
            )?;
            i
        }
    };
    let version: u32 = conn.query_row(
        "SELECT COALESCE(MAX(version),0)+1 FROM secret_versions WHERE secret_id=?1",
        [&secret_id[..]],
        |r| r.get(0),
    )?;
    let version_id = new_id()?;
    let dek = SecretKey32::random()?; // fresh DEK per version
    let payload = aead::seal(&dek, value, &Aad::payload(&secret_id, &version_id, env_id))?;
    let dw = wrap::wrap_dek(vk, &dek, &secret_id, &version_id, vk_version)?;
    conn.execute(
        "INSERT INTO secret_versions(id,secret_id,version,encrypted_dek,dek_nonce,payload,payload_nonce,created_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            &version_id[..],
            &secret_id[..],
            version,
            dw.ct,
            &dw.nonce[..],
            payload.ct,
            &payload.nonce[..],
            now()
        ],
    )?;
    Ok(version)
}

impl Vault {
    /// Creates a new vault in `dir` (header is written last, so a crash leaves no half vault).
    pub fn create(
        dir: &Path,
        passphrase: &[u8],
        params: KdfParams,
        allow_weak: bool,
        phrase: &RecoveryPhrase,
    ) -> Result<Self> {
        ls_core::ensure_private_dir(dir)?;
        check_perms(dir)?;
        if exists(dir) {
            return Err(Error::AlreadyExists("vault".into()));
        }
        let db_path = dir.join(DB_FILE);
        // Without a header the old DB is unopenable anyway; clear leftovers of a crashed init.
        for suffix in ["", "-wal", "-shm"] {
            let mut p = db_path.as_os_str().to_owned();
            p.push(suffix);
            let _ = std::fs::remove_file(p);
        }
        let vk = SecretKey32::random()?;
        let salt = rand::<32>()?;
        let pwk = wrap::passphrase_key(passphrase, &salt, params, allow_weak)?;
        let header = Body {
            format: FORMAT,
            vault_id: new_id()?,
            vk_version: VK_VERSION,
            kdf: params,
            salt,
            pass_wrap: (&wrap::wrap_vk(&pwk, &vk, WRAP_PASSPHRASE, VK_VERSION)?).into(),
            recovery_wrap: (&wrap::recovery_wrap(phrase, &vk, VK_VERSION)?).into(),
            created_at: now() as u64,
        };
        private_file(&db_path)?;
        let mut conn = open_encrypted(&db_path, hkdf(vk.expose(), label::SQLCIPHER).expose())?;
        tune(&conn)?;
        migrate(&mut conn, &db_path, MIGRATIONS)?;
        // K_1 of the audit ratchet comes from the recovery phrase, stored before the header
        // makes the vault visible (v6 review §2.1).
        crate::audit::root_from_phrase(&conn, &vk, phrase)?;
        header::write(dir, &header, &vk)?;
        Ok(Self {
            conn,
            dir: dir.to_path_buf(),
            vk,
            header,
        })
    }

    pub fn open_passphrase(dir: &Path, passphrase: &[u8], allow_weak: bool) -> Result<Self> {
        Self::open(dir, Unlock::Passphrase(passphrase, allow_weak), MIGRATIONS)
    }

    pub fn open_recovery(dir: &Path, phrase: &RecoveryPhrase) -> Result<Self> {
        Self::open(dir, Unlock::Recovery(phrase), MIGRATIONS)
    }

    fn open(dir: &Path, unlock: Unlock, migrations: &[&str]) -> Result<Self> {
        check_perms(dir)?;
        let (body, mac) = header::read(dir)?;
        if body.format != FORMAT {
            return Err(Error::Header("unsupported vault header format".into()));
        }
        // Bound the KDF cost a (possibly tampered) header can demand before running it.
        let k = body.kdf;
        if k.m_kib == 0
            || k.m_kib > 2 * 1024 * 1024
            || !(1..=64).contains(&k.t)
            || !(1..=64).contains(&k.p)
        {
            return Err(Error::Header(
                "vault header has out-of-range KDF parameters".into(),
            ));
        }
        let vk = match unlock {
            Unlock::Passphrase(pw, weak) => {
                let pwk = wrap::passphrase_key(pw, &body.salt, k, weak)?;
                wrap::unwrap_vk(
                    &pwk,
                    &body.pass_wrap.to_sealed(),
                    WRAP_PASSPHRASE,
                    body.vk_version,
                )
            }
            Unlock::Recovery(ph) => {
                wrap::recovery_unwrap(ph, &body.recovery_wrap.to_sealed(), body.vk_version)
            }
        }
        .map_err(|e| match e {
            CryptoError::Integrity => Error::BadCredentials,
            e => e.into(),
        })?;
        if !header::verify(&vk, &body, &mac) {
            return Err(Error::HeaderTampered);
        }
        let db_path = dir.join(DB_FILE);
        if !db_path.exists() {
            return Err(Error::Header(
                "vault.db is missing next to vault.header".into(),
            ));
        }
        let mut conn = open_encrypted(&db_path, hkdf(vk.expose(), label::SQLCIPHER).expose())?;
        tune(&conn)?;
        migrate(&mut conn, &db_path, migrations)?;
        crate::audit::ensure_key(&conn, &vk)?;
        Ok(Self {
            conn,
            dir: dir.to_path_buf(),
            vk,
            header: body,
        })
    }

    /// Rewrites only the passphrase wrap (new salt and parameters).
    pub fn change_passphrase(
        &mut self,
        new: &[u8],
        params: KdfParams,
        allow_weak: bool,
    ) -> Result<()> {
        let salt = rand::<32>()?;
        let pwk = wrap::passphrase_key(new, &salt, params, allow_weak)?;
        let mut h = self.header.clone();
        h.kdf = params;
        h.salt = salt;
        h.pass_wrap = (&wrap::wrap_vk(&pwk, &self.vk, WRAP_PASSPHRASE, h.vk_version)?).into();
        header::write(&self.dir, &h, &self.vk)?;
        self.header = h;
        Ok(())
    }

    /// Replaces the recovery wrap; the previous phrase stops working.
    pub fn rotate_recovery(&mut self, phrase: &RecoveryPhrase) -> Result<()> {
        let mut h = self.header.clone();
        h.recovery_wrap = SealedDto::from(&wrap::recovery_wrap(phrase, &self.vk, h.vk_version)?);
        header::write(&self.dir, &h, &self.vk)?;
        self.header = h;
        // Later audit events are verifiable from the new phrase (earlier ones by chain only).
        crate::audit::root_from_phrase(&self.conn, &self.vk, phrase)
    }

    pub(crate) fn audit_parts(&self) -> (&Connection, &SecretKey32) {
        (&self.conn, &self.vk)
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.header.kdf
    }

    // ---- projects and environments ----

    pub fn add_project(&mut self, name: &str) -> Result<()> {
        check_name("project", name)?;
        let tx = self.conn.transaction()?;
        let dup: Option<i64> = tx
            .query_row("SELECT 1 FROM projects WHERE name=?1", [name], |r| r.get(0))
            .optional()?;
        if dup.is_some() {
            return Err(Error::AlreadyExists(format!("project '{name}'")));
        }
        let (pid, t) = (new_id()?, now());
        tx.execute(
            "INSERT INTO projects(id,name,created_at) VALUES(?1,?2,?3)",
            params![&pid[..], name, t],
        )?;
        tx.execute(
            "INSERT INTO environments(id,project_id,name,created_at) VALUES(?1,?2,'development',?3)",
            params![&new_id()?[..], &pid[..], t],
        )?;
        Ok(tx.commit()?)
    }

    pub fn list_projects(&self) -> Result<Vec<String>> {
        let mut st = self
            .conn
            .prepare("SELECT name FROM projects ORDER BY name")?;
        Ok(st
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    pub fn remove_project(&mut self, name: &str) -> Result<()> {
        let n = self
            .conn
            .execute("DELETE FROM projects WHERE name=?1", [name])?;
        if n == 0 {
            return Err(Error::NotFound(format!("project '{name}'")));
        }
        Ok(())
    }

    fn project_id(conn: &Connection, project: &str) -> Result<[u8; 16]> {
        conn.query_row("SELECT id FROM projects WHERE name=?1", [project], |r| {
            id16(r.get(0)?)
        })
        .optional()?
        .ok_or_else(|| Error::NotFound(format!("project '{project}'")))
    }

    pub fn add_env(&mut self, project: &str, env: &str) -> Result<()> {
        check_name("environment", env)?;
        let pid = Self::project_id(&self.conn, project)?;
        let dup: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM environments WHERE project_id=?1 AND name=?2",
                params![&pid[..], env],
                |r| r.get(0),
            )
            .optional()?;
        if dup.is_some() {
            return Err(Error::AlreadyExists(format!("environment '{env}'")));
        }
        self.conn.execute(
            "INSERT INTO environments(id,project_id,name,created_at) VALUES(?1,?2,?3,?4)",
            params![&new_id()?[..], &pid[..], env, now()],
        )?;
        Ok(())
    }

    pub fn list_envs(&self, project: &str) -> Result<Vec<String>> {
        let pid = Self::project_id(&self.conn, project)?;
        let mut st = self
            .conn
            .prepare("SELECT name FROM environments WHERE project_id=?1 ORDER BY name")?;
        Ok(st
            .query_map([&pid[..]], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    fn env_id(conn: &Connection, project: &str, env: &str) -> Result<[u8; 16]> {
        conn.query_row(
            "SELECT e.id FROM environments e JOIN projects p ON p.id=e.project_id
             WHERE p.name=?1 AND e.name=?2",
            [project, env],
            |r| id16(r.get(0)?),
        )
        .optional()?
        .ok_or_else(|| Error::NotFound(format!("environment '{project}/{env}'")))
    }

    // ---- secrets ----

    /// Stores a new version of `name`; returns its version number.
    pub fn put_secret(
        &mut self,
        project: &str,
        env: &str,
        name: &str,
        value: &[u8],
    ) -> Result<u32> {
        Ok(self.put_secrets(
            project,
            env,
            &[(name.to_string(), SecretBytes::new(value.to_vec()))],
        )?[0])
    }

    /// All-or-nothing batch (used by import).
    pub fn put_secrets(
        &mut self,
        project: &str,
        env: &str,
        items: &[(String, SecretBytes)],
    ) -> Result<Vec<u32>> {
        let tx = self.conn.transaction()?;
        let env_id = Self::env_id(&tx, project, env)?;
        let mut out = Vec::with_capacity(items.len());
        for (name, value) in items {
            out.push(put_in(
                &self.vk,
                self.header.vk_version,
                &tx,
                &env_id,
                name,
                value.expose(),
            )?);
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn list_secrets(
        &self,
        project: Option<&str>,
        env: Option<&str>,
    ) -> Result<Vec<SecretMeta>> {
        let mut st = self.conn.prepare(
            "SELECT p.name, e.name, s.name, v.version, s.created_at, v.created_at
             FROM secrets s JOIN environments e ON e.id=s.environment_id
             JOIN projects p ON p.id=e.project_id
             JOIN secret_versions v ON v.secret_id=s.id
               AND v.version=(SELECT MAX(version) FROM secret_versions WHERE secret_id=s.id)
             WHERE (?1 IS NULL OR p.name=?1) AND (?2 IS NULL OR e.name=?2)
             ORDER BY p.name, e.name, s.name",
        )?;
        let rows = st.query_map(params![project, env], |r| {
            Ok(SecretMeta {
                project: r.get(0)?,
                environment: r.get(1)?,
                name: r.get(2)?,
                version: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    fn secret_id(&self, project: &str, env: &str, name: &str) -> Result<[u8; 16]> {
        self.conn
            .query_row(
                "SELECT s.id FROM secrets s JOIN environments e ON e.id=s.environment_id
                 JOIN projects p ON p.id=e.project_id WHERE p.name=?1 AND e.name=?2 AND s.name=?3",
                [project, env, name],
                |r| id16(r.get(0)?),
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("secret '{name}' in {project}/{env}")))
    }

    pub fn remove_secret(&mut self, project: &str, env: &str, name: &str) -> Result<()> {
        let id = self.secret_id(project, env, name)?;
        self.conn
            .execute("DELETE FROM secrets WHERE id=?1", [&id[..]])?;
        Ok(())
    }

    pub fn history(&self, project: &str, env: &str, name: &str) -> Result<Vec<VersionMeta>> {
        let id = self.secret_id(project, env, name)?;
        let mut st = self.conn.prepare(
            "SELECT version, created_at, version=(SELECT MAX(version) FROM secret_versions WHERE secret_id=?1)
             FROM secret_versions WHERE secret_id=?1 ORDER BY version DESC",
        )?;
        let rows = st.query_map([&id[..]], |r| {
            Ok(VersionMeta {
                version: r.get(0)?,
                created_at: r.get(1)?,
                current: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Decrypts the current version. Fails with an integrity error if the row was tampered with
    /// or moved to another secret, version or environment.
    pub fn get_secret(&self, project: &str, env: &str, name: &str) -> Result<SecretBytes> {
        let row = self
            .conn
            .query_row(
                "SELECT s.id, e.id, v.id, v.encrypted_dek, v.dek_nonce, v.payload, v.payload_nonce
                 FROM secrets s JOIN environments e ON e.id=s.environment_id
                 JOIN projects p ON p.id=e.project_id
                 JOIN secret_versions v ON v.secret_id=s.id
                 WHERE p.name=?1 AND e.name=?2 AND s.name=?3 ORDER BY v.version DESC LIMIT 1",
                [project, env, name],
                |r| {
                    Ok((
                        id16(r.get(0)?)?,
                        id16(r.get(1)?)?,
                        id16(r.get(2)?)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("secret '{name}' in {project}/{env}")))?;
        let (sid, eid, vid, dek_ct, dek_nonce, ct, nonce) = row;
        let sealed = |nonce: Vec<u8>, ct: Vec<u8>| -> Result<aead::Sealed> {
            Ok(aead::Sealed {
                nonce: nonce.try_into().map_err(|_| CryptoError::Integrity)?,
                ct,
            })
        };
        let dek = wrap::unwrap_dek(
            &self.vk,
            &sealed(dek_nonce, dek_ct)?,
            &sid,
            &vid,
            self.header.vk_version,
        )?;
        Ok(aead::open(
            &dek,
            &sealed(nonce, ct)?,
            &Aad::payload(&sid, &vid, &eid),
        )?)
    }

    /// Every current secret of a project (optionally one environment), decrypted: (env, name, value).
    pub fn get_all(
        &self,
        project: &str,
        env: Option<&str>,
    ) -> Result<Vec<(String, String, SecretBytes)>> {
        Self::project_id(&self.conn, project)?;
        self.list_secrets(Some(project), env)?
            .into_iter()
            .map(|m| {
                let v = self.get_secret(&m.project, &m.environment, &m.name)?;
                Ok((m.environment, m.name, v))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEAK: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };
    const CANARY_NAME: &str = "CANARY_KEY_NAME_98765";
    const CANARY_PROJECT: &str = "canary-project-xyz";

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("ls-vault-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            Tmp(p.join("vault"))
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
        }
    }

    fn make(t: &Tmp) -> (Vault, RecoveryPhrase) {
        let phrase = RecoveryPhrase::generate().unwrap();
        let v = Vault::create(&t.0, b"pw", WEAK, true, &phrase).unwrap();
        (v, phrase)
    }

    fn raw_files_contain(dir: &Path, needle: &str) -> bool {
        std::fs::read_dir(dir).unwrap().any(|e| {
            let b = std::fs::read(e.unwrap().path()).unwrap();
            b.windows(needle.len()).any(|w| w == needle.as_bytes())
        })
    }

    #[test]
    fn roundtrip_versions_and_names_absent_from_disk() {
        let t = Tmp::new("rt");
        let (mut v, _) = make(&t);
        v.add_project(CANARY_PROJECT).unwrap();
        assert_eq!(
            v.put_secret(CANARY_PROJECT, "development", CANARY_NAME, b"one")
                .unwrap(),
            1
        );
        assert_eq!(
            v.put_secret(CANARY_PROJECT, "development", CANARY_NAME, b"two")
                .unwrap(),
            2
        );
        assert_eq!(
            v.get_secret(CANARY_PROJECT, "development", CANARY_NAME)
                .unwrap()
                .expose(),
            b"two"
        );
        let h = v
            .history(CANARY_PROJECT, "development", CANARY_NAME)
            .unwrap();
        assert_eq!(
            h.iter().map(|x| (x.version, x.current)).collect::<Vec<_>>(),
            [(2, true), (1, false)]
        );
        // Two versions, two distinct wrapped DEKs and nonces.
        let rows: Vec<(Vec<u8>, Vec<u8>)> = v
            .conn
            .prepare("SELECT encrypted_dek, dek_nonce FROM secret_versions")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_ne!(rows[0].0, rows[1].0);
        assert_ne!(rows[0].1, rows[1].1);
        drop(v);
        for needle in [CANARY_NAME, CANARY_PROJECT, "development", "one", "two"] {
            if needle.len() > 3 {
                assert!(
                    !raw_files_contain(&t.0, needle),
                    "{needle} found in raw bytes"
                );
            }
        }
        let v = Vault::open_passphrase(&t.0, b"pw", true).unwrap();
        assert_eq!(
            v.get_secret(CANARY_PROJECT, "development", CANARY_NAME)
                .unwrap()
                .expose(),
            b"two"
        );
    }

    #[test]
    fn wrong_passphrase_and_recovery_unlock() {
        let t = Tmp::new("unlock");
        let (v, phrase) = make(&t);
        drop(v);
        assert!(matches!(
            Vault::open_passphrase(&t.0, b"nope", true),
            Err(Error::BadCredentials)
        ));
        assert!(Vault::open_recovery(&t.0, &phrase).is_ok());
        let other = RecoveryPhrase::generate().unwrap();
        assert!(matches!(
            Vault::open_recovery(&t.0, &other),
            Err(Error::BadCredentials)
        ));
    }

    #[test]
    fn header_tamper_is_detected() {
        let t = Tmp::new("tamper");
        let (v, _) = make(&t);
        drop(v);
        let hp = t.0.join(HEADER_FILE);
        let orig = std::fs::read(&hp).unwrap();

        // Flip the last byte (inside the MAC).
        let mut b = orig.clone();
        *b.last_mut().unwrap() ^= 1;
        std::fs::write(&hp, &b).unwrap();
        assert!(matches!(
            Vault::open_passphrase(&t.0, b"pw", true),
            Err(Error::HeaderTampered)
        ));

        // Alter a MAC-only field (created_at) and re-sign it with the wrong key.
        std::fs::write(&hp, &orig).unwrap();
        let (mut body, _) = header::read(&t.0).unwrap();
        body.created_at += 1;
        header::write(&t.0, &body, &SecretKey32::from_bytes([9; 32])).unwrap();
        assert!(matches!(
            Vault::open_passphrase(&t.0, b"pw", true),
            Err(Error::HeaderTampered)
        ));

        // Altered KDF parameter: unlock fails, no secrets returned.
        std::fs::write(&hp, &orig).unwrap();
        let (mut body, _) = header::read(&t.0).unwrap();
        body.kdf.p = 2;
        let vk = Vault::open_passphrase(&t.0, b"pw", true).unwrap().vk;
        header::write(&t.0, &body, &vk).unwrap();
        assert!(Vault::open_passphrase(&t.0, b"pw", true).is_err());
        // Absurd cost is refused before any allocation.
        body.kdf.m_kib = u32::MAX;
        header::write(&t.0, &body, &vk).unwrap();
        assert!(matches!(
            Vault::open_passphrase(&t.0, b"pw", true),
            Err(Error::Header(_))
        ));
    }

    #[test]
    fn transplanted_payload_fails() {
        let t = Tmp::new("transplant");
        let (mut v, _) = make(&t);
        v.add_project("p").unwrap();
        v.add_env("p", "production").unwrap();
        v.put_secret("p", "development", "A", b"dev-value").unwrap();
        v.put_secret("p", "production", "A", b"prod-value").unwrap();
        v.conn
            .execute(
                "UPDATE secret_versions SET payload=(SELECT payload FROM secret_versions v2
                   JOIN secrets s ON s.id=v2.secret_id JOIN environments e ON e.id=s.environment_id
                   WHERE e.name='development'), payload_nonce=(SELECT payload_nonce FROM secret_versions v2
                   JOIN secrets s ON s.id=v2.secret_id JOIN environments e ON e.id=s.environment_id
                   WHERE e.name='development')
                 WHERE secret_id=(SELECT s.id FROM secrets s JOIN environments e ON e.id=s.environment_id
                   WHERE e.name='production')",
                [],
            )
            .unwrap();
        assert!(matches!(
            v.get_secret("p", "production", "A"),
            Err(Error::Crypto(CryptoError::Integrity))
        ));
        assert_eq!(
            v.get_secret("p", "development", "A").unwrap().expose(),
            b"dev-value"
        );
    }

    #[test]
    fn passphrase_change_keeps_ciphertext_and_recovery_works() {
        let t = Tmp::new("passwd");
        let (mut v, phrase) = make(&t);
        v.put_secret_default();
        let before: Vec<u8> = v
            .conn
            .query_row("SELECT payload FROM secret_versions", [], |r| r.get(0))
            .unwrap();
        v.change_passphrase(b"new", WEAK, true).unwrap();
        drop(v);
        assert!(Vault::open_passphrase(&t.0, b"pw", true).is_err());
        let v = Vault::open_passphrase(&t.0, b"new", true).unwrap();
        let after: Vec<u8> = v
            .conn
            .query_row("SELECT payload FROM secret_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(before, after);
        drop(v);
        assert!(Vault::open_recovery(&t.0, &phrase).is_ok());
    }

    impl Vault {
        fn put_secret_default(&mut self) {
            self.add_project("d").unwrap();
            self.put_secret("d", "development", "K", b"v").unwrap();
        }
    }

    #[test]
    fn crash_mid_transaction_leaves_no_partial_secret() {
        let t = Tmp::new("atomic");
        let (mut v, _) = make(&t);
        v.add_project("d").unwrap();
        // A batch whose second item is invalid must roll back the first.
        let items = vec![
            ("OK_ONE".to_string(), SecretBytes::new(b"1".to_vec())),
            ("bad name!".to_string(), SecretBytes::new(b"2".to_vec())),
        ];
        assert!(v.put_secrets("d", "development", &items).is_err());
        assert!(v.list_secrets(None, None).unwrap().is_empty());
    }

    #[test]
    fn perms_are_enforced() {
        let t = Tmp::new("perms");
        let (v, _) = make(&t);
        drop(v);
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(t.0.clone()), 0o700);
        assert_eq!(mode(t.0.join(DB_FILE)), 0o600);
        assert_eq!(mode(t.0.join(HEADER_FILE)), 0o600);
        let db = t.0.join(DB_FILE);
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Vault::open_passphrase(&t.0, b"pw", true),
            Err(Error::Perms(_))
        ));
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            Vault::open_passphrase(&t.0, b"pw", true),
            Err(Error::Perms(_))
        ));
    }

    #[test]
    fn forward_migration_writes_backup_first() {
        let t = Tmp::new("migrate");
        let (v, _) = make(&t);
        drop(v);
        let three = [
            SCHEMA_V1,
            crate::audit::SCHEMA_V2,
            "CREATE TABLE extra(x INTEGER);",
        ];
        let v = Vault::open(&t.0, Unlock::Passphrase(b"pw", true), &three).unwrap();
        let ver: u32 = v
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ver, 3);
        let baks: Vec<_> = std::fs::read_dir(&t.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("vault.db.bak-"))
            .collect();
        assert_eq!(baks.len(), 1, "{baks:?}");
        // The backup is the pre-migration DB: openable under the same key, still at v1.
        let key = hkdf(v.vk.expose(), label::SQLCIPHER);
        let b = open_encrypted(&t.0.join(&baks[0]), key.expose()).unwrap();
        let bver: u32 = b
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(bver, 2);
        drop((v, b));
        // And an older build refuses a newer vault.
        assert!(matches!(
            Vault::open(&t.0, Unlock::Passphrase(b"pw", true), MIGRATIONS),
            Err(Error::Schema(_))
        ));
        assert!(check_perms(&t.0).is_ok(), "backup must be 0600");
    }

    #[cfg(test)]
    mod perms_hardening_tests {
        use super::*;

        #[test]
        fn symlink_in_vault_dir_is_refused() {
            let dir = std::env::temp_dir().join(format!("ls-vault-symlink-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::os::unix::fs::symlink("/etc/hosts", dir.join("vault.db")).unwrap();
            let err = check_perms(&dir).unwrap_err();
            assert!(format!("{err}").contains("symlink"), "{err}");
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}
