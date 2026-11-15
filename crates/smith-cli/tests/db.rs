//! M6 database relay e2e: real `locksmithd`, `smith`, and throwaway Postgres (SCRAM over TLS
//! with a test CA), MariaDB (TLS-only user) and Redis (ACL user) servers. Each server test skips
//! with a message when its binaries are missing. Servers refuse to run as root, so as root they
//! are started as the `postgres`/`mysql`/`nobody` user via `setpriv`. Passwords are built at
//! runtime and must never show up in anything the session can see.

mod common;
use common::*;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Once;
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use std::time::{Duration, Instant};

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn bin_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_smith"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn locksmithd() -> PathBuf {
    static BUILD: Once = Once::new();
    let p = bin_dir().join("locksmithd");
    BUILD.call_once(|| {
        if !p.exists() {
            let cargo = std::env::var("CARGO").unwrap_or("cargo".into());
            assert!(
                Command::new(cargo)
                    .args(["build", "-p", "locksmithd"])
                    .status()
                    .unwrap()
                    .success()
            );
        }
    });
    p
}

fn wait_until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(
            t.elapsed() < Duration::from_secs(secs),
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(name))
            .find(|f| f.is_file())
    })
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn uniq() -> u32 {
    static N: AtomicU32 = AtomicU32::new(0);
    N.fetch_add(1, SeqCst)
}

fn run_ok(c: &mut Command) -> Output {
    let o = c.output().unwrap();
    assert!(
        o.status.success(),
        "{c:?}: {} {}",
        s(&o.stdout),
        s(&o.stderr)
    );
    o
}

/// Unprivileged identity for database servers when the tests run as root.
#[derive(Clone)]
struct As(Option<(String, String)>);

impl As {
    fn pick(prefer: &str) -> Option<As> {
        let uid = s(&Command::new("id").arg("-u").output().ok()?.stdout);
        if uid.trim() != "0" {
            return Some(As(None));
        }
        which("setpriv")?;
        for u in [prefer, "nobody"] {
            let id = |f: &str| {
                Command::new("id")
                    .args([f, u])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| s(&o.stdout).trim().to_string())
            };
            if let (Some(uid), Some(gid)) = (id("-u"), id("-g")) {
                return Some(As(Some((uid, gid))));
            }
        }
        None
    }
    fn cmd(&self, prog: impl AsRef<std::ffi::OsStr>) -> Command {
        match &self.0 {
            None => Command::new(prog),
            Some((u, g)) => {
                let mut c = Command::new("setpriv");
                c.args([
                    &format!("--reuid={u}"),
                    &format!("--regid={g}"),
                    "--clear-groups",
                ])
                .arg(prog);
                c
            }
        }
    }
    fn own(&self, p: &Path) {
        if let Some((u, g)) = &self.0 {
            run_ok(
                Command::new("chown")
                    .args(["-R", &format!("{u}:{g}")])
                    .arg(p),
            );
        }
    }
}

/// A scratch directory under /tmp (short paths: Unix socket limits), removed on drop.
struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Scratch {
        let p = PathBuf::from(format!("/tmp/{tag}-{}-{}", std::process::id(), uniq()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A test CA and a `localhost`/127.0.0.1 server certificate (openssl CLI). None if absent.
fn certs(dir: &Path) -> Option<()> {
    which("openssl")?;
    std::fs::write(
        dir.join("ext.cnf"),
        "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n",
    )
    .unwrap();
    let ossl = |args: &[&str]| {
        run_ok(Command::new("openssl").current_dir(dir).args(args));
    };
    ossl(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-days",
        "2",
        "-subj",
        "/CN=Locksmith Test CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ]);
    ossl(&[
        "req",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        "server.key",
        "-out",
        "server.csr",
        "-subj",
        "/CN=localhost",
    ]);
    ossl(&[
        "x509",
        "-req",
        "-in",
        "server.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-out",
        "server.pem",
        "-days",
        "2",
        "-extfile",
        "ext.cnf",
    ]);
    Some(())
}

// ---------------------------------------------------------------- servers

struct Server {
    child: Child,
    port: u16,
    password: String,
    dir: Scratch,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status();
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(10) {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_port(port: u16, child: &mut Child, what: &str) {
    wait_until(what, 60, || {
        if let Ok(Some(st)) = child.try_wait() {
            panic!("{what} exited early: {st}");
        }
        TcpStream::connect(("127.0.0.1", port)).is_ok()
    });
}

fn pg_bin() -> Option<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir("/usr/lib/postgresql")
        .ok()?
        .flatten()
        .map(|e| e.path().join("bin"))
        .filter(|b| b.join("postgres").is_file() && b.join("initdb").is_file())
        .collect();
    v.sort();
    v.pop().or_else(|| {
        which("postgres")
            .filter(|_| which("initdb").is_some())
            .and_then(|p| p.parent().map(Path::to_path_buf))
    })
}

/// Postgres with SCRAM-SHA-256 and TLS-only TCP access (`hostssl`), certificate from the test CA.
fn postgres() -> Option<Server> {
    let bin = pg_bin()?;
    which("psql")?;
    let who = As::pick("postgres")?;
    let dir = Scratch::new("lspg");
    certs(&dir.0)?;
    let password = format!("pgPW_{}_{}_q7Zx", std::process::id(), uniq());
    let data = dir.0.join("data");
    std::fs::write(dir.0.join("pw"), &password).unwrap();
    who.own(&dir.0);
    run_ok(
        who.cmd(bin.join("initdb"))
            .args(["-D", data.to_str().unwrap(), "-U", "postgres", "-E", "UTF8"])
            .args(["--auth=scram-sha-256", "--no-instructions", "--pwfile"])
            .arg(dir.0.join("pw")),
    );
    std::fs::remove_file(dir.0.join("pw")).unwrap();
    std::fs::write(
        data.join("pg_hba.conf"),
        "local all all scram-sha-256\nhostssl all all 127.0.0.1/32 scram-sha-256\nhostssl all all ::1/128 scram-sha-256\n",
    )
    .unwrap();
    for f in ["server.pem", "server.key"] {
        std::fs::copy(dir.0.join(f), data.join(f)).unwrap();
    }
    run_ok(
        Command::new("chmod")
            .arg("600")
            .arg(data.join("server.key")),
    );
    who.own(&dir.0);
    let port = free_port();
    let mut child = who
        .cmd(bin.join("postgres"))
        .args(["-D", data.to_str().unwrap(), "-p", &port.to_string()])
        .args(["-k", dir.0.to_str().unwrap()])
        .args(["-c", "listen_addresses=127.0.0.1", "-c", "ssl=on"])
        .args([
            "-c",
            "ssl_cert_file=server.pem",
            "-c",
            "ssl_key_file=server.key",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_port(port, &mut child, "postgres");
    Some(Server {
        child,
        port,
        password,
        dir,
    })
}

/// MariaDB with a TLS-only (`REQUIRE SSL`) mysql_native_password user `app` on `appdb`.
fn mariadb() -> Option<Server> {
    let server = which("mariadbd")
        .or_else(|| which("mysqld"))
        .or_else(|| Some(PathBuf::from("/usr/sbin/mariadbd")).filter(|p| p.is_file()))?;
    let install = which("mariadb-install-db").or_else(|| which("mysql_install_db"))?;
    which("mariadb")?;
    let who = As::pick("mysql")?;
    let dir = Scratch::new("lsmy");
    certs(&dir.0)?;
    let password = format!("myPW_{}_{}_k3Rv", std::process::id(), uniq());
    let data = dir.0.join("data");
    who.own(&dir.0);
    run_ok(
        who.cmd(&install)
            .args([
                "--no-defaults",
                "--skip-test-db",
                "--auth-root-authentication-method=normal",
            ])
            .arg(format!("--datadir={}", data.display())),
    );
    let port = free_port();
    let sock = dir.0.join("sock");
    let mut child = who
        .cmd(&server)
        .arg("--no-defaults")
        .arg(format!("--datadir={}", data.display()))
        .arg(format!("--socket={}", sock.display()))
        .arg(format!("--pid-file={}", dir.0.join("pid").display()))
        .arg(format!("--port={port}"))
        .args([
            "--bind-address=127.0.0.1",
            "--skip-log-bin",
            "--skip-name-resolve",
        ])
        .arg(format!("--ssl-cert={}", dir.0.join("server.pem").display()))
        .arg(format!("--ssl-key={}", dir.0.join("server.key").display()))
        .arg(format!("--ssl-ca={}", dir.0.join("ca.pem").display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_port(port, &mut child, "mariadbd");
    let sql = format!(
        "CREATE DATABASE appdb; CREATE USER 'app'@'%' IDENTIFIED BY '{password}' REQUIRE SSL; GRANT ALL ON appdb.* TO 'app'@'%';"
    );
    run_ok(
        Command::new("mariadb")
            .args(["--no-defaults", "-uroot"])
            .arg(format!("--socket={}", sock.display()))
            .args(["-e", &sql]),
    );
    Some(Server {
        child,
        port,
        password,
        dir,
    })
}

/// Redis with the default user disabled and an ACL user `app`.
fn redis() -> Option<Server> {
    let bin = which("redis-server")?;
    which("redis-cli")?;
    let who = As::pick("redis")?;
    let dir = Scratch::new("lsrd");
    who.own(&dir.0);
    let password = format!("rdPW_{}_{}_m2Wq", std::process::id(), uniq());
    let port = free_port();
    let mut child = who
        .cmd(bin)
        .args(["--port", &port.to_string(), "--bind", "127.0.0.1"])
        .args(["--save", "", "--appendonly", "no"])
        .arg("--dir")
        .arg(&dir.0)
        .args(["--user", "default", "off"])
        .args([
            "--user",
            "app",
            "on",
            &format!(">{password}"),
            "~*",
            "&*",
            "+@all",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_port(port, &mut child, "redis-server");
    Some(Server {
        child,
        port,
        password,
        dir,
    })
}

macro_rules! need {
    ($e:expr, $what:literal) => {
        match $e {
            Some(x) => x,
            None => {
                eprintln!("SKIP: {} is unavailable", $what);
                return;
            }
        }
    };
}

// ---------------------------------------------------------------- Locksmith side

/// Home + runtime dir + daemon (trusting the test CA) + a work dir with a binding.
struct Env {
    h: Home,
    run: PathBuf,
    work: PathBuf,
    daemon: Option<Child>,
}

impl Env {
    fn new(ca: Option<&Path>, secrets: &[(&str, &str)], toml: &str) -> Env {
        locksmithd();
        let h = Home::new();
        let id =
            h.0.file_name()
                .unwrap()
                .to_string_lossy()
                .replace("smith-e2e-", "");
        let run = PathBuf::from(format!("/tmp/lsd-{id}"));
        let work = h.0.join("work");
        std::fs::create_dir_all(&work).unwrap();
        h.ready();
        for (k, v) in secrets {
            assert!(h.add(k, v).status.success());
        }
        std::fs::write(work.join(".locksmith.toml"), toml).unwrap();
        let mut d = Command::new(locksmithd());
        d.env("LOCKSMITH_HOME", &h.0)
            .env("LOCKSMITH_RUNTIME_DIR", &run)
            .env("LOCKSMITH_INSECURE_TEST_KDF", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(ca) = ca {
            d.env("LOCKSMITH_TEST_DB_CA", ca);
        }
        let daemon = Some(d.spawn().unwrap());
        let sock = run.join("locksmithd.sock");
        wait_until("locksmithd", 30, || sock.exists());
        Env {
            h,
            run,
            work,
            daemon,
        }
    }

    fn smith(&self, args: &[&str]) -> Command {
        let mut c = self.h.cmd(&[]);
        let path = format!("{}:{}", bin_dir().display(), std::env::var("PATH").unwrap());
        c.args(args)
            .current_dir(&self.work)
            .env("LOCKSMITH_RUNTIME_DIR", &self.run)
            .env("PATH", path);
        c
    }

    fn out(&self, args: &[&str]) -> Output {
        let mut c = self.smith(args);
        c.stdin(Stdio::null());
        c.output().unwrap()
    }

    /// `smith session start -- sh -c <script>` in the work dir.
    fn session(&self, script: &str) -> Child {
        let mut c = self
            .smith(&[
                "--passphrase-stdin",
                "session",
                "start",
                "--",
                "sh",
                "-c",
                script,
            ])
            .spawn()
            .unwrap();
        c.stdin
            .take()
            .unwrap()
            .write_all(format!("{PW}\n").as_bytes())
            .unwrap();
        c
    }

    fn audit(&self) -> Vec<serde_json::Value> {
        let o = self.out(&["audit", "ls", "--json", "--limit", "500"]);
        // Empty while the vault is still locked (the session has not started yet).
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_default();
        v["events"].as_array().cloned().unwrap_or_default()
    }

    fn has_event(&self, action: &str, rule: &str) -> bool {
        self.audit().iter().any(|e| {
            e["action"] == action && e["policy_rule"].as_str().unwrap_or("").contains(rule)
                || e["action"] == action && e["target"].as_str().unwrap_or("").contains(rule)
        })
    }

    fn file(&self, name: &str) -> String {
        std::fs::read_to_string(self.work.join(name)).unwrap_or_default()
    }

    /// Wait for `<name>.ready` (written by the script), for gated scripts.
    fn ready(&self, name: &str) {
        let f = self.work.join(format!("{name}.ready"));
        wait_until(name, 30, || f.exists());
    }

    fn go(&self, name: &str) {
        std::fs::write(self.work.join(format!("{name}.go")), "").unwrap();
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if let Some(d) = &mut self.daemon {
            let _ = d.kill();
            let _ = d.wait();
        }
        let _ = std::fs::remove_dir_all(&self.run);
    }
}

fn gate(e: &Env, name: &str) -> String {
    format!(
        "touch {w}/{name}.ready; while [ ! -e {w}/{name}.go ]; do sleep 0.05; done",
        w = e.work.display()
    )
}

/// Every place the session could see: nothing may contain `pw`.
fn assert_never_disclosed(e: &Env, pw: &str, session_out: &Output, files: &[&str]) {
    assert!(!s(&session_out.stdout).contains(pw), "password on stdout");
    assert!(!s(&session_out.stderr).contains(pw), "password on stderr");
    for f in files {
        assert!(!e.file(f).contains(pw), "password in {f}");
    }
    assert!(!e.file(".locksmith.toml").contains(pw));
    let audit = e.out(&["audit", "ls", "--json", "--limit", "500"]);
    assert!(!s(&audit.stdout).contains(pw), "password in the audit log");
}

fn pg_toml(port: u16) -> String {
    format!(
        "[db.main]\nkind = \"postgres\"\nhost = \"localhost\"\nport = {port}\nuser = \"postgres\"\ndatabase = \"postgres\"\npassword_key = \"PG_PASSWORD\"\ntls = \"require\"\n"
    )
}

/// Regression (gate A3): an agent inside the session edits `[db.main]` to point at a server it
/// runs (where it could ask for a cleartext password). The relay keeps the target pinned at
/// session start: the edited copy is refused and audited, the original still works.
#[test]
fn db_target_comes_from_the_binding_pinned_at_session_start() {
    let up = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = up.local_addr().unwrap().port();
    let e = Env::new(
        None,
        &[("PG_PASSWORD", "pinned-test-pw-value")],
        &pg_toml(port),
    );
    let script = r#"cp .locksmith.toml orig.toml
printf '[db.main]\nkind = "postgres"\nhost = "127.0.0.1"\nport = 1\nuser = "postgres"\npassword_key = "PG_PASSWORD"\ntls = "disable"\n' > .locksmith.toml
smith db connect main 2> edited.err; echo "edited=$?"
printf '[db.evil]\nkind = "postgres"\nhost = "127.0.0.1"\nport = 1\nuser = "postgres"\npassword_key = "PG_PASSWORD"\ntls = "disable"\n' >> orig2.toml
cat orig.toml orig2.toml > .locksmith.toml
smith db connect evil 2> added.err; echo "added=$?"
cp orig.toml .locksmith.toml
smith db connect main > ok.txt; echo "ok=$?"
"#;
    let o = e.session(script).wait_with_output().unwrap();
    let out = s(&o.stdout);
    for want in ["edited=3", "added=3", "ok=0"] {
        assert!(out.contains(want), "{want}: {out} {}", s(&o.stderr));
    }
    assert!(
        e.file("edited.err")
            .contains("differs from the copy this session started with"),
        "{}",
        e.file("edited.err")
    );
    assert!(
        e.file("ok.txt")
            .starts_with("postgres://postgres@127.0.0.1:")
    );
    assert!(e.has_event("BLOCKED", "binding_changed"));
    drop(up);
}

const MIGRATION: &str = "CREATE TABLE widgets (id serial PRIMARY KEY, name text NOT NULL);\nINSERT INTO widgets (name) VALUES ('a'), ('b');\n";

#[test]
fn postgres_psql_and_migrations_over_scram_tls() {
    let pg = need!(postgres(), "Postgres (initdb/postgres/psql/openssl)");
    let ca = pg.dir.0.join("ca.pem");
    let e = Env::new(
        Some(&ca),
        &[("PG_PASSWORD", &pg.password)],
        &pg_toml(pg.port),
    );
    std::fs::write(e.work.join("migrate.sql"), MIGRATION).unwrap();
    let sqlx = which("sqlx").is_some();
    if sqlx {
        let m = e.work.join("migrations");
        std::fs::create_dir_all(&m).unwrap();
        std::fs::write(
            m.join("20260101000000_gadgets.sql"),
            "CREATE TABLE gadgets (id int PRIMARY KEY);\n",
        )
        .unwrap();
    } else {
        eprintln!("NOTE: sqlx-cli not on PATH; the sqlx migrate step is skipped");
    }
    let script = format!(
        r#"set -u
smith --json db connect main > ep.json; echo "json=$?"
smith db connect main > ep.txt
smith db connect main -- psql -X -q -v ON_ERROR_STOP=1 -f migrate.sql; echo "mig=$?"
smith db connect main -- psql -X -tA -c "select count(*) from widgets" > count.txt
smith db connect main -- psql -X -tA -c "select ssl from pg_stat_ssl where pid = pg_backend_pid()" > ssl.txt
smith db connect main -- psql -X -tA -c "select 1/0" 2> err.txt; echo "div=$?"
smith db connect main -- env > env.txt
{sqlx}
ss -tpn > ss.txt 2>&1 || true
ps -eo args > ps.txt 2>&1 || true
"#,
        sqlx = if sqlx {
            "smith db connect main -- sqlx migrate run > sqlx.txt 2>&1; echo \"sqlx=$?\"\nsmith db connect main -- psql -X -tA -c \"select count(*) from gadgets\" >> sqlx.txt"
        } else {
            ""
        }
    );
    let o = e.session(&script).wait_with_output().unwrap();
    let out = s(&o.stdout);
    assert!(out.contains("json=0"), "{out} {}", s(&o.stderr));
    assert!(out.contains("mig=0"), "{out} {}", s(&o.stderr));
    assert_eq!(e.file("count.txt").trim(), "2", "{}", s(&o.stderr));
    assert_eq!(e.file("ssl.txt").trim(), "t", "upstream leg is not TLS");
    assert!(!out.contains("div=0"));
    assert!(
        e.file("err.txt").contains("division by zero"),
        "{}",
        e.file("err.txt")
    );
    if sqlx {
        assert!(out.contains("sqlx=0"), "{out} {}", e.file("sqlx.txt"));
        assert!(
            e.file("sqlx.txt").trim_end().ends_with('0'),
            "{}",
            e.file("sqlx.txt")
        );
    }
    let ep: serde_json::Value = serde_json::from_str(&e.file("ep.json")).unwrap();
    assert_eq!(ep["host"], "127.0.0.1");
    assert_eq!(ep["user"], "postgres");
    let url = ep["url"].as_str().unwrap();
    assert!(
        url.starts_with("postgres://postgres@127.0.0.1:")
            && url.ends_with("/postgres?sslmode=disable"),
        "{url}"
    );
    assert!(
        e.file("ep.txt").starts_with(url),
        "same relay reused: {}",
        e.file("ep.txt")
    );
    let env = e.file("env.txt");
    assert!(
        env.contains("PGPORT=") && env.contains("DATABASE_URL=postgres://"),
        "{env}"
    );
    assert_never_disclosed(
        &e,
        &pg.password,
        &o,
        &[
            "ep.json",
            "ep.txt",
            "env.txt",
            "err.txt",
            "ss.txt",
            "ps.txt",
            "count.txt",
            "sqlx.txt",
        ],
    );
    assert!(e.has_event("ACCESS", "db:main"));
}

#[test]
fn postgres_relay_refuses_outside_session_and_closes_on_session_end() {
    let pg = need!(postgres(), "Postgres (initdb/postgres/psql/openssl)");
    let ca = pg.dir.0.join("ca.pem");
    let e = Env::new(
        Some(&ca),
        &[("PG_PASSWORD", &pg.password)],
        &pg_toml(pg.port),
    );
    let script = format!(
        "smith --json db connect main > ep.json; {}; echo done",
        gate(&e, "a")
    );
    let agent = e.session(&script);
    e.ready("a");
    let ep: serde_json::Value = serde_json::from_str(&e.file("ep.json")).unwrap();
    let port = ep["port"].as_u64().unwrap().to_string();
    // This test process is not inside the session tree.
    let o = Command::new("psql")
        .args([
            "-X",
            "-h",
            "127.0.0.1",
            "-p",
            &port,
            "-U",
            "postgres",
            "-tA",
        ])
        .args(["-c", "select 1", "postgres"])
        .env("PGSSLMODE", "disable")
        .env("PGCONNECT_TIMEOUT", "5")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        !o.status.success(),
        "outside client was served: {}",
        s(&o.stdout)
    );
    let err = s(&o.stderr);
    assert!(
        err.contains("Locksmith") && err.contains("no active session"),
        "{err}"
    );
    assert!(!err.contains(&pg.password));
    assert!(e.has_event("BLOCKED", "db:main"), "{:?}", e.audit());
    e.go("a");
    let o = agent.wait_with_output().unwrap();
    assert!(s(&o.stdout).contains("done"));
    // The session ended: its listener is gone.
    let p: u16 = port.parse().unwrap();
    wait_until("listener close", 5, || {
        TcpStream::connect(("127.0.0.1", p)).is_err()
    });
}

#[test]
fn revoke_closes_a_long_query_within_one_second() {
    let pg = need!(postgres(), "Postgres (initdb/postgres/psql/openssl)");
    let ca = pg.dir.0.join("ca.pem");
    let e = Env::new(
        Some(&ca),
        &[("PG_PASSWORD", &pg.password)],
        &pg_toml(pg.port),
    );
    let w = e.work.display().to_string();
    let script = format!(
        "smith db connect main -- psql -X -tA -c 'select pg_sleep(30)' > {w}/q.out 2> {w}/q.err; echo \"rc=$?\" > {w}/q.rc.tmp; mv {w}/q.rc.tmp {w}/q.rc"
    );
    let agent = e.session(&script);
    // The query is running once the relay admitted the connection (ACCESS) and a moment passed.
    wait_until("relay ACCESS", 30, || e.has_event("ACCESS", "db:main"));
    std::thread::sleep(Duration::from_millis(700));
    assert!(
        !e.work.join("q.rc").exists(),
        "query ended early: {}",
        e.file("q.err")
    );
    let t = Instant::now();
    let o = e.out(&["revoke", "--all"]);
    assert!(o.status.success(), "{}", s(&o.stderr));
    let rc = e.work.join("q.rc");
    wait_until("psql exit", 10, || rc.exists());
    let took = t.elapsed();
    eprintln!("revoke -> psql exit: {took:?}");
    assert!(
        took < Duration::from_secs(1),
        "connection closed after {took:?}"
    );
    assert!(!e.file("q.rc").contains("rc=0"), "{}", e.file("q.rc"));
    let _ = agent.wait_with_output();
}

#[test]
fn mariadb_tls_only_user_through_relay() {
    let my = need!(
        mariadb(),
        "MariaDB (mariadbd/mariadb-install-db/mariadb/openssl)"
    );
    let ca = my.dir.0.join("ca.pem");
    let toml = format!(
        "[db.my]\nkind = \"mysql\"\nhost = \"localhost\"\nport = {}\nuser = \"app\"\ndatabase = \"appdb\"\npassword_key = \"MY_PASSWORD\"\n",
        my.port
    );
    let e = Env::new(Some(&ca), &[("MY_PASSWORD", &my.password)], &toml);
    let script = r#"
smith db connect my -- sh -c 'mariadb --no-defaults -h "$MYSQL_HOST" -P "$MYSQL_TCP_PORT" -u "$MYSQL_USER" -D "$MYSQL_DATABASE" -N -e "CREATE TABLE t (x INT); INSERT INTO t VALUES (1),(2),(4); SELECT SUM(x) FROM t;"' > sum.txt 2> my.err; echo "rc=$?"
smith db connect my -- sh -c 'mariadb --no-defaults -h "$MYSQL_HOST" -P "$MYSQL_TCP_PORT" -u "$MYSQL_USER" -N -e "SELECT nosuchcol FROM appdb.t"' 2> err.txt; echo "bad=$?"
smith db connect my -- env > env.txt
"#;
    let o = e.session(script).wait_with_output().unwrap();
    let out = s(&o.stdout);
    assert!(
        out.contains("rc=0"),
        "{out} {} {}",
        s(&o.stderr),
        e.file("my.err")
    );
    assert_eq!(e.file("sum.txt").trim(), "7");
    assert!(!out.contains("bad=0"));
    assert!(
        e.file("err.txt").contains("nosuchcol"),
        "{}",
        e.file("err.txt")
    );
    assert_never_disclosed(
        &e,
        &my.password,
        &o,
        &["sum.txt", "my.err", "err.txt", "env.txt"],
    );
    assert!(e.has_event("ACCESS", "db:my"));
}

#[test]
fn redis_acl_user_through_relay() {
    let rd = need!(redis(), "Redis (redis-server/redis-cli)");
    let toml = format!(
        "[db.cache]\nkind = \"redis\"\nhost = \"127.0.0.1\"\nport = {}\nuser = \"app\"\npassword_key = \"REDIS_PASSWORD\"\n",
        rd.port
    );
    let e = Env::new(None, &[("REDIS_PASSWORD", &rd.password)], &toml);
    let script = r#"
smith db connect cache -- sh -c 'redis-cli -u "$REDIS_URL" SET k v; redis-cli -u "$REDIS_URL" GET k; redis-cli -u "$REDIS_URL" ACL WHOAMI' > r.txt 2>&1; echo "rc=$?"
smith db connect cache -- env > env.txt
"#;
    let o = e.session(script).wait_with_output().unwrap();
    let out = s(&o.stdout);
    assert!(out.contains("rc=0"), "{out} {}", s(&o.stderr));
    let r = e.file("r.txt");
    assert_eq!(
        r.split_whitespace().collect::<Vec<_>>(),
        ["OK", "v", "app"],
        "{r}"
    );
    assert_never_disclosed(&e, &rd.password, &o, &["r.txt", "env.txt"]);
}
