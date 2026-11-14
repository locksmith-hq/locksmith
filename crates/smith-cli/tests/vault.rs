//! e2e: real `smith` binary, throwaway LOCKSMITH_HOME, weak KDF (debug-only override).
//! Canary secret values below must never show up in any output except where stated.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const PW: &str = "correct horse battery";
const VALUE: &str = "sk_live_CANARY_VALUE_4242";

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "smith-e2e-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Home(p)
    }
    fn vault(&self) -> PathBuf {
        self.0.join("vault")
    }
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_smith"));
        c.args(args)
            .env("LOCKSMITH_HOME", &self.0)
            .env("LOCKSMITH_INSECURE_TEST_KDF", "1")
            .env_remove("CLAUDECODE")
            .env_remove("CURSOR_TRACE_ID")
            .env_remove("CODEX_HOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }
    /// Runs with `--passphrase-stdin`; `rest` is whatever follows the passphrase line.
    fn run(&self, args: &[&str], rest: &str) -> Output {
        self.run_pw(PW, args, rest)
    }
    fn run_pw(&self, pw: &str, args: &[&str], rest: &str) -> Output {
        let mut full = vec!["--passphrase-stdin"];
        full.extend_from_slice(args);
        let mut c = self.cmd(&full).spawn().unwrap();
        // smith may refuse (e.g. bad vault perms) and exit before reading stdin; a broken
        // pipe here is expected then, and the exit status is what the test checks.
        let _ = c
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{pw}\n{rest}").as_bytes());
        c.wait_with_output().unwrap()
    }
    /// `smith vault init`, driving the phrase confirmation. Returns the recovery phrase.
    fn init(&self, wrong_words: bool) -> (Option<String>, Output) {
        let mut c = self
            .cmd(&[
                "--passphrase-stdin",
                "--test-confirm-words-from-stdin",
                "vault",
                "init",
            ])
            .spawn()
            .unwrap();
        let mut stdin = c.stdin.take().unwrap();
        writeln!(stdin, "{PW}").unwrap();
        let mut err = BufReader::new(c.stderr.take().unwrap());
        let mut words: Vec<String> = Vec::new();
        let mut line = String::new();
        let positions = loop {
            line.clear();
            assert!(err.read_line(&mut line).unwrap() > 0, "init ended early");
            if let Some(rest) = line.strip_prefix("Confirm words ") {
                break rest
                    .split_whitespace()
                    .take(3)
                    .map(|t| t.trim_start_matches('#').parse::<usize>().unwrap())
                    .collect::<Vec<_>>();
            }
            let t = line.trim();
            if let Some((n, w)) = t.split_once(". ")
                && n.parse::<usize>().is_ok()
            {
                words.push(w.to_string());
            }
        };
        assert_eq!(words.len(), 24);
        let answer: Vec<String> = if wrong_words {
            vec!["abandon".into(), "abandon".into(), "abandon".into()]
        } else {
            positions.iter().map(|p| words[p - 1].clone()).collect()
        };
        // Wrong words: the prompt repeats; EOF then ends init with failure.
        let _ = writeln!(stdin, "{}", answer.join(" "));
        drop(stdin);
        let mut rest = String::new();
        err.read_to_string(&mut rest).unwrap();
        let status = c.wait().unwrap();
        let o = Output {
            status,
            stdout: vec![],
            stderr: rest.into_bytes(),
        };
        (Some(words.join(" ")), o)
    }
    fn ready(&self) -> String {
        let (phrase, o) = self.init(false);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        phrase.unwrap()
    }
    fn add(&self, name: &str, value: &str) -> Output {
        self.run(&["add", name, "--stdin"], value)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}
fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|_| panic!("not json: {}", s(&o.stdout)))
}
fn all_vault_bytes(dir: &Path) -> Vec<u8> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        v.extend(std::fs::read(e.unwrap().path()).unwrap());
    }
    v
}
fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
fn init_requires_correct_confirmation_words() {
    let h = Home::new();
    let (_, o) = h.init(true);
    assert!(!o.status.success());
    assert!(
        !h.vault().join("vault.header").exists(),
        "vault must not exist without confirmation"
    );
}

#[test]
fn add_twice_ls_history_and_no_value_leaks() {
    let h = Home::new();
    h.ready();
    for v in ["first", VALUE] {
        let o = h.add("STRIPE_KEY", v);
        assert!(o.status.success(), "{}", s(&o.stderr));
        assert!(!contains(&o.stdout, VALUE) && !contains(&o.stderr, VALUE));
    }
    let o = h.run(&["ls", "--json"], "");
    assert!(o.status.success());
    let v = json(&o);
    let rows = v["secrets"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], "STRIPE_KEY");
    assert_eq!(rows[0]["version"], 2);
    for k in rows[0].as_object().unwrap().keys() {
        assert!(
            !k.contains("value") && !k.contains("secret"),
            "value-ish field {k}"
        );
    }
    assert!(!contains(&o.stdout, VALUE) && !contains(&o.stdout, "first"));
    let o = h.run(&["history", "STRIPE_KEY", "--json"], "");
    let v = json(&o);
    let vs = v["versions"].as_array().unwrap();
    assert_eq!(vs.len(), 2);
    assert_eq!(vs[0]["current"], true);
    assert_eq!(vs[1]["current"], false);
    assert!(!contains(&o.stdout, VALUE));
    assert_eq!(h.run(&["history", "NOPE"], "").status.code(), Some(5));
}

#[test]
fn key_and_project_names_absent_from_raw_files() {
    let h = Home::new();
    h.ready();
    assert!(
        h.run(&["project", "add", "canaryproject"], "")
            .status
            .success()
    );
    assert!(
        h.run(
            &[
                "add",
                "CANARY_KEY_NAME_777",
                "--stdin",
                "-p",
                "canaryproject"
            ],
            VALUE
        )
        .status
        .success()
    );
    let raw = all_vault_bytes(&h.vault());
    for needle in ["CANARY_KEY_NAME_777", "canaryproject", VALUE] {
        assert!(!contains(&raw, needle), "{needle} readable at rest");
    }
}

#[test]
fn positional_value_is_rejected_with_exit_2() {
    let h = Home::new();
    h.ready();
    let o = h.run(&["add", "STRIPE_KEY", VALUE], "");
    assert_eq!(o.status.code(), Some(2));
    let e = s(&o.stderr);
    assert!(
        e.contains("--stdin") && e.contains("--from-file") && e.contains("prompt"),
        "{e}"
    );
    assert!(!e.contains(VALUE));
    assert_eq!(
        json(&h.run(&["ls", "--json"], ""))["secrets"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn from_file_and_wrong_passphrase() {
    let h = Home::new();
    h.ready();
    let f = h.0.join("val.txt");
    std::fs::write(&f, "from-file-value\n").unwrap();
    let o = h.run(&["add", "K", "--from-file", f.to_str().unwrap()], "");
    assert!(o.status.success(), "{}", s(&o.stderr));
    let o = h.run_pw("wrong", &["ls"], "");
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn reveal_refuses_non_tty_and_agents() {
    let h = Home::new();
    h.ready();
    assert!(h.add("K", VALUE).status.success());
    // Piped stdout/stdin, no agent markers.
    let mut c = h.cmd(&["reveal", "K"]).spawn().unwrap();
    drop(c.stdin.take());
    let o = c.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(3), "{}", s(&o.stderr));
    assert!(!contains(&o.stdout, VALUE) && !contains(&o.stderr, VALUE));
    // Agent detected.
    for (k, v) in [
        ("CLAUDECODE", "1"),
        ("CURSOR_TRACE_ID", "x"),
        ("CODEX_SANDBOX", "1"),
    ] {
        let mut c = h.cmd(&["reveal", "K"]);
        c.env(k, v);
        let mut c = c.spawn().unwrap();
        drop(c.stdin.take());
        let o = c.wait_with_output().unwrap();
        assert_eq!(o.status.code(), Some(3), "{k}");
        assert!(
            s(&o.stderr).contains("your own terminal"),
            "{}",
            s(&o.stderr)
        );
        assert!(!contains(&o.stdout, VALUE) && !contains(&o.stderr, VALUE));
    }
    // --passphrase-stdin is not allowed for reveal.
    let o = h.run(&["reveal", "K"], "");
    assert_eq!(o.status.code(), Some(2));
    assert!(!contains(&o.stdout, VALUE) && !contains(&o.stderr, VALUE));
}

#[test]
fn export_writes_0600_and_refuses_piped_stdout() {
    let h = Home::new();
    h.ready();
    assert!(h.add("A_KEY", VALUE).status.success());
    assert!(h.add("MULTI", "line1\nline \"2\" $x").status.success());
    let out = h.0.join("backup.env");
    let o = h.run(
        &["export", "--format", "env", "--out", out.to_str().unwrap()],
        "",
    );
    assert!(o.status.success(), "{}", s(&o.stderr));
    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let body = std::fs::read_to_string(&out).unwrap();
    assert!(body.contains(&format!("A_KEY={VALUE}")), "{body}");
    assert!(!contains(&o.stdout, VALUE) && !contains(&o.stderr, VALUE));
    // Round-trips through import.
    let h2 = Home::new();
    h2.ready();
    let o = h2.run(&["import", "dotenv", out.to_str().unwrap(), "--keep"], "");
    assert!(o.status.success(), "{}", s(&o.stderr));
    let jo = h.0.join("backup.json");
    assert!(
        h2.run(
            &[
                "export",
                "--format",
                "json",
                "--env",
                "development",
                "--out",
                jo.to_str().unwrap()
            ],
            ""
        )
        .status
        .success()
    );
    let j: serde_json::Value = serde_json::from_slice(&std::fs::read(&jo).unwrap()).unwrap();
    assert_eq!(j["A_KEY"], VALUE);
    assert_eq!(j["MULTI"], "line1\nline \"2\" $x");
    // Existing file is never overwritten; piped stdout is refused.
    assert_eq!(
        h.run(&["export", "--out", out.to_str().unwrap()], "")
            .status
            .code(),
        Some(1)
    );
    let o = h.run(&["export"], "");
    assert_eq!(o.status.code(), Some(3));
    assert!(!contains(&o.stdout, VALUE));
}

#[test]
fn world_readable_vault_exits_1() {
    let h = Home::new();
    h.ready();
    let db = h.vault().join("vault.db");
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = h.run(&["ls"], "");
    assert_eq!(o.status.code(), Some(1));
    assert!(s(&o.stderr).contains("chmod"), "{}", s(&o.stderr));
}

#[test]
fn header_tamper_is_refused() {
    let h = Home::new();
    h.ready();
    let hp = h.vault().join("vault.header");
    let mut b = std::fs::read(&hp).unwrap();
    *b.last_mut().unwrap() ^= 1;
    std::fs::write(&hp, b).unwrap();
    let o = h.run(&["ls"], "");
    assert_eq!(o.status.code(), Some(1));
    assert!(s(&o.stderr).contains("integrity"), "{}", s(&o.stderr));
}

#[test]
fn dotenv_import_with_quotes_multiline_and_export_prefix() {
    let h = Home::new();
    h.ready();
    let f = h.0.join(".env");
    std::fs::write(
        &f,
        "# comment\nPLAIN=abc\nexport EXPORTED=\"quoted # kept\" # trailing\nSINGLE='lit $x \\n'\nMULTI=\"line1\nline2 \\\"q\\\"\"\nEMPTY=\nBARE=v # c\n",
    )
    .unwrap();
    let o = h.run(&["import", "dotenv", f.to_str().unwrap(), "--yes"], "");
    assert!(o.status.success(), "{}", s(&o.stderr));
    assert!(!f.exists(), "--yes deletes the file");
    let out = h.0.join("o.json");
    assert!(
        h.run(
            &[
                "export",
                "--format",
                "json",
                "--env",
                "development",
                "--out",
                out.to_str().unwrap()
            ],
            ""
        )
        .status
        .success()
    );
    let j: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(j["PLAIN"], "abc");
    assert_eq!(j["EXPORTED"], "quoted # kept");
    assert_eq!(j["SINGLE"], "lit $x \\n");
    assert_eq!(j["MULTI"], "line1\nline2 \"q\"");
    assert_eq!(j["EMPTY"], "");
    assert_eq!(j["BARE"], "v");
    // --keep keeps.
    std::fs::write(&f, "K2=v\n").unwrap();
    assert!(
        h.run(&["import", "dotenv", f.to_str().unwrap(), "--keep"], "")
            .status
            .success()
    );
    assert!(f.exists());
}

#[test]
fn projects_and_environments() {
    let h = Home::new();
    h.ready();
    assert!(h.run(&["project", "add", "api"], "").status.success());
    assert_eq!(h.run(&["project", "add", "api"], "").status.code(), Some(2));
    assert!(
        h.run(&["env", "add", "production", "-p", "api"], "")
            .status
            .success()
    );
    let v = json(&h.run(&["env", "ls", "-p", "api", "--json"], ""));
    assert_eq!(
        v["environments"],
        serde_json::json!(["development", "production"])
    );
    assert!(
        h.run(
            &["add", "K", "--stdin", "-p", "api", "-e", "production"],
            "v"
        )
        .status
        .success()
    );
    assert_eq!(
        h.run(&["add", "K", "--stdin", "-p", "api", "-e", "nope"], "v")
            .status
            .code(),
        Some(5)
    );
    assert!(
        h.run(&["rm", "K", "-p", "api", "-e", "production"], "")
            .status
            .success()
    );
    assert!(
        h.run(&["project", "rm", "api", "--yes"], "")
            .status
            .success()
    );
    let v = json(&h.run(&["project", "ls", "--json"], ""));
    assert_eq!(v["projects"].as_array().unwrap().len(), 1); // only "default" left
}

#[test]
fn recover_with_phrase_then_new_passphrase_works() {
    let h = Home::new();
    let phrase = h.ready();
    assert!(h.add("K", VALUE).status.success());
    // Wrong phrase changes nothing.
    let bad = ["abandon"; 24].join(" ");
    assert_ne!(
        h.run_pw(&bad, &["vault", "recover"], "newpass\n")
            .status
            .code(),
        Some(0)
    );
    assert!(h.run(&["ls"], "").status.success());
    // Right phrase: line 1 phrase, line 2 new passphrase.
    let o = h.run_pw(&phrase, &["vault", "recover"], "brand new pass\n");
    assert!(o.status.success(), "{}", s(&o.stderr));
    assert_eq!(
        h.run(&["ls"], "").status.code(),
        Some(1),
        "old passphrase must stop working"
    );
    let out = h.0.join("x.json");
    let o = h.run_pw(
        "brand new pass",
        &[
            "export",
            "--format",
            "json",
            "--env",
            "development",
            "--out",
            out.to_str().unwrap(),
        ],
        "",
    );
    assert!(o.status.success(), "{}", s(&o.stderr));
    assert!(contains(&std::fs::read(&out).unwrap(), VALUE));
}

#[test]
fn passwd_and_recovery_rotate() {
    let h = Home::new();
    let old_phrase = h.ready();
    assert!(h.add("K", "v").status.success());
    let o = h.run(&["vault", "passwd"], "second pass\n");
    assert!(o.status.success(), "{}", s(&o.stderr));
    assert!(h.run_pw("second pass", &["ls"], "").status.success());
    assert_eq!(h.run(&["ls"], "").status.code(), Some(1));

    // Rotate: drive confirmation like init.
    let mut c = h
        .cmd(&[
            "--passphrase-stdin",
            "--test-confirm-words-from-stdin",
            "vault",
            "recovery",
            "rotate",
        ])
        .spawn()
        .unwrap();
    let mut stdin = c.stdin.take().unwrap();
    writeln!(stdin, "second pass").unwrap();
    let mut err = BufReader::new(c.stderr.take().unwrap());
    let (mut words, mut line) = (Vec::new(), String::new());
    let positions: Vec<usize> = loop {
        line.clear();
        assert!(err.read_line(&mut line).unwrap() > 0);
        if let Some(r) = line.strip_prefix("Confirm words ") {
            break r
                .split_whitespace()
                .take(3)
                .map(|t| t.trim_start_matches('#').parse().unwrap())
                .collect();
        }
        if let Some((n, w)) = line.trim().split_once(". ")
            && n.parse::<usize>().is_ok()
        {
            words.push(w.to_string());
        }
    };
    let ans: Vec<_> = positions.iter().map(|p| words[p - 1].clone()).collect();
    writeln!(stdin, "{}", ans.join(" ")).unwrap();
    drop(stdin);
    let mut rest = String::new();
    err.read_to_string(&mut rest).unwrap();
    assert!(c.wait().unwrap().success());

    // Old phrase no longer recovers; new one does.
    assert_ne!(
        h.run_pw(&old_phrase, &["vault", "recover"], "x y z\n")
            .status
            .code(),
        Some(0)
    );
    let new_phrase = words.join(" ");
    assert!(
        h.run_pw(&new_phrase, &["vault", "recover"], "third pass\n")
            .status
            .success()
    );
    assert!(h.run_pw("third pass", &["ls"], "").status.success());
}

fn spawn_add(h: &Home, name: &str) -> Child {
    let mut c = h
        .cmd(&["--passphrase-stdin", "add", name, "--stdin"])
        .spawn()
        .unwrap();
    c.stdin
        .take()
        .unwrap()
        .write_all(format!("{PW}\nvalue-for-{name}").as_bytes())
        .unwrap();
    c
}

/// Task 2.2: SIGKILL a writer at varying points, 100 times; the vault must always reopen and
/// every secret must be either fully present (with its exact value) or absent.
#[test]
fn kill_during_add_never_corrupts_the_vault() {
    let h = Home::new();
    h.ready();
    assert!(h.add("BASE", "base-value").status.success());
    let mut present = 0;
    for i in 0..100u64 {
        let name = format!("KILL_{i}");
        let mut c = spawn_add(&h, &name);
        std::thread::sleep(std::time::Duration::from_millis((i * 7) % 90));
        let _ = c.kill(); // SIGKILL
        let _ = c.wait();
        let o = h.run(&["ls", "--json"], "");
        assert!(
            o.status.success(),
            "iteration {i}: reopen failed: {}",
            s(&o.stderr)
        );
        let v = json(&o);
        let hit: Vec<_> = v["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["name"] == name.as_str())
            .collect();
        assert!(hit.len() <= 1, "iteration {i}");
        if let Some(r) = hit.first() {
            assert_eq!(r["version"], 1, "iteration {i}: partial version");
            present += 1;
        }
    }
    eprintln!("kill test: {present}/100 adds had committed when killed");
    // Everything present decrypts to exactly its value.
    let out = h.0.join("all.json");
    let o = h.run(
        &[
            "export",
            "--format",
            "json",
            "--env",
            "development",
            "--out",
            out.to_str().unwrap(),
        ],
        "",
    );
    assert!(o.status.success(), "{}", s(&o.stderr));
    let j: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(j["BASE"], "base-value");
    for (k, v) in j.as_object().unwrap() {
        if k.starts_with("KILL_") {
            assert_eq!(v.as_str().unwrap(), format!("value-for-{k}"));
        }
    }
}
