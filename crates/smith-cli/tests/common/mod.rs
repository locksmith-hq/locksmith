//! Shared e2e helpers: throwaway LOCKSMITH_HOME and the real `smith` binary.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

pub const PW: &str = "correct horse battery";
pub const VALUE: &str = "sk_live_CANARY_VALUE_4242";

pub struct Home(pub PathBuf);
impl Home {
    pub fn new() -> Self {
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
    pub fn vault(&self) -> PathBuf {
        self.0.join("vault")
    }
    pub fn cmd(&self, args: &[&str]) -> Command {
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
    pub fn run(&self, args: &[&str], rest: &str) -> Output {
        self.run_pw(PW, args, rest)
    }
    pub fn run_pw(&self, pw: &str, args: &[&str], rest: &str) -> Output {
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
    pub fn init(&self, wrong_words: bool) -> (Option<String>, Output) {
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
    pub fn ready(&self) -> String {
        let (phrase, o) = self.init(false);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        phrase.unwrap()
    }
    pub fn add(&self, name: &str, value: &str) -> Output {
        self.run(&["add", name, "--stdin"], value)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
