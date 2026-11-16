//! Doctor checks for M7 AWS delegation: `aws.relay`, `aws.policy`, `aws.upstream_identity`. Pure
//! functions over explicit facts (like doctor_m5/doctor_m6), so the tests need no daemon, AWS CLI
//! or credentials.

use crate::binding;
use ls_diag::{Check, Outcome};
use ls_ipc::{Client, Request, Response};
use ls_proxy::aws::policy::Policy;
use ls_redact::binding::Binding;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(20);

/// `reply`: `None` when the daemon is not running.
fn relay_outcome(reply: Option<std::io::Result<Response>>) -> Outcome {
    match reply {
        None => Outcome::skip("locksmithd is not running"),
        Some(Ok(Response::AwsInfo { port })) => {
            Outcome::ok(format!("listening on 127.0.0.1:{port}"))
        }
        Some(Ok(Response::Error { message, .. })) => Outcome::fail(message, "smith daemon status"),
        Some(Ok(_)) => Outcome::fail("unexpected daemon reply", "smith daemon status"),
        Some(Err(e)) => Outcome::fail(format!("daemon did not answer: {e}"), "smith daemon status"),
    }
}

/// Same rule as the vault's key names (`ls-vault`): 1-128 of `A-Z a-z 0-9 _ . -`.
fn valid_key_name(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 128
        && k.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

fn policy_outcome(b: Option<&Binding>) -> Outcome {
    let Some(b) = b.filter(|b| !b.aws.profiles.is_empty()) else {
        return Outcome::skip("AWS delegation not configured");
    };
    const FIX_POLICY: &str = "fix [aws.policy] in .locksmith.toml";
    let mut warnings: Vec<(String, String)> = Vec::new();
    let allow_part = match &b.aws.policy {
        None => "read-only default".to_string(),
        Some(t) => {
            let p: Policy = match toml::Value::Table(t.clone()).try_into() {
                Ok(p) => p,
                Err(e) => {
                    return Outcome::fail(format!("invalid [aws.policy]: {e}"), FIX_POLICY);
                }
            };
            if p.allow.iter().any(|a| matches!(a.trim(), "*" | "*:*")) {
                warnings.push((
                    "policy allows every action".into(),
                    "narrow `allow` in [aws.policy]".into(),
                ));
            }
            let allow = if p.allow.is_empty() {
                "read-only default".to_string()
            } else {
                format!("{} allow", p.allow.len())
            };
            format!(
                "{allow}, {} deny, {} resource pattern(s)",
                p.deny.len(),
                p.resources.len()
            )
        }
    };
    for (name, prof) in &b.aws.profiles {
        if prof.region.trim().is_empty() {
            warnings.push((
                format!("[aws.profiles.{name}] has an empty region"),
                format!("set region in [aws.profiles.{name}]"),
            ));
        }
        if !valid_key_name(&prof.key) {
            warnings.push((
                format!(
                    "[aws.profiles.{name}] key {:?} is not a valid vault key name",
                    prof.key
                ),
                format!("set key in [aws.profiles.{name}] to a vault key name"),
            ));
        }
    }
    if warnings.is_empty() {
        let n = b.aws.profiles.len();
        return Outcome::ok(format!("{n} profile(s); policy: {allow_part}"));
    }
    let (summary, fix): (Vec<_>, Vec<_>) = warnings.into_iter().unzip();
    Outcome::warn(summary.join("; "), fix.join("; "))
}

/// What running `smith run --aws <profile> -- aws sts get-caller-identity` did.
enum Run {
    Done {
        ok: bool,
        stdout: String,
        stderr: String,
    },
    TimedOut,
    Failed(String),
}

fn identity_outcome(
    profile: &str,
    in_session: bool,
    aws_present: bool,
    run: Option<Run>,
) -> Outcome {
    let fix = format!("smith run --aws {profile} -- aws sts get-caller-identity");
    if !in_session {
        return Outcome::skip("run inside `smith session start` to check");
    }
    if !aws_present {
        return Outcome::skip("AWS CLI not installed");
    }
    match run {
        None => Outcome::skip("not run"),
        Some(Run::TimedOut) => {
            Outcome::fail(format!("timed out after {}s", TIMEOUT.as_secs()), fix)
        }
        Some(Run::Failed(e)) => Outcome::fail(format!("cannot run smith: {e}"), fix),
        Some(Run::Done {
            ok: false, stderr, ..
        }) => Outcome::fail(
            stderr.lines().next().unwrap_or("command failed").trim(),
            fix,
        ),
        Some(Run::Done { stdout, .. }) => {
            match serde_json::from_str::<serde_json::Value>(&stdout)
                .ok()
                .and_then(|v| v["Arn"].as_str().map(str::to_owned))
            {
                Some(arn) => Outcome::ok(format!("upstream credentials work as {arn}")),
                None => Outcome::fail("sts get-caller-identity returned no Arn", fix),
            }
        }
    }
}

fn aws_on_path() -> bool {
    std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| d.join("aws").is_file() || d.join("aws.exe").is_file())
    })
}

fn spawn_identity(profile: &str) -> Run {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return Run::Failed(e.to_string()),
    };
    let mut child = match Command::new(exe)
        .args([
            "run",
            "--aws",
            profile,
            "--",
            "aws",
            "sts",
            "get-caller-identity",
            "--output",
            "json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Run::Failed(e.to_string()),
    };
    fn drain(mut r: impl Read + Send + 'static) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = r.read_to_string(&mut s);
            s
        })
    }
    let out = drain(child.stdout.take().expect("piped"));
    let err = drain(child.stderr.take().expect("piped"));
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Run::TimedOut;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Run::Failed(e.to_string()),
        }
    };
    Run::Done {
        ok: status.success(),
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    }
}

fn load_binding() -> Option<Binding> {
    let dir = std::env::current_dir().ok()?;
    binding::load(&binding::find(&dir)?).ok().map(|(b, _)| b)
}

/// Never starts the daemon.
fn relay() -> Outcome {
    let reply = Client::connect_default()
        .ok()
        .map(|mut c| c.call(&Request::AwsInfo));
    relay_outcome(reply)
}

fn policy() -> Outcome {
    policy_outcome(load_binding().as_ref())
}

fn upstream_identity() -> Outcome {
    let b = load_binding();
    let Some(profile) = b.as_ref().and_then(|b| b.aws.profiles.keys().next()) else {
        return Outcome::skip("AWS delegation not configured");
    };
    let in_session = crate::session::in_session();
    let aws_present = aws_on_path();
    let run = (in_session && aws_present).then(|| spawn_identity(profile));
    identity_outcome(profile, in_session, aws_present, run)
}

inventory::submit! { Check { id: "aws.relay", run: relay } }
inventory::submit! { Check { id: "aws.policy", run: policy } }
inventory::submit! { Check { id: "aws.upstream_identity", run: upstream_identity } }

#[cfg(test)]
mod tests {
    use super::*;
    use ls_diag::Status;
    use ls_ipc::ErrorCode;

    #[track_caller]
    fn expect(out: &Outcome, status: Status, summary: &str, remediation: Option<&str>) {
        assert_eq!(out.status, status, "status for {summary:?}");
        assert_eq!(out.summary, summary);
        assert_eq!(out.remediation.as_deref(), remediation);
    }

    fn binding(toml: &str) -> Binding {
        ls_redact::binding::parse(toml.as_bytes()).unwrap()
    }

    #[test]
    fn relay_branches() {
        expect(
            &relay_outcome(None),
            Status::Skip,
            "locksmithd is not running",
            None,
        );
        expect(
            &relay_outcome(Some(Ok(Response::AwsInfo { port: 4244 }))),
            Status::Ok,
            "listening on 127.0.0.1:4244",
            None,
        );
        let e = Response::Error {
            code: ErrorCode::Internal,
            message: "AWS relay is not running".into(),
        };
        expect(
            &relay_outcome(Some(Ok(e))),
            Status::Fail,
            "AWS relay is not running",
            Some("smith daemon status"),
        );
        expect(
            &relay_outcome(Some(Ok(Response::Ok))),
            Status::Fail,
            "unexpected daemon reply",
            Some("smith daemon status"),
        );
        expect(
            &relay_outcome(Some(Err(std::io::Error::other("boom")))),
            Status::Fail,
            "daemon did not answer: boom",
            Some("smith daemon status"),
        );
    }

    const PROFILE: &str = "[aws.profiles.dev]\nkey = \"AWS_DEV\"\nregion = \"us-east-1\"\n";

    #[test]
    fn policy_branches() {
        let skip = "AWS delegation not configured";
        expect(&policy_outcome(None), Status::Skip, skip, None);
        expect(
            &policy_outcome(Some(&binding(""))),
            Status::Skip,
            skip,
            None,
        );
        // A policy without profiles is not "configured".
        let b = binding("[aws.policy]\nallow = [\"s3:Get*\"]\n");
        expect(&policy_outcome(Some(&b)), Status::Skip, skip, None);

        expect(
            &policy_outcome(Some(&binding(PROFILE))),
            Status::Ok,
            "1 profile(s); policy: read-only default",
            None,
        );
        let b = binding(&format!(
            "{PROFILE}[aws.policy]\nallow = [\"s3:Get*\", \"s3:ListBucket\"]\ndeny = [\"s3:DeleteObject\"]\nresources = [\"arn:aws:s3:::b/*\"]\n"
        ));
        expect(
            &policy_outcome(Some(&b)),
            Status::Ok,
            "1 profile(s); policy: 2 allow, 1 deny, 1 resource pattern(s)",
            None,
        );
        let b = binding(&format!("{PROFILE}[aws.policy]\ndeny = [\"s3:Put*\"]\n"));
        expect(
            &policy_outcome(Some(&b)),
            Status::Ok,
            "1 profile(s); policy: read-only default, 1 deny, 0 resource pattern(s)",
            None,
        );

        let b = binding(&format!(
            "{PROFILE}[aws.policy]\nallow = [\"s3:Get*\", \"*\"]\n"
        ));
        let w = Some("narrow `allow` in [aws.policy]");
        expect(
            &policy_outcome(Some(&b)),
            Status::Warn,
            "policy allows every action",
            w,
        );
        let b = binding(&format!("{PROFILE}[aws.policy]\nallow = [\"*:*\"]\n"));
        expect(
            &policy_outcome(Some(&b)),
            Status::Warn,
            "policy allows every action",
            w,
        );

        let b = binding(&format!("{PROFILE}[aws.policy]\nallow = \"s3:*\"\n"));
        let o = policy_outcome(Some(&b));
        assert_eq!(o.status, Status::Fail);
        assert!(
            o.summary.starts_with("invalid [aws.policy]: "),
            "{}",
            o.summary
        );
        assert_eq!(
            o.remediation.as_deref(),
            Some("fix [aws.policy] in .locksmith.toml")
        );
        let b = binding(&format!("{PROFILE}[aws.policy]\nallows = [\"s3:*\"]\n"));
        let o = policy_outcome(Some(&b));
        assert_eq!(o.status, Status::Fail);
        assert!(o.summary.contains("allows"), "{}", o.summary);

        let b = binding("[aws.profiles.dev]\nkey = \"AWS_DEV\"\nregion = \" \"\n");
        expect(
            &policy_outcome(Some(&b)),
            Status::Warn,
            "[aws.profiles.dev] has an empty region",
            Some("set region in [aws.profiles.dev]"),
        );
        let b = binding(
            "[aws.profiles.dev]\nkey = \"my key\"\nregion = \"\"\n[aws.policy]\nallow = [\"*\"]\n",
        );
        expect(
            &policy_outcome(Some(&b)),
            Status::Warn,
            "policy allows every action; [aws.profiles.dev] has an empty region; [aws.profiles.dev] key \"my key\" is not a valid vault key name",
            Some(
                "narrow `allow` in [aws.policy]; set region in [aws.profiles.dev]; set key in [aws.profiles.dev] to a vault key name",
            ),
        );
    }

    #[test]
    fn key_names() {
        assert!(valid_key_name("AWS_DEV-1.x"));
        assert!(!valid_key_name(""));
        assert!(!valid_key_name("a b"));
        assert!(!valid_key_name(&"a".repeat(129)));
    }

    #[test]
    fn identity_branches() {
        let fix = "smith run --aws dev -- aws sts get-caller-identity";
        let done = |ok, stdout: &str, stderr: &str| {
            Some(Run::Done {
                ok,
                stdout: stdout.into(),
                stderr: stderr.into(),
            })
        };
        expect(
            &identity_outcome("dev", false, true, None),
            Status::Skip,
            "run inside `smith session start` to check",
            None,
        );
        expect(
            &identity_outcome("dev", true, false, None),
            Status::Skip,
            "AWS CLI not installed",
            None,
        );
        expect(
            &identity_outcome(
                "dev",
                true,
                true,
                done(
                    true,
                    r#"{"UserId":"AIDA","Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/dev"}"#,
                    "",
                ),
            ),
            Status::Ok,
            "upstream credentials work as arn:aws:iam::123456789012:user/dev",
            None,
        );
        expect(
            &identity_outcome("dev", true, true, done(true, "{}", "")),
            Status::Fail,
            "sts get-caller-identity returned no Arn",
            Some(fix),
        );
        expect(
            &identity_outcome("dev", true, true, done(true, "not json", "")),
            Status::Fail,
            "sts get-caller-identity returned no Arn",
            Some(fix),
        );
        expect(
            &identity_outcome(
                "dev",
                true,
                true,
                done(
                    false,
                    "",
                    "An error occurred (InvalidClientTokenId)\nsecond line",
                ),
            ),
            Status::Fail,
            "An error occurred (InvalidClientTokenId)",
            Some(fix),
        );
        expect(
            &identity_outcome("dev", true, true, done(false, "", "")),
            Status::Fail,
            "command failed",
            Some(fix),
        );
        expect(
            &identity_outcome("dev", true, true, Some(Run::TimedOut)),
            Status::Fail,
            "timed out after 20s",
            Some(fix),
        );
        expect(
            &identity_outcome("dev", true, true, Some(Run::Failed("nope".into()))),
            Status::Fail,
            "cannot run smith: nope",
            Some(fix),
        );
    }
}
