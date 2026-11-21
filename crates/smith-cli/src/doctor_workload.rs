//! Doctor check `workload.login` (the `workload` check of the task; ids must be dotted per doctor.v1) (D4 task 5.2): the policy handle is present and well formed, the
//! runner's token source is there and reachable, and the agent token in `agent.json` is not
//! expired. Pure outcome function over explicit facts; the probe reads the environment, the state
//! file and does one short TCP connect. It never reads or prints a token value.

use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ls_connector::{
    GITHUB_REQUEST_URL_ENV, KUBERNETES_DEFAULT_TOKEN_FILE, State, WORKLOAD_POLICY_ENV,
    WORKLOAD_TOKEN_FILE_ENV, valid_policy_handle,
};
use ls_diag::{Check, Outcome};

const FIX_POLICY: &str = "set LOCKSMITH_WORKLOAD_POLICY to the policy handle (lsw_...) shown by \
     the workload identity, or pass --policy";

/// Where the external token would come from.
enum Source {
    /// GitHub runner request variables.
    Github,
    /// Projected token file and whether it is readable.
    Kubernetes {
        readable: bool,
    },
    None,
}

struct Facts {
    /// `None` when the variable is unset or blank.
    policy: Option<String>,
    source: Source,
    reachable: Option<bool>,
    /// Unix expiry of the stored agent token, if a state file loads.
    expires_at: Option<u64>,
    now: u64,
}

fn outcome(f: &Facts) -> Outcome {
    let Some(policy) = &f.policy else {
        return Outcome::skip("workload login not configured");
    };
    if !valid_policy_handle(policy) {
        return Outcome::fail("the workload policy handle is malformed", FIX_POLICY);
    }
    let source = match &f.source {
        Source::Github => match f.reachable {
            Some(false) => {
                return Outcome::fail(
                    "the runner's identity token endpoint is not reachable",
                    "check the runner's network access",
                );
            }
            _ => "GitHub runner",
        },
        Source::Kubernetes { readable: true } => "projected token file",
        Source::Kubernetes { readable: false } => {
            return Outcome::fail(
                "the projected token file is missing or unreadable",
                "mount a projected service account token with the policy audience and set \
                 LOCKSMITH_WORKLOAD_TOKEN_FILE",
            );
        }
        Source::None => {
            return Outcome::fail(
                "no token source: not in GitHub Actions with OIDC and no token file",
                "add `permissions: id-token: write` to the job, or set LOCKSMITH_WORKLOAD_TOKEN_FILE",
            );
        }
    };
    let token = match f.expires_at {
        None => "no agent token yet".to_string(),
        Some(e) if e <= f.now => {
            return Outcome::warn(
                format!("policy handle present, {source} ok, agent token expired"),
                "run `smith login --workload github|kubernetes` again",
            );
        }
        Some(e) => format!("agent token valid for {} s", e - f.now),
    };
    Outcome::ok(format!("policy handle present, {source} ok, {token}"))
}

fn tcp_reachable(host: &str, port: u16) -> bool {
    (host, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .is_some_and(|a| TcpStream::connect_timeout(&a, Duration::from_secs(2)).is_ok())
}

fn probe() -> Outcome {
    let policy = std::env::var(WORKLOAD_POLICY_ENV)
        .ok()
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty());
    let github = std::env::var(GITHUB_REQUEST_URL_ENV)
        .ok()
        .and_then(|u| url::Url::parse(&u).ok())
        .and_then(|u| Some((u.host_str()?.to_owned(), u.port_or_known_default()?)));
    let token_file = std::env::var_os(WORKLOAD_TOKEN_FILE_ENV).map(PathBuf::from);
    let (source, reachable) = if let Some((host, port)) = github {
        let r = policy.is_some().then(|| tcp_reachable(&host, port));
        (Source::Github, r)
    } else if let Some(p) = token_file {
        (
            Source::Kubernetes {
                readable: std::fs::File::open(p).is_ok(),
            },
            None,
        )
    } else if std::path::Path::new(KUBERNETES_DEFAULT_TOKEN_FILE).exists() {
        (Source::Kubernetes { readable: true }, None)
    } else {
        (Source::None, None)
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    outcome(&Facts {
        policy,
        source,
        reachable,
        expires_at: State::load().ok().map(|s| s.expires_at()),
        now,
    })
}

inventory::submit! { Check { id: "workload.login", run: probe } }

#[cfg(test)]
mod tests {
    use super::*;
    use ls_diag::Status;

    const HANDLE: &str = "lsw_AAECAwQFBgcICQoLDA0ODw";

    fn facts() -> Facts {
        Facts {
            policy: Some(HANDLE.into()),
            source: Source::Github,
            reachable: Some(true),
            expires_at: None,
            now: 1000,
        }
    }

    #[test]
    fn workload_check_branches() {
        let f = Facts {
            policy: None,
            ..facts()
        };
        assert_eq!(outcome(&f).status, Status::Skip);
        let f = Facts {
            policy: Some("nope".into()),
            ..facts()
        };
        assert_eq!(outcome(&f).status, Status::Fail);
        assert_eq!(outcome(&facts()).status, Status::Ok);
        let f = Facts {
            reachable: Some(false),
            ..facts()
        };
        assert_eq!(outcome(&f).status, Status::Fail);
        let f = Facts {
            source: Source::None,
            ..facts()
        };
        assert_eq!(outcome(&f).status, Status::Fail);
        let f = Facts {
            source: Source::Kubernetes { readable: false },
            ..facts()
        };
        assert_eq!(outcome(&f).status, Status::Fail);
        let f = Facts {
            expires_at: Some(900),
            ..facts()
        };
        assert_eq!(outcome(&f).status, Status::Warn);
        let f = Facts {
            expires_at: Some(1600),
            ..facts()
        };
        let o = outcome(&f);
        assert_eq!(o.status, Status::Ok);
        assert!(o.summary.contains("600 s"));
    }
}
