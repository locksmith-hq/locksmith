//! `smith token issue|ls|revoke` and `smith http status|providers|ca` (M6). Tokens are minted by
//! the daemon under the caller's lease; this side never sees a credential. The CA private key
//! goes straight from generation into the vault; only the public certificate touches disk.

use crate::input::{self, Opts};
use crate::session::{call, connect};
use crate::vault_cmds::{fail as vfail, unlock};
use crate::{Fail, binding};
use clap::{Args, Subcommand};
use ls_core::ExitCode;
use ls_ipc::{Client, Request, Response};
use ls_proxy::{ca, catalog};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fail(c: ExitCode, m: impl Into<String>) -> Fail {
    Fail(c, m.into())
}

fn unexpected() -> Fail {
    fail(ExitCode::Failure, "unexpected daemon reply")
}

fn binding_bytes() -> Result<Option<Vec<u8>>, Fail> {
    let cwd = std::env::current_dir().map_err(|e| fail(ExitCode::Failure, e.to_string()))?;
    Ok(match binding::find(&cwd) {
        Some(p) => Some(binding::load(&p)?.1),
        None => None,
    })
}

#[derive(Subcommand)]
pub enum TokenCmd {
    /// Mint an opaque `lsk_` token for a vault key, usable only through the HTTP relay by this
    /// session (prints the token; it is a placeholder, not the key).
    Issue(IssueArgs),
    /// List live tokens (key names, hosts, placement, session; never values).
    Ls,
    /// Revoke a token (the token or its first 12 characters), or all of them.
    Revoke {
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        token: Option<String>,
        #[arg(long)]
        all: bool,
    },
}

#[derive(Args)]
pub struct IssueArgs {
    /// Vault key name, e.g. STRIPE_KEY.
    key: String,
    /// Upstream host the token may reach (repeatable; `*.example.com` for subdomains).
    #[arg(long)]
    host: Vec<String>,
    /// bearer, basic, header:<Name> or query:<param> (comma-separated for several).
    #[arg(long)]
    placement: Option<String>,
    /// Take hosts and placement from this catalog provider (`smith http providers`).
    #[arg(long)]
    provider: Option<String>,
}

pub fn token(json: bool, cmd: TokenCmd) -> Result<ExitCode, Fail> {
    match cmd {
        TokenCmd::Issue(a) => {
            let req = Request::TokenIssue {
                key: a.key,
                provider: a.provider,
                hosts: a.host,
                placement: a.placement,
                binding: binding_bytes()?,
            };
            let mut c = connect(false).map_err(|Fail(_, m)| {
                fail(
                    ExitCode::Locked,
                    format!("{m}; start a session with `smith session start`"),
                )
            })?;
            let Response::HttpToken(t) = call(&mut c, &req)? else {
                return Err(unexpected());
            };
            let ls_ipc::IssuedToken {
                token,
                key,
                hosts,
                placement,
                lease,
                base_url,
            } = *t;
            if json {
                println!(
                    "{}",
                    json!({"token": token, "key": key, "hosts": hosts, "placement": placement,
                           "session": lease, "base_url": base_url})
                );
            } else {
                println!("{token}");
                eprintln!(
                    "{key}: {} via {placement}{}",
                    hosts.join(", "),
                    base_url.map_or(String::new(), |u| format!("; base URL {u}"))
                );
            }
            Ok(ExitCode::Ok)
        }
        TokenCmd::Ls => {
            let Ok(mut c) = connect(false) else {
                if json {
                    println!("{}", json!({"tokens": []}));
                } else {
                    println!("locksmithd is not running; no tokens exist");
                }
                return Ok(ExitCode::Ok);
            };
            let Response::HttpTokens { tokens } = call(&mut c, &Request::TokenList)? else {
                return Err(unexpected());
            };
            if json {
                let v: Vec<_> = tokens
                    .iter()
                    .map(|t| {
                        json!({"prefix": t.prefix, "key": t.key, "project": t.project,
                               "env": t.env, "hosts": t.hosts, "placement": t.placement,
                               "session": t.lease, "created_at": t.created_at})
                    })
                    .collect();
                println!("{}", json!({ "tokens": v }));
            } else if tokens.is_empty() {
                println!("no tokens");
            } else {
                for t in tokens {
                    println!(
                        "{}…  {}/{}/{}  {}  [{}]  {}",
                        t.prefix,
                        t.project,
                        t.env,
                        t.key,
                        t.hosts.join(","),
                        t.placement,
                        t.lease
                    );
                }
            }
            Ok(ExitCode::Ok)
        }
        TokenCmd::Revoke { token, .. } => {
            let Ok(mut c) = connect(false) else {
                println!("locksmithd is not running; no tokens exist");
                return Ok(ExitCode::Ok);
            };
            let Response::Revoked { count } = call(&mut c, &Request::TokenRevoke { token })? else {
                return Err(unexpected());
            };
            if json {
                println!("{}", json!({ "revoked": count }));
            } else {
                println!("revoked {count} token(s)");
            }
            Ok(ExitCode::Ok)
        }
    }
}

#[derive(Subcommand)]
pub enum HttpCmd {
    /// Show the relay port and explicit-proxy state.
    Status,
    /// List the built-in provider catalog.
    Providers,
    /// Explicit-proxy mode: a local CA constrained to the enabled hosts (opt-in).
    Ca {
        #[command(subcommand)]
        cmd: CaCmd,
    },
}

#[derive(Subcommand)]
pub enum CaCmd {
    /// Create the CA (key into the vault), write its certificate and trust it.
    Install(CaArgs),
    /// Remove the CA from the trust store, the vault and disk.
    Uninstall(CaArgs),
    /// Show the CA, its name constraints and trust-store state.
    Status,
}

#[derive(Args)]
pub struct CaArgs {
    /// Enable this catalog provider's hosts (repeatable). Install only.
    #[arg(long)]
    provider: Vec<String>,
    /// Enable this host (repeatable). Install only.
    #[arg(long)]
    host: Vec<String>,
    /// Only write the certificate; do not touch the system trust store.
    #[arg(long)]
    no_trust_store: bool,
    /// Do not ask before running `sudo` for the trust store.
    #[arg(long)]
    yes: bool,
}

/// Never starts the daemon.
fn relay_port() -> Option<u16> {
    match Client::connect_default().ok()?.call(&Request::HttpInfo) {
        Ok(Response::HttpInfo { port, .. }) => Some(port),
        _ => None,
    }
}

pub fn http(o: &Opts, cmd: HttpCmd) -> Result<ExitCode, Fail> {
    match cmd {
        HttpCmd::Status => {
            let mut c = connect(true)?;
            let Response::HttpInfo { port, ca_hosts } = call(&mut c, &Request::HttpInfo)? else {
                return Err(unexpected());
            };
            if o.json {
                println!("{}", json!({"port": port, "ca_hosts": ca_hosts}));
            } else {
                println!("relay: http://127.0.0.1:{port}/h/<host>/<path>");
                if ca_hosts.is_empty() {
                    println!("explicit proxy: off (`smith http ca install` to enable)");
                } else {
                    println!(
                        "explicit proxy: HTTPS_PROXY=http://127.0.0.1:{port} for {}",
                        ca_hosts.join(", ")
                    );
                }
            }
            Ok(ExitCode::Ok)
        }
        HttpCmd::Providers => {
            let all = catalog::all();
            if o.json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({ "providers": all })).expect("serializes")
                );
            } else {
                for p in all {
                    println!(
                        "{:<12} {:<20} {:<40} {:<30} {}",
                        p.id,
                        p.name,
                        p.hosts.join(","),
                        p.placement,
                        match p.base_url_override.as_str() {
                            "none" => "needs CA mode".to_string(),
                            _ if p.base_url_env.is_empty() => "base URL in code".to_string(),
                            _ => p.base_url_env.join(","),
                        }
                    );
                }
            }
            Ok(ExitCode::Ok)
        }
        HttpCmd::Ca { cmd } => match cmd {
            CaCmd::Install(a) => ca_install(o, a),
            CaCmd::Uninstall(a) => ca_uninstall(o, a),
            CaCmd::Status => ca_status(o),
        },
    }
}

/// Hosts to enable: flags, else the providers and hosts of this project's `[http.keys]`.
fn enabled_hosts(a: &CaArgs) -> Result<Vec<String>, Fail> {
    let mut hosts: Vec<String> = Vec::new();
    let mut add = |r: catalog::Resolved| hosts.extend(r.hosts);
    for p in &a.provider {
        add(catalog::resolve(None, Some(p), &[], None).map_err(|e| fail(ExitCode::Usage, e))?);
    }
    if !a.host.is_empty() {
        add(catalog::resolve(None, None, &a.host, None).map_err(|e| fail(ExitCode::Usage, e))?);
    }
    if a.provider.is_empty() && a.host.is_empty() {
        let cwd = std::env::current_dir().map_err(|e| fail(ExitCode::Failure, e.to_string()))?;
        if let Some(p) = binding::find(&cwd) {
            let (b, _) = binding::load(&p)?;
            for (k, v) in &b.http.keys {
                add(catalog::resolve(Some(v), None, &[], None)
                    .map_err(|e| fail(ExitCode::Usage, format!("[http.keys] {k}: {e}")))?);
            }
        }
    }
    hosts.sort();
    hosts.dedup();
    if hosts.is_empty() {
        return Err(fail(
            ExitCode::Usage,
            "no hosts to enable: pass --provider or --host, or bind keys under [http.keys]",
        ));
    }
    Ok(hosts)
}

fn trust_state_path(cfg: &Path) -> PathBuf {
    cfg.join("http").join("ca-trust")
}

/// Write `body` to `path`, truncating. `private`: owner-only (0600 on Unix, an owner-only ACL on
/// Windows); otherwise world-readable (0644 on Unix, the directory's inherited ACL on Windows).
fn write_file(path: &Path, body: &[u8], private: bool) -> Result<(), Fail> {
    let io = |e: std::io::Error| fail(ExitCode::Failure, format!("{}: {e}", path.display()));
    let mut f = if private {
        ls_platform::fs::PrivateFile::new()
            .truncate(true)
            .open(path)
    } else {
        let mut o = std::fs::OpenOptions::new();
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o644);
        o.write(true).create(true).truncate(true).open(path)
    }
    .map_err(io)?;
    std::io::Write::write_all(&mut f, body).map_err(io)
}

fn sh(prog: &str, args: &[&str]) -> Result<(), Fail> {
    let ok = Command::new(prog)
        .args(args)
        .status()
        .is_ok_and(|s| s.success());
    ok.then_some(()).ok_or_else(|| {
        fail(
            ExitCode::Failure,
            format!("`{prog} {}` failed", args.join(" ")),
        )
    })
}

fn have(prog: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(prog).is_file()))
}

/// Linux trust anchor location and refresh command (Debian family, then Fedora family).
fn linux_store() -> Option<(&'static str, &'static [&'static str])> {
    if Path::new("/usr/local/share/ca-certificates").is_dir() && have("update-ca-certificates") {
        Some((
            "/usr/local/share/ca-certificates/locksmith-local-ca.crt",
            &["update-ca-certificates"],
        ))
    } else if Path::new("/etc/pki/ca-trust/source/anchors").is_dir() && have("update-ca-trust") {
        Some((
            "/etc/pki/ca-trust/source/anchors/locksmith-local-ca.pem",
            &["update-ca-trust", "extract"],
        ))
    } else {
        None
    }
}

/// `sudo` unless already root; asks first unless `yes`.
fn privileged(cmds: &[Vec<String>], yes: bool) -> Result<(), Fail> {
    #[cfg(unix)]
    let root = ls_platform::current_uid() == 0;
    #[cfg(not(unix))]
    let root = false;
    let shown: Vec<String> = cmds
        .iter()
        .map(|c| format!("{}{}", if root { "" } else { "sudo " }, c.join(" ")))
        .collect();
    if !yes {
        let ok = input::tty_line(&format!(
            "This runs:\n  {}\nContinue? [y/N] ",
            shown.join("\n  ")
        ))
        .is_some_and(|s| s.eq_ignore_ascii_case("y"));
        if !ok {
            return Err(fail(ExitCode::Blocked, "not confirmed"));
        }
    }
    for c in cmds {
        let args: Vec<&str> = c.iter().map(String::as_str).collect();
        if root {
            sh(args[0], &args[1..])?;
        } else {
            sh("sudo", &args)?;
        }
    }
    Ok(())
}

fn login_keychain() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{home}/Library/Keychains/login.keychain-db")
}

/// Adds the certificate to the OS trust store; returns what to record for uninstall.
fn trust_install(cert: &Path, yes: bool) -> Result<String, Fail> {
    let c = cert.display().to_string();
    if cfg!(target_os = "macos") {
        // User trust settings in the login keychain; macOS asks for confirmation itself.
        sh(
            "security",
            &[
                "add-trusted-cert",
                "-r",
                "trustRoot",
                "-k",
                &login_keychain(),
                &c,
            ],
        )?;
        return Ok("macos".into());
    }
    let Some((dst, refresh)) = linux_store() else {
        return Err(fail(
            ExitCode::Failure,
            "no supported trust store (update-ca-certificates or update-ca-trust); rerun with --no-trust-store and point clients at the certificate",
        ));
    };
    let install: Vec<String> = ["install", "-m", "0644", &c, dst]
        .iter()
        .map(|s| s.to_string())
        .collect();
    privileged(
        &[install, refresh.iter().map(|s| s.to_string()).collect()],
        yes,
    )?;
    Ok(format!("linux:{dst}"))
}

fn trust_uninstall(state: &str, cert: &Path, cn: Option<&str>, yes: bool) -> Result<(), Fail> {
    if state == "macos" {
        let _ = sh(
            "security",
            &["remove-trusted-cert", &cert.display().to_string()],
        );
        if let Some(cn) = cn {
            let _ = sh(
                "security",
                &["delete-certificate", "-c", cn, &login_keychain()],
            );
        }
        return Ok(());
    }
    if let Some(dst) = state.strip_prefix("linux:") {
        let refresh: Vec<String> = if dst.starts_with("/etc/pki") {
            vec!["update-ca-trust".into(), "extract".into()]
        } else {
            vec!["update-ca-certificates".into(), "--fresh".into()]
        };
        return privileged(&[vec!["rm".into(), "-f".into(), dst.into()], refresh], yes);
    }
    Ok(())
}

fn ca_install(o: &Opts, a: CaArgs) -> Result<ExitCode, Fail> {
    let cfg = ls_core::config_dir();
    let cert_path = ca::cert_path(&cfg);
    if cert_path.exists() {
        return Err(fail(
            ExitCode::Usage,
            "a local CA is already installed (its name constraints are fixed); run `smith http ca uninstall` first",
        ));
    }
    let hosts = enabled_hosts(&a)?;
    let new = ca::generate(&hosts).map_err(|e| fail(ExitCode::Failure, e))?;
    let mut v = unlock(o)?;
    match v.add_project(ca::KEY_PROJECT) {
        Ok(()) | Err(ls_vault::Error::AlreadyExists(_)) => {}
        Err(e) => return Err(vfail(e)),
    }
    v.put_secret(
        ca::KEY_PROJECT,
        ca::KEY_ENV,
        ca::KEY_NAME,
        new.key_pem.as_bytes(),
    )
    .map_err(vfail)?;
    drop(new.key_pem);
    crate::audit_cmds::record(&v, "CA_INSTALL", hosts.join(","), "http_ca")?;
    drop(v);
    let dir = cert_path.parent().expect("has parent");
    ls_platform::fs::ensure_private_dir(dir).map_err(|e| fail(ExitCode::Failure, e.to_string()))?;
    write_file(
        &ca::hosts_path(&cfg),
        format!("{}\n", hosts.join("\n")).as_bytes(),
        true,
    )?;
    write_file(&cert_path, new.cert_pem.as_bytes(), false)?;
    let trust = if a.no_trust_store {
        "none".to_string()
    } else {
        trust_install(&cert_path, a.yes)?
    };
    write_file(&trust_state_path(&cfg), trust.as_bytes(), true)?;
    let port = relay_port();
    if o.json {
        println!(
            "{}",
            json!({"certificate": cert_path, "hosts": hosts, "trust_store": trust, "port": port})
        );
    } else {
        println!(
            "Local CA {} created; key stored in the vault.",
            new.common_name
        );
        println!("certificate: {}", cert_path.display());
        println!("constrained to: {}", hosts.join(", "));
        println!(
            "trust store: {}",
            if trust == "none" {
                "not changed (--no-trust-store)"
            } else {
                &trust
            }
        );
        let p = port.map_or("<port>".into(), |p| p.to_string());
        println!("Use it inside a session: HTTPS_PROXY=http://127.0.0.1:{p}");
        println!(
            "Runtimes with their own CA list need the certificate too, e.g. NODE_EXTRA_CA_CERTS={}",
            cert_path.display()
        );
        println!("Clients that pin certificates are not supported.");
    }
    Ok(ExitCode::Ok)
}

fn ca_uninstall(o: &Opts, a: CaArgs) -> Result<ExitCode, Fail> {
    let cfg = ls_core::config_dir();
    let cert_path = ca::cert_path(&cfg);
    let state = std::fs::read_to_string(trust_state_path(&cfg)).unwrap_or_default();
    let cn = std::fs::read_to_string(&cert_path)
        .ok()
        .and_then(|p| ca::inspect(&p).ok())
        .and_then(|i| {
            i.subject
                .split("CN=")
                .nth(1)
                .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        });
    if !cert_path.exists() && state.is_empty() {
        println!("no local CA is installed");
        return Ok(ExitCode::Ok);
    }
    if !a.no_trust_store {
        trust_uninstall(state.trim(), &cert_path, cn.as_deref(), a.yes)?;
    }
    let mut v = unlock(o)?;
    match v.remove_secret(ca::KEY_PROJECT, ca::KEY_ENV, ca::KEY_NAME) {
        Ok(()) | Err(ls_vault::Error::NotFound(_)) => {}
        Err(e) => return Err(vfail(e)),
    }
    crate::audit_cmds::record(&v, "CA_UNINSTALL", cn.unwrap_or_default(), "http_ca")?;
    for p in [cert_path, ca::hosts_path(&cfg), trust_state_path(&cfg)] {
        let _ = std::fs::remove_file(p);
    }
    if !o.json {
        println!("Local CA removed from the trust store, the vault and disk.");
    }
    Ok(ExitCode::Ok)
}

fn ca_status(o: &Opts) -> Result<ExitCode, Fail> {
    let cfg = ls_core::config_dir();
    let cert_path = ca::cert_path(&cfg);
    let Ok(pem) = std::fs::read_to_string(&cert_path) else {
        if o.json {
            println!("{}", json!({"installed": false}));
        } else {
            println!("no local CA (explicit-proxy mode is off)");
        }
        return Ok(ExitCode::NotFound);
    };
    let info = ca::inspect(&pem).map_err(|e| fail(ExitCode::Failure, e))?;
    let trust = std::fs::read_to_string(trust_state_path(&cfg)).unwrap_or_default();
    let hosts = ca::enabled_hosts(&cfg);
    if o.json {
        println!(
            "{}",
            json!({"installed": true, "certificate": cert_path, "subject": info.subject,
                   "hosts": hosts, "permitted_dns": info.permitted_dns,
                   "name_constrained": info.constrained && info.excludes_ip,
                   "trust_store": trust.trim(), "not_after": info.not_after})
        );
    } else {
        println!("certificate: {}", cert_path.display());
        println!("subject:     {}", info.subject);
        println!("enabled:     {}", hosts.join(", "));
        println!(
            "constraints: {}",
            if info.constrained && info.excludes_ip {
                format!(
                    "critical, DNS {} only, no IPs",
                    info.permitted_dns.join(", ")
                )
            } else {
                "MISSING".into()
            }
        );
        println!("trust store: {}", trust.trim());
    }
    Ok(ExitCode::Ok)
}
