//! Self-update: signed manifest + SHA-256 verified, atomic binary replacement.
//!
//! M0 transport (GitHub Releases or any HTTP base). M12 replaces it with TUF.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const MANIFEST: &str = "manifest.json";
pub const MANIFEST_SIG: &str = "manifest.json.minisig";
/// Release signing key (minisign). The secret half never lives in this repo.
pub const EMBEDDED_PUBKEY: &str = include_str!("../update-pubkey.txt");
pub const DEFAULT_SOURCE: &str = "github://locksmith-hq/locksmith";

#[derive(Debug)]
pub enum Error {
    Network(String),
    BadSignature,
    BadManifest(String),
    NoTarget(String),
    HashMismatch { expected: String, actual: String },
    SmokeTest(String),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Network(e) => write!(f, "network error: {e}"),
            Error::BadSignature => write!(f, "manifest signature is invalid"),
            Error::BadManifest(e) => write!(f, "manifest is malformed: {e}"),
            Error::NoTarget(t) => write!(f, "no build for target {t} in this release"),
            Error::HashMismatch { expected, actual } => {
                write!(f, "hash mismatch: expected sha256 {expected}, got {actual}")
            }
            Error::SmokeTest(e) => write!(f, "new binary failed its smoke test: {e}"),
            Error::Io(e) => write!(f, "io error: {e}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub targets: HashMap<String, Artifact>,
}

#[derive(Debug, Deserialize)]
pub struct Artifact {
    /// Asset file name, resolved against the source.
    pub name: String,
    pub sha256: String,
}

/// Where release files come from.
#[derive(Debug, Clone)]
pub enum Source {
    /// `<base>/<file>` over HTTP(S).
    Http(String),
    /// Latest release assets of `owner/repo` via the GitHub API (works for private repos with a token).
    GitHub { repo: String, token: Option<String> },
}

impl Source {
    /// `github://owner/repo` or an http(s) base URL. Token comes from `GH_TOKEN`/`GITHUB_TOKEN`.
    pub fn parse(s: &str) -> Self {
        match s.strip_prefix("github://") {
            Some(repo) => Source::GitHub {
                repo: repo.trim_end_matches('/').to_string(),
                token: std::env::var("GH_TOKEN")
                    .or_else(|_| std::env::var("GITHUB_TOKEN"))
                    .ok(),
            },
            None => Source::Http(s.trim_end_matches('/').to_string()),
        }
    }

    fn agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .user_agent("locksmith-updater")
            .build()
            .into()
    }

    fn open(&self, file: &str) -> Result<Box<dyn Read + Send>, Error> {
        let net = |e: ureq::Error| Error::Network(e.to_string());
        let agent = Self::agent();
        match self {
            Source::Http(base) => {
                let resp = agent.get(&format!("{base}/{file}")).call().map_err(net)?;
                if !resp.status().is_success() {
                    return Err(Error::Network(format!("{file}: HTTP {}", resp.status())));
                }
                Ok(Box::new(resp.into_body().into_reader()))
            }
            Source::GitHub { repo, token } => {
                let auth = |r: ureq::RequestBuilder<ureq::typestate::WithoutBody>| match token {
                    Some(t) => r.header("Authorization", &format!("Bearer {t}")),
                    None => r,
                };
                // `releases/latest` skips prereleases; M0 testers run alphas, so take the newest non-draft.
                // shortcut: no channel filtering yet, M12 adds stable/beta/nightly channels.
                let api = format!("https://api.github.com/repos/{repo}/releases?per_page=20");
                let mut resp = auth(
                    agent
                        .get(&api)
                        .header("Accept", "application/vnd.github+json"),
                )
                .call()
                .map_err(net)?;
                if !resp.status().is_success() {
                    return Err(Error::Network(format!(
                        "GitHub release lookup: HTTP {} (private repo needs GH_TOKEN)",
                        resp.status()
                    )));
                }
                let releases: serde_json::Value = resp.body_mut().read_json().map_err(net)?;
                let release = releases
                    .as_array()
                    .and_then(|r| r.iter().find(|x| x["draft"] == false))
                    .ok_or_else(|| Error::Network("no published release".into()))?;
                let asset_url = release["assets"]
                    .as_array()
                    .and_then(|a| a.iter().find(|x| x["name"] == file))
                    .and_then(|x| x["url"].as_str())
                    .ok_or_else(|| Error::Network(format!("release has no asset {file}")))?
                    .to_string();
                let resp = auth(
                    agent
                        .get(&asset_url)
                        .header("Accept", "application/octet-stream"),
                )
                .call()
                .map_err(net)?;
                // GitHub redirects to a presigned storage URL; follow it WITHOUT the token.
                let resp = if resp.status().is_redirection() {
                    let loc = resp
                        .headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .ok_or_else(|| Error::Network("redirect without location".into()))?
                        .to_string();
                    agent.get(&loc).call().map_err(net)?
                } else {
                    resp
                };
                if !resp.status().is_success() {
                    return Err(Error::Network(format!("{file}: HTTP {}", resp.status())));
                }
                Ok(Box::new(resp.into_body().into_reader()))
            }
        }
    }

    fn read_small(&self, file: &str) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        self.open(file)?.take(1 << 20).read_to_end(&mut buf)?;
        Ok(buf)
    }
}

pub struct Updater {
    pub source: Source,
    pub pubkey_b64: String,
    pub target: String,
    pub current: semver::Version,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    UpToDate { current: String, latest: String },
    Available { current: String, latest: String },
    Installed { from: String, to: String },
}

impl Updater {
    /// Download the manifest and its signature; return the manifest only if the signature verifies.
    pub fn verified_manifest(&self) -> Result<Manifest, Error> {
        let body = self.source.read_small(MANIFEST)?;
        let sig = self.source.read_small(MANIFEST_SIG)?;
        let pk = minisign_verify::PublicKey::from_base64(self.pubkey_b64.trim())
            .map_err(|_| Error::BadSignature)?;
        let sig = std::str::from_utf8(&sig)
            .ok()
            .and_then(|s| minisign_verify::Signature::decode(s).ok())
            .ok_or(Error::BadSignature)?;
        pk.verify(&body, &sig, false)
            .map_err(|_| Error::BadSignature)?;
        serde_json::from_slice(&body).map_err(|e| Error::BadManifest(e.to_string()))
    }

    fn latest(&self, m: &Manifest) -> Result<semver::Version, Error> {
        semver::Version::parse(&m.version).map_err(|e| Error::BadManifest(e.to_string()))
    }

    pub fn check(&self) -> Result<Outcome, Error> {
        let m = self.verified_manifest()?;
        let latest = self.latest(&m)?;
        let (current, l) = (self.current.to_string(), latest.to_string());
        Ok(if latest > self.current {
            Outcome::Available { current, latest: l }
        } else {
            Outcome::UpToDate { current, latest: l }
        })
    }

    /// Replace `exe` with the latest verified build. The old binary stays untouched on any error.
    pub fn install(&self, exe: &Path) -> Result<Outcome, Error> {
        let m = self.verified_manifest()?;
        let latest = self.latest(&m)?;
        if latest <= self.current {
            return Ok(Outcome::UpToDate {
                current: self.current.to_string(),
                latest: latest.to_string(),
            });
        }
        let art = m
            .targets
            .get(&self.target)
            .ok_or_else(|| Error::NoTarget(self.target.clone()))?;
        let staged = staging_path(exe);
        let result = self.stage(art, &staged).and_then(|()| {
            smoke_test(&staged)?;
            std::fs::rename(&staged, exe)?; // atomic on the same filesystem
            Ok(())
        });
        if result.is_err() {
            let _ = std::fs::remove_file(&staged);
        }
        result?;
        Ok(Outcome::Installed {
            from: self.current.to_string(),
            to: latest.to_string(),
        })
    }

    fn stage(&self, art: &Artifact, staged: &Path) -> Result<(), Error> {
        let mut reader = self.source.open(&art.name)?;
        let mut file = std::fs::File::create(staged)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| Error::Network(e.to_string()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n])?;
        }
        file.sync_all()?;
        let actual = hex::encode(hasher.finalize());
        if !actual.eq_ignore_ascii_case(art.sha256.trim()) {
            return Err(Error::HashMismatch {
                expected: art.sha256.clone(),
                actual,
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(staged, std::fs::Permissions::from_mode(0o755))?;
        }
        Ok(())
    }
}

fn staging_path(exe: &Path) -> PathBuf {
    let name = exe.file_name().and_then(|n| n.to_str()).unwrap_or("smith");
    exe.with_file_name(format!(".{name}.update-{}", std::process::id()))
}

fn smoke_test(bin: &Path) -> Result<(), Error> {
    let out = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .map_err(|e| Error::SmokeTest(e.to_string()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(Error::SmokeTest(format!("exit status {}", out.status)))
    }
}

fn update_reachable() -> ls_diag::Outcome {
    let src = std::env::var("LOCKSMITH_UPDATE_URL").unwrap_or_else(|_| DEFAULT_SOURCE.to_string());
    match Source::parse(&src).read_small(MANIFEST) {
        Ok(_) => ls_diag::Outcome::ok(format!("update source reachable ({src})")),
        Err(e) => ls_diag::Outcome::warn(
            format!("update source unreachable: {e}"),
            "check network; for the private repo export GH_TOKEN (e.g. GH_TOKEN=$(gh auth token))",
        ),
    }
}

inventory::submit! { ls_diag::Check { id: "update.reachable", run: update_reachable } }
