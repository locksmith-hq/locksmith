//! Git delegation over HTTPS (D1): the binding shape that says which repositories a secret may
//! be used for through `/git/{host}/{owner}/{repo}/...`, and the smart-HTTP path allow-list.
//!
//! This module holds the contract (D1 task 1.1): [`GitBinding`], [`GitService`] and the pure path
//! check [`GitBinding::authorize`]. It never touches a credential value.

use serde::Deserialize;
use uuid::Uuid;

/// What a Git operation does to the repository; a grant for one does not allow the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitService {
    /// `git-upload-pack`: clone and fetch.
    Fetch,
    /// `git-receive-pack`: push.
    Push,
}

impl GitService {
    /// The ledger event name for a completed operation.
    pub fn event(self) -> &'static str {
        match self {
            GitService::Fetch => "git.fetch",
            GitService::Push => "git.push",
        }
    }
}

/// One allowed Git use of a secret: the host, the repositories under a prefix, the services.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitBinding {
    pub secret_id: Uuid,
    /// Exact host, lowercase, no scheme, port or path (for example `github.com`).
    pub host: String,
    /// `owner` (every repository of the owner) or `owner/repo` (exactly that repository).
    pub repo_prefix: String,
    /// Allowed services; empty is rejected by validation.
    pub services: Vec<GitService>,
    /// Permit the host to resolve to a private or loopback address (the local test fixture).
    #[serde(default)]
    pub allow_private_hosts: bool,
}

/// Why a Git request is not allowed. Carries no request data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitDenied {
    /// Not one of the three smart-HTTP paths.
    PathNotAllowed,
    /// Host or repository is outside the binding.
    NotBound,
    /// The binding does not allow this service.
    ServiceNotAllowed,
}

/// A request that passed [`GitBinding::authorize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitTarget {
    pub owner: String,
    pub repo: String,
    pub service: GitService,
    /// `info/refs` advertisement (GET) rather than the service call (POST).
    pub advertisement: bool,
}

fn valid_segment(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

impl GitBinding {
    /// Field name of the first invalid field, for the config error.
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        let host_ok = !self.host.is_empty()
            && self.host == self.host.to_ascii_lowercase()
            && self
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'));
        if !host_ok {
            return Err("host");
        }
        let mut parts = self.repo_prefix.split('/');
        let (owner, repo) = (parts.next(), parts.next());
        let shape_ok = owner.is_some_and(valid_segment)
            && repo.is_none_or(valid_segment)
            && parts.next().is_none();
        if !shape_ok {
            return Err("repo_prefix");
        }
        if self.services.is_empty() {
            return Err("services");
        }
        Ok(())
    }

    fn covers(&self, owner: &str, repo: &str) -> bool {
        match self.repo_prefix.split_once('/') {
            Some((o, r)) => o.eq_ignore_ascii_case(owner) && r.eq_ignore_ascii_case(repo),
            None => self.repo_prefix.eq_ignore_ascii_case(owner),
        }
    }

    /// Check a request before any credential is read. `path` is what follows
    /// `/git/{host}/` (`owner/repo[.git]/info/refs`, `.../git-upload-pack`,
    /// `.../git-receive-pack`), `query` the raw query string, `post` the method.
    pub fn authorize(
        &self,
        host: &str,
        path: &str,
        query: Option<&str>,
        post: bool,
    ) -> Result<GitTarget, GitDenied> {
        let segs: Vec<&str> = path.split('/').collect();
        let (owner, repo_raw, tail) = match segs.as_slice() {
            [o, r, rest @ ..] if !rest.is_empty() => (*o, *r, rest.join("/")),
            _ => return Err(GitDenied::PathNotAllowed),
        };
        let (service, advertisement) = match (tail.as_str(), post, query) {
            ("info/refs", false, Some("service=git-upload-pack")) => (GitService::Fetch, true),
            ("info/refs", false, Some("service=git-receive-pack")) => (GitService::Push, true),
            ("git-upload-pack", true, None) => (GitService::Fetch, false),
            ("git-receive-pack", true, None) => (GitService::Push, false),
            _ => return Err(GitDenied::PathNotAllowed),
        };
        let repo = repo_raw.strip_suffix(".git").unwrap_or(repo_raw);
        if !valid_segment(owner) || !valid_segment(repo) {
            return Err(GitDenied::PathNotAllowed);
        }
        if !host.eq_ignore_ascii_case(&self.host) || !self.covers(owner, repo) {
            return Err(GitDenied::NotBound);
        }
        if !self.services.contains(&service) {
            return Err(GitDenied::ServiceNotAllowed);
        }
        Ok(GitTarget {
            owner: owner.to_owned(),
            repo: repo.to_owned(),
            service,
            advertisement,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Bindings;

    const FIXTURE: &str = r#"
org_id = "0197c1f0-0000-7000-8000-000000000001"

[[git_binding]]
secret_id = "0197c1f0-0000-7000-8000-000000000003"
host = "github.com"
repo_prefix = "acme/widgets"
services = ["fetch"]

[[git_binding]]
secret_id = "0197c1f0-0000-7000-8000-000000000004"
host = "github.com"
repo_prefix = "acme"
services = ["fetch", "push"]
"#;

    fn bindings() -> Bindings {
        Bindings::parse(FIXTURE).expect("fixture parses")
    }

    fn id(n: u8) -> Uuid {
        Uuid::parse_str(&format!("0197c1f0-0000-7000-8000-00000000000{n}")).unwrap()
    }

    #[test]
    fn git_binding_fixture_parses() {
        let b = bindings();
        assert_eq!(b.git_bindings.len(), 2);
        assert_eq!(b.git_for_secret(id(3)).unwrap().repo_prefix, "acme/widgets");
        assert!(b.git_for_secret(id(9)).is_none());
    }

    #[test]
    fn git_binding_allows_bound_fetch_and_push() {
        let b = bindings();
        let org = b.git_for_secret(id(4)).unwrap();
        let t = org
            .authorize(
                "github.com",
                "acme/tools.git/info/refs",
                Some("service=git-receive-pack"),
                false,
            )
            .unwrap();
        assert_eq!(
            (t.repo.as_str(), t.service, t.advertisement),
            ("tools", GitService::Push, true)
        );
        let t = org
            .authorize("github.com", "acme/tools/git-upload-pack", None, true)
            .unwrap();
        assert_eq!((t.service, t.advertisement), (GitService::Fetch, false));
    }

    #[test]
    fn git_binding_denies_unbound_repo_host_and_service() {
        let b = bindings();
        let one = b.git_for_secret(id(3)).unwrap();
        let refs = "info/refs";
        let q = Some("service=git-upload-pack");
        assert_eq!(
            one.authorize("github.com", &format!("acme/other/{refs}"), q, false),
            Err(GitDenied::NotBound)
        );
        assert_eq!(
            one.authorize("gitlab.com", &format!("acme/widgets/{refs}"), q, false),
            Err(GitDenied::NotBound)
        );
        assert_eq!(
            one.authorize("github.com", "acme/widgets.git.git/info/refs", q, false),
            Err(GitDenied::NotBound)
        );
        assert_eq!(
            one.authorize("github.com", "acme/widgets/git-receive-pack", None, true),
            Err(GitDenied::ServiceNotAllowed)
        );
    }

    #[test]
    fn git_binding_denies_everything_but_the_three_paths() {
        let b = bindings();
        let org = b.git_for_secret(id(4)).unwrap();
        for (path, query, post) in [
            ("acme/widgets/objects/info/packs", None, false),
            ("acme/widgets/info/refs", None, false),
            (
                "acme/widgets/info/refs",
                Some("service=git-upload-pack"),
                true,
            ),
            ("acme/widgets/git-upload-pack", None, false),
            ("acme/widgets/git-upload-pack", Some("x=1"), true),
            (
                "acme/../widgets/info/refs",
                Some("service=git-upload-pack"),
                false,
            ),
            ("acme/widgets", None, false),
            (
                "acme/widgets/info/refs/",
                Some("service=git-upload-pack"),
                false,
            ),
            (
                "acme/%2e%2e/info/refs",
                Some("service=git-upload-pack"),
                false,
            ),
            (
                "acme/.git/info/refs",
                Some("service=git-upload-pack"),
                false,
            ),
            ("acme//info/refs", Some("service=git-upload-pack"), false),
            ("acme", None, false),
            ("api/v3/repos/acme/widgets", None, false),
        ] {
            assert!(
                org.authorize("github.com", path, query, post).is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn git_binding_rejects_duplicate_secret_id() {
        let one = "[[git_binding]]\nsecret_id = \"0197c1f0-0000-7000-8000-000000000003\"\nhost = \"github.com\"\nrepo_prefix = \"a\"\nservices = [\"fetch\"]\n";
        let toml = format!("org_id = \"0197c1f0-0000-7000-8000-000000000001\"\n{one}{one}");
        assert!(Bindings::parse(&toml).is_err());
    }

    #[test]
    fn git_binding_rejects_invalid_config() {
        for bad in [
            r#"host = "GitHub.com"
repo_prefix = "a"
services = ["fetch"]"#,
            r#"host = "github.com"
repo_prefix = "a/b/c"
services = ["fetch"]"#,
            r#"host = "github.com"
repo_prefix = "a"
services = []"#,
            r#"host = "https://github.com"
repo_prefix = "a"
services = ["fetch"]"#,
        ] {
            let toml = format!(
                "org_id = \"0197c1f0-0000-7000-8000-000000000001\"\n[[git_binding]]\nsecret_id = \"0197c1f0-0000-7000-8000-000000000003\"\n{bad}\n"
            );
            assert!(Bindings::parse(&toml).is_err(), "{bad}");
        }
    }
}
