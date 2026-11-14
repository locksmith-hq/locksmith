//! Forwarders that add upstream credentials on behalf of a session (M5: Git smart HTTP).
//!
//! The forwarder is synchronous (one thread per connection, like `locksmithd`). Each proxied
//! request goes upstream with `Connection: close` and the response bytes are copied verbatim, so
//! no response framing is re-encoded. Who may use it and with which upstream credential is decided
//! by the daemon through [`Authority`]; this crate never sees the vault.

pub mod forward;
pub mod github;
pub mod policy;

use std::net::SocketAddr;
use zeroize::Zeroizing;

/// A parsed forwarder path: `/git/<host>/<owner>/<repo>.git/<rest>?<query>` (design D1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Upstream host, e.g. `github.com` (lowercase, may carry `:port`).
    pub host: String,
    /// `owner/repo` without `.git` (GitLab subgroups: `group/sub/repo`).
    pub repo: String,
    /// Path after `<repo>.git/`, e.g. `info/refs` or `git-receive-pack`.
    pub rest: String,
    pub query: Option<String>,
}

/// One ref update from a `git-receive-pack` request (hex object ids, 40 or 64 chars).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub old: String,
    pub new: String,
    pub name: String,
}

/// What the daemon allows for one authorized request.
pub struct Grant {
    /// Full `Authorization` header value for the upstream (e.g. `Basic …`). Never logged.
    pub upstream_auth: Zeroizing<String>,
    /// Protected ref patterns (`main`, `refs/heads/release/*`): delete and stale-old updates
    /// are refused (design D4).
    pub protected: Vec<String>,
    /// Lease id, for audit messages.
    pub lease: String,
}

/// Why a request was refused. `status` is the HTTP status sent to Git (401 asks Git for
/// credentials; 403 is final). `message` is safe to show to the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deny {
    pub status: u16,
    pub message: String,
}

/// Decides each request. Implemented by `locksmithd`.
pub trait Authority: Send + Sync {
    /// `token` is the password from the request's Basic auth (`None` when absent). `client` and
    /// `server` are the TCP endpoints of the accepted connection, used to find the peer process.
    fn authorize(
        &self,
        token: Option<&str>,
        client: SocketAddr,
        server: SocketAddr,
        route: &Route,
    ) -> Result<Grant, Deny>;

    /// A push was refused by policy after authorization (audited as BLOCKED by the daemon).
    fn push_denied(&self, route: &Route, grant: &Grant, why: &str);

    /// The request was forwarded (audited as a Git ACCESS event).
    fn forwarded(&self, route: &Route, grant: &Grant, service: &str);
}
