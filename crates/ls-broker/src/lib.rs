//! Caller classification and session leases (design: openspec/changes/m3-daemon-sessions/design.md
//! D2, D3).
//!
//! A request is authorized only when (1) the caller is an attested Locksmith binary
//! ([`Manifest::classify`]), (2) the calling process descends, by a live kernel parent walk
//! re-done on every request, from the root of an active lease ([`Leases::authorize`]), and
//! (3) the lease's project, environment and scopes cover the operation.

use ls_ipc::{LeaseInfo, SelfReport, SessionSource, StartedBy};
use ls_platform::proc::{Digest, Peer, Pin, ProcId, descends_from, info, pin};
use std::path::{Path, PathBuf};

mod doctor;
pub mod source;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Smith,
    Mcp,
    Desktop,
    /// Anything that failed attestation: only `Ping` is served.
    Unknown,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Smith => "smith",
            Role::Mcp => "locksmith-mcp",
            Role::Desktop => "locksmith-desktop",
            Role::Unknown => "unknown",
        }
    }
}

/// Digests of the Locksmith binaries installed beside the daemon, pinned when it starts.
pub struct Manifest {
    entries: Vec<(Pin, Role, PathBuf)>,
}

impl Manifest {
    /// Pin `smith`, `locksmith-mcp` and `locksmith-desktop` found in `dir` (missing ones are
    /// skipped). A binary replaced on disk after this point is not trusted until restart.
    pub fn from_dir(dir: &Path) -> Manifest {
        let entries = [
            ("smith", Role::Smith),
            ("locksmith-mcp", Role::Mcp),
            ("locksmith-desktop", Role::Desktop),
        ]
        .into_iter()
        .filter_map(|(name, role)| {
            let p = dir.join(name);
            pin(&p).ok().map(|d| (d, role, p))
        })
        .collect();
        Manifest { entries }
    }

    /// The daemon's own directory (where `smith` is installed next to `locksmithd`).
    pub fn beside_current_exe() -> Manifest {
        let dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok())
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_default();
        Self::from_dir(&dir)
    }

    pub fn pinned(&self) -> impl Iterator<Item = (&Digest, Role, &Path)> {
        self.entries
            .iter()
            .map(|(d, r, p)| (&d.digest, *r, p.as_path()))
    }

    /// Kernel-verified role of a peer. The request contents never influence this.
    pub fn classify(&self, peer: &Peer) -> Role {
        self.matched(peer).map_or(Role::Unknown, |(_, r, _)| *r)
    }

    /// The pinned digest a peer matched (for audit records).
    pub fn digest_of(&self, peer: &Peer) -> Option<&Digest> {
        self.matched(peer).map(|(d, _, _)| &d.digest)
    }

    fn matched(&self, peer: &Peer) -> Option<&(Pin, Role, PathBuf)> {
        if peer.uid != ls_platform::current_uid() {
            return None;
        }
        self.entries.iter().find(|(d, _, _)| peer.runs_pin(d))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    Active,
    Revoked,
    Expired,
}

/// The raw `.locksmith.toml` a session was started with. An agent inside the session can edit the
/// file (same OS user), so decisions about where a credential may go (HTTP token hosts, database
/// relay targets) use this copy, taken while the human typed the passphrase. Debug shows only
/// the length: a binding should hold names only, but a mistaken literal must not reach a log.
#[derive(Clone, PartialEq, Eq)]
pub struct PinnedBinding(pub Vec<u8>);

impl std::fmt::Debug for PinnedBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PinnedBinding({} bytes)", self.0.len())
    }
}

#[derive(Debug, Clone)]
pub struct Lease {
    pub id: String,
    /// The `.locksmith.toml` the session was started with, if any (see [`PinnedBinding`]).
    pub binding: Option<PinnedBinding>,
    pub root: ProcId,
    /// Processes the daemon spawned for this lease (`smith run` children): their descendants
    /// are in the session too.
    pub spawned: Vec<ProcId>,
    pub project: String,
    pub env: String,
    pub scopes: Vec<String>,
    pub command: String,
    /// Started by the agent through `AgentSessionStart` (only such a lease may be replaced by
    /// another agent start from the same root).
    pub agent: bool,
    /// Display-only origin hints (M10d), set once at start by [`Leases::describe`].
    pub root_exe: String,
    pub source: SessionSource,
    pub host: Option<String>,
    /// The agent's own claim about its client and model. Never used for authorization.
    pub report: Option<SelfReport>,
    /// Agent leases only (M10e D1): keys `smith run` may inject, from the agent policy at start.
    /// `None` (human lease): no restriction.
    pub inject: Option<Vec<String>>,
    pub created_at: i64,
    pub expires_at: i64,
    pub state: LeaseState,
}

impl Lease {
    fn state_at(&self, now: i64) -> LeaseState {
        match self.state {
            LeaseState::Active if now >= self.expires_at => LeaseState::Expired,
            s => s,
        }
    }

    pub fn info(&self, now: i64) -> LeaseInfo {
        LeaseInfo {
            id: self.id.clone(),
            root_pid: self.root.pid,
            command: self.command.clone(),
            project: self.project.clone(),
            env: self.env.clone(),
            scopes: self.scopes.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            state: match self.state_at(now) {
                LeaseState::Active => "active",
                LeaseState::Revoked => "revoked",
                LeaseState::Expired => "expired",
            }
            .into(),
            root_exe: self.root_exe.clone(),
            started_by: if self.agent {
                StartedBy::Agent
            } else {
                StartedBy::Human
            },
            source: self.source.clone(),
            host: self.host.clone(),
            report: self.report.clone(),
            inject: self.inject.clone(),
        }
    }
}

/// Why an operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// The caller is not inside any session tree (or the daemon restarted). Exit 4.
    NoLease,
    /// The caller's session was revoked or expired. Exit 4.
    Inactive { id: String, state: LeaseState },
    /// Inside a session, but outside its project, environment or scopes. Exit 3.
    OutOfScope { id: String, why: String },
}

impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Denial::NoLease => f.write_str(
                "no active session for this process; start one with `smith session start -- <agent>`",
            ),
            Denial::Inactive { id, state } => write!(
                f,
                "session {id} is {}; start a new one with `smith session start`",
                if *state == LeaseState::Revoked {
                    "revoked"
                } else {
                    "expired"
                }
            ),
            Denial::OutOfScope { id, why } => write!(f, "session {id} does not allow this: {why}"),
        }
    }
}

/// In-memory lease table. Never persisted: a daemon restart drops every lease (fail closed).
#[derive(Default)]
pub struct Leases {
    all: Vec<Lease>,
}

fn new_id() -> String {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("OS RNG");
    format!(
        "ls_{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

/// Root for an agent-started lease (M10b D4): the kernel-identified parent of `caller` (the
/// agent that launched the MCP server over stdio), so the lease covers the agent's own shell
/// commands. Never taken from the request. Refused when the parent cannot be read, is pid <= 1
/// (orphaned caller), belongs to another uid, or is younger than the caller (recycled pid), or
/// when the caller is not the same live process or was reparented while we looked.
pub fn agent_root(caller: ProcId, uid: u32) -> Result<ProcId, String> {
    let me = info(caller.pid).map_err(|_| "calling process is gone".to_string())?;
    if me.id != caller {
        return Err("calling process changed".into());
    }
    if me.ppid <= 1 {
        return Err("calling process has no parent agent".into());
    }
    let parent = info(me.ppid).map_err(|_| "parent process cannot be identified".to_string())?;
    if parent.uid != uid {
        return Err("parent process belongs to another user".into());
    }
    if parent.id.start > caller.start {
        return Err("parent pid was recycled".into());
    }
    match info(caller.pid) {
        Ok(again) if again.id == caller && again.ppid == parent.id.pid => Ok(parent.id),
        _ => Err("calling process was reparented".into()),
    }
}

/// `"run"` is the only M3 operation scope; `"*"` grants every scope.
pub fn scope_allows(scopes: &[String], scope: &str) -> bool {
    scopes.iter().any(|s| s == "*" || s == scope)
}

impl Leases {
    /// Create a lease rooted at `root` (the kernel-identified `smith session start` process, or for
    /// an agent start the agent that launched the MCP server, see [`agent_root`]).
    /// An existing lease with the same root is revoked first.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        &mut self,
        root: ProcId,
        ttl_secs: u64,
        project: String,
        env: String,
        scopes: Vec<String>,
        command: String,
        now: i64,
    ) -> &Lease {
        for l in self.all.iter_mut().filter(|l| l.root == root) {
            l.state = LeaseState::Revoked;
        }
        self.all.push(Lease {
            id: new_id(),
            binding: None,
            root,
            spawned: Vec::new(),
            project,
            env,
            scopes,
            command,
            agent: false,
            root_exe: String::new(),
            source: SessionSource::default(),
            host: None,
            report: None,
            inject: None,
            created_at: now,
            expires_at: now.saturating_add(ttl_secs.min(i64::MAX as u64) as i64),
            state: LeaseState::Active,
        });
        self.all.last().expect("just pushed")
    }

    /// The lease whose tree contains `caller`, active ones first. Re-walks the kernel parent
    /// chain on every call (never cached).
    pub fn find(&self, caller: ProcId, now: i64) -> Option<&Lease> {
        let inside = |l: &&Lease| {
            let mut roots = vec![l.root];
            roots.extend(&l.spawned);
            descends_from(caller, &roots)
        };
        let active = self
            .all
            .iter()
            .filter(|l| l.state_at(now) == LeaseState::Active)
            .find(inside);
        active.or_else(|| self.all.iter().rev().find(inside))
    }

    /// Authorize `scope` on `project`/`env` for `caller`.
    pub fn authorize(
        &self,
        caller: ProcId,
        scope: &str,
        project: &str,
        env: &str,
        now: i64,
    ) -> Result<&Lease, Denial> {
        let l = self.find(caller, now).ok_or(Denial::NoLease)?;
        let st = l.state_at(now);
        if st != LeaseState::Active {
            return Err(Denial::Inactive {
                id: l.id.clone(),
                state: st,
            });
        }
        let out = |why: String| Denial::OutOfScope {
            id: l.id.clone(),
            why,
        };
        if !scope_allows(&l.scopes, scope) {
            return Err(out(format!("scope '{scope}' not granted")));
        }
        if l.project != project || l.env != env {
            return Err(out(format!(
                "it covers {}/{}, not {project}/{env}",
                l.project, l.env
            )));
        }
        Ok(l)
    }

    /// Revoke one lease by id, or all with `None`. Returns how many were active.
    pub fn revoke(&mut self, id: Option<&str>, now: i64) -> u32 {
        let mut n = 0;
        for l in self.all.iter_mut().filter(|l| id.is_none_or(|i| i == l.id)) {
            if l.state_at(now) == LeaseState::Active {
                n += 1;
            }
            l.state = LeaseState::Revoked;
        }
        n
    }

    /// End the lease rooted at `root` (the agent exited). Returns its id.
    pub fn end(&mut self, root: ProcId) -> Option<String> {
        let l = self
            .all
            .iter_mut()
            .rev()
            .find(|l| l.root == root && l.state == LeaseState::Active)?;
        l.state = LeaseState::Revoked;
        Some(l.id.clone())
    }

    /// Pin the binding a lease was started with (`SessionStart`).
    pub fn pin(&mut self, id: &str, binding: Option<Vec<u8>>) {
        if let Some(l) = self.all.iter_mut().find(|l| l.id == id) {
            l.binding = binding.map(PinnedBinding);
        }
    }

    /// Mark an `AgentSessionStart` lease, with the keys the agent policy lets it inject.
    pub fn mark_agent(&mut self, id: &str, inject: Vec<String>) {
        if let Some(l) = self.all.iter_mut().find(|l| l.id == id) {
            l.agent = true;
            l.inject = Some(inject);
        }
    }

    /// Record where the lease's agent runs (display only, see [`source`]).
    pub fn describe(
        &mut self,
        id: &str,
        (source, host, root_exe): (SessionSource, Option<String>, String),
        report: Option<SelfReport>,
    ) {
        if let Some(l) = self.all.iter_mut().find(|l| l.id == id) {
            (l.source, l.host, l.root_exe, l.report) = (source, host, root_exe, report);
        }
    }

    pub fn add_spawned(&mut self, id: &str, p: ProcId) {
        if let Some(l) = self.all.iter_mut().find(|l| l.id == id) {
            l.spawned.push(p);
        }
    }

    pub fn remove_spawned(&mut self, id: &str, p: ProcId) {
        if let Some(l) = self.all.iter_mut().find(|l| l.id == id) {
            l.spawned.retain(|x| *x != p);
        }
    }

    /// Active leases for `smith status`.
    /// Active leases plus up to `ended` most recently created ended ones (revoked or expired),
    /// for the desktop's "struck from the schedule" view. Memory only, like every lease.
    pub fn with_recent(&self, now: i64, ended: usize) -> Vec<LeaseInfo> {
        let mut out = self.active(now);
        out.extend(
            self.all
                .iter()
                .rev()
                .filter(|l| l.state_at(now) != LeaseState::Active)
                .take(ended)
                .map(|l| l.info(now)),
        );
        out
    }

    pub fn active(&self, now: i64) -> Vec<LeaseInfo> {
        self.all
            .iter()
            .filter(|l| l.state_at(now) == LeaseState::Active)
            .map(|l| l.info(now))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ls_platform::proc::id_of;

    fn me() -> ProcId {
        id_of(std::process::id()).unwrap()
    }

    fn child() -> (std::process::Child, ProcId) {
        let c = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let id = id_of(c.id()).unwrap();
        (c, id)
    }

    fn start(ls: &mut Leases, root: ProcId, ttl: u64, now: i64) -> String {
        ls.start(
            root,
            ttl,
            "p".into(),
            "dev".into(),
            vec!["run".into()],
            "agent".into(),
            now,
        )
        .id
        .clone()
    }

    #[test]
    fn descendant_allowed_outsider_denied() {
        let (mut c, kid) = child();
        let mut ls = Leases::default();
        start(&mut ls, me(), 60, 0);
        assert!(
            ls.authorize(kid, "run", "p", "dev", 1).is_ok(),
            "child of root"
        );
        assert!(
            ls.authorize(me(), "run", "p", "dev", 1).is_ok(),
            "root itself"
        );
        // A lease rooted at the child does not cover its parent (the "outside terminal").
        let mut other = Leases::default();
        start(&mut other, kid, 60, 0);
        assert_eq!(
            other.authorize(me(), "run", "p", "dev", 1).unwrap_err(),
            Denial::NoLease
        );
        c.kill().unwrap();
        c.wait().unwrap();
    }

    #[test]
    fn expiry_revoke_and_scope() {
        let mut ls = Leases::default();
        let id = start(&mut ls, me(), 60, 1000);
        assert!(ls.authorize(me(), "run", "p", "dev", 1059).is_ok());
        assert!(matches!(
            ls.authorize(me(), "run", "p", "dev", 1061),
            Err(Denial::Inactive {
                state: LeaseState::Expired,
                ..
            })
        ));
        let id2 = start(&mut ls, me(), 60, 2000);
        assert_ne!(id, id2);
        assert!(matches!(
            ls.authorize(me(), "git", "p", "dev", 2001),
            Err(Denial::OutOfScope { .. })
        ));
        assert!(matches!(
            ls.authorize(me(), "run", "p", "prod", 2001),
            Err(Denial::OutOfScope { .. })
        ));
        assert_eq!(ls.active(2001).len(), 1);
        assert_eq!(ls.revoke(Some(&id2), 2001), 1);
        assert!(matches!(
            ls.authorize(me(), "run", "p", "dev", 2002),
            Err(Denial::Inactive {
                state: LeaseState::Revoked,
                ..
            })
        ));
        assert!(ls.active(2002).is_empty());
        // Ended leases follow the active ones, newest first, capped.
        let live = start(&mut ls, me(), 600, 3000);
        let all = ls.with_recent(3001, 1);
        assert_eq!(all.len(), 2);
        assert_eq!(
            (all[0].id.as_str(), all[0].state.as_str()),
            (live.as_str(), "active")
        );
        assert_eq!(
            (all[1].id.as_str(), all[1].state.as_str()),
            (id2.as_str(), "revoked")
        );
        assert_eq!(ls.with_recent(3001, 10).len(), 3);
    }

    #[test]
    fn spawned_children_extend_the_tree_until_removed() {
        let mut ls = Leases::default();
        let (mut c, kid) = child();
        // The root is not an ancestor of `kid`; it only gets in through `spawned`.
        let (mut r, root) = child();
        let id = start(&mut ls, root, 60, 0);
        assert_eq!(
            ls.authorize(kid, "run", "p", "dev", 1).unwrap_err(),
            Denial::NoLease
        );
        ls.add_spawned(&id, kid);
        assert!(ls.authorize(kid, "run", "p", "dev", 1).is_ok());
        ls.remove_spawned(&id, kid);
        assert_eq!(
            ls.authorize(kid, "run", "p", "dev", 1).unwrap_err(),
            Denial::NoLease
        );
        for p in [&mut c, &mut r] {
            p.kill().unwrap();
            p.wait().unwrap();
        }
    }

    #[test]
    fn manifest_classifies_only_pinned_same_uid_binaries() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let peer = Peer::of(&a).unwrap();
        let exe = std::env::current_exe().unwrap();
        let dir = std::env::temp_dir().join(format!("ls-broker-m-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            Manifest::from_dir(&dir).classify(&peer),
            Role::Unknown,
            "nothing pinned"
        );
        // Pin a copy of this very binary as `smith`: the running test is now "smith".
        std::fs::copy(&exe, dir.join("smith")).unwrap();
        let m = Manifest::from_dir(&dir);
        assert_eq!(m.pinned().count(), 1, "test binary must be pinnable");
        assert_eq!(m.classify(&peer), Role::Smith);
        // Pin different code under the same name: the running test no longer matches.
        // Linux: one flipped byte changes the file SHA-256. macOS pins the cdhash, which a
        // flipped code byte does not change (the kernel kills such code on page validation
        // instead), so pin another binary there.
        #[cfg(target_os = "linux")]
        {
            let mut bytes = std::fs::read(dir.join("smith")).unwrap();
            bytes[0x1000] ^= 0xff;
            std::fs::write(dir.join("smith"), bytes).unwrap();
        }
        #[cfg(not(target_os = "linux"))]
        std::fs::copy("/bin/ls", dir.join("smith")).unwrap();
        let m = Manifest::from_dir(&dir);
        assert_eq!(m.classify(&peer), Role::Unknown);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// `sh` standing in for the agent, with two `sleep` children: the MCP server and a shell
    /// command the agent ran. Returns (agent, [mcp, shell]).
    fn agent_tree() -> (std::process::Child, [ProcId; 2]) {
        use std::io::BufRead;
        let mut sh = std::process::Command::new("sh")
            .args(["-c", "sleep 30 & echo $!; sleep 30 & echo $!; wait"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = std::io::BufReader::new(sh.stdout.take().unwrap()).lines();
        let mut kid = || id_of(out.next().unwrap().unwrap().trim().parse().unwrap()).unwrap();
        let kids = [kid(), kid()];
        (sh, kids)
    }

    fn kill(p: u32) {
        let _ = std::process::Command::new("kill")
            .arg(p.to_string())
            .status();
    }

    #[test]
    fn agent_root_is_the_mcp_servers_parent_and_covers_its_shell() {
        let uid = ls_platform::current_uid();
        let (mut agent, [mcp, shell]) = agent_tree();
        let root = agent_root(mcp, uid).unwrap();
        assert_eq!(root, id_of(agent.id()).unwrap());
        let mut ls = Leases::default();
        start(&mut ls, root, 60, 0);
        assert!(
            ls.authorize(shell, "run", "p", "dev", 1).is_ok(),
            "agent's shell"
        );
        assert!(
            ls.authorize(mcp, "run", "p", "dev", 1).is_ok(),
            "MCP server"
        );
        assert_eq!(
            ls.authorize(me(), "run", "p", "dev", 1).unwrap_err(),
            Denial::NoLease,
            "the agent's parent (the terminal)"
        );
        for p in [mcp, shell] {
            kill(p.pid);
        }
        agent.wait().unwrap();
    }

    #[test]
    fn agent_root_refusals() {
        let uid = ls_platform::current_uid();
        assert!(agent_root(me(), uid).is_ok());
        assert!(agent_root(me(), uid.wrapping_add(1)).is_err(), "other uid");
        let reused = ProcId {
            pid: me().pid,
            start: me().start + 1,
        };
        assert!(agent_root(reused, uid).is_err(), "pid reuse");
        let (mut c, gone) = child();
        c.kill().unwrap();
        c.wait().unwrap();
        assert!(agent_root(gone, uid).is_err(), "exited caller");
        // Not readable by a normal user on macOS; the orphan below covers pid 1 there.
        if let Ok(init) = id_of(1) {
            assert!(agent_root(init, uid).is_err(), "pid 1 has no parent agent");
        }
        // An orphan reparented to pid 1 has no agent to root at.
        let (mut sh, [a, b]) = agent_tree();
        kill(sh.id());
        sh.wait().unwrap();
        // macOS has no subreapers; Linux may reparent to one (pid > 1), so only check pid 1 there.
        #[cfg(target_os = "macos")]
        assert_eq!(info(a.pid).unwrap().ppid, 1, "orphan reparented to launchd");
        if info(a.pid).is_ok_and(|i| i.ppid == 1) {
            assert!(agent_root(a, uid).is_err(), "orphan");
        }
        kill(a.pid);
        kill(b.pid);
    }
}
