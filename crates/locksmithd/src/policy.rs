//! Agent-session policy (M10b D1): which project/env pairs, scopes and TTL an agent may grant
//! itself through `locksmith-mcp` without the passphrase. The file is human-owned and lives
//! outside any repository; the daemon reads it only when the vault is unlocked (by the human),
//! so an agent editing it mid-session changes nothing until the next unlock.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const FILE: &str = "agent-policy.toml";

/// ```toml
/// max_ttl_secs = 3600
/// scopes = ["run", "http"]
/// [projects.myapp]
/// envs = ["dev", "staging"]
/// ```
#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub max_ttl_secs: u64,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub projects: BTreeMap<String, Project>,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub envs: Vec<String>,
}

pub fn default_path() -> PathBuf {
    ls_core::config_dir().join(FILE)
}

/// Refuse a policy path an agent could plausibly write: a symlink, anything inside a git work
/// tree, or a file/parent dir not owned by `uid` or writable by group/others.
pub fn check_path(path: &Path, uid: u32) -> Result<(), String> {
    let p = path.display();
    let md = std::fs::symlink_metadata(path).map_err(|e| format!("{p}: {e}"))?;
    if md.file_type().is_symlink() || !md.is_file() {
        return Err(format!("{p} must be a regular file, not a symlink"));
    }
    let parent = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()
        .map_err(|e| format!("{p}: {e}"))?;
    if let Some(repo) = parent.ancestors().find(|d| d.join(".git").exists()) {
        return Err(format!(
            "{p} is inside the git work tree {}; keep the agent policy outside any repository",
            repo.display()
        ));
    }
    let pmd = std::fs::metadata(&parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    for (what, m) in [(p.to_string(), &md), (parent.display().to_string(), &pmd)] {
        if m.uid() != uid {
            return Err(format!(
                "{what} is owned by uid {}, not the current user (uid {uid})",
                m.uid()
            ));
        }
        if m.mode() & 0o022 != 0 {
            return Err(format!(
                "{what} is writable by group or others (mode {:o})",
                m.mode() & 0o777
            ));
        }
    }
    Ok(())
}

/// Check the path, then parse and validate the policy.
pub fn load(path: &Path, uid: u32) -> Result<Policy, String> {
    if !path.exists() {
        return Err(format!(
            "no agent policy at {}; agent-started sessions are off",
            path.display()
        ));
    }
    check_path(path, uid)?;
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let pol: Policy = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Some(s) = pol
        .scopes
        .iter()
        .find(|s| !crate::SCOPES.contains(&s.as_str()))
    {
        return Err(format!("{}: unknown scope '{s}'", path.display()));
    }
    Ok(pol)
}

impl Policy {
    /// Does the request fit as asked? Never clamps: any excess is a refusal with the reason.
    pub fn check(
        &self,
        project: &str,
        env: &str,
        scopes: &[String],
        ttl: u64,
    ) -> Result<(), String> {
        let Some(p) = self.projects.get(project) else {
            return Err(format!("project '{project}' is not in the agent policy"));
        };
        if !p.envs.iter().any(|e| e == env) {
            return Err(format!("env '{project}/{env}' is not in the agent policy"));
        }
        if let Some(s) = scopes.iter().find(|s| !self.scopes.contains(s)) {
            return Err(format!("scope '{s}' is not in the agent policy"));
        }
        if ttl > self.max_ttl_secs {
            return Err(format!(
                "ttl {ttl}s exceeds the agent policy maximum of {}s",
                self.max_ttl_secs
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const GOOD: &str = "max_ttl_secs = 600\nscopes = [\"http\", \"run\"]\n\
                        [projects.app]\nenvs = [\"dev\"]\n[projects.ops]\nenvs = [\"prod\"]\n";

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A fresh 0700 dir under the system temp dir (outside this repo's work tree).
    fn tmp(tag: &str) -> Tmp {
        let d = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("lsd-pol-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        Tmp(d)
    }

    fn write(path: &Path, body: &str, mode: u32) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn uid() -> u32 {
        ls_platform::current_uid()
    }

    #[test]
    fn loads_and_checks_without_clamping() {
        let t = tmp("ok");
        let f = t.0.join(FILE);
        write(&f, GOOD, 0o600);
        let p = load(&f, uid()).unwrap();
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(p.check("app", "dev", &s(&["http"]), 600).is_ok());
        assert!(
            p.check("app", "prod", &s(&["http"]), 60)
                .unwrap_err()
                .contains("app/prod")
        );
        assert!(p.check("other", "dev", &s(&["http"]), 60).is_err());
        assert!(
            p.check("app", "dev", &s(&["git"]), 60)
                .unwrap_err()
                .contains("git")
        );
        assert!(
            p.check("app", "dev", &s(&["run"]), 601)
                .unwrap_err()
                .contains("601")
        );
    }

    #[test]
    fn missing_bad_schema_and_unknown_scope_are_refused() {
        let t = tmp("schema");
        let f = t.0.join(FILE);
        assert!(
            load(&f, uid())
                .unwrap_err()
                .contains("agent-started sessions are off")
        );
        write(&f, "max_ttl_secs = 1\nscopes = []\nextra = 1\n", 0o600);
        assert!(load(&f, uid()).is_err());
        write(&f, "max_ttl_secs = 1\nscopes = [\"*\"]\n", 0o600);
        assert!(load(&f, uid()).unwrap_err().contains("unknown scope"));
    }

    #[test]
    fn agent_writable_paths_are_refused() {
        let t = tmp("perm");
        let f = t.0.join(FILE);
        write(&f, GOOD, 0o620);
        assert!(load(&f, uid()).unwrap_err().contains("writable"));
        write(&f, GOOD, 0o602);
        assert!(load(&f, uid()).unwrap_err().contains("writable"));
        write(&f, GOOD, 0o600);
        assert!(load(&f, uid() + 1).unwrap_err().contains("owned by uid"));

        // Group-writable parent dir: the file could be replaced.
        std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(load(&f, uid()).unwrap_err().contains("writable"));
        std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Symlink to a good file.
        let l = t.0.join("link.toml");
        std::os::unix::fs::symlink(&f, &l).unwrap();
        assert!(load(&l, uid()).unwrap_err().contains("symlink"));
    }

    #[test]
    fn paths_inside_a_git_work_tree_are_refused() {
        let t = tmp("git");
        // `.git` as a dir (normal repo) and as a file (worktree/submodule), checked from a subdir.
        for git_is_file in [false, true] {
            let g = t.0.join(".git");
            let _ = std::fs::remove_dir_all(&g);
            let _ = std::fs::remove_file(&g);
            if git_is_file {
                std::fs::write(&g, "gitdir: /elsewhere\n").unwrap();
            } else {
                std::fs::create_dir(&g).unwrap();
            }
            let sub = t.0.join("config");
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
            let f = sub.join(FILE);
            write(&f, GOOD, 0o600);
            assert!(load(&f, uid()).unwrap_err().contains("git work tree"));
        }
    }
}
