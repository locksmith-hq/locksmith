//! `smith init` (M4 task 3.3): binding, `.env` import, .gitignore, pre-commit scanner and agent
//! hooks and MCP server, with a preview of every change, idempotent, `--yes` for CI.

use crate::input::{self, Opts};
use crate::precommit::{self, Change};
use crate::vault_cmds::{self, Target};
use crate::{Fail, agents, binding, dotenv};
use ls_core::ExitCode;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;

const IGNORE: [&str; 4] = [
    ".env*",
    "!.env.example",
    ".claude/settings.local.json",
    ".locksmith/",
];

/// `.env` to move into the vault: file, target project/env and entry count (never values).
struct Import {
    file: PathBuf,
    target: (String, String),
    count: usize,
}

struct Plan {
    import: Option<Import>,
    changes: Vec<Change>,
    notes: Vec<String>,
}

fn usage(m: impl Into<String>) -> Fail {
    Fail(ExitCode::Usage, m.into())
}

fn repo_root() -> Result<PathBuf, Fail> {
    let o = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| usage(format!("cannot run git: {e}")))?;
    if !o.status.success() {
        return Err(usage("not inside a git repository"));
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()))
}

fn read(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

fn build(root: &Path, hub: Option<&str>, gateway: Option<&[String]>) -> Result<Plan, Fail> {
    let hub_url = hub
        .map(|h| agents::hub_mcp_url(h).map_err(usage))
        .transpose()?;
    let mut p = Plan {
        import: None,
        changes: vec![],
        notes: vec![],
    };

    // 1. binding
    let bind = root.join(binding::FILE);
    if !bind.exists() {
        p.changes.push(Change {
            path: binding::FILE.into(),
            before: None,
            after: binding::DEFAULT_BODY.into(),
            exec: false,
        });
    }
    let target = if bind.is_file() {
        let (b, _) = binding::load(&bind)?;
        (
            b.project.unwrap_or("default".into()),
            b.env.unwrap_or("development".into()),
        )
    } else {
        ("default".into(), "development".into())
    };

    // 2. .env import. Only `.env` itself: one unlock, one target. Other secret-bearing
    // `.env.*` files stay put and are listed.
    let env = root.join(".env");
    if env.is_file() {
        if !ls_vault::exists(&vault_cmds::dir()) {
            p.notes.push(".env left in place: no vault yet (run `smith vault init`, then re-run `smith init`)".into());
        } else {
            match std::fs::read_to_string(&env)
                .map_err(|e| e.to_string())
                .and_then(|s| dotenv::parse(&s))
            {
                Ok(items) if !items.is_empty() => {
                    p.import = Some(Import {
                        file: env,
                        target,
                        count: items.len(),
                    });
                }
                Ok(_) => {}
                Err(e) => p.notes.push(format!(".env not imported: {e}")),
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(root) {
        let mut others: Vec<String> = rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| {
                n != ".env" && n.starts_with(".env") && ls_hooks::is_secret_path(Path::new(n))
            })
            .collect();
        others.sort();
        for n in others {
            p.notes.push(format!(
                "{n} left in place (import it with `smith import dotenv {n} --env <name>`)"
            ));
        }
    }

    // 3. .gitignore
    let gi = root.join(".gitignore");
    let before = read(&gi);
    let have: Vec<&str> = before
        .as_deref()
        .unwrap_or("")
        .lines()
        .map(str::trim)
        .collect();
    // Last match wins in .gitignore: a new `.env*` must be followed by the negation again, even
    // when the file already had `!.env.example` above it.
    let env_missing = !have.contains(&IGNORE[0]);
    let missing: Vec<&str> = IGNORE
        .into_iter()
        .filter(|e| !have.contains(e) || (env_missing && *e == IGNORE[1]))
        .collect();
    if !missing.is_empty() {
        let mut after = before.clone().unwrap_or_default();
        if !after.is_empty() && !after.ends_with('\n') {
            after.push('\n');
        }
        after.push_str("# Locksmith\n");
        for m in missing {
            after.push_str(m);
            after.push('\n');
        }
        p.changes.push(Change {
            path: ".gitignore".into(),
            before,
            after,
            exec: false,
        });
    }

    // 4. pre-commit scanner
    match precommit::plan(root) {
        Ok(Some((_, c))) => p.changes.extend(c),
        Ok(None) => {}
        Err(e) => p
            .notes
            .push(format!("pre-commit scanner not installed: {e}")),
    }

    // 5. agent hooks and the MCP server. Codex keeps both in one file, so its text is chained.
    for a in agents::detect(root) {
        // Only Windsurf (Devin Desktop) is still gated: wiring its hooks now would install a hook
        // that exits 2 on every call. Say so instead of skipping silently.
        if !agents::hook_handler_ready(a) {
            p.notes.push(format!(
                "{}: detected but not wired (no hook handler for its format yet), so it is not protected{}",
                a.id(),
                agents::mcp_user_hint(a).map_or(String::new(), |h| format!(
                    "; add the locksmith MCP server by hand to {h} (command `locksmith-mcp`)"
                ))
            ));
            continue;
        }
        let f = agents::config_path(a, root);
        let before = read(&f);
        let mut after = agents::merge_hooks(a, before.as_deref())
            .map_err(|e| usage(format!("{}: {e}", f.display())))?;
        let mut files = vec![(f, before, None)];
        let mcp = agents::mcp_path(a, root);
        let m = mcp.clone().unwrap_or_default();
        match mcp {
            Some(mp) if mp == files[0].0 => {
                after = agents::merge_mcp(a, Some(&after))
                    .map_err(|e| usage(format!("{}: {e}", m.display())))?;
            }
            Some(mp) => {
                let mb = read(&mp);
                let ma = agents::merge_mcp(a, mb.as_deref())
                    .map_err(|e| usage(format!("{}: {e}", m.display())))?;
                files.push((mp, mb, Some(ma)));
            }
            None => {
                if let Some(h) = agents::mcp_user_hint(a) {
                    p.notes.push(format!(
                        "{}: add the locksmith MCP server by hand to {h} (command `locksmith-mcp`)",
                        a.id()
                    ));
                }
            }
        }
        if let Some(url) = &hub_url {
            if !a.remote_mcp() {
                p.notes.push(format!(
                    "no remote Hub MCP entry for {}: remote MCP with OAuth is not verified for it",
                    a.id()
                ));
            } else if a == agents::Agent::Codex {
                after = agents::merge_hub_mcp(a, Some(&after), url)
                    .map_err(|e| usage(format!("{}: {e}", m.display())))?;
            } else {
                let last = files.last_mut().expect("mcp file");
                let merged = agents::merge_hub_mcp(a, last.2.as_deref(), url)
                    .map_err(|e| usage(format!("{}: {e}", m.display())))?;
                last.2 = Some(merged);
            }
        }
        files[0].2 = Some(after);
        // Task 6.3: swap entries for the gateway's upstreams with the stdio bridge. The preview
        // shows the old entry with every value masked, and the token is not saved anywhere.
        let mut masked: Option<(PathBuf, String)> = None;
        if let Some(upstreams) = gateway {
            if let Some(mp) = agents::mcp_path(a, root) {
                for (f, _, after) in &mut files {
                    if *f != mp {
                        continue;
                    }
                    let text = after.clone().unwrap_or_default();
                    let text = if text.trim().is_empty() {
                        "{}".to_owned()
                    } else {
                        text
                    };
                    if let Some(r) = agents::rewrite_gateway_mcp(a, &text, upstreams)
                        .map_err(|e| usage(format!("{}: {e}", mp.display())))?
                    {
                        p.notes.push(format!(
                            "{}: {} now run through `smith mcp bridge`; the credential removed from {} is not saved",
                            a.id(),
                            r.rewritten.join(", "),
                            mp.strip_prefix(root).unwrap_or(&mp).display()
                        ));
                        masked = Some((mp.clone(), r.masked_before));
                        *after = Some(r.after);
                    }
                }
            } else if let Some(h) = agents::mcp_user_hint(a) {
                p.notes.push(format!(
                    "{}: --mcp-gateway does not edit user-level files; replace the entries for {} in {h} with command `smith`, args `mcp bridge <name>` by hand",
                    a.id(),
                    upstreams.join(", ")
                ));
            }
        }
        for (f, before, after) in files {
            let before = match &masked {
                Some((mp, text)) if *mp == f => Some(text.clone()),
                _ => before,
            };
            let after = after.unwrap_or_default();
            if before.as_deref() != Some(after.as_str()) {
                let path = f.strip_prefix(root).unwrap_or(&f).to_path_buf();
                p.changes.push(Change {
                    path,
                    before,
                    after,
                    exec: a == agents::Agent::Cline && f.ends_with("PreToolUse"),
                });
            }
        }
    }
    Ok(p)
}

/// Unified-diff-style text: common prefix and suffix are trimmed, two lines of context kept.
fn diff(c: &Change) -> String {
    let b: Vec<&str> = c.before.as_deref().unwrap_or("").lines().collect();
    let a: Vec<&str> = c.after.lines().collect();
    let pre = b.iter().zip(&a).take_while(|(x, y)| x == y).count();
    let suf = b[pre..]
        .iter()
        .rev()
        .zip(a[pre..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (bm, am) = (&b[pre..b.len() - suf], &a[pre..a.len() - suf]);
    let ctx_start = pre.saturating_sub(2);
    let tail = &b[b.len() - suf..b.len().min(b.len() - suf + 2)];
    let p = c.path.display();
    let mut s = match &c.before {
        None => format!("--- /dev/null\n+++ b/{p}\n"),
        Some(_) => format!("--- a/{p}\n+++ b/{p}\n"),
    };
    let (bn, an) = (
        pre - ctx_start + bm.len() + tail.len(),
        pre - ctx_start + am.len() + tail.len(),
    );
    let (bs, as_) = (
        if bn == 0 { 0 } else { ctx_start + 1 },
        if an == 0 { 0 } else { ctx_start + 1 },
    );
    s.push_str(&format!("@@ -{bs},{bn} +{as_},{an} @@\n"));
    for l in &b[ctx_start..pre] {
        s.push_str(&format!(" {l}\n"));
    }
    for l in bm {
        s.push_str(&format!("-{l}\n"));
    }
    for l in am {
        s.push_str(&format!("+{l}\n"));
    }
    for l in tail {
        s.push_str(&format!(" {l}\n"));
    }
    s
}

fn preview(p: &Plan) -> String {
    let mut s = String::new();
    if let Some(i) = &p.import {
        s.push_str(&format!(
            "import {} ({} entries) into the vault ({}/{}), then delete it\n\n",
            i.file.file_name().unwrap_or_default().to_string_lossy(),
            i.count,
            i.target.0,
            i.target.1
        ));
    }
    for c in &p.changes {
        s.push_str(&diff(c));
        s.push('\n');
    }
    for n in &p.notes {
        s.push_str(&format!("note: {n}\n"));
    }
    s
}

pub fn run(
    o: &Opts,
    binding_only: bool,
    yes: bool,
    hub: Option<&str>,
    mcp_gateway: bool,
    dry_run: bool,
) -> Result<ExitCode, Fail> {
    if binding_only {
        return crate::run_cmd::init(true);
    }
    let root = repo_root()?;
    let upstreams = if mcp_gateway {
        // The upstreams this agent may use, from the gateway (names only).
        let st = ls_connector::State::load_fresh()?;
        Some(ls_connector::mcp::upstreams(&st)?)
    } else {
        None
    };
    let plan = build(&root, hub, upstreams.as_deref())?;
    if plan.import.is_none() && plan.changes.is_empty() {
        print!("{}", preview(&plan));
        println!("already set up");
        return Ok(ExitCode::Ok);
    }
    print!("{}", preview(&plan));
    if dry_run {
        println!("dry run: nothing changed");
        return Ok(ExitCode::Ok);
    }
    if !yes {
        if !std::io::stdin().is_terminal() {
            return Err(usage(
                "refusing to change files without a terminal to ask; pass --yes to apply the plan above",
            ));
        }
        if !input::tty_line("Apply these changes? [y/N] ")
            .is_some_and(|a| a.eq_ignore_ascii_case("y"))
        {
            return Err(Fail(
                ExitCode::Failure,
                "not confirmed; nothing changed".into(),
            ));
        }
    }
    // Import first: it needs the passphrase, and a failure must leave the rest untouched.
    if let Some(i) = &plan.import {
        let t = Target {
            project: i.target.0.clone(),
            env: i.target.1.clone(),
        };
        vault_cmds::import_dotenv(o, &i.file, &t, true, false)?;
    }
    for c in &plan.changes {
        precommit::apply(&root, c).map_err(|e| {
            Fail(
                ExitCode::Failure,
                format!("cannot write {}: {e}", c.path.display()),
            )
        })?;
    }
    println!("smith init done");
    Ok(ExitCode::Ok)
}
