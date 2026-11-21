//! e2e for `smith init` and the pre-commit installer, with the real `git` and `smith`.
//! lefthook and pre-commit (the framework) are not installed in CI, so for those two the test
//! runs the command our config step declares, the way the manager would.
//! Unix only: the hooks and the `smith` shim are `/bin/sh` scripts with exec bits.
#![cfg(unix)]

mod common;
use common::*;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};

const SECRET: &str = "fake_db_password_9f3a1c77";

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn path_with(shim: &Path) -> String {
    format!("{}:{}", shim.display(), std::env::var("PATH").unwrap())
}

fn setup() -> (Home, Repo) {
    let h = Home::new();
    h.ready();
    assert!(h.add("DATABASE_URL", SECRET).status.success());
    (h, Repo::new())
}

fn init_yes(h: &Home, r: &Repo) -> Output {
    let o = h.smith_in(&r.0, &["init", "--yes"]);
    assert!(o.status.success(), "{}{}", s(&o.stdout), s(&o.stderr));
    o
}

fn commit(h: &Home, r: &Repo, extra_env: &[(&str, String)]) -> Output {
    let mut c = Command::new("git");
    c.args(["commit", "-q", "-m", "x"])
        .current_dir(&r.0)
        .env("PATH", path_with(&h.smith_shim()));
    for (k, v) in extra_env {
        c.env(k, v);
    }
    c.output().unwrap()
}

/// Secret commit is blocked with `file:line: KEY`; a clean commit passes.
fn check_blocks_and_passes(h: &Home, r: &Repo, run: &dyn Fn(&Home, &Repo) -> Output) {
    r.write(
        "src/db.js",
        &format!("const a = 1;\nconst u = \"{SECRET}\";\n"),
    );
    r.git(&["add", "-A"]);
    let o = run(h, r);
    assert!(!o.status.success(), "commit must be blocked");
    let all = format!("{}{}", s(&o.stdout), s(&o.stderr));
    assert!(all.contains("src/db.js:2: DATABASE_URL"), "{all}");
    assert!(!all.contains(SECRET));
    r.write("src/db.js", "const a = 1;\n");
    r.git(&["add", "-A"]);
    let o = run(h, r);
    assert!(o.status.success(), "{}{}", s(&o.stdout), s(&o.stderr));
}

#[test]
fn git_hook_blocks_and_chains_existing_hook() {
    let (h, r) = setup();
    r.write(".git/hooks/pre-commit", "#!/bin/sh\necho chained-ran\n");
    std::fs::set_permissions(
        r.0.join(".git/hooks/pre-commit"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    init_yes(&h, &r);
    check_blocks_and_passes(&h, &r, &|h, r| commit(h, r, &[]));
    let hook = Command::new(r.0.join(".git/hooks/pre-commit"))
        .current_dir(&r.0)
        .env("PATH", path_with(&h.smith_shim()))
        .output()
        .unwrap();
    assert!(s(&hook.stdout).contains("chained-ran"));
}

#[test]
fn hook_fails_visibly_when_smith_is_missing() {
    let (h, r) = setup();
    init_yes(&h, &r);
    r.write("a.txt", "hello\n");
    r.git(&["add", "-A"]);
    let o = Command::new("git")
        .args(["commit", "-q", "-m", "x"])
        .current_dir(&r.0)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(
        s(&o.stderr).contains("'smith' not found"),
        "{}",
        s(&o.stderr)
    );
}

#[test]
fn husky_step_is_appended_not_replaced() {
    let (h, r) = setup();
    r.write(".husky/pre-commit", "echo husky-existing\n");
    std::fs::set_permissions(
        r.0.join(".husky/pre-commit"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    // husky points core.hooksPath at its directory; the scripts there run directly.
    r.git(&["config", "core.hooksPath", ".husky"]);
    init_yes(&h, &r);
    let body = std::fs::read_to_string(r.0.join(".husky/pre-commit")).unwrap();
    assert!(
        body.starts_with("echo husky-existing\n# locksmith:pre-commit\n"),
        "{body}"
    );
    check_blocks_and_passes(&h, &r, &|h, r| commit(h, r, &[]));
}

/// Runs the first `key: value` command of our step the way lefthook / pre-commit would.
fn run_declared(h: &Home, r: &Repo, file: &str, key: &str) -> Output {
    let cfg = std::fs::read_to_string(r.0.join(file)).unwrap();
    let cmd = cfg
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix(key)
                .filter(|c| c.contains("smith scan"))
        })
        .expect("step declared")
        .trim()
        .to_string();
    Command::new("sh")
        .args(["-c", &cmd])
        .current_dir(&r.0)
        .env("PATH", path_with(&h.smith_shim()))
        .output()
        .unwrap()
}

#[test]
fn lefthook_step_is_merged_into_existing_config() {
    let (h, r) = setup();
    r.write(
        "lefthook.yml",
        "pre-commit:\n  commands:\n    lint:\n      run: echo lint\n",
    );
    init_yes(&h, &r);
    let cfg = std::fs::read_to_string(r.0.join("lefthook.yml")).unwrap();
    assert!(
        cfg.contains("lint:\n      run: echo lint") && cfg.contains("locksmith-scan:"),
        "{cfg}"
    );
    check_blocks_and_passes(&h, &r, &|h, r| run_declared(h, r, "lefthook.yml", "run:"));
}

#[test]
fn pre_commit_framework_step_is_appended() {
    let (h, r) = setup();
    r.write(
        ".pre-commit-config.yaml",
        "repos:\n  - repo: https://github.com/pre-commit/pre-commit-hooks\n    rev: v4.5.0\n    hooks:\n      - id: end-of-file-fixer\n",
    );
    init_yes(&h, &r);
    let cfg = std::fs::read_to_string(r.0.join(".pre-commit-config.yaml")).unwrap();
    assert!(
        cfg.contains("end-of-file-fixer") && cfg.contains("  - repo: local"),
        "{cfg}"
    );
    check_blocks_and_passes(&h, &r, &|h, r| {
        run_declared(h, r, ".pre-commit-config.yaml", "entry:")
    });
}

/// Every file except git internals, plus the hook files, with contents and exec bit.
fn tree(root: &Path) -> BTreeMap<String, (Vec<u8>, bool)> {
    use std::os::unix::fs::PermissionsExt;
    fn go(root: &Path, dir: &Path, out: &mut BTreeMap<String, (Vec<u8>, bool)>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            if rel.starts_with(".git/") && !rel.starts_with(".git/hooks/")
                || rel.ends_with(".sample")
            {
                continue;
            }
            if p.is_dir() {
                go(root, &p, out);
            } else {
                let exec = std::fs::metadata(&p).unwrap().permissions().mode() & 0o111 != 0;
                out.insert(rel, (std::fs::read(&p).unwrap(), exec));
            }
        }
    }
    let mut out = BTreeMap::new();
    go(root, root, &mut out);
    out
}

#[test]
fn init_yes_twice_changes_nothing_and_imports_env() {
    let (h, r) = setup();
    r.write(".husky/pre-commit", "echo hi\n");
    r.write(
        ".claude/settings.json",
        "{\"permissions\": {\"allow\": [\"Bash(ls)\"]}}\n",
    );
    r.write(".gitignore", "node_modules/\n");
    r.write(
        ".env",
        "API_TOKEN=fake_api_token_5588aa11\nOTHER=fake_other_value_9911bb22\n",
    );
    let first = init_yes(&h, &r);
    assert!(s(&first.stdout).contains("import .env (2 entries)"));
    assert!(!r.0.join(".env").exists(), ".env deleted after import");
    let ls = h.run(&["ls"], "");
    assert!(s(&ls.stdout).contains("API_TOKEN"), "{}", s(&ls.stdout));
    let gi = std::fs::read_to_string(r.0.join(".gitignore")).unwrap();
    for e in [
        ".env*",
        "!.env.example",
        ".claude/settings.local.json",
        ".locksmith/",
        "node_modules/",
    ] {
        assert!(gi.lines().any(|l| l == e), "{gi}");
    }
    assert!(r.0.join(".locksmith.toml").exists());
    let cl = std::fs::read_to_string(r.0.join(".claude/settings.json")).unwrap();
    assert!(cl.contains("Bash(ls)") && cl.contains("smith hook claude-code PreToolUse"));
    let mcp = std::fs::read_to_string(r.0.join(".mcp.json")).unwrap();
    assert!(mcp.contains("\"locksmith-mcp\""), "{mcp}");
    let before = tree(&r.0);
    let second = init_yes(&h, &r);
    assert!(
        s(&second.stdout).contains("already set up"),
        "{}",
        s(&second.stdout)
    );
    assert_eq!(before, tree(&r.0));
}

#[test]
fn existing_env_example_negation_survives_init() {
    let (h, r) = setup();
    r.write(".gitignore", "dist/\n!.env.example\n");
    assert!(init_yes(&h, &r).status.success());
    let ignored = |p: &str| {
        std::process::Command::new("git")
            .args(["check-ignore", "-q", p])
            .current_dir(&r.0)
            .status()
            .unwrap()
            .success()
    };
    assert!(ignored(".env") && !ignored(".env.example"));
    let before = tree(&r.0);
    init_yes(&h, &r);
    assert_eq!(before, tree(&r.0));
}

#[test]
fn preview_is_shown_and_no_terminal_without_yes_refuses() {
    let h = Home::new(); // no vault: generic-only is fine for init
    let r = Repo::new();
    r.write(".husky/pre-commit", "echo hi\n");
    r.write(".gitignore", "node_modules/\n");
    let before = tree(&r.0);
    let o = h.smith_in(&r.0, &["init"]);
    assert_eq!(o.status.code(), Some(2), "{}", s(&o.stderr));
    assert!(s(&o.stderr).contains("--yes"));
    assert_eq!(before, tree(&r.0), "nothing written");
    assert_eq!(s(&o.stdout), include_str!("fixtures/init_preview.txt"));
}

/// Every new agent marker in one repo: hooks and MCP are merged, user-level MCP configs get a
/// manual-step note, Windsurf is reported as not wired, and a second run changes nothing.
#[test]
fn init_wires_new_agents_idempotently_and_prints_manual_steps() {
    let h = Home::new();
    let r = Repo::new();
    r.write(".gemini/settings.json", "{\"theme\": \"dark\"}\n");
    r.write(".github/copilot-instructions.md", "# hi\n");
    r.write(".clinerules/rules.md", "# rules\n");
    r.write(".devin/notes.md", "# devin\n");
    let first = init_yes(&h, &r);
    let out = s(&first.stdout);
    let read = |p: &str| std::fs::read_to_string(r.0.join(p)).unwrap();
    let gem = read(".gemini/settings.json");
    assert!(gem.contains("\"theme\"") && gem.contains("smith hook gemini-cli BeforeTool"));
    assert!(gem.contains("smith hook gemini-cli BeforeAgent") && gem.contains("locksmith-mcp"));
    assert!(read(".github/hooks/locksmith.json").contains("smith hook copilot preToolUse"));
    assert!(read(".vscode/mcp.json").contains("locksmith-mcp"));
    assert!(read(".clinerules/hooks/PreToolUse").contains("smith hook cline PreToolUse"));
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(r.0.join(".clinerules/hooks/PreToolUse"))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0, "Cline hook must be executable");
    }
    assert!(!r.0.join(".windsurf").exists(), "windsurf stays unwired");
    assert!(
        out.contains("note: cline: add the locksmith MCP server by hand"),
        "{out}"
    );
    assert!(
        out.contains("note: windsurf: detected but not wired"),
        "{out}"
    );
    let before = tree(&r.0);
    let second = init_yes(&h, &r);
    assert!(
        s(&second.stdout).contains("already set up"),
        "{}",
        s(&second.stdout)
    );
    assert_eq!(before, tree(&r.0));
}

/// An unparsable config makes init stop with an error and leaves every file as it was.
#[test]
fn init_leaves_invalid_agent_configs_untouched() {
    let h = Home::new();
    for (file, body) in [
        (".gemini/settings.json", "{not json"),
        (".github/hooks/locksmith.json", "[1, 2"),
        (".clinerules/hooks/PreToolUse", "#!/bin/sh\necho mine\n"),
    ] {
        let r = Repo::new();
        r.write(file, body);
        let before = tree(&r.0);
        let o = h.smith_in(&r.0, &["init", "--yes"]);
        assert!(!o.status.success(), "{file}: {}", s(&o.stdout));
        assert!(s(&o.stderr).contains(file), "{file}: {}", s(&o.stderr));
        assert_eq!(before, tree(&r.0), "{file} untouched, nothing else written");
    }
}

/// Doctor names the protection of hooked agents and flags Windsurf as not protected.
#[test]
fn doctor_reports_new_agents_with_protection_labels() {
    let h = Home::new();
    let r = Repo::new();
    r.write(".gemini/settings.json", "{}\n");
    r.write(".github/hooks/keep", "");
    r.write(".devin/notes.md", "# devin\n");
    let before = h.smith_in(&r.0, &["doctor"]);
    let text = s(&before.stdout);
    assert!(
        text.contains("hooks.gemini_cli ")
            && text.contains("agent detected but Locksmith hooks are missing"),
        "{text}"
    );
    assert!(
        text.contains("hooks.windsurf") && text.contains("not protected"),
        "{text}"
    );
    init_yes(&h, &r);
    let after = h.smith_in(&r.0, &["doctor"]);
    let text = s(&after.stdout);
    let line = |id: &str| {
        text.lines()
            .find(|l| l.contains(id))
            .unwrap_or_else(|| panic!("no {id} line in {text}"))
            .to_string()
    };
    assert!(line("hooks.gemini_cli ").contains("protection: prevention (blocking hook)"));
    assert!(line("hooks.copilot ").contains("protection: prevention (blocking hook)"));
    assert!(line("hooks.copilot.timeout").contains("fail-open"));
    assert!(line("hooks.cline ").contains("skip"));
}
