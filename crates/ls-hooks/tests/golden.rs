//! Golden JSON tests: `fixtures/<agent>/<case>.in.json` -> `.out.json` through the adapters,
//! with `NoVault` and a temp cwd holding `.env`. Regenerate with `UPDATE_GOLDEN=1`.

use ls_hooks::NoVault;
use ls_hooks::adapters::handle;
use serde_json::{Value, json};
use std::path::Path;

#[test]
fn golden() {
    let cwd = std::env::temp_dir().join(format!("ls-hooks-golden-{}", std::process::id()));
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::write(cwd.join(".env"), "A=1\n").unwrap();
    // Built at runtime so gitleaks does not flag this repository.
    let key = format!("{}{}", "sk_live_", "Q".repeat(24));
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    let mut n = 0;
    for agent in [
        "claude-code",
        "cursor",
        "codex",
        "gemini-cli",
        "copilot",
        "cline",
    ] {
        let mut files: Vec<_> = std::fs::read_dir(root.join(agent))
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.to_string_lossy().ends_with(".in.json"))
            .collect();
        files.sort();
        for p in files {
            let input = std::fs::read_to_string(&p)
                .unwrap()
                .replace("__CWD__", &cwd.to_string_lossy())
                .replace("__KEY__", &key);
            let event = serde_json::from_str::<Value>(&input)
                .ok()
                .and_then(|v| v["hook_event_name"].as_str().map(String::from))
                // Copilot's camelCase payload carries no event name; its hook file does.
                .unwrap_or_else(|| {
                    if agent == "copilot" {
                        "preToolUse"
                    } else {
                        "PreToolUse"
                    }
                    .into()
                });
            let h = handle(agent, &event, &input, &NoVault).unwrap();
            let stdout = if h.out.stdout.is_empty() {
                Value::Null
            } else {
                serde_json::from_str(&h.out.stdout).unwrap()
            };
            let mut got = json!({"code": h.out.code, "stdout": stdout});
            if !h.out.stderr.is_empty() {
                got["stderr"] = h.out.stderr.trim_end().into();
            }
            assert!(!h.out.stdout.contains(&key) && !h.out.stderr.contains(&key));
            let out = p.to_string_lossy().replace(".in.json", ".out.json");
            if update {
                std::fs::write(&out, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
            }
            let want: Value =
                serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
            assert_eq!(got, want, "{}", p.display());
            n += 1;
        }
    }
    let _ = std::fs::remove_dir_all(&cwd);
    assert!(n >= 89, "only {n} golden cases ran");
}
