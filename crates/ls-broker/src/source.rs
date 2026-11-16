//! Where a session's agent runs (M10d, design: openspec/changes/m10d-agent-source/design.md).
//!
//! A display hint from executable paths the kernel reports (never arguments or environment).
//! Any process can name its binary `claude`, so nothing here is used for trust. Anything not in
//! the tables is shown as `other` with its executable name, never guessed.

use ls_ipc::{SessionSource, SourceKind};
use ls_platform::proc::{exe_path, info};
use std::path::{Component, Path, PathBuf};

/// How a rule matches one executable path.
enum M {
    /// Exact executable file name.
    Name(&'static str),
    /// An app bundle directly inside an `Applications` directory (`/Applications`,
    /// `~/Applications`, `/System/Applications/Utilities` does not count) whose name starts
    /// with this and ends with `.app`.
    Bundle(&'static str),
    /// A fixed fragment of the path.
    Under(&'static str),
}

use M::*;
use SourceKind::*;

/// Agent table, first match wins. Paths before names so a helper inside an app bundle
/// is attributed to the app.
const AGENTS: &[(M, SourceKind, &str)] = &[
    // Claude Code bundled with the desktop app (Application Support/Claude/claude-code/<ver>/).
    (
        Under("/Library/Application Support/Claude/claude-code/"),
        ClaudeDesktopApp,
        "Claude desktop app",
    ),
    (Bundle("Claude.app"), ClaudeDesktopApp, "Claude desktop app"),
    (Bundle("Cursor.app"), Cursor, "Cursor"),
    (Bundle("Windsurf.app"), Windsurf, "Windsurf"),
    (Bundle("Visual Studio Code"), Vscode, "VS Code"),
    (Bundle("IntelliJ IDEA"), Jetbrains, "JetBrains"),
    (Bundle("PyCharm"), Jetbrains, "JetBrains"),
    (Bundle("WebStorm"), Jetbrains, "JetBrains"),
    (Bundle("GoLand"), Jetbrains, "JetBrains"),
    (Bundle("RustRover"), Jetbrains, "JetBrains"),
    (Bundle("CLion"), Jetbrains, "JetBrains"),
    (Bundle("Rider"), Jetbrains, "JetBrains"),
    (Bundle("PhpStorm"), Jetbrains, "JetBrains"),
    (Name("claude"), ClaudeCodeCli, "Claude Code"),
    (Name("codex"), Codex, "Codex"),
    (Name("cursor-agent"), Cursor, "Cursor"),
    (Name("cursor"), Cursor, "Cursor"),
    (Name("grok"), Grok, "Grok"),
    (Name("gemini"), GeminiCli, "Gemini CLI"),
    (Name("aider"), Aider, "Aider"),
    (Name("windsurf"), Windsurf, "Windsurf"),
    (Name("Code Helper"), Vscode, "VS Code"),
    (Name("Code Helper (Plugin)"), Vscode, "VS Code"),
    (Name("code"), Vscode, "VS Code"),
    (Name("copilot"), Copilot, "GitHub Copilot"),
    (Name("opencode"), Opencode, "opencode"),
    (Name("idea"), Jetbrains, "JetBrains"),
    (Name("pycharm"), Jetbrains, "JetBrains"),
    (Name("webstorm"), Jetbrains, "JetBrains"),
    (Name("goland"), Jetbrains, "JetBrains"),
    (Name("rustrover"), Jetbrains, "JetBrains"),
    (Name("clion"), Jetbrains, "JetBrains"),
];

/// Terminals, multiplexers and IDEs an agent runs inside (the `host` field).
const HOSTS: &[(M, &str)] = &[
    (Name("tmux"), "tmux"),
    (Name("screen"), "screen"),
    (Name("zellij"), "zellij"),
    (Name("Terminal"), "Terminal"),
    (Name("iTerm2"), "iTerm2"),
    (Bundle("Warp.app"), "Warp"),
    (Name("warp"), "Warp"),
    (Name("ghostty"), "ghostty"),
    (Name("kitty"), "kitty"),
    (Name("alacritty"), "Alacritty"),
    (Name("wezterm-gui"), "WezTerm"),
    (Name("Hyper"), "Hyper"),
    (Name("gnome-terminal-server"), "GNOME Terminal"),
    (Name("konsole"), "Konsole"),
    (Bundle("Visual Studio Code"), "VS Code"),
    (Name("code"), "VS Code"),
    (Bundle("Cursor.app"), "Cursor"),
    (Bundle("Windsurf.app"), "Windsurf"),
    (Bundle("IntelliJ IDEA"), "JetBrains"),
    (Bundle("PyCharm"), "JetBrains"),
];

/// How many parents are read for `host`.
const MAX_ANCESTORS: usize = 8;
/// Labels and paths come from process names an attacker can choose: printable, bounded.
const MAX_LABEL: usize = 64;
const MAX_PATH: usize = 512;

fn matches(m: &M, p: &Path) -> bool {
    match m {
        Name(n) => p.file_name().is_some_and(|f| f == *n),
        Under(frag) => p.to_string_lossy().contains(frag),
        Bundle(prefix) => {
            let c: Vec<_> = p
                .components()
                .filter_map(|c| match c {
                    Component::Normal(s) => Some(s.to_string_lossy()),
                    _ => None,
                })
                .collect();
            c.windows(2).any(|w| {
                w[0] == "Applications" && w[1].starts_with(prefix) && w[1].ends_with(".app")
            })
        }
    }
}

/// Printable text only (control characters dropped), at most `max` characters.
pub fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// Classify the agent at `root` (its executable path, `None` when unreadable) and the host
/// among its `ancestors` (nearest first).
pub fn classify(root: Option<&Path>, ancestors: &[PathBuf]) -> (SessionSource, Option<String>) {
    let source = match root {
        None => SessionSource {
            kind: Unknown,
            label: "unknown".into(),
        },
        Some(p) => match AGENTS.iter().find(|(m, _, _)| matches(m, p)) {
            Some((_, kind, label)) => SessionSource {
                kind: *kind,
                label: (*label).into(),
            },
            None => match p
                .file_name()
                .map(|f| clean(&f.to_string_lossy(), MAX_LABEL))
            {
                Some(n) if !n.is_empty() => SessionSource {
                    kind: Other,
                    label: n,
                },
                _ => SessionSource {
                    kind: Unknown,
                    label: "unknown".into(),
                },
            },
        },
    };
    let host = ancestors
        .iter()
        .find_map(|a| HOSTS.iter().find(|(m, _)| matches(m, a)))
        .map(|(_, l)| l.to_string())
        .filter(|h| *h != source.label);
    (source, host)
}

/// Executable paths of up to [`MAX_ANCESTORS`] parents of `pid`, nearest first. Stops at
/// pid 1, an unreadable hop, or a parent younger than its child (recycled pid).
pub fn ancestors(pid: u32) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(mut cur) = info(pid) else {
        return out;
    };
    while out.len() < MAX_ANCESTORS && cur.ppid > 1 {
        let Ok(p) = info(cur.ppid) else { break };
        if p.id.start > cur.id.start {
            break;
        }
        let Some(x) = exe_path(p.id.pid) else { break };
        out.push(x);
        cur = p;
    }
    out
}

/// Source, host and root executable (cleaned) of a lease rooted at `root_pid`. For a
/// human-started lease the root is `smith` itself and the agent is not spawned yet, so the
/// source comes from the first word of the agent `command` the human typed.
pub fn detect(
    root_pid: u32,
    human_command: Option<&str>,
) -> (SessionSource, Option<String>, String) {
    let exe = exe_path(root_pid);
    let root_exe = exe
        .as_ref()
        .map(|p| clean(&p.to_string_lossy(), MAX_PATH))
        .unwrap_or_default();
    let anc = ancestors(root_pid);
    let (source, host) = match human_command {
        Some(cmd) => {
            let first = cmd.split_whitespace().next().map(PathBuf::from);
            classify(first.as_deref(), &anc)
        }
        None => classify(exe.as_deref(), &anc),
    };
    (source, host, root_exe)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(root: &str) -> (SourceKind, String) {
        let (s, _) = classify(Some(Path::new(root)), &[]);
        (s.kind, s.label)
    }

    #[test]
    fn agent_table() {
        for (path, want) in [
            ("/Users/a/.local/bin/claude", ClaudeCodeCli),
            ("/opt/homebrew/bin/codex", Codex),
            ("/usr/local/bin/cursor-agent", Cursor),
            ("/usr/bin/grok", Grok),
            ("/usr/bin/gemini", GeminiCli),
            ("/home/a/.local/bin/aider", Aider),
            ("/usr/bin/windsurf", Windsurf),
            ("/usr/bin/copilot", Copilot),
            ("/usr/bin/opencode", Opencode),
            ("/usr/bin/code", Vscode),
            (
                "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper",
                ClaudeDesktopApp,
            ),
            (
                "/Users/a/Applications/Claude.app/Contents/MacOS/Claude",
                ClaudeDesktopApp,
            ),
            // Claude Code as the desktop app ships it (seen live on macOS).
            (
                "/Users/a/Library/Application Support/Claude/claude-code/2.1.325/485fdac4332e/claude.app/Contents/MacOS/claude",
                ClaudeDesktopApp,
            ),
            (
                "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Plugin).app/Contents/MacOS/Cursor Helper (Plugin)",
                Cursor,
            ),
            (
                "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)",
                Vscode,
            ),
            (
                "/Users/a/Applications/IntelliJ IDEA Ultimate.app/Contents/MacOS/idea",
                Jetbrains,
            ),
            (
                "/Applications/Windsurf.app/Contents/MacOS/Electron",
                Windsurf,
            ),
        ] {
            assert_eq!(kind(path).0, want, "{path}");
        }
    }

    #[test]
    fn unknown_and_renamed_binaries_are_shown_honestly() {
        // Near misses are not fuzzy-matched.
        assert_eq!(
            kind("/usr/local/bin/my-claude"),
            (Other, "my-claude".into())
        );
        assert_eq!(kind("/usr/bin/node"), (Other, "node".into()));
        assert_eq!(kind("/tmp/Claude"), (Other, "Claude".into()));
        // A bundle not directly in an Applications directory is not the app.
        assert_eq!(kind("/tmp/Claude.app/Contents/MacOS/Claude").0, Other);
        // Spaces survive; control characters do not reach the label.
        assert_eq!(
            kind("/Users/a/My Tools/agent runner"),
            (Other, "agent runner".into())
        );
        assert_eq!(kind("/x/evil\x1b[2Jname"), (Other, "evil[2Jname".into()));
        assert_eq!(kind(&format!("/x/{}", "a".repeat(200))).1.len(), MAX_LABEL);
        assert_eq!(classify(None, &[]).0.kind, Unknown);
        assert_eq!(classify(Some(Path::new("/")), &[]).0.kind, Unknown);
    }

    #[test]
    fn host_from_nearest_known_ancestor_never_the_source() {
        let a = |v: &[&str]| v.iter().map(PathBuf::from).collect::<Vec<_>>();
        let root = Path::new("/Users/a/.local/bin/claude");
        let (s, h) = classify(
            Some(root),
            &a(&[
                "/bin/zsh",
                "/usr/bin/login",
                "/Applications/iTerm.app/Contents/MacOS/iTerm2",
            ]),
        );
        assert_eq!((s.kind, h.as_deref()), (ClaudeCodeCli, Some("iTerm2")));
        let (_, h) = classify(
            Some(root),
            &a(&[
                "/bin/zsh",
                "/opt/homebrew/bin/tmux",
                "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
            ]),
        );
        assert_eq!(h.as_deref(), Some("tmux"));
        let (_, h) = classify(
            Some(root),
            &a(&["/bin/zsh", "/Applications/Warp.app/Contents/MacOS/stable"]),
        );
        assert_eq!(h.as_deref(), Some("Warp"));
        // Unknown parents: no host, and a terminal never becomes the source.
        let (s, h) = classify(Some(Path::new("/bin/zsh")), &a(&["/bin/launchd-ish"]));
        assert_eq!((s.kind, h), (Other, None));
        // The app as its own host is not repeated.
        let (s, h) = classify(
            Some(Path::new("/Applications/Cursor.app/Contents/MacOS/Cursor")),
            &a(&["/Applications/Cursor.app/Contents/MacOS/Cursor"]),
        );
        assert_eq!((s.kind, h), (Cursor, None));
    }

    #[test]
    fn detect_reads_this_process_and_a_human_command() {
        let me = std::process::id();
        let (s, _, exe) = detect(me, None);
        assert!(!exe.is_empty(), "own exe readable");
        assert_ne!(s.kind, Unknown);
        let (s, _, _) = detect(me, Some("claude --resume"));
        assert_eq!(s.kind, ClaudeCodeCli);
        let (s, _, _) = detect(me, Some(""));
        assert_eq!(s.kind, Unknown);
    }
}
