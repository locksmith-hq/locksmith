//! Menu-bar / tray icon (task 2.1): lock state, active sessions, revoke all, lock, open.
//! [`model`] and [`glyph`] are pure; [`setup`] turns them into a Tauri menu and a template icon
//! and refreshes both from `Status`.

use crate::daemon::{Daemon, Result};
use ls_ipc::desktop::{CommandErrorCode, StatusView};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{App, AppHandle, Manager, Runtime};

const REFRESH: Duration = Duration::from_secs(3);
const MAX_COMMAND: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// Disabled text line.
    Label(String),
    Action {
        id: &'static str,
        text: String,
    },
    Separator,
}

fn expiry(secs: i64) -> String {
    match secs {
        ..=0 => "expiring".into(),
        1..60 => format!("expires in {secs}s"),
        60..3600 => format!("expires in {}m", secs / 60),
        _ => format!("expires in {}h {}m", secs / 3600, secs % 3600 / 60),
    }
}

fn short(s: &str) -> String {
    match s.char_indices().nth(MAX_COMMAND) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_string(),
    }
}

/// Menu-bar glyph: the shear-line mark split (open) or whole (locked).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Glyph {
    Locked,
    Unlocked,
}

impl Glyph {
    /// 36 px (@2x of the 18 px grid in src-tauri/icons/source/tray-*.svg); the menu bar draws it at 18 pt.
    fn png(self) -> &'static [u8] {
        match self {
            Glyph::Locked => include_bytes!("../icons/tray/locked@2x.png"),
            Glyph::Unlocked => include_bytes!("../icons/tray/unlocked@2x.png"),
        }
    }

    fn image(self) -> tauri::Result<Image<'static>> {
        Image::from_bytes(self.png())
    }
}

/// Only a reachable, unlocked vault shows the open glyph; a daemon error never looks open.
pub fn glyph(status: &Result<StatusView>) -> Glyph {
    match status {
        Ok(s) if !s.locked => Glyph::Unlocked,
        _ => Glyph::Locked,
    }
}

/// The tray menu for a `Status` result at unix time `now`.
pub fn model(status: &Result<StatusView>, now: i64) -> Vec<Item> {
    let action = |id, text: &str| Item::Action {
        id,
        text: text.into(),
    };
    let mut m = Vec::new();
    match status {
        Err(e) if e.code == CommandErrorCode::Unavailable => {
            m.push(Item::Label("Daemon not running".into()))
        }
        Err(e) => m.push(Item::Label(format!("Daemon: {}", short(&e.message)))),
        Ok(s) => {
            m.push(Item::Label(
                if s.locked { "Locked" } else { "Unlocked" }.into(),
            ));
            m.push(Item::Separator);
            if s.leases.is_empty() {
                m.push(Item::Label("No active sessions".into()));
            }
            for l in &s.leases {
                m.push(Item::Label(format!(
                    "{}  {}  {}",
                    l.id,
                    short(&l.command),
                    expiry(l.expires_at - now)
                )));
            }
            if !s.leases.is_empty() || !s.locked {
                m.push(Item::Separator);
            }
            if !s.leases.is_empty() {
                m.push(action("revoke_all", "Revoke all sessions"));
            }
            if !s.locked {
                m.push(action("lock", "Lock"));
            }
        }
    }
    m.push(Item::Separator);
    m.push(action("open", "Open Locksmith"));
    m.push(action("quit", "Quit"));
    m
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn build_menu<R: Runtime>(app: &AppHandle<R>, items: &[Item]) -> tauri::Result<Menu<R>> {
    let menu = Menu::new(app)?;
    for i in items {
        match i {
            Item::Label(t) => menu.append(&MenuItem::new(app, t, false, None::<&str>)?)?,
            Item::Action { id, text } => {
                menu.append(&MenuItem::with_id(app, *id, text, true, None::<&str>)?)?
            }
            Item::Separator => menu.append(&PredefinedMenuItem::separator(app)?)?,
        }
    }
    Ok(menu)
}

fn on_menu<R: Runtime>(app: &AppHandle<R>, id: &str) {
    match id {
        // Off the main thread: daemon calls block.
        "revoke_all" => drop(std::thread::spawn(|| Daemon::default().revoke(None))),
        "lock" => drop(std::thread::spawn(|| Daemon::default().lock())),
        "open" => {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }
        }
        "quit" => app.exit(0),
        _ => {}
    }
}

pub fn setup(app: &App) -> tauri::Result<()> {
    let handle = app.handle().clone();
    let status = Daemon::default().status();
    let mut shown = glyph(&status);
    let tray = TrayIconBuilder::with_id("main")
        .tooltip("Locksmith")
        .icon(shown.image()?)
        .icon_as_template(true)
        .menu(&build_menu(&handle, &model(&status, now()))?)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, e| on_menu(app, e.id().as_ref()))
        .build(app)?;
    std::thread::spawn(move || {
        let mut last = None;
        loop {
            std::thread::sleep(REFRESH);
            let status = Daemon::default().status();
            let g = glyph(&status);
            if g != shown {
                if let Ok(img) = g.image() {
                    let _ = tray.set_icon(Some(img));
                    let _ = tray.set_icon_as_template(true);
                }
                shown = g;
            }
            let m = model(&status, now());
            if last.as_ref() != Some(&m) {
                if let Ok(menu) = build_menu(&handle, &m) {
                    let _ = tray.set_menu(Some(menu));
                }
                last = Some(m);
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ls_ipc::LeaseInfo;
    use ls_ipc::desktop::CommandError;

    fn lease(id: &str, command: &str, expires_at: i64) -> LeaseInfo {
        LeaseInfo {
            id: id.into(),
            root_pid: 1,
            command: command.into(),
            project: "p".into(),
            env: "dev".into(),
            scopes: vec!["run".into()],
            created_at: 0,
            expires_at,
            state: "active".into(),
            root_exe: String::new(),
            started_by: Default::default(),
            source: Default::default(),
            host: None,
            report: None,
            inject: None,
        }
    }

    fn texts(m: &[Item]) -> Vec<String> {
        m.iter()
            .map(|i| match i {
                Item::Label(t) => t.clone(),
                Item::Action { id, .. } => format!("[{id}]"),
                Item::Separator => "-".into(),
            })
            .collect()
    }

    #[test]
    fn unlocked_with_sessions() {
        let s = Ok(StatusView {
            locked: false,
            leases: vec![
                lease("s1", "claude", 1000 + 25 * 60),
                lease("s2", &"x".repeat(60), 1000 + 2 * 3600 + 5 * 60),
            ],
        });
        assert_eq!(
            texts(&model(&s, 1000)),
            [
                "Unlocked".to_string(),
                "-".into(),
                "s1  claude  expires in 25m".into(),
                format!("s2  {}…  expires in 2h 5m", "x".repeat(40)),
                "-".into(),
                "[revoke_all]".into(),
                "[lock]".into(),
                "-".into(),
                "[open]".into(),
                "[quit]".into(),
            ]
        );
    }

    #[test]
    fn locked_without_sessions_offers_no_lock_or_revoke() {
        let s = Ok(StatusView {
            locked: true,
            leases: vec![],
        });
        assert_eq!(
            texts(&model(&s, 0)),
            ["Locked", "-", "No active sessions", "-", "[open]", "[quit]"]
        );
    }

    #[test]
    fn glyph_is_open_only_when_reachable_and_unlocked() {
        let open = Ok(StatusView {
            locked: false,
            leases: vec![],
        });
        let shut = Ok(StatusView {
            locked: true,
            leases: vec![],
        });
        let down = Err(CommandError {
            code: CommandErrorCode::Unavailable,
            message: "cannot reach".into(),
        });
        assert_eq!(glyph(&open), Glyph::Unlocked);
        assert_eq!(glyph(&shut), Glyph::Locked);
        assert_eq!(glyph(&down), Glyph::Locked);
        // The embedded glyphs decode as images.
        assert!(Glyph::Locked.image().is_ok() && Glyph::Unlocked.image().is_ok());
    }

    #[test]
    fn daemon_errors() {
        let down = Err(CommandError {
            code: CommandErrorCode::Unavailable,
            message: "cannot reach".into(),
        });
        assert_eq!(texts(&model(&down, 0))[0], "Daemon not running");
        let denied = Err(CommandError {
            code: CommandErrorCode::Denied,
            message: "caller is not an attested Locksmith binary".into(),
        });
        assert_eq!(
            texts(&model(&denied, 0))[0],
            "Daemon: caller is not an attested Locksmith bina…"
        );
        assert_eq!(expiry(-5), "expiring");
        assert_eq!(expiry(59), "expires in 59s");
    }
}
