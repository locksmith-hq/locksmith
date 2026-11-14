//! Screen-lock and sleep notifications for auto-lock (design D5, with the deviation recorded
//! there: macOS polls the session dictionary instead of an NSWorkspace observer).
//!
//! [`watch`] calls `on_event` with "screen_lock" or (Linux) "sleep" from a background thread.
//! The daemon also detects sleep itself on every OS (wall clock jumping ahead of monotonic).
//! Spurious events only cause an early lock, so the sources need not be authenticated.

use std::io;

/// Start watching. Returns once the watcher threads are running.
pub fn watch(on_event: impl Fn(&'static str) + Send + Sync + 'static) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    return macos::watch(on_event);
    #[cfg(target_os = "linux")]
    return linux::watch(on_event);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = on_event;
        Err(io::Error::other("screen-lock watching is not supported"))
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::string::CFString;

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    }

    /// `Some(true)` while the login session's screen is locked; `None` outside a GUI session.
    pub fn screen_locked() -> Option<bool> {
        // SAFETY: CGSessionCopyCurrentDictionary takes no arguments and returns either null or
        // a +1 retained CFDictionary, which wrap_under_create_rule takes ownership of.
        let d = unsafe {
            let r = CGSessionCopyCurrentDictionary();
            if r.is_null() {
                return None;
            }
            CFDictionary::<CFString, CFType>::wrap_under_create_rule(r)
        };
        Some(d.contains_key(&CFString::from_static_string("CGSSessionScreenIsLocked")))
    }

    pub fn watch(on_event: impl Fn(&'static str) + Send + Sync + 'static) -> std::io::Result<()> {
        // shortcut: 1 s polling meets the 2 s spec bound; switch to NSWorkspace notifications
        // (objc2) if polling cost ever matters.
        super::poll(screen_locked, on_event);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use futures_lite::StreamExt;
    use std::sync::Arc;
    use zbus::{Connection, MatchRule, MessageStream, message::Type};

    /// logind `Session.Lock` and `Manager.PrepareForSleep(true)` on the system bus
    /// (`DBUS_SYSTEM_BUS_ADDRESS` is honoured, which the test uses). zbus 6 has no blocking API,
    /// so each subscription runs on its own thread under zbus's built-in `block_on` runtime.
    pub fn watch(on_event: impl Fn(&'static str) + Send + Sync + 'static) -> std::io::Result<()> {
        let err = |e: zbus::Error| std::io::Error::other(e.to_string());
        let conn = zbus::block_on(Connection::system()).map_err(err)?;
        let on_event = Arc::new(on_event);
        let subs = [
            ("org.freedesktop.login1.Session", "Lock", "screen_lock"),
            ("org.freedesktop.login1.Manager", "PrepareForSleep", "sleep"),
        ];
        for (iface, member, reason) in subs {
            let rule = MatchRule::builder()
                .msg_type(Type::Signal)
                .interface(iface)
                .member(member)
                .build()
                .map_err(err)?;
            let mut stream =
                zbus::block_on(MessageStream::for_match_rule(rule, &conn, None)).map_err(err)?;
            let (cb, conn) = (on_event.clone(), conn.clone());
            std::thread::spawn(move || {
                let _keep = conn;
                zbus::block_on(async move {
                    while let Some(m) = stream.next().await {
                        let Ok(m) = m else { continue };
                        // PrepareForSleep(false) is the resume notification: ignore it.
                        if member == "PrepareForSleep"
                            && m.body().deserialize::<bool>().ok() != Some(true)
                        {
                            continue;
                        }
                        cb(reason);
                    }
                });
            });
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use std::process::{Command, Stdio};
        use std::sync::mpsc;
        use std::time::Duration;

        /// Fakes logind on a private bus: start dbus-daemon, emit the signals, expect callbacks.
        #[test]
        fn fake_logind_signals_trigger_lock() {
            let Ok(mut bus) = Command::new("dbus-daemon")
                .args(["--session", "--nofork", "--print-address"])
                .stdout(Stdio::piped())
                .spawn()
            else {
                eprintln!("dbus-daemon not installed; skipping");
                return;
            };
            let mut addr = String::new();
            std::io::BufRead::read_line(
                &mut std::io::BufReader::new(bus.stdout.take().unwrap()),
                &mut addr,
            )
            .unwrap();
            let addr = addr.trim().to_string();
            // SAFETY: only this test reads DBUS_SYSTEM_BUS_ADDRESS; set before watch() connects.
            unsafe { std::env::set_var("DBUS_SYSTEM_BUS_ADDRESS", &addr) };
            let (tx, rx) = mpsc::channel();
            let tx = std::sync::Mutex::new(tx);
            super::watch(move |r| {
                let _ = tx.lock().unwrap().send(r);
            })
            .unwrap();
            let send = |path: &str, sig: &str, args: &[&str]| {
                let st = Command::new("dbus-send")
                    .args([&format!("--bus={addr}"), "--type=signal", path, sig])
                    .args(args)
                    .status()
                    .unwrap();
                assert!(st.success());
            };
            send(
                "/org/freedesktop/login1/session/auto",
                "org.freedesktop.login1.Session.Lock",
                &[],
            );
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                "screen_lock"
            );
            let sleep = "org.freedesktop.login1.Manager.PrepareForSleep";
            send("/org/freedesktop/login1", sleep, &["boolean:false"]);
            send("/org/freedesktop/login1", sleep, &["boolean:true"]);
            assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), "sleep");
            assert!(
                rx.recv_timeout(Duration::from_millis(300)).is_err(),
                "resume ignored"
            );
            let _ = bus.kill();
        }
    }
}

/// Call `on_event("screen_lock")` on each unlocked → locked transition, checking every second.
#[cfg(target_os = "macos")]
fn poll(locked: fn() -> Option<bool>, on_event: impl Fn(&'static str) + Send + Sync + 'static) {
    std::thread::spawn(move || {
        let mut was = false;
        loop {
            let now = locked() == Some(true);
            if now && !was {
                on_event("screen_lock");
            }
            was = now;
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    });
}
