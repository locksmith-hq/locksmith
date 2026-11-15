//! Native secure text input (task 1.2, design D1): the human types a secret into an OS
//! widget owned by the Rust side, never into the webview.
//!
//! Known limit: the toolkit keeps its own copy of the typed text (an `NSString` / GTK buffer)
//! until it frees it; we clear the field afterwards but cannot zeroize toolkit memory.

use zeroize::Zeroizing;

pub trait SecurePrompt {
    /// Show a modal secure field. `None` when the user cancels (or leaves it empty).
    fn ask(&self, title: &str, message: &str) -> Option<Zeroizing<String>>;
}

/// The platform dialog. Must be called on the main (UI) thread; [`crate::OnMainThread`] wraps it
/// for command handlers that run elsewhere.
pub struct NativePrompt;

impl SecurePrompt for NativePrompt {
    fn ask(&self, title: &str, message: &str) -> Option<Zeroizing<String>> {
        platform::ask(title, message).filter(|v| !v.is_empty())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use objc2::{MainThreadMarker, MainThreadOnly};
    use objc2_app_kit::{NSAlert, NSAlertFirstButtonReturn, NSApplication, NSSecureTextField};
    use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};
    use zeroize::Zeroizing;

    pub fn ask(title: &str, message: &str) -> Option<Zeroizing<String>> {
        let mtm = MainThreadMarker::new()?; // off the main thread: refuse rather than crash
        let alert = NSAlert::new(mtm);
        alert.setMessageText(&NSString::from_str(title));
        alert.setInformativeText(&NSString::from_str(message));
        alert.addButtonWithTitle(&NSString::from_str("OK"));
        alert.addButtonWithTitle(&NSString::from_str("Cancel"));
        let frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(280.0, 24.0));
        let field = NSSecureTextField::initWithFrame(NSSecureTextField::alloc(mtm), frame);
        alert.setAccessoryView(Some(&field));
        alert.layout();
        alert.window().setInitialFirstResponder(Some(&field));
        NSApplication::sharedApplication(mtm).activate();
        let ok = alert.runModal() == NSAlertFirstButtonReturn;
        let v = ok.then(|| Zeroizing::new(field.stringValue().to_string()));
        field.setStringValue(&NSString::from_str(""));
        v
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)] // only `destroy`, which gtk-rs marks unsafe
mod platform {
    use gtk::prelude::*;
    use zeroize::Zeroizing;

    pub fn ask(title: &str, message: &str) -> Option<Zeroizing<String>> {
        if !gtk::is_initialized_main_thread() {
            return None;
        }
        let d = gtk::Dialog::with_buttons(
            Some(title),
            None::<&gtk::Window>,
            gtk::DialogFlags::MODAL,
            &[
                ("Cancel", gtk::ResponseType::Cancel),
                ("OK", gtk::ResponseType::Ok),
            ],
        );
        d.set_default_response(gtk::ResponseType::Ok);
        d.set_keep_above(true);
        let entry = gtk::Entry::builder()
            .visibility(false)
            .activates_default(true)
            .build();
        let area = d.content_area();
        area.set_spacing(8);
        area.add(&gtk::Label::new(Some(message)));
        area.add(&entry);
        d.show_all();
        let ok = d.run() == gtk::ResponseType::Ok;
        let v = ok.then(|| Zeroizing::new(entry.text().to_string()));
        entry.set_text("");
        // SAFETY: the dialog is ours, modal and finished; nothing uses it after this.
        unsafe { d.destroy() };
        v
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use zeroize::Zeroizing;

    // shortcut: no Windows dialog yet (Windows build is M16); every prompt reads as cancelled.
    pub fn ask(_: &str, _: &str) -> Option<Zeroizing<String>> {
        None
    }
}
