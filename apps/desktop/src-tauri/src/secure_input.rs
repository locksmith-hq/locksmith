//! Native secure text input (task 1.2, design D1): the human types a secret into an OS
//! widget owned by the Rust side, never into the webview.
//!
//! Known limit: the toolkit keeps its own copy of the typed text (an `NSString` / GTK buffer)
//! until it frees it (on Windows, the edit control's buffer); we clear the field afterwards but
//! cannot zeroize toolkit memory.

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

/// Builds the in-memory DLGTEMPLATE for the Windows prompt. Pure (no Win32 calls) so its byte
/// layout is unit-tested on every OS; `cargo check` cannot catch a misplaced header word.
#[cfg(any(windows, test))]
mod dlgtemplate {
    pub const ID_EDIT: i32 = 100;
    const IDOK: u16 = 1;
    const IDCANCEL: u16 = 2;
    const ID_STATIC: u16 = 0xFFFF;
    // Window and dialog styles (winuser.h).
    const WS_POPUP: u32 = 0x8000_0000;
    const WS_CAPTION: u32 = 0x00C0_0000;
    const WS_SYSMENU: u32 = 0x0008_0000;
    const WS_CHILD: u32 = 0x4000_0000;
    const WS_VISIBLE: u32 = 0x1000_0000;
    const WS_TABSTOP: u32 = 0x0001_0000;
    const WS_BORDER: u32 = 0x0080_0000;
    const DS_MODALFRAME: u32 = 0x80;
    const DS_CENTER: u32 = 0x0800;
    const ES_PASSWORD: u32 = 0x20;
    const ES_AUTOHSCROLL: u32 = 0x80;
    const BS_PUSHBUTTON: u32 = 0;
    const BS_DEFPUSHBUTTON: u32 = 1;
    // Dialog-template class atoms: button, edit, static.
    const BUTTON: u16 = 0x0080;
    const EDIT: u16 = 0x0081;
    const STATIC: u16 = 0x0082;

    fn wide(s: &str) -> Vec<u16> {
        s.chars()
            .filter(|c| *c != '\0')
            .collect::<String>()
            .encode_utf16()
            .chain(Some(0))
            .collect()
    }

    fn item(t: &mut Vec<u16>, style: u32, rect: [i16; 4], id: u16, class: u16, text: &str) {
        if t.len() % 2 == 1 {
            t.push(0); // each DLGITEMTEMPLATE starts on a DWORD boundary
        }
        t.extend([style as u16, (style >> 16) as u16, 0, 0]); // style, exstyle
        t.extend(rect.map(|v| v as u16));
        t.extend([id, 0xFFFF, class]);
        t.extend(wide(text));
        t.push(0); // no creation data
    }

    /// DLGTEMPLATE: style (DWORD), exstyle (DWORD), cdit, x, y, cx, cy, menu, class, title; then
    /// the message, a password edit, OK and Cancel.
    pub fn template(title: &str, message: &str) -> Vec<u16> {
        let style = DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU;
        let mut t: Vec<u16> = vec![style as u16, (style >> 16) as u16, 0, 0];
        t.push(4); // cdit: item count
        t.extend([0, 0, 220, 78]); // x, y, cx, cy
        t.extend([0, 0]); // no menu, default class
        t.extend(wide(title));
        let vis = WS_CHILD | WS_VISIBLE;
        item(&mut t, vis, [8, 8, 204, 16], ID_STATIC, STATIC, message);
        let edit = vis | WS_TABSTOP | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL;
        item(&mut t, edit, [8, 28, 204, 14], ID_EDIT as u16, EDIT, "");
        let ok = vis | WS_TABSTOP | BS_DEFPUSHBUTTON;
        item(&mut t, ok, [100, 56, 50, 14], IDOK, BUTTON, "OK");
        let cancel = vis | WS_TABSTOP | BS_PUSHBUTTON;
        item(
            &mut t,
            cancel,
            [160, 56, 50, 14],
            IDCANCEL,
            BUTTON,
            "Cancel",
        );
        t
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn header_is_laid_out_as_dlgtemplate() {
            let t = template("Unlock", "Passphrase");
            let style = u32::from(t[0]) | u32::from(t[1]) << 16;
            assert_eq!(style & WS_POPUP, WS_POPUP);
            assert_eq!((t[2], t[3]), (0, 0), "no extended style");
            assert_eq!(t[4], 4, "cdit");
            assert_eq!(&t[5..9], &[0, 0, 220, 78], "x y cx cy");
            assert_eq!((t[9], t[10]), (0, 0), "no menu, default class");
            let title: Vec<u16> = "Unlock".encode_utf16().chain(Some(0)).collect();
            assert_eq!(&t[11..11 + title.len()], &title[..]);
        }

        #[test]
        fn items_are_dword_aligned_and_counted() {
            let t = template("Unlock", "Passphrase");
            let mut i = 11 + "Unlock".len() + 1;
            for (class, text) in [
                (STATIC, "Passphrase"),
                (EDIT, ""),
                (BUTTON, "OK"),
                (BUTTON, "Cancel"),
            ] {
                i += i % 2; // DWORD boundary
                assert_eq!(t[i + 9], 0xFFFF, "class marker");
                assert_eq!(t[i + 10], class);
                let want: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
                assert_eq!(&t[i + 11..i + 11 + want.len()], &want[..]);
                i += 11 + want.len() + 1; // header, text, creation-data word
            }
            assert_eq!(i, t.len(), "exactly four items, nothing trailing");
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)] // Win32 dialog calls only
mod platform {
    use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DialogBoxIndirectParamW, EndDialog, GetDlgItem, GetWindowTextLengthW, GetWindowTextW,
        IDCANCEL, IDOK, SetForegroundWindow, SetWindowTextW, WM_COMMAND, WM_INITDIALOG,
    };
    use zeroize::{Zeroize, Zeroizing};

    use super::dlgtemplate::{ID_EDIT, template};

    unsafe extern "system" fn proc(h: HWND, msg: u32, w: WPARAM, _l: LPARAM) -> isize {
        match msg {
            WM_INITDIALOG => {
                unsafe { SetForegroundWindow(h) };
                // Returning 1 lets the dialog manager focus the first tab stop (the edit).
                1
            }
            WM_COMMAND => {
                let id = (w & 0xFFFF) as i32;
                if id == IDOK || id == IDCANCEL {
                    let result = if id == IDOK { read_edit(h) } else { 0 };
                    unsafe { EndDialog(h, result) };
                    1
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    thread_local! {
        static ANSWER: std::cell::RefCell<Option<Zeroizing<String>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Copy the edit text into `ANSWER`, wipe the control, return 1 (empty input is filtered by `NativePrompt::ask`).
    fn read_edit(dlg: HWND) -> isize {
        unsafe {
            let edit = GetDlgItem(dlg, ID_EDIT);
            let n = GetWindowTextLengthW(edit).max(0) as usize;
            let mut buf = vec![0u16; n + 1];
            let got = GetWindowTextW(edit, buf.as_mut_ptr(), buf.len() as i32).max(0) as usize;
            let mut text = Zeroizing::new(String::with_capacity(got * 3)); // no regrowth copies
            text.extend(
                char::decode_utf16(buf[..got].iter().copied()).map(|c| c.unwrap_or('\u{FFFD}')),
            );
            buf.zeroize();
            let empty: [u16; 1] = [0];
            SetWindowTextW(edit, empty.as_ptr());
            ANSWER.with(|a| *a.borrow_mut() = Some(text));
        }
        1
    }

    pub fn ask(title: &str, message: &str) -> Option<Zeroizing<String>> {
        let tpl = template(title, message);
        ANSWER.with(|a| *a.borrow_mut() = None);
        // SAFETY: `tpl` is a well-formed DLGTEMPLATE (unit-tested layout; the Windows allocator
        // gives >= 8-byte alignment) that outlives the modal call; `proc` matches
        // DLGPROC. A null parent makes the dialog top-level.
        let r = unsafe {
            DialogBoxIndirectParamW(
                GetModuleHandleW(std::ptr::null()),
                tpl.as_ptr().cast(),
                std::ptr::null_mut(),
                Some(proc),
                0,
            )
        };
        let v = ANSWER.with(|a| a.borrow_mut().take());
        if r == 1 { v } else { None }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod platform {
    use zeroize::Zeroizing;

    pub fn ask(_: &str, _: &str) -> Option<Zeroizing<String>> {
        None
    }
}
