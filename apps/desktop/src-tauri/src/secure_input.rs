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

#[cfg(windows)]
#[allow(unsafe_code)] // Win32 dialog calls only
mod platform {
    use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        BS_DEFPUSHBUTTON, BS_PUSHBUTTON, DS_CENTER, DS_MODALFRAME, DialogBoxIndirectParamW,
        EndDialog, ES_AUTOHSCROLL, ES_PASSWORD, GetDlgItem, GetWindowTextLengthW, GetWindowTextW,
        IDCANCEL, IDOK, SetForegroundWindow, SetWindowTextW, WM_COMMAND, WM_INITDIALOG, WS_BORDER,
        WS_CAPTION, WS_CHILD, WS_POPUP, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
    };
    use zeroize::{Zeroize, Zeroizing};

    const ID_EDIT: i32 = 100;
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

    /// An in-memory DLGTEMPLATE: message, a password edit, OK and Cancel.
    fn template(title: &str, message: &str) -> Vec<u16> {
        let style = DS_MODALFRAME as u32 | DS_CENTER as u32 | WS_POPUP | WS_CAPTION | WS_SYSMENU;
        let mut t: Vec<u16> = vec![style as u16, (style >> 16) as u16, 0, 0, 4, 0];
        t.extend([0, 0, 220, 78]); // x, y, cx, cy
        t.extend([0, 0]); // no menu, default class
        t.extend(wide(title));
        let vis = WS_CHILD | WS_VISIBLE;
        item(&mut t, vis, [8, 8, 204, 16], 0xFFFF, STATIC, message);
        let edit = vis | WS_TABSTOP | WS_BORDER | ES_PASSWORD as u32 | ES_AUTOHSCROLL as u32;
        item(&mut t, edit, [8, 28, 204, 14], ID_EDIT as u16, EDIT, "");
        let ok = vis | WS_TABSTOP | BS_DEFPUSHBUTTON as u32;
        item(&mut t, ok, [100, 56, 50, 14], IDOK as u16, BUTTON, "OK");
        let cancel = vis | WS_TABSTOP | BS_PUSHBUTTON as u32;
        item(&mut t, cancel, [160, 56, 50, 14], IDCANCEL as u16, BUTTON, "Cancel");
        t[4] = 4; // item count
        t
    }

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

    /// Copy the edit text into `ANSWER`, wipe the control, return 1 (or 0 when empty).
    fn read_edit(dlg: HWND) -> isize {
        unsafe {
            let edit = GetDlgItem(dlg, ID_EDIT);
            let n = GetWindowTextLengthW(edit).max(0) as usize;
            let mut buf = vec![0u16; n + 1];
            let got = GetWindowTextW(edit, buf.as_mut_ptr(), buf.len() as i32).max(0) as usize;
            let text = Zeroizing::new(String::from_utf16_lossy(&buf[..got]));
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
        // SAFETY: `tpl` is a well-formed DLGTEMPLATE that outlives the modal call; `proc` matches
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
