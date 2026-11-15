//! `locksmith-desktop` (M14): a thin, attested daemon client (design D2). The webview calls
//! the commands below; secret values are typed into native secure fields and sent from Rust
//! straight to `locksmithd`, so the webview only ever learns "submitted" (design D1).

// No console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod daemon;
mod secure_input;
mod tray;

use daemon::{Daemon, Result};
use ls_ipc::desktop::{
    AuditVerifyView, CommandError, CommandErrorCode, RelayInfo, SecureOutcome, StatusView,
};
use ls_ipc::{AuditEvent, HttpTokenInfo};
use secure_input::{NativePrompt, SecurePrompt};
use std::sync::mpsc;
use tauri::{AppHandle, WindowEvent};
use zeroize::Zeroizing;

/// Runs [`NativePrompt`] on the UI thread (AppKit and GTK require it) for a command handler
/// running on a worker thread, and waits for the answer.
struct OnMainThread(AppHandle);

impl SecurePrompt for OnMainThread {
    fn ask(&self, title: &str, message: &str) -> Option<Zeroizing<String>> {
        let (tx, rx) = mpsc::channel();
        let (title, message) = (title.to_string(), message.to_string());
        self.0
            .run_on_main_thread(move || {
                let _ = tx.send(NativePrompt.ask(&title, &message));
            })
            .ok()?;
        rx.recv().ok().flatten()
    }
}

/// Daemon calls block (Unlock runs the KDF); keep them off the UI thread.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| CommandError {
            code: CommandErrorCode::Internal,
            message: e.to_string(),
        })?
}

#[tauri::command]
async fn status() -> Result<StatusView> {
    blocking(|| Daemon::default().status()).await
}

#[tauri::command]
async fn lock() -> Result<()> {
    blocking(|| Daemon::default().lock()).await
}

#[tauri::command]
async fn unlock_secure(app: AppHandle) -> Result<SecureOutcome> {
    blocking(move || Daemon::default().unlock_secure(&OnMainThread(app))).await
}

#[tauri::command]
async fn revoke(id: Option<String>) -> Result<u32> {
    blocking(move || Daemon::default().revoke(id)).await
}

#[tauri::command]
async fn audit_list(limit: u32) -> Result<Vec<AuditEvent>> {
    blocking(move || Daemon::default().audit_list(limit)).await
}

#[tauri::command]
async fn audit_verify() -> Result<AuditVerifyView> {
    blocking(|| Daemon::default().audit_verify()).await
}

#[tauri::command]
async fn key_names(project: String, env: String) -> Result<Vec<String>> {
    blocking(move || Daemon::default().key_names(project, env)).await
}

#[tauri::command]
async fn put_secret_secure(
    app: AppHandle,
    project: String,
    env: String,
    name: String,
) -> Result<SecureOutcome> {
    blocking(move || Daemon::default().put_secret_secure(&OnMainThread(app), project, env, name))
        .await
}

#[tauri::command]
async fn token_list() -> Result<Vec<HttpTokenInfo>> {
    blocking(|| Daemon::default().token_list()).await
}

#[tauri::command]
async fn token_revoke(token: String) -> Result<u32> {
    blocking(move || Daemon::default().token_revoke(token)).await
}

#[tauri::command]
async fn relay_info() -> Result<RelayInfo> {
    blocking(|| Daemon::default().relay_info()).await
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            status,
            lock,
            unlock_secure,
            revoke,
            audit_list,
            audit_verify,
            key_names,
            put_secret_secure,
            token_list,
            token_revoke,
            relay_info
        ])
        .setup(|app| Ok(tray::setup(app)?))
        // Closing the window keeps the tray app running; "Quit" is in the tray menu.
        .on_window_event(|w, e| {
            if let WindowEvent::CloseRequested { api, .. } = e {
                let _ = w.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running Locksmith");
}
