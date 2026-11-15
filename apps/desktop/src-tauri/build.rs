use tauri_build::{AppManifest, Attributes};

/// Every command the webview may invoke. Each gets an `allow-<name>` permission, and
/// `capabilities/default.json` lists exactly these (design D1).
const COMMANDS: &[&str] = &[
    "status",
    "lock",
    "unlock_secure",
    "revoke",
    "audit_list",
    "audit_verify",
    "key_names",
    "put_secret_secure",
    "token_list",
    "token_revoke",
    "relay_info",
];

fn main() {
    // `generate_context!` embeds `../dist`. Rust-only builds (cargo test/clippy in CI) run
    // before or without the UI build, so give them a placeholder; `dist/` is gitignored and
    // `vite build` replaces it.
    let dist = std::path::Path::new("../dist");
    if !dist.join("index.html").exists() {
        std::fs::create_dir_all(dist).expect("create ../dist");
        std::fs::write(
            dist.join("index.html"),
            "<!doctype html><title>Locksmith</title><p>UI not built: run npm run build in apps/desktop.</p>\n",
        )
        .expect("write ../dist/index.html");
    }
    tauri_build::try_build(Attributes::new().app_manifest(AppManifest::new().commands(COMMANDS)))
        .expect("tauri build script");
}
