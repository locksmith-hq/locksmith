//! Task 2.3: fails if a session-level `SET app.*` or `set_config(..., false)` appears in
//! non-test Rust code anywhere in the repository.

use std::path::Path;

#[test]
fn no_session_level_tenant_settings_in_non_test_code() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let root = root.canonicalize().expect("repo root");
    assert!(
        root.join("AGENTS.md").is_file(),
        "not the repo root: {root:?}"
    );
    let findings = a0_spikes::tenant_lint::scan_tree(&root).expect("scan repository");
    let report: Vec<String> = findings
        .iter()
        .map(|f| format!("{}:{}: {}", f.path.display(), f.line, f.rule))
        .collect();
    assert!(
        report.is_empty(),
        "tenant context must be transaction-local (set_config('app.org_id', $1, true)); found:\n{}",
        report.join("\n")
    );
}
