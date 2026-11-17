//! Task 2.3: the shared A0 tenant lint (`ls-tenant-lint`) covers `services/`: no session-level
//! `SET app.*` or `set_config(..., false)` in non-test service code.

use std::path::Path;

#[test]
fn services_have_no_session_level_tenant_settings() {
    let services = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .expect("services/ directory");
    assert!(services.ends_with("services"), "{services:?}");

    let files = ls_tenant_lint::scanned_files(&services).expect("list services/");
    assert!(
        files.iter().any(|f| f.ends_with("control-plane/src/db.rs")),
        "the lint must scan the tenant helper; scanned {files:?}"
    );

    let findings = ls_tenant_lint::scan_tree(&services).expect("scan services/");
    let report: Vec<String> = findings
        .iter()
        .map(|f| format!("services/{}:{}: {}", f.path.display(), f.line, f.rule))
        .collect();
    assert!(
        report.is_empty(),
        "tenant context must be transaction-local (Database::with_org); found:\n{}",
        report.join("\n")
    );
}

#[test]
fn lint_flags_a_session_level_setting_in_service_code() {
    let src = "async fn bad(c: &mut PgConnection) {\n    query(\"SELECT set_config('app.org_id', $1, false)\");\n}\n";
    assert_eq!(
        ls_tenant_lint::scan_source(src),
        vec![(2, ls_tenant_lint::RULE_SET_CONFIG_FALSE)]
    );
}
