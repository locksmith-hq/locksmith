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

/// T1 task 3.1 (A0-4): every table the control-plane migrations create has RLS enabled, forced
/// and a policy, so `users` (and any later table) cannot ship readable without a tenant bound.
#[test]
fn migrations_enable_force_and_police_every_table() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let findings = ls_tenant_lint::scan_migrations(&dir).expect("scan migrations");
    let report: Vec<String> = findings
        .iter()
        .map(|f| format!("table `{}`: {}", f.table, f.rule))
        .collect();
    assert!(report.is_empty(), "RLS missing:\n{}", report.join("\n"));
    let users = std::fs::read_to_string(dir.join("0011_users.sql")).expect("0011_users.sql");
    assert!(
        users.contains("CREATE TABLE users"),
        "the lint must see the users table"
    );
}

/// M1 task 1.4: the MCP tables are org-scoped and policed, and the lint sees them.
#[test]
fn mcp_tables_are_seen_by_the_migration_lint() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mcp = std::fs::read_to_string(dir.join("0012_mcp.sql")).expect("0012_mcp.sql");
    for table in ["mcp_tool_settings", "mcp_clients"] {
        assert!(mcp.contains(&format!("CREATE TABLE {table}")), "{table}");
        assert!(
            mcp.contains(&format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY")),
            "{table}"
        );
    }
}

/// T6 task 2.2: the membership tables are org-scoped, forced and policed, and the lint sees them.
#[test]
fn membership_tables_are_seen_by_the_migration_lint() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let sql = std::fs::read_to_string(dir.join("0016_memberships.sql")).expect("0016");
    for table in ["memberships", "invites"] {
        assert!(sql.contains(&format!("CREATE TABLE {table}")), "{table}");
        assert!(
            sql.contains(&format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY")),
            "{table}"
        );
        assert!(sql.contains(&format!("ON {table}")), "{table} has a policy");
    }
    let findings = ls_tenant_lint::scan_migrations(&dir).expect("scan migrations");
    assert!(
        findings
            .iter()
            .all(|f| f.table != "memberships" && f.table != "invites"),
        "{findings:?}"
    );
}
