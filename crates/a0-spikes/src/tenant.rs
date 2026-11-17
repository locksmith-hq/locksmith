//! Tenant context, set per transaction (design decision 5).
//!
//! The only supported way to scope queries to an org: the setting is transaction-local
//! (`is_local = true`), so it resets at COMMIT/ROLLBACK and cannot leak to the next checkout
//! of a pooled connection.

use crate::db::{self, PgPool, PgTransaction};
use uuid::Uuid;

/// Begin a transaction scoped to `org_id`. Every tenant query must run inside it.
pub async fn begin_for_org(pool: &PgPool, org_id: Uuid) -> db::Result<PgTransaction<'static>> {
    let mut tx = pool.begin().await?;
    db::query("SELECT set_config('app.org_id', $1, true)")
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}
