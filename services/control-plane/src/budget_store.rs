//! The daily call counter behind agent budgets (T9). One atomic upsert per lease.

use sqlx_core::row::Row;
use uuid::Uuid;

use crate::api::internal::BudgetLease;
use crate::db::sql::{self, PgConnection};

/// Lease up to `count` calls from today's (UTC) budget of `limit`: raise the counter by
/// `min(count, max(limit - used, 0))` in one `INSERT ... ON CONFLICT DO UPDATE ... RETURNING`.
/// The conflicting row is locked by the upsert and re-read under it, so concurrent leases are
/// serialised and the total never passes `limit`. `limit` and `count` are at least 1.
pub async fn lease(
    c: &mut PgConnection,
    org_id: Uuid,
    agent_id: Uuid,
    grant_id: Option<Uuid>,
    limit: i32,
    count: i32,
) -> sql::Result<BudgetLease> {
    let row = sql::query(
        "INSERT INTO agent_budget_usage AS u (org_id, agent_id, grant_id, day, used, last_granted) \
         VALUES ($1, $2, $3, (now() AT TIME ZONE 'utc')::date, LEAST($5, $4), LEAST($5, $4)) \
         ON CONFLICT (org_id, agent_id, (COALESCE(grant_id, '00000000-0000-0000-0000-000000000000'::uuid)), day) \
         DO UPDATE SET \
             used = u.used + LEAST($5, GREATEST($4 - u.used, 0)), \
             last_granted = LEAST($5, GREATEST($4 - u.used, 0)), \
             updated_at = now() \
         RETURNING last_granted, used, day::text AS day",
    )
    .bind(org_id)
    .bind(agent_id)
    .bind(grant_id)
    .bind(limit)
    .bind(count)
    .fetch_one(c)
    .await?;
    Ok(BudgetLease {
        granted: row.try_get("last_granted")?,
        used: row.try_get("used")?,
        day: row.try_get("day")?,
    })
}
