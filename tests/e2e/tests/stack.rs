//! Smoke e2e: F0 Postgres answers, and the WireMock journal records a request we make.
//! Requires `just up`. Dev-only credentials come from infra/compose/.env.example.

use std::env;

fn pg_conn_str() -> String {
    let host = env::var("E2E_PG_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let user = env::var("E2E_PG_USER").unwrap_or_else(|_| "locksmith".into());
    let pass = env::var("E2E_PG_PASSWORD").unwrap_or_else(|_| "locksmith-dev-only".into());
    let db = env::var("E2E_PG_DB").unwrap_or_else(|_| "locksmith".into());
    format!("host={host} user={user} password={pass} dbname={db}")
}

fn wiremock_url() -> String {
    env::var("E2E_WIREMOCK_URL").unwrap_or_else(|_| "http://127.0.0.1:8089".into())
}

#[tokio::test]
async fn postgres_is_reachable() {
    let (client, conn) = tokio_postgres::connect(&pg_conn_str(), tokio_postgres::NoTls)
        .await
        .expect("connect to F0 Postgres (is `just up` running?)");
    tokio::spawn(conn);
    let row = client.query_one("SELECT 1::int4", &[]).await.unwrap();
    assert_eq!(row.get::<_, i32>(0), 1);
}

#[tokio::test]
async fn wiremock_journal_records_request() {
    let base = wiremock_url();
    let http = reqwest::Client::new();
    let path = format!("/e2e-probe-{}", std::process::id());

    http.get(format!("{base}/__admin/health"))
        .send()
        .await
        .expect("reach WireMock (is `just up` running?)");
    // The response status is irrelevant (unstubbed => 404); the journal must still record it.
    http.get(format!("{base}{path}")).send().await.unwrap();

    let journal: serde_json::Value = http
        .get(format!("{base}/__admin/requests"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let urls: Vec<&str> = journal["requests"]
        .as_array()
        .expect("journal has requests array")
        .iter()
        .filter_map(|r| r["request"]["url"].as_str())
        .collect();
    assert!(
        urls.contains(&path.as_str()),
        "journal missing {path}: {urls:?}"
    );
}
