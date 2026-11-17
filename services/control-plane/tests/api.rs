//! Tasks 3.1-3.5: the `/v1` resource API against a throwaway `postgres:18` container
//! (testcontainers; needs a Docker daemon). Each test starts its own container.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use ls_control_plane::app::{self, AppState};
use ls_control_plane::db::PoolSettings;
use ls_control_plane::migrate;
use ls_control_plane::readiness::ReadyFlag;
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use sqlx_core::query_scalar::query_scalar;
use tower::ServiceExt;
use uuid::Uuid;

const CANARY: &str = "CANARY-7f3a91c2-do-not-echo";

struct Api {
    app: Router,
    pg: common::Pg,
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Api {
    async fn start() -> Self {
        let pg = common::Pg::start().await;
        migrate::run(pg.bootstrap())
            .await
            .expect("migrations apply");
        let db = pg.app_db(PoolSettings::default());
        let state = AppState::new(true, Arc::new(ReadyFlag::new(true)), db);
        Self {
            app: app::build(state),
            pg,
        }
    }

    async fn call(&self, method: &str, uri: &str, org: Option<Uuid>, body: Option<Value>) -> Reply {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(o) = org {
            b = b.header("X-Locksmith-Dev-Org", o.to_string());
        }
        let req = match body {
            Some(v) => b
                .header("content-type", "application/json")
                .body(Body::from(v.to_string())),
            None => b.body(Body::empty()),
        }
        .unwrap();
        self.send(req).await
    }

    async fn send(&self, req: Request<Body>) -> Reply {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        Reply {
            status: parts.status,
            headers: parts.headers,
            body,
        }
    }

    async fn org(&self, name: &str) -> Uuid {
        let r = self
            .call("POST", "/v1/orgs", None, Some(json!({ "name": name })))
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        r.body["id"].as_str().unwrap().parse().unwrap()
    }

    async fn post(&self, uri: &str, org: Uuid, body: Value) -> Reply {
        self.call("POST", uri, Some(org), Some(body)).await
    }

    async fn get(&self, uri: &str, org: Uuid) -> Reply {
        self.call("GET", uri, Some(org), None).await
    }

    /// Row count in the database, bypassing row-level security (bootstrap superuser).
    async fn count(&self, table: &str) -> i64 {
        let mut c = self.pg.admin().await;
        let n = query_scalar(sqlx_core::sql_str::AssertSqlSafe(format!(
            "SELECT count(*) FROM {table}"
        )))
        .fetch_one(&mut c)
        .await
        .unwrap();
        c.close().await.unwrap();
        n
    }
}

fn location(r: &Reply) -> String {
    r.headers
        .get("location")
        .expect("Location header")
        .to_str()
        .unwrap()
        .to_owned()
}

fn assert_problem(r: &Reply, status: StatusCode, slug: &str) {
    assert_eq!(r.status, status, "{:?}", r.body);
    assert_eq!(
        r.headers.get("content-type").unwrap(),
        "application/problem+json"
    );
    assert_eq!(r.body["type"], format!("urn:locksmith:problem:{slug}"));
    assert_eq!(r.body["status"], status.as_u16());
    assert!(r.body["title"].is_string());
}

fn assert_rfc3339_utc(v: &Value) {
    let s = v.as_str().expect("timestamp string");
    assert!(s.ends_with('Z') && s.contains('T'), "{s}");
}

#[tokio::test]
async fn project_tree_create_read_patch_delete() {
    let api = Api::start().await;
    let org = api.org("acme").await;
    let org_get = api.get(&format!("/v1/orgs/{org}"), org).await;
    assert_eq!(org_get.status, StatusCode::OK);
    assert_eq!(org_get.body["name"], "acme");

    let p = api
        .post(
            "/v1/projects",
            org,
            json!({"name": "billing", "description": "d"}),
        )
        .await;
    assert_eq!(p.status, StatusCode::CREATED);
    let p_loc = location(&p);
    assert_eq!(
        p_loc,
        format!("/v1/projects/{}", p.body["id"].as_str().unwrap())
    );
    assert_rfc3339_utc(&p.body["created_at"]);
    assert_rfc3339_utc(&p.body["updated_at"]);
    assert_eq!(api.get(&p_loc, org).await.body, p.body);

    let e = api
        .post(
            &format!("{p_loc}/environments"),
            org,
            json!({"name": "dev"}),
        )
        .await;
    assert_eq!(e.status, StatusCode::CREATED);
    let e_loc = location(&e);
    assert_eq!(api.get(&e_loc, org).await.body, e.body);
    assert_eq!(e.body["project_id"], p.body["id"]);

    let s = api
        .post(
            &format!("{e_loc}/secrets"),
            org,
            json!({"name": "STRIPE_KEY", "description": "payments key"}),
        )
        .await;
    assert_eq!(s.status, StatusCode::CREATED);
    let s_loc = location(&s);
    assert_eq!(api.get(&s_loc, org).await.body, s.body);
    assert_eq!(s.body["version_count"], 0);
    assert_eq!(s.body["environment_id"], e.body["id"]);
    assert!(s.body.get("value").is_none());

    // Patch name and description; updated_at moves, created_at does not.
    let patched = api
        .call(
            "PATCH",
            &p_loc,
            Some(org),
            Some(json!({"description": "new"})),
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK);
    assert_eq!(patched.body["description"], "new");
    assert_eq!(patched.body["name"], "billing");
    assert_eq!(patched.body["created_at"], p.body["created_at"]);
    let patched = api
        .call("PATCH", &s_loc, Some(org), Some(json!({"name": "STRIPE"})))
        .await;
    assert_eq!(patched.body["name"], "STRIPE");
    let patched = api
        .call("PATCH", &e_loc, Some(org), Some(json!({"name": "prod"})))
        .await;
    assert_eq!(patched.body["name"], "prod");
    let empty_patch = api.call("PATCH", &e_loc, Some(org), Some(json!({}))).await;
    assert_problem(&empty_patch, StatusCode::BAD_REQUEST, "validation");

    // RESTRICT: a parent with children cannot be deleted (409), children go first.
    let blocked = api.call("DELETE", &p_loc, Some(org), None).await;
    assert_problem(&blocked, StatusCode::CONFLICT, "conflict");
    let blocked = api.call("DELETE", &e_loc, Some(org), None).await;
    assert_problem(&blocked, StatusCode::CONFLICT, "conflict");
    for loc in [&s_loc, &e_loc, &p_loc] {
        let d = api.call("DELETE", loc, Some(org), None).await;
        assert_eq!(d.status, StatusCode::NO_CONTENT, "{loc}");
        let gone = api.get(loc, org).await;
        assert_problem(&gone, StatusCode::NOT_FOUND, "not-found");
        let again = api.call("DELETE", loc, Some(org), None).await;
        assert_problem(&again, StatusCode::NOT_FOUND, "not-found");
    }
}

#[tokio::test]
async fn ids_are_time_ordered_and_names_unique_per_parent() {
    let api = Api::start().await;
    let org = api.org("acme").await;
    let a = api.post("/v1/projects", org, json!({"name": "a"})).await;
    let b = api.post("/v1/projects", org, json!({"name": "b"})).await;
    assert!(a.body["id"].as_str().unwrap() < b.body["id"].as_str().unwrap());

    let dup = api.post("/v1/projects", org, json!({"name": "a"})).await;
    assert_problem(&dup, StatusCode::CONFLICT, "conflict");
    assert_eq!(api.count("projects").await, 2);

    let a_loc = location(&a);
    let b_loc = location(&b);
    let env = |loc: &str| format!("{loc}/environments");
    let e1 = api.post(&env(&a_loc), org, json!({"name": "dev"})).await;
    assert_eq!(e1.status, StatusCode::CREATED);
    let dup = api.post(&env(&a_loc), org, json!({"name": "dev"})).await;
    assert_problem(&dup, StatusCode::CONFLICT, "conflict");
    assert_eq!(api.count("environments").await, 1);
    // The same name under another project is fine.
    let other = api.post(&env(&b_loc), org, json!({"name": "dev"})).await;
    assert_eq!(other.status, StatusCode::CREATED);

    let secrets = format!("{}/secrets", location(&e1));
    assert_eq!(
        api.post(&secrets, org, json!({"name": "K"})).await.status,
        StatusCode::CREATED
    );
    let dup = api.post(&secrets, org, json!({"name": "K"})).await;
    assert_problem(&dup, StatusCode::CONFLICT, "conflict");
    assert_eq!(api.count("secrets").await, 1);

    // Renaming onto an existing name is a conflict too.
    let clash = api
        .call(
            "PATCH",
            &location(&b),
            Some(org),
            Some(json!({"name": "a"})),
        )
        .await;
    assert_problem(&clash, StatusCode::CONFLICT, "conflict");
}

#[tokio::test]
async fn other_orgs_resources_do_not_exist() {
    let api = Api::start().await;
    let a = api.org("a").await;
    let b = api.org("b").await;
    let p = api
        .post("/v1/projects", b, json!({"name": "secret-plans"}))
        .await;
    let p_loc = location(&p);
    let e = api
        .post(&format!("{p_loc}/environments"), b, json!({"name": "dev"}))
        .await;
    let e_loc = location(&e);
    let s = api
        .post(&format!("{e_loc}/secrets"), b, json!({"name": "K"}))
        .await;
    let s_loc = location(&s);

    // Org A sees the same 404 as for an id that never existed.
    let missing = api
        .get(&format!("/v1/projects/{}", Uuid::now_v7()), a)
        .await;
    assert_problem(&missing, StatusCode::NOT_FOUND, "not-found");
    for loc in [&p_loc, &e_loc, &s_loc] {
        let r = api.get(loc, a).await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not-found");
        // Same problem document as for an id that never existed.
        assert_eq!(r.body, missing.body);
        let r = api
            .call("PATCH", loc, Some(a), Some(json!({"name": "x"})))
            .await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not-found");
        let r = api.call("DELETE", loc, Some(a), None).await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not-found");
    }
    // Children of another org's parents: list and create are 404, not empty or forbidden.
    for uri in [format!("{p_loc}/environments"), format!("{e_loc}/secrets")] {
        assert_problem(&api.get(&uri, a).await, StatusCode::NOT_FOUND, "not-found");
        let r = api.post(&uri, a, json!({"name": "x"})).await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not-found");
    }
    assert_problem(
        &api.get(&format!("/v1/orgs/{b}"), a).await,
        StatusCode::NOT_FOUND,
        "not-found",
    );

    // Lists show only the caller's own rows, and B's data is untouched.
    assert!(
        api.get("/v1/projects", a).await.body["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        api.get("/v1/projects", b).await.body["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(api.get(&s_loc, b).await.status, StatusCode::OK);

    // Same names in two orgs do not collide.
    assert_eq!(
        api.post("/v1/projects", a, json!({"name": "secret-plans"}))
            .await
            .status,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn request_without_org_is_401_problem() {
    let api = Api::start().await;
    let r = api.call("GET", "/v1/projects", None, None).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    let r = api
        .call("POST", "/v1/projects", None, Some(json!({"name": "x"})))
        .await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    assert_eq!(api.count("projects").await, 0);
}

#[tokio::test]
async fn invalid_input_is_a_problem_and_value_is_never_stored() {
    let api = Api::start().await;
    let org = api.org("acme").await;
    let p = api.post("/v1/projects", org, json!({"name": "p"})).await;
    let e = api
        .post(
            &format!("{}/environments", location(&p)),
            org,
            json!({"name": "dev"}),
        )
        .await;
    let secrets = format!("{}/secrets", location(&e));

    // A `value` field is an unknown field: 400 naming it, nothing stored.
    let r = api
        .post(&secrets, org, json!({"name": "K", "value": CANARY}))
        .await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    assert!(r.body["detail"].as_str().unwrap().contains("`value`"));
    assert!(!r.body.to_string().contains(CANARY));
    assert_eq!(api.count("secrets").await, 0);
    assert!(
        api.get(&secrets, org).await.body["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // The same holds for every input type, including patches.
    let r = api
        .post("/v1/projects", org, json!({"name": "q", "value": CANARY}))
        .await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    let r = api
        .post(
            &format!("{}/environments", location(&p)),
            org,
            json!({"name": "q", "extra": 1}),
        )
        .await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    let s = api.post(&secrets, org, json!({"name": "K"})).await;
    let r = api
        .call(
            "PATCH",
            &location(&s),
            Some(org),
            Some(json!({"value": CANARY})),
        )
        .await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    assert_eq!(api.count("projects").await, 1);
    assert_eq!(api.count("environments").await, 1);
    assert_eq!(api.count("secrets").await, 1);

    // Empty or blank name.
    for name in ["", "   "] {
        let r = api.post("/v1/projects", org, json!({ "name": name })).await;
        assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    }
    // Missing field, wrong type: no echo of the supplied value.
    let r = api.post("/v1/projects", org, json!({})).await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    let r = api
        .post(
            "/v1/projects",
            org,
            json!({"name": 5, "description": CANARY}),
        )
        .await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    let r = api
        .post(
            "/v1/projects",
            org,
            json!({"name": CANARY, "description": [CANARY]}),
        )
        .await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    assert!(!r.body.to_string().contains(CANARY));

    // Malformed JSON and wrong content type.
    let req = Request::builder()
        .method("POST")
        .uri("/v1/projects")
        .header("X-Locksmith-Dev-Org", org.to_string())
        .header("content-type", "application/json")
        .body(Body::from(format!("{{\"name\": \"{CANARY}")))
        .unwrap();
    let r = api.send(req).await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    assert!(!r.body.to_string().contains(CANARY));
    let req = Request::builder()
        .method("POST")
        .uri("/v1/projects")
        .header("X-Locksmith-Dev-Org", org.to_string())
        .header("content-type", "text/plain")
        .body(Body::from("{\"name\": \"x\"}"))
        .unwrap();
    assert_problem(
        &api.send(req).await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported-media-type",
    );

    // Unknown routes and malformed ids are 404 problems too.
    let r = api.get("/v1/nope", org).await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not-found");
    let r = api.get("/v1/projects/not-a-uuid", org).await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not-found");

    // Bad paging parameters.
    for q in [
        "limit=0",
        "limit=101",
        "limit=abc",
        "cursor=!!!",
        "cursor=AAAA",
        "bogus=1",
    ] {
        let r = api.get(&format!("/v1/projects?{q}"), org).await;
        assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    }
}

#[tokio::test]
async fn keyset_pagination_returns_every_item_once_in_creation_order() {
    let api = Api::start().await;
    let org = api.org("acme").await;
    let mut created = Vec::new();
    for i in 0..120 {
        let r = api
            .post("/v1/projects", org, json!({"name": format!("p{i:03}")}))
            .await;
        assert_eq!(r.status, StatusCode::CREATED);
        created.push(r.body["id"].as_str().unwrap().to_owned());
    }

    let mut seen = Vec::new();
    let mut sizes = Vec::new();
    let mut uri = "/v1/projects?limit=50".to_owned();
    loop {
        let r = api.get(&uri, org).await;
        assert_eq!(r.status, StatusCode::OK);
        let items = r.body["items"].as_array().unwrap();
        sizes.push(items.len());
        seen.extend(items.iter().map(|p| p["id"].as_str().unwrap().to_owned()));
        match r.body["next"].as_str() {
            Some(next) => uri = format!("/v1/projects?limit=50&cursor={next}"),
            None => break,
        }
    }
    assert_eq!(sizes, [50, 50, 20]);
    assert_eq!(seen, created);

    // Exactly one full page has no `next`; the default and maximum limits work.
    let r = api.get("/v1/projects?limit=100", org).await;
    assert_eq!(r.body["items"].as_array().unwrap().len(), 100);
    assert!(r.body["next"].is_string());
    let r = api.get("/v1/projects?limit=120", org).await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    let r = api.get("/v1/projects", org).await;
    assert_eq!(r.body["items"].as_array().unwrap().len(), 50);

    // Child lists paginate the same way.
    let p_loc = format!("/v1/projects/{}", created[0]);
    let e = api
        .post(
            &format!("{p_loc}/environments"),
            org,
            json!({"name": "dev"}),
        )
        .await;
    let secrets = format!("{}/secrets", location(&e));
    for i in 0..3 {
        api.post(&secrets, org, json!({"name": format!("s{i}")}))
            .await;
    }
    let first = api.get(&format!("{secrets}?limit=2"), org).await;
    assert_eq!(first.body["items"].as_array().unwrap().len(), 2);
    let next = first.body["next"].as_str().unwrap();
    let second = api
        .get(&format!("{secrets}?limit=2&cursor={next}"), org)
        .await;
    assert_eq!(second.body["items"].as_array().unwrap().len(), 1);
    assert!(second.body["next"].is_null());
}
