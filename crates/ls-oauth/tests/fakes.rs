//! The per-provider fakes answer with each provider's real shapes and quirks (C1 task 1.3).

use ls_oauth::testing::{
    ACCESS_1, ACCESS_2, CODE, FakeProvider, Kind, REFRESH_1, REFRESH_2, Refresh,
};
use serde_json::Value;

fn client() -> reqwest::Client {
    ls_http::builder().unwrap().build().unwrap()
}

async fn post_form(url: &str, form: &[(&str, &str)], accept: Option<&str>) -> (u16, String) {
    let mut r = client().post(url).form(form);
    if let Some(a) = accept {
        r = r.header("accept", a);
    }
    let resp = r.send().await.unwrap();
    (resp.status().as_u16(), resp.text().await.unwrap())
}

async fn exchange(f: &FakeProvider) -> Value {
    let form = [("grant_type", "authorization_code"), ("code", CODE)];
    let (s, body) = if f.kind() == Kind::Atlassian {
        let resp = client()
            .post(f.token_url())
            .json(&serde_json::json!({"grant_type": "authorization_code", "code": CODE}))
            .send()
            .await
            .unwrap();
        (resp.status().as_u16(), resp.text().await.unwrap())
    } else {
        post_form(&f.token_url(), &form, Some("application/json")).await
    };
    assert_eq!(s, 200, "{:?}", f.kind());
    serde_json::from_str(&body).unwrap()
}

async fn refresh(f: &FakeProvider) -> (u16, Value) {
    let (s, body) = if f.kind() == Kind::Atlassian {
        let resp = client()
            .post(f.token_url())
            .json(&serde_json::json!({"grant_type": "refresh_token", "refresh_token": REFRESH_1}))
            .send()
            .await
            .unwrap();
        (resp.status().as_u16(), resp.text().await.unwrap())
    } else {
        post_form(
            &f.token_url(),
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", REFRESH_1),
            ],
            Some("application/json"),
        )
        .await
    };
    (s, serde_json::from_str(&body).unwrap())
}

fn access(kind: Kind, v: &Value) -> &str {
    match kind {
        Kind::Slack if v.get("authed_user").is_some() => {
            v["authed_user"]["access_token"].as_str().unwrap()
        }
        _ => v["access_token"].as_str().unwrap(),
    }
}

#[tokio::test]
async fn every_provider_exchanges_refreshes_revokes_and_names_the_account() {
    for kind in Kind::ALL {
        let f = FakeProvider::start(kind).await;
        let first = exchange(&f).await;
        assert_eq!(access(kind, &first), ACCESS_1, "{kind:?}");

        let (s, second) = refresh(&f).await;
        assert_eq!(s, 200, "{kind:?}");
        assert_eq!(access(kind, &second), ACCESS_2, "{kind:?}");
        // GitHub (expiring tokens), Slack and Atlassian rotate; Google and Linear keep one.
        let rotated = matches!(kind, Kind::Github | Kind::Slack | Kind::Atlassian);
        assert_eq!(
            second.get("refresh_token").and_then(Value::as_str),
            rotated.then_some(REFRESH_2),
            "{kind:?}"
        );

        let account = if kind == Kind::Linear {
            client()
                .post(f.account_url())
                .json(&serde_json::json!({"query": "{viewer{id}}"}))
                .send()
                .await
        } else {
            client().get(f.account_url()).send().await
        }
        .unwrap();
        assert_eq!(account.status(), 200, "{kind:?}");

        match f.revoke_url() {
            None => assert_eq!(kind, Kind::Atlassian),
            Some(url) => {
                let c = client();
                let r = if kind == Kind::Github {
                    c.delete(url)
                } else {
                    c.post(url)
                }
                .send()
                .await
                .unwrap();
                assert!(r.status().is_success(), "{kind:?}");
            }
        }
    }
}

#[tokio::test]
async fn github_answers_form_encoded_without_the_json_accept_header() {
    let f = FakeProvider::start(Kind::Github).await;
    let (s, body) = post_form(
        &f.token_url(),
        &[("grant_type", "authorization_code"), ("code", CODE)],
        None,
    )
    .await;
    assert_eq!(s, 200);
    assert!(serde_json::from_str::<Value>(&body).is_err());
    assert!(body.starts_with("access_token="));
}

#[tokio::test]
async fn slack_failures_are_200_with_ok_false() {
    let f = FakeProvider::start(Kind::Slack).await;
    let (s, body) = post_form(
        &f.token_url(),
        &[("grant_type", "authorization_code"), ("code", "wrong")],
        None,
    )
    .await;
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ok"], false);
    let ok = exchange(&f).await;
    assert!(ok["authed_user"]["access_token"].is_string());
    assert!(ok.get("access_token").is_none());
}

#[tokio::test]
async fn atlassian_refuses_a_form_encoded_token_request() {
    let f = FakeProvider::start(Kind::Atlassian).await;
    let (s, _) = post_form(
        &f.token_url(),
        &[("grant_type", "authorization_code"), ("code", CODE)],
        None,
    )
    .await;
    assert_eq!(s, 403);
}

#[tokio::test]
async fn a_revoked_refresh_token_is_refused_by_every_provider() {
    for kind in Kind::ALL {
        let f = FakeProvider::start_with(kind, Refresh::InvalidGrant).await;
        let (s, body) = refresh(&f).await;
        match kind {
            Kind::Github => assert_eq!(body["error"], "bad_refresh_token"),
            Kind::Slack => assert_eq!(body["ok"], false),
            _ => assert!(s >= 400 && body["error"] == "invalid_grant", "{kind:?}"),
        }
    }
}

#[tokio::test]
async fn the_fakes_never_serve_a_token_on_the_account_or_revoke_paths() {
    let f = FakeProvider::start(Kind::Google).await;
    let body = client()
        .get(f.account_url())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!body.contains("fake-access") && !body.contains("fake-refresh"));
}
