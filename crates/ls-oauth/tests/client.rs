//! The provider client against every provider's fake (C1 task 2.4): exchange, refresh with
//! rotation, revoke, account lookup, Slack `ok:false`, redirects and oversized bodies refused,
//! and no token in any error or Debug output.

use ls_oauth::testing::{
    ACCESS_1, ACCESS_2, CODE, FakeProvider, Kind, REFRESH_1, REFRESH_2, Refresh,
};
use ls_oauth::{ErrorSlug, OAuthClient, OAuthError, ProviderEndpoints, Quirk, Reason};
use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CANARY: &str = "CANARY-tok-9f3a1c77";

fn http() -> reqwest::Client {
    ls_http::builder().unwrap().build().unwrap()
}

fn secret(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn endpoints(f: &FakeProvider) -> ProviderEndpoints {
    let quirk = match f.kind() {
        Kind::Github => Quirk::Github,
        Kind::Slack => Quirk::Slack,
        Kind::Atlassian => Quirk::Atlassian,
        Kind::Google | Kind::Linear => Quirk::Standard,
    };
    ProviderEndpoints {
        authorize_url: format!("{}/authorize", f.base_url()),
        token_url: f.token_url(),
        revoke_url: f.revoke_url(),
        account_url: f.account_url(),
        quirk,
        authorize_params: if f.kind() == Kind::Atlassian {
            vec![("audience".into(), "api.atlassian.com".into())]
        } else {
            vec![]
        },
    }
}

fn client_for(f: &FakeProvider) -> OAuthClient {
    OAuthClient::new(
        http(),
        endpoints(f),
        "client-1".into(),
        secret("client-secret-1"),
        "https://gw.example.test/oauth/callback",
    )
    .unwrap()
}

fn err<T>(r: Result<T, OAuthError>) -> OAuthError {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

#[tokio::test]
async fn every_provider_exchanges_a_code_and_names_the_account() {
    for kind in Kind::ALL {
        let f = FakeProvider::start(kind).await;
        let c = client_for(&f);
        let start = c.authorize(&["a.read".into()]);
        let t = c
            .exchange_code(secret(CODE), start.verifier)
            .await
            .unwrap_or_else(|e| panic!("{kind:?}: {e}"));
        assert_eq!(t.access.expose_secret(), ACCESS_1, "{kind:?}");
        assert_eq!(
            t.refresh.as_ref().map(|r| r.expose_secret()),
            Some(REFRESH_1),
            "{kind:?}"
        );
        assert!(t.expires_in.is_some(), "{kind:?}");

        let a = c
            .account(&t.access)
            .await
            .unwrap_or_else(|e| panic!("{kind:?}: {e}"));
        let want = match kind {
            Kind::Github => ("1001", "alice-gh"),
            Kind::Google => ("g-1001", "alice@example.test"),
            Kind::Slack => ("U1", "alice"),
            Kind::Linear => ("l-1001", "alice"),
            Kind::Atlassian => ("a-1001", "alice"),
        };
        assert_eq!((a.id.as_str(), a.login.as_str()), want, "{kind:?}");
    }
}

#[tokio::test]
async fn exchange_sends_the_pkce_verifier_and_github_asks_for_json() {
    let f = FakeProvider::start(Kind::Github).await;
    let c = client_for(&f);
    let start = c.authorize(&[]);
    let verifier = start.verifier.expose_secret().to_owned();
    c.exchange_code(secret(CODE), start.verifier).await.unwrap();
    let reqs = f.requests().await;
    let body = String::from_utf8(reqs[0].body.clone()).unwrap();
    assert!(
        body.contains(&format!("code_verifier={verifier}")),
        "verifier sent"
    );
    assert_eq!(
        reqs[0].headers.get("accept").unwrap().to_str().unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn refresh_rotates_where_the_provider_rotates() {
    for kind in Kind::ALL {
        let f = FakeProvider::start(kind).await;
        let c = client_for(&f);
        let t = c
            .refresh(&secret(REFRESH_1))
            .await
            .unwrap_or_else(|e| panic!("{kind:?}: {e}"));
        assert_eq!(t.access.expose_secret(), ACCESS_2, "{kind:?}");
        let rotated = matches!(kind, Kind::Github | Kind::Slack | Kind::Atlassian);
        assert_eq!(
            t.refresh.as_ref().map(|r| r.expose_secret()),
            rotated.then_some(REFRESH_2),
            "{kind:?}"
        );
    }
}

#[tokio::test]
async fn a_refused_refresh_token_needs_a_reconnect_for_every_provider() {
    for kind in Kind::ALL {
        let f = FakeProvider::start_with(kind, Refresh::InvalidGrant).await;
        let e = err(client_for(&f).refresh(&secret(REFRESH_1)).await);
        assert_eq!(e.slug, ErrorSlug::ConnectionNeedsReconnect, "{kind:?}");
        assert_eq!(e.reason, Reason::InvalidGrant, "{kind:?}");
        assert!(e.is_permanent());
    }
}

#[tokio::test]
async fn revoke_reaches_the_providers_endpoint() {
    for kind in Kind::ALL {
        let f = FakeProvider::start(kind).await;
        let c = client_for(&f);
        let (a, r) = (secret(ACCESS_1), secret(REFRESH_1));
        let res = c.revoke(&a, Some(&r)).await;
        match f.revoke_url() {
            None => {
                assert_eq!(kind, Kind::Atlassian);
                assert_eq!(err(res).reason, Reason::Unsupported);
            }
            Some(url) => {
                res.unwrap_or_else(|e| panic!("{kind:?}: {e}"));
                let p = url.replace(&f.base_url(), "");
                assert!(
                    f.requests().await.iter().any(|q| q.url.path() == p),
                    "{kind:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn slack_ok_false_is_a_refused_code() {
    let f = FakeProvider::start(Kind::Slack).await;
    let c = client_for(&f);
    let start = c.authorize(&[]);
    let e = err(c.exchange_code(secret("wrong"), start.verifier).await);
    assert_eq!(
        (e.slug, e.reason),
        (ErrorSlug::ExchangeFailed, Reason::InvalidGrant)
    );
}

#[tokio::test]
async fn authorize_url_has_pkce_s256_state_and_exactly_the_scopes() {
    for kind in Kind::ALL {
        let f = FakeProvider::start(kind).await;
        let c = client_for(&f);
        let s = c.authorize(&["a.read".into(), "b.write".into()]);
        let url = reqwest::Url::parse(&s.url).unwrap();
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["code_challenge_method"], "S256", "{kind:?}");
        assert!(q["code_challenge"].len() >= 43);
        assert_eq!(q["state"], s.state);
        assert!(s.state.len() >= 43, "32 random bytes, base64: {kind:?}");
        assert_eq!(q["client_id"], "client-1");
        assert_eq!(q["redirect_uri"], "https://gw.example.test/oauth/callback");
        assert!(!s.url.contains(s.verifier.expose_secret()), "{kind:?}");
        match kind {
            Kind::Slack => {
                assert_eq!(q["user_scope"], "a.read,b.write");
                assert!(!q.contains_key("scope"));
            }
            _ => assert_eq!(q["scope"], "a.read b.write", "{kind:?}"),
        }
        if kind == Kind::Atlassian {
            assert_eq!(q["audience"], "api.atlassian.com");
        }
    }
    // Two starts never share a state or a verifier.
    let f = FakeProvider::start(Kind::Google).await;
    let c = client_for(&f);
    let (a, b) = (c.authorize(&[]), c.authorize(&[]));
    assert_ne!(a.state, b.state);
    assert_ne!(a.verifier.expose_secret(), b.verifier.expose_secret());
}

/// A server whose token, revoke and account paths all answer with `resp`.
async fn server_answering(resp: ResponseTemplate) -> MockServer {
    let s = MockServer::start().await;
    for p in ["/token", "/revoke", "/user"] {
        Mock::given(method("POST"))
            .and(path(p))
            .respond_with(resp.clone())
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(resp.clone())
            .mount(&s)
            .await;
    }
    s
}

fn client_at(s: &MockServer, quirk: Quirk) -> OAuthClient {
    OAuthClient::new(
        http(),
        ProviderEndpoints {
            authorize_url: format!("{}/authorize", s.uri()),
            token_url: format!("{}/token", s.uri()),
            revoke_url: Some(format!("{}/revoke", s.uri())),
            account_url: format!("{}/user", s.uri()),
            quirk,
            authorize_params: vec![],
        },
        "client-1".into(),
        secret("client-secret-1"),
        "https://gw.example.test/oauth/callback",
    )
    .unwrap()
}

#[tokio::test]
async fn a_redirect_is_refused_and_not_followed() {
    let s = MockServer::start().await;
    let elsewhere = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/steal?t={CANARY}", elsewhere.uri())),
        )
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/steal", elsewhere.uri())),
        )
        .mount(&s)
        .await;
    let c = client_at(&s, Quirk::Standard);
    let start = c.authorize(&[]);
    let e = err(c.exchange_code(secret(CODE), start.verifier).await);
    assert_eq!(e.reason, Reason::Redirect);
    assert_eq!(
        err(c.refresh(&secret(REFRESH_1)).await).reason,
        Reason::Redirect
    );
    assert_eq!(
        err(c.account(&secret(ACCESS_1)).await).reason,
        Reason::Redirect
    );
    assert_eq!(
        err(c.revoke(&secret(ACCESS_1), None).await).reason,
        Reason::Redirect
    );
    assert!(
        elsewhere.received_requests().await.unwrap().is_empty(),
        "redirect was followed"
    );
    assert!(!format!("{e} {e:?}").contains(CANARY));
}

#[tokio::test]
async fn an_oversized_body_is_refused() {
    let big = format!(
        r#"{{"access_token":"{CANARY}","pad":"{}"}}"#,
        "x".repeat(8 * 1024)
    );
    let s =
        server_answering(ResponseTemplate::new(200).set_body_raw(big, "application/json")).await;
    let c = client_at(&s, Quirk::Standard).with_max_body(1024);
    let start = c.authorize(&[]);
    let e = err(c.exchange_code(secret(CODE), start.verifier).await);
    assert_eq!(e.reason, Reason::TooLarge);
    assert_eq!(
        err(c.refresh(&secret(REFRESH_1)).await).reason,
        Reason::TooLarge
    );
    assert_eq!(
        err(c.account(&secret(ACCESS_1)).await).reason,
        Reason::TooLarge
    );
    assert!(!format!("{e} {e:?}").contains(CANARY));
}

#[tokio::test]
async fn no_token_appears_in_any_error_or_debug_output() {
    // Provider answers that carry the canary as a token or inside a refusal, in shapes that fail
    // at every stage: unparseable, wrong shape, error response, 5xx, Slack ok:false.
    let bodies: [(u16, String); 6] = [
        (200, format!("access_token={CANARY}&refresh_token={CANARY}")),
        (
            200,
            format!(r#"{{"access_token":"{CANARY}","refresh_token":"{CANARY}""#),
        ),
        (
            200,
            format!(r#"{{"refresh_token":"{CANARY}","token_type":7}}"#),
        ),
        (
            400,
            format!(r#"{{"error":"invalid_grant","error_description":"{CANARY}"}}"#),
        ),
        (500, format!("{CANARY} {CANARY}")),
        (
            200,
            format!(r#"{{"ok":false,"error":"{CANARY}","access_token":"{CANARY}"}}"#),
        ),
    ];
    for (status, body) in bodies {
        for quirk in [
            Quirk::Standard,
            Quirk::Slack,
            Quirk::Github,
            Quirk::Atlassian,
        ] {
            let s = server_answering(
                ResponseTemplate::new(status).set_body_raw(body.clone(), "application/json"),
            )
            .await;
            let c = client_at(&s, quirk);
            let start = c.authorize(&[]);
            let errors = [
                err(c.exchange_code(secret(CODE), start.verifier).await),
                err(c.refresh(&secret(CANARY)).await),
                err(c.account(&secret(CANARY)).await),
            ];
            let revoke = c.revoke(&secret(CANARY), Some(&secret(CANARY))).await;
            for e in errors.into_iter().chain(revoke.err()) {
                let out = format!("{e} | {e:?} | {:#?} | {}", e, e.slug.as_str());
                assert!(!out.contains(CANARY), "{status} {quirk:?}: {out}");
                assert!(!out.contains("client-secret-1"));
            }
        }
    }
}

#[tokio::test]
async fn token_holding_types_have_no_debug_or_clone() {
    use std::marker::PhantomData;
    macro_rules! implements {
        ($t:ty, $tr:path) => {{
            struct Probe<T>(PhantomData<T>);
            #[allow(dead_code)]
            trait Fallback {
                fn yes(&self) -> bool {
                    false
                }
            }
            impl<T> Fallback for Probe<T> {}
            #[allow(dead_code)]
            impl<T: $tr> Probe<T> {
                fn yes(&self) -> bool {
                    true
                }
            }
            Probe::<$t>(PhantomData).yes()
        }};
    }
    // The probe works on a type that has the trait.
    assert!(implements!(ls_oauth::Account, std::fmt::Debug));
    for (name, dbg, clone) in [
        (
            "Tokens",
            implements!(ls_oauth::Tokens, std::fmt::Debug),
            implements!(ls_oauth::Tokens, Clone),
        ),
        (
            "AuthorizeStart",
            implements!(ls_oauth::AuthorizeStart, std::fmt::Debug),
            implements!(ls_oauth::AuthorizeStart, Clone),
        ),
        (
            "OAuthClient",
            implements!(ls_oauth::OAuthClient, std::fmt::Debug),
            implements!(ls_oauth::OAuthClient, Clone),
        ),
    ] {
        assert!(!dbg && !clone, "{name} must not derive Debug or Clone");
    }
    assert!(!implements!(ls_oauth::Tokens, std::fmt::Display));
}
