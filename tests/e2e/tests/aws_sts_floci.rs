//! d2-aws-sts task 1.2 spike: `ls-proxy::aws::sts::assume_role` against Floci 2.5.0. Records
//! what Floci enforces.
//!
//! - `assume_role_returns_usable_keys` uses the compose Floci (`docker compose -f
//!   infra/compose/compose.yaml up -d --wait floci`, 127.0.0.1:4566 or `FLOCI_URL`), which runs
//!   without IAM enforcement, and skips when it is unreachable.
//! - `floci_iam_enforcement` starts its own throwaway Floci container with IAM enforcement and
//!   signature validation on (`FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED`,
//!   `FLOCI_AUTH_VALIDATE_SIGNATURES`; startup settings, so the shared compose service is never
//!   switched) and skips when Docker is unavailable.
//!
//! `E2E_REQUIRE_FLOCI=1` turns either skip into a failure. All credentials are Floci fakes and are
//! never printed.
//!
//! Run: `cargo nextest run -p ls-e2e --test aws_sts_floci`.

use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ls_e2e::{floci, uniq};
use ls_proxy::aws::Credentials;
use ls_proxy::aws::sigv4::{self, Request, Scope};
use ls_proxy::aws::sts::assume_role;
use zeroize::Zeroizing;

/// Floci's fixed account id.
const ACCOUNT: &str = "000000000000";
const REGION: &str = "us-east-1";
const IMAGE: &str = "floci/floci:2.5.0";

fn skip_or_fail(test: &str, why: &str) {
    assert!(
        std::env::var("E2E_REQUIRE_FLOCI").is_err(),
        "{test}: {why} and E2E_REQUIRE_FLOCI is set"
    );
    eprintln!("{test}: skipped, {why}");
}

fn healthy(base: &str) -> bool {
    agent()
        .get(&format!("{base}/_floci/health"))
        .call()
        .is_ok_and(|r| r.status().is_success())
}

/// The compose Floci's base URL when it answers, else `None` (skip).
fn floci_or_skip(test: &str) -> Option<String> {
    let base = floci();
    if healthy(&base) {
        return Some(base);
    }
    skip_or_fail(
        test,
        &format!("Floci is not reachable at {base} (start it with `just up`)"),
    );
    None
}

/// A throwaway Floci container, removed on drop.
struct Container(String);
impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
    }
}

/// A fresh Floci with IAM enforcement and SigV4 validation on, or `None` (skip) without Docker.
fn enforcing_floci_or_skip(test: &str) -> Option<(String, Container)> {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let image = std::env::var("FLOCI_IMAGE").unwrap_or_else(|_| IMAGE.into());
    let out = Command::new("docker")
        .args(["run", "-d", "--rm", "-p", &format!("127.0.0.1:{port}:4566")])
        .args(["-e", "FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true"])
        .args(["-e", "FLOCI_AUTH_VALIDATE_SIGNATURES=true"])
        .arg(&image)
        .output();
    let out = match out {
        Ok(o) if o.status.success() => o,
        _ => {
            skip_or_fail(test, "Docker could not start a Floci container");
            return None;
        }
    };
    let c = Container(String::from_utf8_lossy(&out.stdout).trim().to_string());
    let base = format!("http://127.0.0.1:{port}");
    for _ in 0..120 {
        if healthy(&base) {
            return Some((base, c));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("{test}: the enforcing Floci container did not become healthy");
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into()
}

/// Fake base key (not an AWS key format the leak scanners match; Floci accepts anything without
/// IAM enforcement).
fn fake_base() -> Credentials {
    Credentials {
        access_key_id: "AKIALOCKSMITHE2E0000".into(),
        secret_access_key: Zeroizing::new("locksmith-e2e-fake-secret-not-real".into()),
        session_token: None,
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A SigV4-signed AWS query-protocol POST to Floci. Returns (status, body). Never print the body
/// of a call that returns credentials.
fn query(base: &str, creds: &Credentials, service: &str, params: &[(&str, &str)]) -> (u16, String) {
    let body = params
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    let url = format!("{base}/");
    let host = base
        .split_once("://")
        .map_or(base, |(_, h)| h)
        .trim_end_matches('/')
        .to_string();
    let ct = "application/x-www-form-urlencoded; charset=utf-8";
    let req = Request {
        method: "POST".into(),
        path: "/".into(),
        query: String::new(),
        headers: vec![("host".into(), host), ("content-type".into(), ct.into())],
        payload_hash: sigv4::hex_sha256(body.as_bytes()),
    };
    let amz_date = sigv4::amz_date(SystemTime::now());
    let scope = Scope {
        date: amz_date[..8].to_string(),
        region: REGION.into(),
        service: service.into(),
    };
    let signed = sigv4::sign(&req, creds, &scope, &amz_date, &[]);
    let mut rb = agent().post(&url).header("content-type", ct);
    for (k, v) in &signed.headers {
        rb = rb.header(*k, v.as_str());
    }
    let mut resp = rb.send(body.as_bytes()).expect("reach Floci");
    let status = resp.status().as_u16();
    (status, resp.body_mut().read_to_string().unwrap_or_default())
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn between<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = xml.find(&open)? + open.len();
    let len = xml[start..].find(&format!("</{name}>"))?;
    Some(&xml[start..start + len])
}

fn allow(actions: &[&str], resource: &str) -> String {
    let actions = actions
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":[{actions}],"Resource":"{resource}"}}]}}"#
    )
}

/// Floci's root key in the enforcing container (any other unknown key is refused there).
fn root() -> Credentials {
    Credentials {
        access_key_id: "test".into(),
        secret_access_key: Zeroizing::new("test".into()),
        session_token: None,
    }
}

fn iam(base: &str, creds: &Credentials, params: &[(&str, &str)]) -> (u16, String) {
    let mut p = params.to_vec();
    p.push(("Version", "2010-05-08"));
    query(base, creds, "iam", &p)
}

/// A role every principal may assume (Floci refuses AssumeRole on an unknown role).
fn create_open_role(base: &str, creds: &Credentials, name: &str) {
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}"#;
    let (s, _) = iam(
        base,
        creds,
        &[
            ("Action", "CreateRole"),
            ("RoleName", name),
            ("AssumeRolePolicyDocument", trust),
        ],
    );
    assert_eq!(s, 200, "CreateRole");
}

/// AssumeRole returns temporary keys Floci recognises as the assumed role (no IAM enforcement:
/// any base key is accepted, but the role must exist).
#[test]
fn assume_role_returns_usable_keys() {
    let Some(base) = floci_or_skip("assume_role_returns_usable_keys") else {
        return;
    };
    let role_name = uniq("ls-e2e-spike");
    let role = format!("arn:aws:iam::{ACCOUNT}:role/{role_name}");
    let policy = allow(&["iam:ListRoles"], "*");
    let missing = assume_role(
        &fake_base(),
        REGION,
        &role,
        None,
        "ls-e2e-session",
        Some(&policy),
        900,
        Some(&format!("{base}/")),
    );
    assert!(
        missing
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("AccessDenied")),
        "Floci refuses an unknown role"
    );
    create_open_role(&base, &fake_base(), &role_name);
    let (tmp, expiry) = assume_role(
        &fake_base(),
        REGION,
        &role,
        Some("ext-id-1"),
        "ls-e2e-session",
        Some(&policy),
        900,
        Some(&format!("{base}/")),
    )
    .expect("AssumeRole against Floci");

    assert!(tmp.access_key_id.starts_with("ASIA"), "temporary key id");
    assert_ne!(tmp.access_key_id, fake_base().access_key_id);
    assert!(tmp.secret_access_key.len() >= 20, "secret present");
    assert!(
        tmp.session_token.as_ref().is_some_and(|t| t.len() >= 20),
        "session token present"
    );
    let left = expiry - now();
    assert!((840..=960).contains(&left), "expiry honours 900 s: {left}");

    let (status, body) = query(
        &base,
        &tmp,
        "sts",
        &[("Action", "GetCallerIdentity"), ("Version", "2011-06-15")],
    );
    assert_eq!(status, 200, "GetCallerIdentity with the temporary keys");
    assert_eq!(
        between(&body, "Arn"),
        Some(format!("arn:aws:sts::{ACCOUNT}:assumed-role/{role_name}/ls-e2e-session").as_str())
    );
    assert_eq!(between(&body, "Account"), Some(ACCOUNT));
}

/// What Floci checks with IAM enforcement and signature validation on. The asserts record Floci
/// 2.5.0's behaviour; a failure after a Floci upgrade means design.md decision 6 needs revisiting.
#[test]
fn floci_iam_enforcement() {
    let Some((base, _container)) = enforcing_floci_or_skip("floci_iam_enforcement") else {
        return;
    };
    let base = base.as_str();
    let root = root();
    let iam = |creds: &Credentials, params: &[(&str, &str)]| iam(base, creds, params);

    // Setup as root: a base IAM user allowed to assume one role, the role trusting that user
    // with an external id, and a role policy allowing ListRoles and ListUsers.
    let user = uniq("ls-e2e-base");
    let role_name = uniq("ls-e2e-role");
    let role = format!("arn:aws:iam::{ACCOUNT}:role/{role_name}");
    let user_arn = format!("arn:aws:iam::{ACCOUNT}:user/{user}");
    assert_eq!(
        iam(&root, &[("Action", "CreateUser"), ("UserName", &user)]).0,
        200
    );
    let (s, key_xml) = iam(&root, &[("Action", "CreateAccessKey"), ("UserName", &user)]);
    assert_eq!(s, 200, "CreateAccessKey");
    let base_creds = Credentials {
        access_key_id: between(&key_xml, "AccessKeyId").unwrap().to_string(),
        secret_access_key: Zeroizing::new(between(&key_xml, "SecretAccessKey").unwrap().into()),
        session_token: None,
    };
    drop(key_xml);
    let user_policy = allow(&["sts:AssumeRole"], &role);
    let s = iam(
        &root,
        &[
            ("Action", "PutUserPolicy"),
            ("UserName", &user),
            ("PolicyName", "assume"),
            ("PolicyDocument", &user_policy),
        ],
    );
    assert_eq!(s.0, 200, "PutUserPolicy");
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{user_arn}"}},"Action":"sts:AssumeRole","Condition":{{"StringEquals":{{"sts:ExternalId":"ext-ok"}}}}}}]}}"#
    );
    let s = iam(
        &root,
        &[
            ("Action", "CreateRole"),
            ("RoleName", &role_name),
            ("AssumeRolePolicyDocument", &trust),
        ],
    );
    assert_eq!(s.0, 200, "CreateRole");
    let role_policy = allow(&["iam:ListRoles", "iam:ListUsers"], "*");
    let s = iam(
        &root,
        &[
            ("Action", "PutRolePolicy"),
            ("RoleName", &role_name),
            ("PolicyName", "work"),
            ("PolicyDocument", &role_policy),
        ],
    );
    assert_eq!(s.0, 200, "PutRolePolicy");

    let sts = format!("{base}/");
    let session_policy = allow(&["iam:ListRoles"], "*");
    let assume = |creds: &Credentials, ext: &str, policy: &str| {
        assume_role(
            creds,
            REGION,
            &role,
            Some(ext),
            "ls-e2e-iam",
            Some(policy),
            900,
            Some(&sts),
        )
    };

    // 1. The base key is authenticated and authorised: an unknown key is refused.
    let e = assume(&fake_base(), "ext-ok", &session_policy)
        .err()
        .expect("unknown key");
    assert!(
        e.contains("HTTP 403") && e.contains("InvalidClientTokenId"),
        "{e}"
    );

    // 2. The role trust policy is enforced, including the sts:ExternalId condition.
    let e = assume(&base_creds, "ext-wrong", &session_policy)
        .err()
        .expect("wrong external id");
    assert!(e.contains("HTTP 403") && e.contains("AccessDenied"), "{e}");

    // 3. Correct external id: usable keys, and Floci verifies their SigV4 signature.
    let (tmp, _) = assume(&base_creds, "ext-ok", &session_policy).expect("AssumeRole");
    let (s, _) = iam(&tmp, &[("Action", "ListRoles")]);
    assert_eq!(
        s, 200,
        "ListRoles: in the role policy and the session policy"
    );
    let tampered = Credentials {
        access_key_id: tmp.access_key_id.clone(),
        secret_access_key: Zeroizing::new("wrong-secret-for-signature-check".into()),
        session_token: tmp.session_token.clone(),
    };
    let (s, body) = iam(&tampered, &[("Action", "ListRoles")]);
    assert_eq!(s, 403, "bad signature refused");
    assert!(body.contains("SignatureDoesNotMatch"), "bad signature code");

    // 4. The role's own policies are enforced: an action outside them is denied.
    let (s, body) = iam(&tmp, &[("Action", "ListGroups")]);
    assert_eq!(s, 403, "ListGroups is outside the role policy");
    assert!(body.contains("AccessDenied"));

    // 5. The session policy IS enforced: ListUsers is in the role policy but not in the session
    //    policy, and Floci denies it, as real AWS does.
    let (s, body) = iam(&tmp, &[("Action", "ListUsers")]);
    assert_eq!(s, 403, "ListUsers is outside the session policy");
    assert!(body.contains("AccessDenied"));
    // The same role without a session policy may list users: the denial came from the policy.
    let (wide, _) = assume_role(
        &base_creds,
        REGION,
        &role,
        Some("ext-ok"),
        "ls-e2e-wide",
        None,
        900,
        Some(&sts),
    )
    .expect("AssumeRole without a session policy");
    assert_eq!(iam(&wide, &[("Action", "ListUsers")]).0, 200);

    // 6. Floci does not validate the session policy on AssumeRole: malformed JSON and a policy
    //    over the STS 2048-character packed limit are both accepted, so the gateway's renderer
    //    (task 2.2) must check size and shape itself.
    assume(&base_creds, "ext-ok", "{not-json").expect("Floci accepts a malformed policy");
    let big = allow(&["iam:ListRoles"; 200], "*");
    assert!(big.len() > 2048);
    assume(&base_creds, "ext-ok", &big).expect("Floci accepts an oversized policy");

    // 7. Unlike moto, a parameter containing spaces (a pretty-printed policy) passes signature
    //    validation. The renderer still emits compact JSON.
    let spaced = "{ \"Version\": \"2012-10-17\", \"Statement\": [] }";
    assume(&base_creds, "ext-ok", spaced).expect("Floci accepts a spaced parameter");
}
