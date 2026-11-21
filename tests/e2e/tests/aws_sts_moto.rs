//! d2-aws-sts task 1.2 spike: `ls-proxy::aws::sts::assume_role` against moto
//! (`docker compose -f infra/compose/compose.yaml up -d --wait moto`, 127.0.0.1:5000 or
//! `E2E_MOTO_URL`). Records what moto 5.1.20 enforces; the findings are in
//! `openspec/changes/d2-aws-sts/design.md` (decision 6).
//!
//! The tests skip (pass with a note) when moto is unreachable; set `E2E_REQUIRE_MOTO=1` to make
//! that a failure. All credentials are moto fakes and are never printed.
//!
//! moto's IAM enforcement mode is server-global (`POST /moto-api/reset-auth`), so every test
//! here holds [`LOCK`] (`cargo test`, one process) and runs in the nextest `moto` test group
//! (`.config/nextest.toml`, one at a time across processes); the IAM-mode test restores
//! "auth off" on exit. Do not run another moto client against the same server meanwhile.
//!
//! Run: `cargo nextest run -p ls-e2e --test aws_sts_moto`.

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ls_e2e::{moto, uniq};
use ls_proxy::aws::Credentials;
use ls_proxy::aws::sigv4::{self, Request, Scope};
use ls_proxy::aws::sts::assume_role;
use zeroize::Zeroizing;

const ACCOUNT: &str = "123456789012";
const REGION: &str = "us-east-1";

static LOCK: Mutex<()> = Mutex::new(());

/// The base URL when moto answers, else `None` (skip), or panic with `E2E_REQUIRE_MOTO=1`.
fn moto_or_skip(test: &str) -> Option<(String, MutexGuard<'static, ()>)> {
    let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let base = moto();
    let up = agent()
        .get(&format!("{base}/moto-api/"))
        .call()
        .is_ok_and(|r| r.status().is_success());
    if up {
        return Some((base, guard));
    }
    assert!(
        std::env::var("E2E_REQUIRE_MOTO").is_err(),
        "{test}: moto is not reachable at {base} and E2E_REQUIRE_MOTO is set"
    );
    eprintln!("{test}: skipped, moto is not reachable at {base} (start it with `just up`)");
    None
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into()
}

/// Fake base key (not an AWS key format the leak scanners match; moto accepts anything when
/// IAM mode is off).
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

/// A SigV4-signed AWS query-protocol POST to moto. Returns (status, body). Never print the body
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
    let mut resp = rb.send(body.as_bytes()).expect("reach moto");
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

/// `POST /moto-api/reset-auth`: `"0"` turns IAM enforcement on for every request, `"inf"` off.
fn set_iam_mode(base: &str, on: bool) {
    let r = agent()
        .post(&format!("{base}/moto-api/reset-auth"))
        .send(if on { "0" } else { "inf" })
        .expect("reach moto reset-auth");
    assert_eq!(r.status().as_u16(), 200, "moto reset-auth");
}

/// Turns IAM mode off again even when an assertion fails.
struct IamModeOff<'a>(&'a str);
impl Drop for IamModeOff<'_> {
    fn drop(&mut self) {
        set_iam_mode(self.0, false);
    }
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

/// AssumeRole returns temporary keys moto recognises as the assumed role (IAM mode off: the
/// role need not exist and the base key is not checked).
#[test]
fn assume_role_returns_usable_keys() {
    let Some((base, _g)) = moto_or_skip("assume_role_returns_usable_keys") else {
        return;
    };
    set_iam_mode(&base, false);
    let role_name = uniq("ls-e2e-spike");
    let role = format!("arn:aws:iam::{ACCOUNT}:role/{role_name}");
    let policy = allow(&["iam:ListRoles"], "*");
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
    .expect("AssumeRole against moto");

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

    // How later tasks assert the session policy: moto stores the Policy and ExternalId it
    // received per assumed role, readable from `GET /moto-api/data.json` by access key id.
    let (policy_seen, ext_seen) = moto_session(&base, &tmp.access_key_id);
    assert_eq!(policy_seen.as_deref(), Some(policy.as_str()));
    assert_eq!(ext_seen.as_deref(), Some("ext-id-1"));
}

/// The (Policy, ExternalId) moto recorded for the assumed-role session with `access_key_id`.
/// `data.json` also holds moto's fake secrets: only these two fields are taken from it.
fn moto_session(base: &str, access_key_id: &str) -> (Option<String>, Option<String>) {
    let mut r = agent()
        .get(&format!("{base}/moto-api/data.json"))
        .call()
        .expect("reach moto data.json");
    let v: serde_json::Value =
        serde_json::from_str(&r.body_mut().read_to_string().unwrap()).expect("data.json");
    let role = v["sts"]["AssumedRole"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|x| x["access_key_id"].as_str() == Some(access_key_id))
        })
        .expect("moto recorded the session");
    let field = |k: &str| role[k].as_str().map(str::to_string);
    (field("policy"), field("external_id"))
}

/// What moto checks with IAM mode on (`reset-auth 0`). The asserts record moto 5.1.20's
/// behaviour; a failure after a moto upgrade means design.md decision 6 needs revisiting.
#[test]
fn moto_iam_mode_enforcement() {
    let Some((base, _g)) = moto_or_skip("moto_iam_mode_enforcement") else {
        return;
    };
    set_iam_mode(&base, false);
    let fake = fake_base();
    let iam = |creds: &Credentials, params: &[(&str, &str)]| {
        let mut p = params.to_vec();
        p.push(("Version", "2010-05-08"));
        query(&base, creds, "iam", &p)
    };

    // Setup with IAM mode off: a base IAM user allowed to assume one role, the role trusting
    // that user with an external id, and a role policy allowing ListRoles and ListUsers.
    let user = uniq("ls-e2e-base");
    let role_name = uniq("ls-e2e-role");
    let role = format!("arn:aws:iam::{ACCOUNT}:role/{role_name}");
    let user_arn = format!("arn:aws:iam::{ACCOUNT}:user/{user}");
    assert_eq!(
        iam(&fake, &[("Action", "CreateUser"), ("UserName", &user)]).0,
        200
    );
    let (s, key_xml) = iam(&fake, &[("Action", "CreateAccessKey"), ("UserName", &user)]);
    assert_eq!(s, 200, "CreateAccessKey");
    let base_creds = Credentials {
        access_key_id: between(&key_xml, "AccessKeyId").unwrap().to_string(),
        secret_access_key: Zeroizing::new(between(&key_xml, "SecretAccessKey").unwrap().into()),
        session_token: None,
    };
    drop(key_xml);
    let user_policy = allow(&["sts:AssumeRole"], &role);
    let s = iam(
        &fake,
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
        &fake,
        &[
            ("Action", "CreateRole"),
            ("RoleName", &role_name),
            ("AssumeRolePolicyDocument", &trust),
        ],
    );
    assert_eq!(s.0, 200, "CreateRole");
    let role_policy = allow(&["iam:ListRoles", "iam:ListUsers"], "*");
    let s = iam(
        &fake,
        &[
            ("Action", "PutRolePolicy"),
            ("RoleName", &role_name),
            ("PolicyName", "work"),
            ("PolicyDocument", &role_policy),
        ],
    );
    assert_eq!(s.0, 200, "PutRolePolicy");

    set_iam_mode(&base, true);
    let _off = IamModeOff(&base);
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
    let e = assume(&fake, "ext-ok", &session_policy)
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

    // 3. Correct external id: usable keys, and moto verifies their SigV4 signature.
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

    // 5. The session policy is NOT enforced: ListUsers is in the role policy but not in the
    //    session policy, and moto allows it (real AWS denies it). Enforcement must therefore
    //    be asserted from the Policy parameter sent to STS, plus the P1 real-AWS check.
    let (s, _) = iam(&tmp, &[("Action", "ListUsers")]);
    assert_eq!(
        s, 200,
        "moto now enforces session policies: update design.md decision 6"
    );

    // 6. moto does not validate the session policy on AssumeRole: malformed JSON and a policy
    //    over the STS 2048-character packed limit are both accepted, so the gateway's renderer
    //    (task 2.2) must check size and shape itself.
    assume(&base_creds, "ext-ok", "{not-json").expect("moto accepts malformed policy");
    let big = allow(&["iam:ListRoles"; 200], "*");
    assert!(big.len() > 2048);
    assume(&base_creds, "ext-ok", &big).expect("moto accepts an oversized policy");

    // 7. moto quirk: in IAM mode it re-encodes form parameters for signature verification, so a
    //    parameter containing a space (here a pretty-printed policy) fails with
    //    SignatureDoesNotMatch although real AWS accepts it. Render compact JSON.
    let spaced = "{ \"Version\": \"2012-10-17\", \"Statement\": [] }";
    let e = assume(&base_creds, "ext-ok", spaced)
        .err()
        .expect("moto rejects a spaced parameter in IAM mode");
    assert!(e.contains("SignatureDoesNotMatch"), "{e}");
}
