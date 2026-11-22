//! Workload identity login (D4 task 5.1): fetch an external OIDC token from the runner (GitHub
//! Actions request variables, or a projected Kubernetes token file), exchange it at the control
//! plane's `POST /v1/workload-tokens` and keep only the resulting agent token in `agent.json`.
//!
//! The external token lives in a `SecretString` for one call: it is never an argv element, never
//! written to disk and never part of an error or output. Errors are fixed slugs like the rest of
//! this crate.

use super::*;

/// Environment variable naming the trust policy handle (`lsw_...`, not a secret).
pub const WORKLOAD_POLICY_ENV: &str = "LOCKSMITH_WORKLOAD_POLICY";
/// Environment variable with the audience to request (default: the control plane URL).
pub const WORKLOAD_AUDIENCE_ENV: &str = "LOCKSMITH_WORKLOAD_AUDIENCE";
/// Environment variable with the projected token file (Kubernetes).
pub const WORKLOAD_TOKEN_FILE_ENV: &str = "LOCKSMITH_WORKLOAD_TOKEN_FILE";
/// GitHub Actions runner variable: URL to request an OIDC token from.
pub const GITHUB_REQUEST_URL_ENV: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
/// GitHub Actions runner variable: bearer token for that request.
pub const GITHUB_REQUEST_TOKEN_ENV: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
/// Kubernetes default service account token path, used when no file is given.
pub const KUBERNETES_DEFAULT_TOKEN_FILE: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/token";
/// Largest token file or runner response read (an OIDC JWT is a few KiB).
const MAX_TOKEN_BYTES: u64 = 64 * 1024;

/// `lsw_` followed by base64url characters: shape check only, the server decides validity.
pub fn valid_policy_handle(h: &str) -> bool {
    h.len() <= 256
        && h.strip_prefix("lsw_").is_some_and(|r| {
            !r.is_empty()
                && r.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'=')
        })
}

/// The runner request URL: `https`, or `http` on loopback (tests); no credentials. A query is
/// expected (GitHub adds one) and kept.
fn parse_runner_url(raw: &str) -> Result<Url> {
    let bad = || usage("the runner token request URL is not an https URL");
    let url = Url::parse(raw).map_err(|_| bad())?;
    let loopback = match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(a)) => a.is_loopback(),
        Some(url::Host::Ipv6(a)) => a.is_loopback(),
        None => return Err(bad()),
    };
    let ok = url.scheme() == "https" || (url.scheme() == "http" && loopback);
    if !ok || !url.username().is_empty() || url.password().is_some() {
        return Err(bad());
    }
    Ok(url)
}

/// Ask the GitHub Actions runner for an OIDC token with `audience`.
pub fn fetch_github_token(
    request_url: &str,
    request_token: &SecretString,
    audience: &str,
) -> Result<SecretString> {
    let mut url = parse_runner_url(request_url)?;
    url.query_pairs_mut().append_pair("audience", audience);
    let resp = client()?
        .get(url)
        .bearer_auth(request_token.expose_secret())
        .header("accept", "application/json")
        .send()
        .map_err(|e| transport(&e))?;
    let status = resp.status();
    let body = read_body(resp)?;
    if !status.is_success() {
        return Err(fail(&format!(
            "the runner refused the identity token request ({})",
            status.as_u16()
        )));
    }
    #[derive(Deserialize)]
    struct Value {
        value: String,
    }
    let v: Value = serde_json::from_slice(&body)
        .map_err(|_| fail("the runner identity token response is unexpected"))?;
    let v = Zeroizing::new(v.value);
    if v.trim().is_empty() {
        return Err(fail("the runner returned no identity token"));
    }
    Ok(SecretString::from(v.trim().to_owned()))
}

/// Read a projected service account token file (refuses an oversized or empty file).
pub fn read_token_file(path: &std::path::Path) -> Result<SecretString> {
    let mut buf = Zeroizing::new(Vec::new());
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_TOKEN_BYTES + 1).read_to_end(&mut buf))
        .map_err(|_| fail("cannot read the projected token file"))?;
    if buf.len() as u64 > MAX_TOKEN_BYTES {
        return Err(fail("the projected token file is too large"));
    }
    let s = Zeroizing::new(
        String::from_utf8(std::mem::take(&mut *buf))
            .map_err(|_| fail("the projected token file is not text"))?,
    );
    let t = s.trim();
    if t.is_empty() {
        return Err(fail("the projected token file is empty"));
    }
    Ok(SecretString::from(t.to_owned()))
}

/// Exchange an external token at `POST /v1/workload-tokens` and save the agent token.
pub fn login_workload(
    control_plane: &str,
    gateway: &str,
    policy: &str,
    external: &SecretString,
) -> Result<(State, u64)> {
    let control_plane = parse_endpoint(control_plane)?;
    let gateway = parse_endpoint(gateway)?;
    if !valid_policy_handle(policy) {
        return Err(usage(
            "the workload policy handle is not valid (expected lsw_...)",
        ));
    }
    let mut req = Zeroizing::new(
        serde_json::to_vec(&json!({ "policy": policy, "token": external.expose_secret() }))
            .map_err(|_| fail("cannot encode the request"))?,
    );
    let resp = client()?
        .post(format!("{control_plane}/v1/workload-tokens"))
        .header("content-type", "application/json")
        .body(std::mem::take(&mut *req))
        .send()
        .map_err(|e| transport(&e))?;
    let status = resp.status();
    let body = read_body(resp)?;
    if !status.is_success() {
        return Err(Error {
            kind: ErrorKind::Failure,
            message: format!(
                "workload login failed: {} (token not accepted by the policy)",
                status.as_u16()
            ),
        });
    }
    let t: TokenResponse = serde_json::from_slice(&body)
        .map_err(|_| fail("workload login failed: unexpected response from the control plane"))?;
    let state = State {
        token: SecretString::from(t.access_token),
        expires_at: now_unix() + t.expires_in,
        control_plane_url: control_plane,
        gateway_url: gateway,
    };
    state.save()?;
    Ok((state, t.expires_in))
}
