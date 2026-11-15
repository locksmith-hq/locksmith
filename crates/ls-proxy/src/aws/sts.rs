//! M7 AWS: STS AssumeRole for upstream roles, the contained fallback (task 2.1) and the
//! revoke-older-sessions deny policy (task 2.2). Synchronous HTTPS via `ureq`, SigV4 via
//! [`super::sigv4::sign`]. Error messages carry AWS error codes/messages and HTTP status only:
//! never request bodies, response bodies or credentials.

use super::Credentials;
use super::sigv4::{self, Request, Scope};
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

/// Contained credentials last the STS minimum: 15 minutes.
pub const CONTAINED_DURATION_SECS: u32 = 900;

/// Name of the inline role policy written by [`revoke_older_sessions`].
pub const REVOKE_POLICY_NAME: &str = "LocksmithRevokeOlderSessions";

/// Console notice printed when contained credentials are handed out.
pub const CONTAINED_NOTICE: &str = "Contained AWS credentials: these are real temporary STS \
credentials and they are visible to the child process (disclosed but contained). They are \
limited to this project's AWS policy, applied as an STS session policy, and they expire within \
15 minutes. Anything the child does with them before then is not seen or audited by Locksmith.";

const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded; charset=utf-8";
const TIMEOUT: Duration = Duration::from_secs(30);

/// `sts:AssumeRole` signed with `base`, at the regional STS endpoint (or `endpoint`, tests).
/// Returns the temporary credentials and their expiry (unix seconds).
#[allow(clippy::too_many_arguments)]
pub fn assume_role(
    base: &Credentials,
    region: &str,
    role_arn: &str,
    external_id: Option<&str>,
    session_name: &str,
    policy_json: Option<&str>,
    duration_secs: u32,
    endpoint: Option<&str>,
) -> Result<(Credentials, i64), String> {
    check_region(region)?;
    check_role_arn(role_arn)?;
    if !(900..=43200).contains(&duration_secs) {
        return Err(format!(
            "AssumeRole: duration {duration_secs}s is outside 900..=43200"
        ));
    }
    let session = session_name_for(session_name)?;
    let duration = duration_secs.to_string();
    let mut params = vec![
        ("Action", "AssumeRole"),
        ("Version", "2011-06-15"),
        ("RoleArn", role_arn),
        ("RoleSessionName", session.as_str()),
        ("DurationSeconds", duration.as_str()),
    ];
    if let Some(x) = external_id {
        if !(2..=1224).contains(&x.len()) {
            return Err("AssumeRole: external id must be 2..=1224 characters".into());
        }
        params.push(("ExternalId", x));
    }
    if let Some(p) = policy_json {
        if p.trim().is_empty() {
            return Err("AssumeRole: session policy is empty".into());
        }
        params.push(("Policy", p));
    }
    let url = endpoint
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://sts.{region}.amazonaws.com/"));
    let xml = post_query(base, &url, region, "sts", &params)?;
    let creds = between(&xml, "Credentials")
        .ok_or("AssumeRole: response has no Credentials")?
        .to_string();
    let field = |name: &str| {
        between(&creds, name)
            .map(|v| Zeroizing::new(unescape(v)))
            .ok_or_else(|| format!("AssumeRole: response has no {name}"))
    };
    let expiration = field("Expiration")?;
    let expiry =
        time::OffsetDateTime::parse(&expiration, &time::format_description::well_known::Rfc3339)
            .map_err(|_| "AssumeRole: response has a bad Expiration".to_string())?
            .unix_timestamp();
    Ok((
        Credentials {
            access_key_id: field("AccessKeyId")?.to_string(),
            secret_access_key: field("SecretAccessKey")?,
            session_token: Some(field("SessionToken")?),
        },
        expiry,
    ))
}

/// Contained fallback (task 2.1): [`assume_role`] for [`CONTAINED_DURATION_SECS`] with the
/// project policy as a REQUIRED session policy. Print [`CONTAINED_NOTICE`] when handing them out.
pub fn contained(
    base: &Credentials,
    region: &str,
    role_arn: &str,
    external_id: Option<&str>,
    session_name: &str,
    policy_json: Option<&str>,
    endpoint: Option<&str>,
) -> Result<(Credentials, i64), String> {
    let policy = policy_json
        .filter(|p| !p.trim().is_empty())
        .ok_or("contained credentials require a session policy")?;
    assume_role(
        base,
        region,
        role_arn,
        external_id,
        session_name,
        Some(policy),
        CONTAINED_DURATION_SECS,
        endpoint,
    )
}

/// Revoke-older-sessions (task 2.2): IAM `PutRolePolicy` of [`revoke_policy_document`] as the
/// inline policy [`REVOKE_POLICY_NAME`] on the role, denying every session issued before
/// `issued_before_unix`. Signed with `base` (which needs `iam:PutRolePolicy` on the role).
// shortcut: always the global `aws` partition IAM endpoint; pass `endpoint` for aws-cn/aws-us-gov.
pub fn revoke_older_sessions(
    base: &Credentials,
    role_arn: &str,
    issued_before_unix: i64,
    endpoint: Option<&str>,
) -> Result<(), String> {
    check_role_arn(role_arn)?;
    rfc3339(issued_before_unix).ok_or("revoke: timestamp out of range")?;
    let role_name = role_arn.rsplit('/').next().unwrap_or_default();
    let doc = revoke_policy_document(issued_before_unix);
    let params = [
        ("Action", "PutRolePolicy"),
        ("Version", "2010-05-08"),
        ("RoleName", role_name),
        ("PolicyName", REVOKE_POLICY_NAME),
        ("PolicyDocument", doc.as_str()),
    ];
    let url = endpoint.unwrap_or("https://iam.amazonaws.com/");
    post_query(base, url, "us-east-1", "iam", &params).map(drop)
}

/// The deny-all policy for sessions whose token was issued before `issued_before_unix`.
pub fn revoke_policy_document(issued_before_unix: i64) -> String {
    let t = rfc3339(issued_before_unix).unwrap_or_else(|| "1970-01-01T00:00:00Z".into());
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Action":"*","Resource":"*","Condition":{{"DateLessThan":{{"aws:TokenIssueTime":"{t}"}}}}}}]}}"#
    )
}

fn rfc3339(unix: i64) -> Option<String> {
    let t = time::OffsetDateTime::from_unix_timestamp(unix).ok()?;
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    ))
}

/// POST an AWS query-protocol request (form body), SigV4-signed with `base`. Returns the
/// response body on 2xx; on error, the AWS `Code`/`Message` and the HTTP status.
fn post_query(
    base: &Credentials,
    url: &str,
    region: &str,
    service: &str,
    params: &[(&str, &str)],
) -> Result<Zeroizing<String>, String> {
    let action = params
        .iter()
        .find(|(k, _)| *k == "Action")
        .map_or("", |(_, v)| *v);
    let uri: ureq::http::Uri = url
        .parse()
        .map_err(|_| format!("{action}: bad endpoint URL"))?;
    let host = uri
        .authority()
        .ok_or_else(|| format!("{action}: endpoint URL has no host"))?
        .as_str()
        .to_string();
    let body = Zeroizing::new(
        params
            .iter()
            .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
            .collect::<Vec<_>>()
            .join("&"),
    );
    let req = Request {
        method: "POST".into(),
        path: uri.path().to_string(),
        query: String::new(),
        headers: vec![
            ("host".into(), host),
            ("content-type".into(), FORM_CONTENT_TYPE.into()),
        ],
        payload_hash: sigv4::hex_sha256(body.as_bytes()),
    };
    let amz_date = sigv4::amz_date(SystemTime::now());
    let scope = Scope {
        date: amz_date[..8].to_string(),
        region: region.into(),
        service: service.into(),
    };
    let signed = sigv4::sign(&req, base, &scope, &amz_date, &[]);
    let mut rb = ureq::post(url)
        .config()
        .http_status_as_error(false)
        .timeout_global(Some(TIMEOUT))
        .build()
        .header("content-type", FORM_CONTENT_TYPE);
    for (k, v) in &signed.headers {
        rb = rb.header(*k, v.as_str());
    }
    let mut resp = rb
        .send(body.as_bytes())
        .map_err(|e| format!("{action}: request failed: {e}"))?;
    let status = resp.status().as_u16();
    let text = Zeroizing::new(
        resp.body_mut()
            .read_to_string()
            .map_err(|_| format!("{action}: could not read the response (HTTP {status})"))?,
    );
    if (200..300).contains(&status) {
        return Ok(text);
    }
    let code = between(&text, "Code").map(unescape);
    let message = between(&text, "Message").map(unescape);
    Err(match (code, message) {
        (Some(c), Some(m)) => format!("{action} failed: HTTP {status} {c}: {m}"),
        (Some(c), None) => format!("{action} failed: HTTP {status} {c}"),
        _ => format!("{action} failed: HTTP {status}"),
    })
}

/// Text of the first `<name>…</name>` element (no attributes) in `xml`, still escaped.
fn between<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = xml.find(&open)? + open.len();
    let len = xml[start..].find(&format!("</{name}>"))?;
    Some(&xml[start..start + len])
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// RFC 3986 percent-encoding (unreserved kept), as AWS query requests expect.
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn check_region(region: &str) -> Result<(), String> {
    let ok = !region.is_empty()
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    ok.then_some(())
        .ok_or_else(|| format!("bad AWS region {region:?}"))
}

/// `arn:aws[-a-z]*:iam::<12 digits>:role/<path/>name`.
fn check_role_arn(arn: &str) -> Result<(), String> {
    let bad = || format!("bad IAM role ARN {arn:?}");
    let rest = arn.strip_prefix("arn:aws").ok_or_else(bad)?;
    let (partition, rest) = rest.split_once(":iam::").ok_or_else(bad)?;
    let (account, role) = rest.split_once(":role/").ok_or_else(bad)?;
    let ok = partition
        .bytes()
        .all(|b| b == b'-' || b.is_ascii_lowercase())
        && account.len() == 12
        && account.bytes().all(|b| b.is_ascii_digit())
        && !role.is_empty()
        && !role.ends_with('/')
        && !role.contains(char::is_whitespace);
    ok.then_some(()).ok_or_else(bad)
}

/// `name` mapped to `[\w+=,.@-]{2,64}`: other characters become `-`, then truncated to 64.
fn session_name_for(name: &str) -> Result<String, String> {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "_+=,.@-".contains(c) {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    if s.len() < 2 {
        return Err("AssumeRole: session name must be at least 2 characters".into());
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_arns() {
        for ok in [
            "arn:aws:iam::123456789012:role/dev",
            "arn:aws-us-gov:iam::123456789012:role/path/to/dev",
            "arn:aws-cn:iam::123456789012:role/a+b=c,d.e@f-g_h",
        ] {
            assert!(check_role_arn(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "arn:aws:iam::12345678901:role/dev",
            "arn:aws:iam::123456789012:user/dev",
            "arn:aws:iam::123456789012:role/",
            "arn:aws:sts::123456789012:role/dev",
            "arn:AWS:iam::123456789012:role/dev",
            "arn:aws:iam::123456789012:role/a b",
        ] {
            assert!(check_role_arn(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn session_names() {
        assert_eq!(
            session_name_for("locksmith-lease 1/x").unwrap(),
            "locksmith-lease-1-x"
        );
        assert_eq!(session_name_for(&"a".repeat(100)).unwrap().len(), 64);
        assert!(session_name_for("a").is_err());
        assert_eq!(session_name_for("é!").unwrap(), "--");
    }

    #[test]
    fn xml_and_encoding() {
        let x = "<A><Code>X</Code><Message>a &lt;b&gt; &amp;amp;</Message></A>";
        assert_eq!(between(x, "Code"), Some("X"));
        assert_eq!(unescape(between(x, "Message").unwrap()), "a <b> &amp;");
        assert_eq!(between(x, "Nope"), None);
        assert_eq!(encode("a b/+=~"), "a%20b%2F%2B%3D~");
        assert_eq!(rfc3339(0).unwrap(), "1970-01-01T00:00:00Z");
    }
}
