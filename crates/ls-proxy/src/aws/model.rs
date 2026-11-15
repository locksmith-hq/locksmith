//! M7 AWS: map a verified request to `(IAM action, resource)` (design D3).
//!
//! The operation table in `data/aws-model.json` is generated from botocore service models
//! (Apache-2.0, Copyright Amazon.com, Inc. or its affiliates) by `scripts/gen-aws-model.py`;
//! regenerate with `python3 scripts/gen-aws-model.py [BOTOCORE_DATA_DIR]`.
//!
//! Operation identification follows what AWS itself routes on, per the service's protocols:
//! `json` by `X-Amz-Target`, `query`/`ec2` by the `Action` parameter, `rest-*` by method, path
//! template, required query keys and required headers. Ambiguous requests resolve to no action
//! (denied).

use super::Call;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

#[derive(Deserialize)]
struct Table {
    services: BTreeMap<String, Service>,
}

#[derive(Deserialize)]
struct Service {
    endpoint: String,
    iam: String,
    protocols: Vec<String>,
    targets: Vec<String>,
    ops: BTreeMap<String, Option<Rest>>,
}

#[derive(Deserialize)]
struct Rest {
    m: String,
    u: String,
    #[serde(default)]
    h: Vec<String>,
}

fn table() -> &'static Table {
    static T: OnceLock<Table> = OnceLock::new();
    T.get_or_init(|| {
        serde_json::from_str(include_str!("data/aws-model.json")).expect("vendored aws-model.json")
    })
}

/// `(signing name, operation, IAM action)` where the IAM action is not `<prefix>:<operation>`.
/// A value with `:` is a full action in another prefix.
const OVERRIDES: &[(&str, &str, &str)] = &[
    ("s3", "ListObjects", "ListBucket"),
    ("s3", "ListObjectsV2", "ListBucket"),
    ("s3", "HeadBucket", "ListBucket"),
    ("s3", "ListObjectVersions", "ListBucketVersions"),
    ("s3", "ListMultipartUploads", "ListBucketMultipartUploads"),
    ("s3", "ListParts", "ListMultipartUploadParts"),
    ("s3", "ListBuckets", "ListAllMyBuckets"),
    ("s3", "ListDirectoryBuckets", "ListAllMyBuckets"),
    ("s3", "HeadObject", "GetObject"),
    ("s3", "SelectObjectContent", "GetObject"),
    ("s3", "PutObject", "PutObject"),
    ("s3", "UploadPart", "PutObject"),
    ("s3", "CreateMultipartUpload", "PutObject"),
    ("s3", "CompleteMultipartUpload", "PutObject"),
    // shortcut: CopyObject/UploadPartCopy also need s3:GetObject on the source
    // (x-amz-copy-source), which is not checked; Call carries one action.
    ("s3", "CopyObject", "PutObject"),
    ("s3", "UploadPartCopy", "PutObject"),
    ("s3", "DeleteObjects", "DeleteObject"),
    ("s3", "GetBucketCors", "GetBucketCORS"),
    ("s3", "PutBucketCors", "PutBucketCORS"),
    ("s3", "DeleteBucketCors", "PutBucketCORS"),
    ("s3", "GetBucketEncryption", "GetEncryptionConfiguration"),
    ("s3", "PutBucketEncryption", "PutEncryptionConfiguration"),
    ("s3", "DeleteBucketEncryption", "PutEncryptionConfiguration"),
    ("s3", "GetBucketLifecycle", "GetLifecycleConfiguration"),
    (
        "s3",
        "GetBucketLifecycleConfiguration",
        "GetLifecycleConfiguration",
    ),
    ("s3", "PutBucketLifecycle", "PutLifecycleConfiguration"),
    (
        "s3",
        "PutBucketLifecycleConfiguration",
        "PutLifecycleConfiguration",
    ),
    ("s3", "DeleteBucketLifecycle", "PutLifecycleConfiguration"),
    ("s3", "GetBucketReplication", "GetReplicationConfiguration"),
    ("s3", "PutBucketReplication", "PutReplicationConfiguration"),
    (
        "s3",
        "DeleteBucketReplication",
        "PutReplicationConfiguration",
    ),
    ("s3", "DeleteBucketTagging", "PutBucketTagging"),
    (
        "s3",
        "GetBucketNotificationConfiguration",
        "GetBucketNotification",
    ),
    (
        "s3",
        "PutBucketNotificationConfiguration",
        "PutBucketNotification",
    ),
    (
        "s3",
        "GetBucketAccelerateConfiguration",
        "GetAccelerateConfiguration",
    ),
    (
        "s3",
        "PutBucketAccelerateConfiguration",
        "PutAccelerateConfiguration",
    ),
    ("s3", "GetPublicAccessBlock", "GetBucketPublicAccessBlock"),
    ("s3", "PutPublicAccessBlock", "PutBucketPublicAccessBlock"),
    (
        "s3",
        "DeletePublicAccessBlock",
        "PutBucketPublicAccessBlock",
    ),
    (
        "s3",
        "DeleteBucketOwnershipControls",
        "PutBucketOwnershipControls",
    ),
    (
        "s3",
        "GetObjectLockConfiguration",
        "GetBucketObjectLockConfiguration",
    ),
    (
        "s3",
        "PutObjectLockConfiguration",
        "PutBucketObjectLockConfiguration",
    ),
    (
        "s3",
        "GetBucketAnalyticsConfiguration",
        "GetAnalyticsConfiguration",
    ),
    (
        "s3",
        "ListBucketAnalyticsConfigurations",
        "GetAnalyticsConfiguration",
    ),
    (
        "s3",
        "PutBucketAnalyticsConfiguration",
        "PutAnalyticsConfiguration",
    ),
    (
        "s3",
        "DeleteBucketAnalyticsConfiguration",
        "PutAnalyticsConfiguration",
    ),
    (
        "s3",
        "GetBucketInventoryConfiguration",
        "GetInventoryConfiguration",
    ),
    (
        "s3",
        "ListBucketInventoryConfigurations",
        "GetInventoryConfiguration",
    ),
    (
        "s3",
        "PutBucketInventoryConfiguration",
        "PutInventoryConfiguration",
    ),
    (
        "s3",
        "DeleteBucketInventoryConfiguration",
        "PutInventoryConfiguration",
    ),
    (
        "s3",
        "GetBucketMetricsConfiguration",
        "GetMetricsConfiguration",
    ),
    (
        "s3",
        "ListBucketMetricsConfigurations",
        "GetMetricsConfiguration",
    ),
    (
        "s3",
        "PutBucketMetricsConfiguration",
        "PutMetricsConfiguration",
    ),
    (
        "s3",
        "DeleteBucketMetricsConfiguration",
        "PutMetricsConfiguration",
    ),
    (
        "s3",
        "GetBucketIntelligentTieringConfiguration",
        "GetIntelligentTieringConfiguration",
    ),
    (
        "s3",
        "ListBucketIntelligentTieringConfigurations",
        "GetIntelligentTieringConfiguration",
    ),
    (
        "s3",
        "PutBucketIntelligentTieringConfiguration",
        "PutIntelligentTieringConfiguration",
    ),
    (
        "s3",
        "DeleteBucketIntelligentTieringConfiguration",
        "PutIntelligentTieringConfiguration",
    ),
    ("s3", "CreateSession", "s3express:CreateSession"),
    (
        "s3",
        "WriteGetObjectResponse",
        "s3-object-lambda:WriteGetObjectResponse",
    ),
    ("lambda", "Invoke", "InvokeFunction"),
    ("lambda", "InvokeWithResponseStream", "InvokeFunction"),
];

/// Read-only by IAM action name: Get*, List*, Describe*, Head*, BatchGet*, Query, Scan.
pub fn is_read_only(action: &str) -> bool {
    let Some((_, op)) = action.split_once(':') else {
        return false;
    };
    READ_PREFIXES.iter().any(|p| op.starts_with(p)) || op == "Query" || op == "Scan"
}

const READ_PREFIXES: &[&str] = &["Get", "List", "Describe", "Head", "BatchGet"];

/// IAM action patterns equivalent to [`is_read_only`] over the vendored services, e.g.
/// `dynamodb:Query`, `s3:Get*`. Sorted, deduplicated.
pub(crate) fn read_only_patterns() -> Vec<String> {
    let mut out = BTreeSet::new();
    for (name, svc) in &table().services {
        for op in svc.ops.keys() {
            let action = iam_action(name, svc, op);
            if !is_read_only(&action) {
                continue;
            }
            let (prefix, op) = action.split_once(':').unwrap_or_default();
            out.insert(match READ_PREFIXES.iter().find(|p| op.starts_with(*p)) {
                Some(p) => format!("{prefix}:{p}*"),
                None => action.clone(),
            });
        }
    }
    out.into_iter().collect()
}

fn iam_action(name: &str, svc: &Service, op: &str) -> String {
    match OVERRIDES.iter().find(|(s, o, _)| *s == name && *o == op) {
        Some((_, _, a)) if a.contains(':') => (*a).to_owned(),
        Some((_, _, a)) => format!("{}:{a}", svc.iam),
        None => format!("{}:{op}", svc.iam),
    }
}

/// Map a verified request to a [`Call`]. `service` is the signing name from the credential
/// scope; `path` excludes the query; `query` is the raw query string without `?`. `action` is
/// `None` when the operation is unknown or the request is ambiguous; `resource` is `*` when it
/// cannot be derived.
pub fn resolve(
    service: &str,
    region: &str,
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Call {
    let (action, resource) = table()
        .services
        .get(service)
        .and_then(|svc| {
            let req = Req::new(service, method, path, query, headers, body);
            let (op, labels) = identify(svc, &req)?;
            let resource = derive_resource(service, region, op, &labels, &req);
            Some((Some(iam_action(service, svc, op)), resource))
        })
        .unwrap_or((None, "*".to_owned()));
    Call {
        service: service.to_owned(),
        region: region.to_owned(),
        action,
        resource,
    }
}

/// Upstream host for a signing name, e.g. `dynamodb.us-east-1.amazonaws.com`. For S3 with a
/// DNS-compatible bucket (no dots) returns the virtual-hosted form `<bucket>.s3.<region>...`;
/// any other bucket gets the path-style host, so the caller must then keep the bucket in the
/// path. `None` for an unknown service or a malformed region.
pub fn endpoint_host(service: &str, region: &str, bucket: Option<&str>) -> Option<String> {
    let svc = table().services.get(service)?;
    let region_ok = !region.is_empty()
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !region_ok {
        return None;
    }
    let suffix = if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    };
    if service == "iam" && partition(region) == "aws" {
        return Some("iam.amazonaws.com".to_owned());
    }
    Some(match bucket {
        Some(b) if service == "s3" && dns_bucket(b) => format!("{b}.s3.{region}.{suffix}"),
        _ => format!("{}.{region}.{suffix}", svc.endpoint),
    })
}

/// Whether `service` speaks only JSON protocols (`json`, `rest-json`), so its errors are JSON.
pub fn json_protocol(service: &str) -> bool {
    table()
        .services
        .get(service)
        .is_some_and(|s| s.protocols.iter().all(|p| p.contains("json")))
}

/// Bucket named by a virtual-hosted S3 `Host` (`<bucket>.s3[.-]...amazonaws.com[.cn]` or
/// `<bucket>.localhost`), port ignored. `None` for path-style hosts.
pub fn s3_bucket_from_host(host: &str) -> Option<&str> {
    let host = host.rsplit_once(':').map_or(host, |(h, p)| {
        if p.bytes().all(|b| b.is_ascii_digit()) {
            h
        } else {
            host
        }
    });
    let bucket = if let Some(b) = host.strip_suffix(".localhost") {
        b
    } else if host.ends_with(".amazonaws.com") || host.ends_with(".amazonaws.com.cn") {
        let i = host.rfind(".s3.").or_else(|| host.rfind(".s3-"))?;
        &host[..i]
    } else {
        return None;
    };
    (!bucket.is_empty()).then_some(bucket)
}

fn dns_bucket(b: &str) -> bool {
    (3..=63).contains(&b.len())
        && b.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && !b.starts_with('-')
        && !b.ends_with('-')
}

fn partition(region: &str) -> &'static str {
    if region.starts_with("cn-") {
        "aws-cn"
    } else if region.starts_with("us-gov-") {
        "aws-us-gov"
    } else {
        "aws"
    }
}

struct Req<'a> {
    method: &'a str,
    path: String,
    headers: &'a [(String, String)],
    query: Vec<(String, String)>,
    form: Vec<(String, String)>,
    json: Option<Value>,
}

impl<'a> Req<'a> {
    fn new(
        service: &str,
        method: &'a str,
        path: &str,
        query: &str,
        headers: &'a [(String, String)],
        body: &[u8],
    ) -> Self {
        let mut req = Req {
            method,
            path: path.to_owned(),
            headers,
            query: pairs(query),
            form: Vec::new(),
            json: None,
        };
        let ctype = req
            .header("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if ctype.contains("x-www-form-urlencoded") {
            req.form = pairs(&String::from_utf8_lossy(body));
        } else if ctype.contains("json") {
            req.json = serde_json::from_slice(body).ok();
        }
        if service == "s3"
            && let Some(bucket) = req.header("host").and_then(s3_bucket_from_host)
        {
            req.path = format!("/{bucket}{}", req.path);
        }
        req
    }

    /// The header value when present exactly once (case-insensitive name).
    fn header(&self, name: &str) -> Option<&'a str> {
        let mut it = self
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name));
        let (_, v) = it.next()?;
        it.next().is_none().then_some(v.trim())
    }

    /// A parameter from the query, the form body or the top level of a JSON body.
    fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .chain(&self.form)
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .or_else(|| self.json.as_ref()?.get(name)?.as_str())
    }
}

fn identify<'t>(svc: &'t Service, req: &Req) -> Option<(&'t str, BTreeMap<String, String>)> {
    let has = |p: &str| svc.protocols.iter().any(|x| x == p);
    if has("rest-json") || has("rest-xml") {
        return match_rest(svc, req);
    }
    let op = |name: &str| svc.ops.get_key_value(name).map(|(k, _)| k.as_str());
    // A signal that is present but does not resolve makes the whole request unknown.
    let json = has("json")
        .then(|| {
            let target = req.header("x-amz-target");
            let present = req
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("x-amz-target"));
            present.then(|| {
                let (prefix, name) = target?.split_once('.')?;
                svc.targets.iter().any(|t| t == prefix).then_some(())?;
                op(name)
            })
        })
        .flatten();
    let query = (has("query") || has("ec2"))
        .then(|| {
            let actions: Vec<&str> = req
                .query
                .iter()
                .chain(&req.form)
                .filter(|(k, _)| k == "Action")
                .map(|(_, v)| v.as_str())
                .collect();
            let first = *actions.first()?;
            Some(
                actions
                    .iter()
                    .all(|a| *a == first)
                    .then(|| op(first))
                    .flatten(),
            )
        })
        .flatten();
    let name = match (json, query) {
        (Some(a), Some(b)) => (a == b).then_some(a).flatten(),
        (Some(a), None) | (None, Some(a)) => a,
        (None, None) => None,
    }?;
    Some((name, BTreeMap::new()))
}

/// Path labels captured from a REST template, percent-decoded.
type Labels = BTreeMap<String, String>;
/// Template specificity: (literal segments, required query keys + headers, non-greedy labels).
type Score = (usize, usize, usize);

fn match_rest<'t>(svc: &'t Service, req: &Req) -> Option<(&'t str, BTreeMap<String, String>)> {
    let mut best: Option<(Score, Vec<(&'t str, Labels)>)> = None;
    for (name, rest) in &svc.ops {
        let Some(rest) = rest else { continue };
        if !rest.m.eq_ignore_ascii_case(req.method) {
            continue;
        }
        let Some((score, labels)) = match_template(rest, req) else {
            continue;
        };
        match &mut best {
            Some((s, v)) if *s == score => v.push((name, labels)),
            Some((s, _)) if *s > score => {}
            _ => best = Some((score, vec![(name, labels)])),
        }
    }
    let (_, mut found) = best?;
    // Ties are fine only when every candidate is the same IAM action (e.g. S3 legacy aliases).
    let action = |op: &'t str| -> &'t str {
        OVERRIDES
            .iter()
            .find(|(_, o, _)| *o == op)
            .map_or(op, |(_, _, a)| a)
    };
    let first = action(found[0].0);
    found
        .iter()
        .all(|(op, _)| action(op) == first)
        .then(|| found.swap_remove(0))
}

/// Specificity is (literal segments, required query keys + headers, non-greedy labels).
fn match_template(rest: &Rest, req: &Req) -> Option<(Score, Labels)> {
    let (tpath, tquery) = rest.u.split_once('?').unwrap_or((&rest.u, ""));
    let segs: Vec<&str> = req
        .path
        .strip_prefix('/')
        .unwrap_or(&req.path)
        .split('/')
        .collect();
    let mut labels = BTreeMap::new();
    let (mut literals, mut plain) = (0, 0);
    let mut i = 0;
    for t in tpath.split('/').filter(|s| !s.is_empty()) {
        if let Some(label) = t.strip_prefix('{').and_then(|l| l.strip_suffix("+}")) {
            let rest = segs.get(i..)?.join("/");
            if rest.is_empty() {
                return None;
            }
            labels.insert(label.to_owned(), decode(&rest, false));
            i = segs.len();
            continue;
        }
        let seg = segs.get(i).filter(|s| !s.is_empty())?;
        if let Some(label) = t.strip_prefix('{').and_then(|l| l.strip_suffix('}')) {
            labels.insert(label.to_owned(), decode(seg, false));
            plain += 1;
        } else if *seg == t {
            literals += 1;
        } else {
            return None;
        }
        i += 1;
    }
    if segs
        .get(i..)
        .unwrap_or_default()
        .iter()
        .any(|s| !s.is_empty())
    {
        return None;
    }
    let mut extra = 0;
    for q in tquery.split('&').filter(|q| !q.is_empty()) {
        let (k, v) = q.split_once('=').map_or((q, None), |(k, v)| (k, Some(v)));
        req.query
            .iter()
            .any(|(rk, rv)| rk == k && v.is_none_or(|v| v == rv))
            .then_some(())?;
        extra += 1;
    }
    for h in &rest.h {
        req.header(h)?;
        extra += 1;
    }
    Some(((literals, extra, plain), labels))
}

fn derive_resource(
    service: &str,
    region: &str,
    op: &str,
    labels: &BTreeMap<String, String>,
    req: &Req,
) -> String {
    let p = partition(region);
    let arn_or = |v: &str, f: &dyn Fn(&str) -> String| {
        if v.starts_with("arn:") {
            v.to_owned()
        } else {
            f(v)
        }
    };
    let derived = match service {
        "s3" => labels.get("Bucket").map(|b| match labels.get("Key") {
            _ if op == "DeleteObjects" => format!("arn:{p}:s3:::{b}/*"),
            Some(k) => format!("arn:{p}:s3:::{b}/{k}"),
            None => format!("arn:{p}:s3:::{b}"),
        }),
        "dynamodb" => req
            .param("TableName")
            .map(|t| arn_or(t, &|t| format!("arn:{p}:dynamodb:{region}:*:table/{t}"))),
        "sqs" => req
            .param("QueueUrl")
            .and_then(|u| {
                let mut it = u.trim_end_matches('/').rsplit('/');
                let (name, acct) = (it.next()?, it.next()?);
                (!name.is_empty() && !acct.is_empty())
                    .then(|| format!("arn:{p}:sqs:{region}:{acct}:{name}"))
            })
            .or_else(|| {
                let name = req.param("QueueName")?;
                Some(format!("arn:{p}:sqs:{region}:*:{name}"))
            }),
        "lambda" => labels.get("FunctionName").map(|f| {
            arn_or(f, &|f| {
                if f.contains(":function:") {
                    format!("arn:{p}:lambda:{region}:{f}")
                } else {
                    format!("arn:{p}:lambda:{region}:*:function:{f}")
                }
            })
        }),
        "ssm" => req.param("Name").map(|n| {
            arn_or(n, &|n| {
                format!(
                    "arn:{p}:ssm:{region}:*:parameter/{}",
                    n.trim_start_matches('/')
                )
            })
        }),
        "secretsmanager" => req
            .param("SecretId")
            .filter(|s| s.starts_with("arn:"))
            .map(str::to_owned),
        _ => None,
    };
    derived.unwrap_or_else(|| "*".to_owned())
}

fn pairs(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k, true), decode(v, true))
        })
        .collect()
}

fn decode(s: &str, plus: bool) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |j: usize| b.get(j).and_then(|c| (*c as char).to_digit(16));
        match b[i] {
            b'%' if hex(i + 1).is_some() && hex(i + 2).is_some() => {
                out.push((hex(i + 1).unwrap_or(0) * 16 + hex(i + 2).unwrap_or(0)) as u8);
                i += 3;
                continue;
            }
            b'+' if plus => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn call(
        service: &str,
        method: &str,
        path: &str,
        query: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (Option<String>, String) {
        let c = resolve(
            service,
            "us-east-1",
            method,
            path,
            query,
            &h(headers),
            body.as_bytes(),
        );
        (c.action, c.resource)
    }

    fn some(a: &str, r: &str) -> (Option<String>, String) {
        (Some(a.to_owned()), r.to_owned())
    }

    const FORM: (&str, &str) = (
        "Content-Type",
        "application/x-www-form-urlencoded; charset=utf-8",
    );

    #[test]
    fn s3_rest_xml() {
        let host = [("Host", "127.0.0.1:9000")];
        assert_eq!(
            call(
                "s3",
                "GET",
                "/app-bucket",
                "list-type=2&prefix=&delimiter=%2F",
                &host,
                ""
            ),
            some("s3:ListBucket", "arn:aws:s3:::app-bucket")
        );
        assert_eq!(
            call("s3", "GET", "/", "", &host, ""),
            some("s3:ListAllMyBuckets", "*")
        );
        assert_eq!(
            call(
                "s3",
                "PUT",
                "/app-bucket/dir/my%20file.txt",
                "",
                &host,
                "data"
            ),
            some("s3:PutObject", "arn:aws:s3:::app-bucket/dir/my file.txt")
        );
        assert_eq!(
            call("s3", "DELETE", "/app-bucket/x", "", &host, ""),
            some("s3:DeleteObject", "arn:aws:s3:::app-bucket/x")
        );
        assert_eq!(
            call("s3", "HEAD", "/app-bucket/x", "", &host, ""),
            some("s3:GetObject", "arn:aws:s3:::app-bucket/x")
        );
        assert_eq!(
            call("s3", "HEAD", "/app-bucket", "", &host, ""),
            some("s3:ListBucket", "arn:aws:s3:::app-bucket")
        );
        assert_eq!(
            call("s3", "GET", "/app-bucket", "location", &host, ""),
            some("s3:GetBucketLocation", "arn:aws:s3:::app-bucket")
        );
        assert_eq!(
            call("s3", "GET", "/app-bucket/k", "acl", &host, ""),
            some("s3:GetObjectAcl", "arn:aws:s3:::app-bucket/k")
        );
        assert_eq!(
            call("s3", "POST", "/app-bucket/k", "uploads", &host, ""),
            some("s3:PutObject", "arn:aws:s3:::app-bucket/k")
        );
        assert_eq!(
            call(
                "s3",
                "PUT",
                "/app-bucket/k",
                "partNumber=1&uploadId=abc",
                &host,
                ""
            ),
            some("s3:PutObject", "arn:aws:s3:::app-bucket/k")
        );
        assert_eq!(
            call("s3", "GET", "/app-bucket/k", "uploadId=abc", &host, ""),
            some("s3:ListMultipartUploadParts", "arn:aws:s3:::app-bucket/k")
        );
        assert_eq!(
            call("s3", "POST", "/app-bucket", "delete", &host, "<Delete/>"),
            some("s3:DeleteObject", "arn:aws:s3:::app-bucket/*")
        );
        assert_eq!(
            call("s3", "GET", "/app-bucket", "lifecycle", &host, ""),
            some("s3:GetLifecycleConfiguration", "arn:aws:s3:::app-bucket")
        );
        // Virtual-hosted style.
        let vhost = [("host", "app-bucket.s3.us-east-1.amazonaws.com")];
        assert_eq!(
            call("s3", "GET", "/a/b", "", &vhost, ""),
            some("s3:GetObject", "arn:aws:s3:::app-bucket/a/b")
        );
        assert_eq!(
            call("s3", "GET", "/", "list-type=2", &vhost, ""),
            some("s3:ListBucket", "arn:aws:s3:::app-bucket")
        );
        // Methods with no operation are unknown.
        assert_eq!(
            call("s3", "PATCH", "/b/k", "", &host, ""),
            (None, "*".to_owned())
        );
    }

    #[test]
    fn s3_copy_needs_header() {
        let hs = [("x-amz-copy-source", "/src/k")];
        assert_eq!(
            call("s3", "PUT", "/dst/k", "", &hs, ""),
            some("s3:PutObject", "arn:aws:s3:::dst/k")
        );
    }

    #[test]
    fn s3_identical_routes_share_an_action() {
        let s3 = &table().services["s3"];
        let mut routes: BTreeMap<(&str, &str, &Vec<String>), BTreeSet<String>> = BTreeMap::new();
        for (op, rest) in &s3.ops {
            let rest = rest.as_ref().expect("s3 is rest");
            routes
                .entry((&rest.m, &rest.u, &rest.h))
                .or_default()
                .insert(iam_action("s3", s3, op));
        }
        for (route, actions) in routes {
            assert_eq!(actions.len(), 1, "{route:?} -> {actions:?}");
        }
    }

    #[test]
    fn dynamodb_json() {
        let hs = [
            ("X-Amz-Target", "DynamoDB_20120810.GetItem"),
            ("Content-Type", "application/x-amz-json-1.0"),
        ];
        let body = r#"{"TableName":"users","Key":{"id":{"S":"1"}}}"#;
        assert_eq!(
            call("dynamodb", "POST", "/", "", &hs, body),
            some(
                "dynamodb:GetItem",
                "arn:aws:dynamodb:us-east-1:*:table/users"
            )
        );
        let bad = [("X-Amz-Target", "Other_20120810.GetItem")];
        assert_eq!(call("dynamodb", "POST", "/", "", &bad, body).0, None);
        let unknown = [("X-Amz-Target", "DynamoDB_20120810.Explode")];
        assert_eq!(call("dynamodb", "POST", "/", "", &unknown, body).0, None);
        // Action params are not how DynamoDB routes; ignored.
        assert_eq!(
            call("dynamodb", "POST", "/", "Action=GetItem", &[], "").0,
            None
        );
    }

    #[test]
    fn sqs_query_and_json() {
        let body = "Action=SendMessage&Version=2012-11-05&QueueUrl=https%3A%2F%2Fsqs.us-east-1.amazonaws.com%2F123456789012%2Fjobs&MessageBody=hi";
        assert_eq!(
            call("sqs", "POST", "/", "", &[FORM], body),
            some("sqs:SendMessage", "arn:aws:sqs:us-east-1:123456789012:jobs")
        );
        let hs = [
            ("X-Amz-Target", "AmazonSQS.ReceiveMessage"),
            ("Content-Type", "application/x-amz-json-1.0"),
        ];
        let json = r#"{"QueueUrl":"https://sqs.us-east-1.amazonaws.com/123456789012/jobs"}"#;
        assert_eq!(
            call("sqs", "POST", "/", "", &hs, json),
            some(
                "sqs:ReceiveMessage",
                "arn:aws:sqs:us-east-1:123456789012:jobs"
            )
        );
        // Conflicting signals: unknown.
        let both = [("X-Amz-Target", "AmazonSQS.ReceiveMessage"), FORM];
        assert_eq!(
            call("sqs", "POST", "/", "", &both, "Action=DeleteQueue").0,
            None
        );
        // Conflicting Action values: unknown.
        assert_eq!(
            call(
                "sqs",
                "POST",
                "/",
                "Action=ListQueues",
                &[FORM],
                "Action=DeleteQueue"
            )
            .0,
            None
        );
    }

    #[test]
    fn lambda_rest_json() {
        assert_eq!(
            call(
                "lambda",
                "POST",
                "/2015-03-31/functions/fn/invocations",
                "",
                &[],
                "{}"
            ),
            some(
                "lambda:InvokeFunction",
                "arn:aws:lambda:us-east-1:*:function:fn"
            )
        );
        assert_eq!(
            call("lambda", "GET", "/2015-03-31/functions/", "", &[], "")
                .0
                .as_deref(),
            Some("lambda:ListFunctions")
        );
        assert_eq!(
            call(
                "lambda",
                "GET",
                "/2015-03-31/functions/fn/configuration",
                "",
                &[],
                ""
            ),
            some(
                "lambda:GetFunctionConfiguration",
                "arn:aws:lambda:us-east-1:*:function:fn"
            )
        );
    }

    #[test]
    fn ssm_sts_ec2_secrets() {
        let hs = [
            ("X-Amz-Target", "AmazonSSM.GetParameter"),
            ("Content-Type", "application/x-amz-json-1.1"),
        ];
        assert_eq!(
            call(
                "ssm",
                "POST",
                "/",
                "",
                &hs,
                r#"{"Name":"/app/db-host","WithDecryption":true}"#
            ),
            some(
                "ssm:GetParameter",
                "arn:aws:ssm:us-east-1:*:parameter/app/db-host"
            )
        );
        assert_eq!(
            call(
                "sts",
                "POST",
                "/",
                "",
                &[FORM],
                "Action=GetCallerIdentity&Version=2011-06-15"
            ),
            some("sts:GetCallerIdentity", "*")
        );
        assert_eq!(
            call(
                "ec2",
                "POST",
                "/",
                "",
                &[FORM],
                "Action=DescribeInstances&Version=2016-11-15"
            ),
            some("ec2:DescribeInstances", "*")
        );
        assert_eq!(
            call(
                "ec2",
                "GET",
                "/",
                "Action=TerminateInstances&InstanceId.1=i-1",
                &[],
                ""
            ),
            some("ec2:TerminateInstances", "*")
        );
        let sm = [
            ("X-Amz-Target", "secretsmanager.GetSecretValue"),
            ("Content-Type", "application/x-amz-json-1.1"),
        ];
        let arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-AbCdEf";
        assert_eq!(
            call(
                "secretsmanager",
                "POST",
                "/",
                "",
                &sm,
                &format!(r#"{{"SecretId":"{arn}"}}"#)
            ),
            some("secretsmanager:GetSecretValue", arn)
        );
        assert_eq!(
            call(
                "secretsmanager",
                "POST",
                "/",
                "",
                &sm,
                r#"{"SecretId":"db"}"#
            ),
            some("secretsmanager:GetSecretValue", "*")
        );
        assert_eq!(
            call("nosuch", "GET", "/", "", &[], ""),
            (None, "*".to_owned())
        );
    }

    #[test]
    fn endpoint_hosts() {
        let e = |s, r, b| endpoint_host(s, r, b);
        assert_eq!(
            e("s3", "us-east-1", None).as_deref(),
            Some("s3.us-east-1.amazonaws.com")
        );
        assert_eq!(
            e("s3", "eu-west-1", Some("app-bucket")).as_deref(),
            Some("app-bucket.s3.eu-west-1.amazonaws.com")
        );
        assert_eq!(
            e("s3", "eu-west-1", Some("my.dotted.bucket")).as_deref(),
            Some("s3.eu-west-1.amazonaws.com")
        );
        assert_eq!(
            e("ecr", "us-west-2", None).as_deref(),
            Some("api.ecr.us-west-2.amazonaws.com")
        );
        assert_eq!(
            e("states", "us-east-1", None).as_deref(),
            Some("states.us-east-1.amazonaws.com")
        );
        assert_eq!(
            e("iam", "us-east-1", None).as_deref(),
            Some("iam.amazonaws.com")
        );
        assert_eq!(
            e("dynamodb", "cn-north-1", None).as_deref(),
            Some("dynamodb.cn-north-1.amazonaws.com.cn")
        );
        assert_eq!(e("nosuch", "us-east-1", None), None);
        assert_eq!(e("s3", "evil.com/x", None), None);
    }

    #[test]
    fn hosts_to_buckets() {
        assert_eq!(s3_bucket_from_host("b.s3.amazonaws.com"), Some("b"));
        assert_eq!(
            s3_bucket_from_host("a.b.s3.us-east-1.amazonaws.com:443"),
            Some("a.b")
        );
        assert_eq!(
            s3_bucket_from_host("b.s3-us-west-2.amazonaws.com"),
            Some("b")
        );
        assert_eq!(s3_bucket_from_host("b.localhost:4566"), Some("b"));
        assert_eq!(s3_bucket_from_host("s3.us-east-1.amazonaws.com"), None);
        assert_eq!(s3_bucket_from_host("127.0.0.1:9000"), None);
    }

    #[test]
    fn read_only_classification() {
        for a in [
            "s3:ListBucket",
            "dynamodb:Query",
            "dynamodb:Scan",
            "ec2:DescribeInstances",
            "sts:GetCallerIdentity",
            "dynamodb:BatchGetItem",
        ] {
            assert!(is_read_only(a), "{a}");
        }
        for a in [
            "s3:PutObject",
            "dynamodb:BatchWriteItem",
            "lambda:InvokeFunction",
            "nocolon",
        ] {
            assert!(!is_read_only(a), "{a}");
        }
        let p = read_only_patterns();
        assert!(p.contains(&"dynamodb:Query".to_owned()) && p.contains(&"s3:Get*".to_owned()));
        assert!(
            p.iter()
                .all(|x| x.ends_with('*') || x.ends_with(":Query") || x.ends_with(":Scan"))
        );
    }
}
