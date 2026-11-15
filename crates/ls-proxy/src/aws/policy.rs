//! M7 AWS: `[aws.policy]` evaluation (design D3).
//!
//! ```toml
//! [aws.policy]
//! allow = ["s3:Get*", "s3:ListBucket", "dynamodb:Query"]   # empty/absent = read-only default
//! deny = ["s3:DeleteObject"]                               # always wins
//! resources = ["arn:aws:s3:::app-bucket", "arn:aws:s3:::app-bucket/*"]  # empty = any
//! ```
//!
//! Patterns use IAM globbing (`*`, `?`): case-insensitive for actions, case-sensitive for
//! resources. A request whose resource could not be derived has resource `*`, which only a `*`
//! resource pattern matches.

use super::Call;
use super::model::{is_read_only, read_only_patterns};
use serde::Deserialize;
use serde_json::json;

/// Actions that return real AWS credentials to the caller, which would defeat delegation.
/// Denied whatever the policy says.
const CREDENTIAL_MINTING: &[&str] = &[
    "sts:AssumeRole",
    "sts:AssumeRoleWithSAML",
    "sts:AssumeRoleWithWebIdentity",
    "sts:AssumeRoot",
    "sts:GetFederationToken",
    "sts:GetSessionToken",
];

/// "Read" actions that return secret material (secret values, registry login tokens, decrypted
/// parameters). The read-only default does not include them; list them in `allow` explicitly.
const SECRET_READS: &[&str] = &[
    "secretsmanager:GetSecretValue",
    "secretsmanager:BatchGetSecretValue",
    "ecr:GetAuthorizationToken",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "ssm:GetParameterHistory",
];

fn secret_read(action: &str) -> bool {
    SECRET_READS.iter().any(|a| a.eq_ignore_ascii_case(action))
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// Allowed action patterns. Empty = read-only ([`is_read_only`]).
    pub allow: Vec<String>,
    /// Denied action patterns; win over `allow`.
    pub deny: Vec<String>,
    /// Allowed resource ARN patterns. Empty = any resource.
    pub resources: Vec<String>,
}

impl Policy {
    /// `Err` carries the audit rule: `aws_unknown_action`, `aws_denied:<action>`,
    /// `aws_not_allowed:<action>` or `aws_resource_not_allowed:<arn>`.
    pub fn decide(&self, call: &Call) -> Result<(), String> {
        let Some(action) = call.action.as_deref() else {
            return Err("aws_unknown_action".to_owned());
        };
        let minting = CREDENTIAL_MINTING
            .iter()
            .any(|a| a.eq_ignore_ascii_case(action));
        if minting || self.deny.iter().any(|p| glob(p, action, true)) {
            return Err(format!("aws_denied:{action}"));
        }
        let allowed = if self.allow.is_empty() {
            is_read_only(action) && !secret_read(action)
        } else {
            self.allow.iter().any(|p| glob(p, action, true))
        };
        if !allowed {
            return Err(format!("aws_not_allowed:{action}"));
        }
        if !self.resources.is_empty()
            && !self
                .resources
                .iter()
                .any(|p| glob(p, &call.resource, false))
        {
            return Err(format!("aws_resource_not_allowed:{}", call.resource));
        }
        Ok(())
    }

    /// IAM session policy (STS AssumeRole `Policy`) equivalent to this policy, for the contained
    /// fallback. The read-only default expands to per-service read-only patterns over the
    /// vendored services; credential-minting STS actions are always denied.
    pub fn session_policy_json(&self) -> String {
        let allow = if self.allow.is_empty() {
            read_only_patterns()
        } else {
            self.allow.clone()
        };
        let resources = if self.resources.is_empty() {
            vec!["*".to_owned()]
        } else {
            self.resources.clone()
        };
        let mut deny = self.deny.clone();
        deny.extend(CREDENTIAL_MINTING.iter().map(|a| (*a).to_owned()));
        if self.allow.is_empty() {
            // The read-only wildcards (`secretsmanager:Get*`) would cover these.
            deny.extend(SECRET_READS.iter().map(|a| (*a).to_owned()));
        }
        json!({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": allow, "Resource": resources},
                {"Effect": "Deny", "Action": deny, "Resource": "*"},
            ]
        })
        .to_string()
    }
}

/// IAM-style glob: `*` any run (including empty), `?` one character.
fn glob(pattern: &str, value: &str, ignore_case: bool) -> bool {
    let norm = |s: &str| -> Vec<char> {
        if ignore_case {
            s.to_lowercase().chars().collect()
        } else {
            s.chars().collect()
        }
    };
    let (p, v) = (norm(pattern), norm(value));
    let (mut i, mut j) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while j < v.len() {
        if i < p.len() && (p[i] == '?' || p[i] == v[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star = Some((i, j));
            i += 1;
        } else if let Some((si, sj)) = star {
            i = si + 1;
            j = sj + 1;
            star = Some((si, sj + 1));
        } else {
            return false;
        }
    }
    p[i..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
    use super::super::model::resolve;
    use super::*;
    use serde_json::Value;

    fn c(action: Option<&str>, resource: &str) -> Call {
        Call {
            service: "x".into(),
            region: "us-east-1".into(),
            action: action.map(str::to_owned),
            resource: resource.into(),
        }
    }

    fn p(allow: &[&str], deny: &[&str], resources: &[&str]) -> Policy {
        let v = |x: &[&str]| x.iter().map(|s| (*s).to_owned()).collect();
        Policy {
            allow: v(allow),
            deny: v(deny),
            resources: v(resources),
        }
    }

    type Row<'a> = (&'a Policy, Option<&'a str>, &'a str, Result<(), &'a str>);

    #[test]
    fn decision_table() {
        let ro = Policy::default();
        let s3 = p(
            &["s3:*"],
            &["s3:DeleteObject"],
            &["arn:aws:s3:::app-bucket", "arn:aws:s3:::app-bucket/*"],
        );
        let wild = p(&["dynamodb:Get*", "dynamodb:?uery", "SQS:send*"], &[], &[]);
        let ddb = p(
            &["dynamodb:*"],
            &["dynamodb:Delete*"],
            &["arn:aws:dynamodb:*:*:table/users"],
        );
        let all = p(&["*"], &[], &[]);
        let bucket = "arn:aws:s3:::app-bucket";
        let obj = "arn:aws:s3:::app-bucket/x";
        let other = "arn:aws:s3:::other/x";
        let users = "arn:aws:dynamodb:us-east-1:*:table/users";
        #[rustfmt::skip]
        let rows: &[Row] = &[
            // Read-only default.
            (&ro, Some("s3:ListBucket"), bucket, Ok(())),
            (&ro, Some("s3:GetObject"), obj, Ok(())),
            (&ro, Some("s3:ListAllMyBuckets"), "*", Ok(())),
            (&ro, Some("s3:DeleteObject"), obj, Err("aws_not_allowed:s3:DeleteObject")),
            (&ro, Some("s3:PutObject"), obj, Err("aws_not_allowed:s3:PutObject")),
            (&ro, Some("dynamodb:GetItem"), users, Ok(())),
            (&ro, Some("dynamodb:Query"), users, Ok(())),
            (&ro, Some("dynamodb:Scan"), users, Ok(())),
            (&ro, Some("dynamodb:BatchGetItem"), "*", Ok(())),
            (&ro, Some("dynamodb:PutItem"), users, Err("aws_not_allowed:dynamodb:PutItem")),
            (&ro, Some("dynamodb:BatchWriteItem"), "*", Err("aws_not_allowed:dynamodb:BatchWriteItem")),
            (&ro, Some("sts:GetCallerIdentity"), "*", Ok(())),
            (&ro, Some("ec2:DescribeInstances"), "*", Ok(())),
            (&ro, Some("ec2:TerminateInstances"), "*", Err("aws_not_allowed:ec2:TerminateInstances")),
            (&ro, Some("lambda:InvokeFunction"), "*", Err("aws_not_allowed:lambda:InvokeFunction")),
            // Reads that return secret material need an explicit allow.
            (&ro, Some("ssm:GetParameter"), "*", Err("aws_not_allowed:ssm:GetParameter")),
            (&ro, Some("secretsmanager:GetSecretValue"), "*", Err("aws_not_allowed:secretsmanager:GetSecretValue")),
            (&ro, Some("ecr:GetAuthorizationToken"), "*", Err("aws_not_allowed:ecr:GetAuthorizationToken")),
            (&ro, Some("secretsmanager:DescribeSecret"), "*", Ok(())),
            (&ro, Some("sqs:SendMessage"), "*", Err("aws_not_allowed:sqs:SendMessage")),
            // Unknown always denied.
            (&ro, None, "*", Err("aws_unknown_action")),
            (&all, None, "*", Err("aws_unknown_action")),
            // Credential minting always denied.
            (&ro, Some("sts:GetSessionToken"), "*", Err("aws_denied:sts:GetSessionToken")),
            (&all, Some("sts:AssumeRole"), "*", Err("aws_denied:sts:AssumeRole")),
            (&all, Some("sts:GetFederationToken"), "*", Err("aws_denied:sts:GetFederationToken")),
            // Explicit allow + resources.
            (&s3, Some("s3:PutObject"), obj, Ok(())),
            (&s3, Some("s3:ListBucket"), bucket, Ok(())),
            (&s3, Some("s3:PutObject"), other, Err("aws_resource_not_allowed:arn:aws:s3:::other/x")),
            (&s3, Some("s3:ListAllMyBuckets"), "*", Err("aws_resource_not_allowed:*")),
            (&s3, Some("s3:DeleteObject"), obj, Err("aws_denied:s3:DeleteObject")),
            (&s3, Some("s3:deleteobject"), obj, Err("aws_denied:s3:deleteobject")),
            (&s3, Some("dynamodb:GetItem"), users, Err("aws_not_allowed:dynamodb:GetItem")),
            (&s3, Some("s3:PutObject"), "arn:aws:s3:::APP-BUCKET/x", Err("aws_resource_not_allowed:arn:aws:s3:::APP-BUCKET/x")),
            // Globbing.
            (&wild, Some("dynamodb:GetItem"), "*", Ok(())),
            (&wild, Some("dynamodb:Query"), "*", Ok(())),
            (&wild, Some("dynamodb:Scan"), "*", Err("aws_not_allowed:dynamodb:Scan")),
            (&wild, Some("sqs:SendMessage"), "*", Ok(())),
            (&wild, Some("sqs:SendMessageBatch"), "*", Ok(())),
            (&wild, Some("sqs:ReceiveMessage"), "*", Err("aws_not_allowed:sqs:ReceiveMessage")),
            (&wild, Some("dynamodb:PutItem"), "*", Err("aws_not_allowed:dynamodb:PutItem")),
            // Explicit deny wins over a broader allow.
            (&ddb, Some("dynamodb:PutItem"), users, Ok(())),
            (&ddb, Some("dynamodb:DeleteItem"), users, Err("aws_denied:dynamodb:DeleteItem")),
            (&ddb, Some("dynamodb:DeleteTable"), users, Err("aws_denied:dynamodb:DeleteTable")),
            (&ddb, Some("dynamodb:PutItem"), "arn:aws:dynamodb:us-east-1:*:table/orders",
                Err("aws_resource_not_allowed:arn:aws:dynamodb:us-east-1:*:table/orders")),
            (&ddb, Some("dynamodb:PutItem"), "*", Err("aws_resource_not_allowed:*")),
            (&all, Some("ec2:TerminateInstances"), "*", Ok(())),
        ];
        assert!(rows.len() >= 40);
        for (i, (pol, action, resource, want)) in rows.iter().enumerate() {
            let got = pol.decide(&c(*action, resource));
            assert_eq!(
                got,
                want.map_err(str::to_owned),
                "row {i}: {action:?} on {resource}"
            );
        }
    }

    #[test]
    fn default_read_only_end_to_end() {
        let ro = Policy::default();
        let host = [("Host".to_owned(), "127.0.0.1:9000".to_owned())];
        // aws s3 ls s3://app-bucket
        let ls = resolve(
            "s3",
            "us-east-1",
            "GET",
            "/app-bucket",
            "list-type=2&delimiter=%2F",
            &host,
            b"",
        );
        assert_eq!(ro.decide(&ls), Ok(()));
        // aws s3 rm s3://app-bucket/x
        let rm = resolve("s3", "us-east-1", "DELETE", "/app-bucket/x", "", &host, b"");
        assert_eq!(
            ro.decide(&rm),
            Err("aws_not_allowed:s3:DeleteObject".to_owned())
        );
    }

    #[test]
    fn toml_section() {
        #[derive(Deserialize)]
        struct Root {
            policy: Policy,
        }
        let r: Root = toml::from_str("[policy]\nallow = [\"s3:*\"]\n").expect("parses");
        assert_eq!(r.policy, p(&["s3:*"], &[], &[]));
        assert!(toml::from_str::<Root>("[policy]\nalow = []\n").is_err());
    }

    #[test]
    fn session_policy_golden() {
        let pol = p(
            &["s3:Get*", "s3:ListBucket"],
            &["s3:GetObjectAcl"],
            &["arn:aws:s3:::app-bucket", "arn:aws:s3:::app-bucket/*"],
        );
        let got: Value = serde_json::from_str(&pol.session_policy_json()).expect("json");
        let want: Value = serde_json::from_str(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Action":["s3:Get*","s3:ListBucket"],
                 "Resource":["arn:aws:s3:::app-bucket","arn:aws:s3:::app-bucket/*"]},
                {"Effect":"Deny","Action":["s3:GetObjectAcl","sts:AssumeRole","sts:AssumeRoleWithSAML",
                 "sts:AssumeRoleWithWebIdentity","sts:AssumeRoot","sts:GetFederationToken","sts:GetSessionToken"],
                 "Resource":"*"}]}"#,
        )
        .expect("golden");
        assert_eq!(got, want);
    }

    #[test]
    fn session_policy_default_fits_sts_limit() {
        let s = Policy::default().session_policy_json();
        let v: Value = serde_json::from_str(&s).expect("json");
        let allow = v["Statement"][0]["Action"].as_array().expect("actions");
        for a in [
            "s3:Get*",
            "s3:List*",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:BatchGet*",
            "ec2:Describe*",
            "sts:Get*",
        ] {
            assert!(allow.iter().any(|x| x == a), "{a} missing from {s}");
        }
        assert_eq!(v["Statement"][0]["Resource"], json!(["*"]));
        // STS rejects session policies over 2048 characters of plaintext.
        assert!(s.len() <= 2048, "{} chars", s.len());
    }

    #[test]
    fn glob_edges() {
        assert!(glob("*", "", false));
        assert!(glob("a*b*c", "aXXbYYc", false));
        assert!(!glob("a*b*c", "aXXbYY", false));
        assert!(glob("a?c", "abc", false));
        assert!(!glob("a?c", "ac", false));
        assert!(glob("S3:*", "s3:GetObject", true));
        assert!(!glob("S3:*", "s3:GetObject", false));
    }
}
