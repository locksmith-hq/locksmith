//! Doctor check for D2 AWS credential vending: `aws.vend`. A pure function over the AWS config
//! and credentials file text, so the tests need no home directory. It never prints a value from
//! either file, only counts and section names.

use crate::aws_cmd::{self, DEFAULT_PROFILE};
use ls_diag::{Check, Outcome};

const TEARDOWN: &str = "smith aws teardown";

/// Whether `text` has an uncommented `aws_access_key_id` or `aws_secret_access_key` assignment
/// with a value. Returns how many.
fn long_lived_keys(text: &str) -> usize {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with(['#', ';']))
        .filter(|l| {
            l.split_once('=').is_some_and(|(k, v)| {
                let k = k.trim().to_ascii_lowercase();
                matches!(k.as_str(), "aws_access_key_id" | "aws_secret_access_key")
                    && !v.trim().is_empty()
            })
        })
        .count()
}

/// The `[profile …]` section names that use `credential_process = … aws credential-process`.
fn vend_profiles(config: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut section: Option<String> = None;
    for l in config.lines().map(str::trim) {
        if l.starts_with(['#', ';']) {
            continue;
        }
        if let Some(h) = l.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            let h = h.trim();
            section = Some(h.strip_prefix("profile ").unwrap_or(h).trim().to_owned());
        } else if let Some((k, v)) = l.split_once('=')
            && k.trim().eq_ignore_ascii_case("credential_process")
            && v.contains("aws credential-process")
            && let Some(s) = &section
        {
            out.push(s.clone());
        }
    }
    out
}

/// `config` / `credentials`: file contents, `None` when the file is absent.
pub fn vend_outcome(config: Option<&str>, credentials: Option<&str>) -> Outcome {
    let profiles = config.map(vend_profiles).unwrap_or_default();
    if profiles.is_empty() {
        return Outcome::skip(format!(
            "AWS credential vending is off (no keyless profile); `smith aws setup` turns it on, \
             and the credentials are then visible to the agent for their lifetime \
             (default profile name: {DEFAULT_PROFILE})"
        ));
    }
    let names = profiles.join(", ");
    let n_cred = credentials.map_or(0, long_lived_keys);
    let n_cfg = config.map_or(0, long_lived_keys);
    if n_cred + n_cfg > 0 {
        let where_ = match (n_cred > 0, n_cfg > 0) {
            (true, true) => "the AWS credentials and config files",
            (true, false) => "the AWS credentials file",
            _ => "the AWS config file",
        };
        return Outcome::fail(
            format!(
                "long-lived AWS keys found in {where_} next to vended profile {names}; the agent can read them"
            ),
            "remove the static keys (aws configure list; delete aws_access_key_id and aws_secret_access_key), then rotate them",
        );
    }
    Outcome::warn(
        format!(
            "profile {names} vends short-lived AWS credentials that are visible to the agent for their lifetime"
        ),
        format!(
            "`{TEARDOWN}` turns vending off; keep the gateway binding's vend and grant scope narrow"
        ),
    )
}

fn read(p: Option<std::path::PathBuf>) -> Option<String> {
    p.and_then(|p| std::fs::read_to_string(p).ok())
}

fn vend() -> Outcome {
    vend_outcome(
        read(aws_cmd::config_path()).as_deref(),
        read(aws_cmd::credentials_path()).as_deref(),
    )
}

inventory::submit! { Check { id: "aws.vend", run: vend } }

#[cfg(test)]
mod tests {
    use super::*;
    use ls_diag::Status;

    const PROFILE: &str =
        "[profile locksmith]\ncredential_process = \"/x/smith\" aws credential-process\n";

    #[test]
    fn aws_vend_off_by_default() {
        for (c, k) in [(None, None), (Some("[default]\nregion=x\n"), None)] {
            let o = vend_outcome(c, k);
            assert_eq!(o.status, Status::Skip);
            assert!(o.summary.contains("off"), "{}", o.summary);
        }
    }

    #[test]
    fn aws_vend_profile_present_warns_about_agent_visibility() {
        let o = vend_outcome(Some(PROFILE), Some("# aws_access_key_id = AKIA\n"));
        assert_eq!(o.status, Status::Warn);
        assert!(o.summary.contains("visible to the agent"));
        assert!(o.remediation.unwrap().contains("smith aws teardown"));
    }

    #[test]
    fn aws_vend_long_lived_keys_fail_without_echoing_values() {
        let creds = "[default]\naws_access_key_id = AKIAEXAMPLEKEY0000\naws_secret_access_key = SECRETCANARY\n";
        let o = vend_outcome(Some(PROFILE), Some(creds));
        assert_eq!(o.status, Status::Fail);
        let all = format!("{} {:?}", o.summary, o.remediation);
        assert!(!all.contains("AKIAEXAMPLEKEY0000") && !all.contains("SECRETCANARY"));
        // Keys with no vended profile are not this check's business.
        assert_eq!(vend_outcome(None, Some(creds)).status, Status::Skip);
        // Keys inside the config file count too.
        let cfg = format!("{PROFILE}[profile x]\naws_access_key_id=AKIA1\n");
        assert_eq!(vend_outcome(Some(&cfg), None).status, Status::Fail);
    }
}
