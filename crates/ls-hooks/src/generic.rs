//! High-confidence generic secret patterns (a gitleaks subset). Used when the vault cannot be
//! consulted, and by `smith scan` alongside the vault-aware matcher. Only patterns with a
//! distinctive prefix are included, so normal source code does not match.

use regex::Regex;
use std::sync::OnceLock;

const RULES: &[(&str, &str)] = &[
    ("aws-access-key-id", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    (
        "github-fine-grained-token",
        r"\bgithub_pat_[A-Za-z0-9_]{82}\b",
    ),
    ("gitlab-token", r"\bglpat-[A-Za-z0-9_\-]{20}\b"),
    ("stripe-live-key", r"\b[sr]k_live_[A-Za-z0-9]{20,99}\b"),
    ("slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    (
        "anthropic-api-key",
        r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}",
    ),
    ("openai-project-key", r"\bsk-proj-[A-Za-z0-9_\-]{40,}"),
    ("npm-token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    // A key body must follow (raw or `\n`-escaped newlines, optional PEM headers), so docs that
    // show only the header with `...` do not match.
    (
        "private-key",
        r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----(?:\\n|\s)+(?:[A-Za-z-]+:[^\n]*(?:\\n|\s)+)*[A-Za-z0-9+/]{40}",
    ),
];

fn compiled() -> &'static [(&'static str, Regex)] {
    static C: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    C.get_or_init(|| {
        RULES
            .iter()
            .map(|(id, re)| (*id, Regex::new(re).expect("rule compiles")))
            .collect()
    })
}

/// Rule id and byte offset of every generic match.
pub fn find(text: &str) -> Vec<(&'static str, usize)> {
    let mut out: Vec<_> = compiled()
        .iter()
        .flat_map(|(id, re)| re.find_iter(text).map(move |m| (*id, m.start())))
        .collect();
    out.sort_by_key(|(_, o)| *o);
    out
}

#[cfg(test)]
mod tests {
    use super::find;

    // Built at runtime so the repository's own secret scanner (gitleaks) does not flag the source.
    fn fake(prefix: &str, body: &str) -> String {
        format!("{prefix}{body}")
    }

    #[test]
    fn each_rule_matches_a_synthetic_token() {
        let a = "A".repeat(36);
        let cases = [
            (fake("AKIA", "ABCDEFGHIJKLMNOP"), "aws-access-key-id"),
            (fake("ghp_", &a), "github-token"),
            (
                fake("sk_li", &format!("ve_{}", "a1".repeat(12))),
                "stripe-live-key",
            ),
            (fake("xoxb-", "1234567890-abcdef"), "slack-token"),
            (fake("AIza", &"b".repeat(35)), "google-api-key"),
            (fake("npm_", &a), "npm-token"),
            (
                fake(
                    "-----BEGIN RSA PRIV",
                    &format!("ATE KEY-----\n{}", "M".repeat(64)),
                ),
                "private-key",
            ),
            (
                fake(
                    "-----BEGIN PRIV",
                    &format!("ATE KEY-----\\n{}", "M".repeat(64)),
                ),
                "private-key",
            ),
        ];
        for (t, id) in cases {
            let got = find(&format!("x = \"{t}\""));
            assert_eq!(got.first().map(|g| g.0), Some(id), "{id}");
        }
    }

    #[test]
    fn ordinary_code_does_not_match() {
        let header = fake("-----BEGIN RSA PRIV", "ATE KEY-----");
        for t in [
            "const AKIA = 1; // AKIA prefix alone".to_string(),
            "let token = std::env::var(\"GITHUB_TOKEN\")?;".to_string(),
            fake("sk_te", "st_placeholder and sk_live_short"),
            "import { xox } from './slack';".to_string(),
            "-----BEGIN CERTIFICATE-----".to_string(),
            // Docs examples: a header with no key body.
            format!("{header}\n...\nKh9NV...\n-----END"),
            format!("{header}\\nKh9NV...\\n-----END"),
            "ghp_short".to_string(),
        ] {
            assert!(find(&t).is_empty(), "{t}");
        }
    }
}
