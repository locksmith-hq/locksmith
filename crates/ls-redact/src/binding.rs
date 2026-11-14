//! `.locksmith.toml` parsing shared by `smith` and `locksmithd`: names only, never values.

use crate::Redactor;
use serde::Deserialize;

pub const FILE: &str = ".locksmith.toml";

#[derive(Deserialize, Default, Debug, PartialEq)]
pub struct Binding {
    pub project: Option<String>,
    pub env: Option<String>,
    #[serde(default)]
    pub keys: Vec<String>,
}

pub fn parse(bytes: &[u8]) -> Result<Binding, String> {
    toml::from_str(std::str::from_utf8(bytes).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

/// 1-based line of the first line a stored secret appears on (0: only across lines).
pub fn secret_line(bytes: &[u8], r: &Redactor) -> Option<usize> {
    if r.is_empty() || r.redact_all(bytes) == bytes {
        return None;
    }
    Some(
        bytes
            .split_inclusive(|b| *b == b'\n')
            .position(|l| r.redact_all(l) != l)
            .map_or(0, |i| i + 1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Secret;

    #[test]
    fn parses_fields() {
        let b =
            parse(b"project=\"p\"\nenv=\"e\"\nkeys=[\"A\",\"B\"]\n[commands]\nx=\"y\"\n").unwrap();
        assert_eq!(b.project.as_deref(), Some("p"));
        assert_eq!(b.keys, ["A", "B"]);
        assert!(parse(b"keys = 3").is_err());
    }

    #[test]
    fn detects_value_and_line_without_leaking() {
        let r = Redactor::new(&[Secret::new("K", b"fake_live_abcdef123456")]);
        assert_eq!(
            secret_line(b"a=1\nb=\"fake_live_abcdef123456\"\n", &r),
            Some(2)
        );
        assert_eq!(secret_line(b"project=\"x\"\nkeys=[\"K\"]\n", &r), None);
    }
}
