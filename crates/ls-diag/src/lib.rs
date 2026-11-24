//! Doctor checks: a registry any crate can add to, plus the `doctor.v1` report.

use serde::Serialize;

pub mod checks;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Warn,
    Fail,
    Skip,
}

#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub status: Status,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    pub fixable: bool,
}

impl Outcome {
    pub fn ok(summary: impl Into<String>) -> Self {
        Self {
            status: Status::Ok,
            summary: summary.into(),
            remediation: None,
            fixable: false,
        }
    }
    pub fn skip(summary: impl Into<String>) -> Self {
        Self {
            status: Status::Skip,
            summary: summary.into(),
            remediation: None,
            fixable: false,
        }
    }
    pub fn warn(summary: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            status: Status::Warn,
            summary: summary.into(),
            remediation: Some(fix.into()),
            fixable: false,
        }
    }
    pub fn fail(summary: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            status: Status::Fail,
            summary: summary.into(),
            remediation: Some(fix.into()),
            fixable: false,
        }
    }
}

/// A check registered with `inventory::submit!`. `id` is dotted and stable.
pub struct Check {
    pub id: &'static str,
    pub run: fn() -> Outcome,
}
inventory::collect!(Check);

/// A family of checks whose ids are only known at run time (e.g. `db.relay.<name>` per
/// configured target). `run` returns `(id, outcome)` pairs; ids should start with `prefix`.
pub struct CheckSet {
    pub prefix: &'static str,
    pub run: fn() -> Vec<(String, Outcome)>,
}
inventory::collect!(CheckSet);

#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub id: &'static str,
    #[serde(flatten)]
    pub outcome: Outcome,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub version: &'static str,
    pub platform: String,
    pub checks: Vec<CheckResult>,
}

impl Report {
    pub fn failed(&self) -> bool {
        self.checks.iter().any(|c| c.outcome.status == Status::Fail)
    }

    pub fn render_human(&self) -> String {
        let mut out = String::new();
        for c in &self.checks {
            let tag = match c.outcome.status {
                Status::Ok => "ok  ",
                Status::Warn => "WARN",
                Status::Fail => "FAIL",
                Status::Skip => "skip",
            };
            out.push_str(&format!("[{tag}] {:<28} {}\n", c.id, c.outcome.summary));
            if let Some(r) = &c.outcome.remediation {
                out.push_str(&format!("       fix: {r}\n"));
            }
        }
        out
    }
}

/// Run every registered check, sorted by id for stable output.
pub fn run_all(version: &'static str) -> Report {
    let mut checks: Vec<CheckResult> = inventory::iter::<Check>
        .into_iter()
        .map(|c| CheckResult {
            id: c.id,
            outcome: (c.run)(),
        })
        .collect();
    for set in inventory::iter::<CheckSet> {
        // The process runs doctor once and exits: leaking the few dynamic ids is fine.
        checks.extend((set.run)().into_iter().map(|(id, outcome)| CheckResult {
            id: id.leak(),
            outcome,
        }));
    }
    checks.sort_by_key(|c| c.id);
    Report {
        schema: "doctor.v1",
        version,
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The serialized report must carry every field `docs/schemas/doctor.v1.json` requires.
    #[test]
    fn report_matches_schema_required_fields() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../docs/schemas/doctor.v1.json")).unwrap();
        let report = serde_json::to_value(run_all("0.0.0-test")).unwrap();
        for k in schema["required"].as_array().unwrap() {
            assert!(report.get(k.as_str().unwrap()).is_some(), "missing {k}");
        }
        let item_req = schema["properties"]["checks"]["items"]["required"]
            .as_array()
            .unwrap();
        let statuses = ["ok", "warn", "fail", "skip"];
        for c in report["checks"].as_array().unwrap() {
            for k in item_req {
                assert!(c.get(k.as_str().unwrap()).is_some(), "check missing {k}");
            }
            assert!(statuses.contains(&c["status"].as_str().unwrap()));
        }
        assert_eq!(report["schema"], "doctor.v1");
    }
}
