//! Built-in provider catalog (`providers.toml`, embedded) and resolution of one key's relay
//! binding from the catalog, `.locksmith.toml` `[http.keys]` and command-line overrides.

use crate::http::{Placement, valid_host_pattern};
use ls_redact::binding::HttpKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::OnceLock;

const SOURCE: &str = include_str!("../providers.toml");

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    #[serde(skip_deserializing)]
    pub id: String,
    pub name: String,
    pub hosts: Vec<String>,
    pub placement: String,
    pub base_url: String,
    pub base_url_env: Vec<String>,
    /// `env`, `config` or `none` (needs explicit-proxy mode).
    #[serde(rename = "override")]
    pub base_url_override: String,
    pub keys: Vec<String>,
}

/// Every provider, sorted by id.
pub fn all() -> &'static [Provider] {
    static ALL: OnceLock<Vec<Provider>> = OnceLock::new();
    ALL.get_or_init(|| {
        let m: BTreeMap<String, Provider> =
            toml::from_str(SOURCE).expect("providers.toml is valid");
        m.into_iter()
            .map(|(id, mut p)| {
                p.id = id;
                p
            })
            .collect()
    })
}

pub fn get(id: &str) -> Option<&'static Provider> {
    all().iter().find(|p| p.id.eq_ignore_ascii_case(id))
}

/// What a token for one key may do, and how `smith run` points the app at the relay.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    pub provider: Option<String>,
    pub hosts: Vec<String>,
    pub placements: Vec<Placement>,
    /// `https://…` base of the API, when it has a fixed host.
    pub base_url: Option<String>,
    pub base_url_env: Vec<String>,
}

/// Merge, in increasing priority: the catalog entry (`provider`, or the binding's), the binding's
/// table fields, then explicit `hosts` / `placement`. Fails when no host or placement results.
pub fn resolve(
    bound: Option<&HttpKey>,
    provider: Option<&str>,
    hosts: &[String],
    placement: Option<&str>,
) -> Result<Resolved, String> {
    let pid = provider.or_else(|| bound.and_then(HttpKey::provider));
    let p = match pid {
        Some(id) => Some(get(id).ok_or_else(|| {
            format!("unknown provider {id:?}; `smith http providers` lists the catalog")
        })?),
        None => None,
    };
    let spec = match bound {
        Some(HttpKey::Custom(s)) => Some(s),
        _ => None,
    };
    let pick = |explicit: &[String], table: Option<&Vec<String>>, cat: Option<&Vec<String>>| {
        if !explicit.is_empty() {
            explicit.to_vec()
        } else if let Some(t) = table.filter(|t| !t.is_empty()) {
            t.clone()
        } else {
            cat.cloned().unwrap_or_default()
        }
    };
    let hosts: Vec<String> = pick(hosts, spec.map(|s| &s.hosts), p.map(|p| &p.hosts))
        .into_iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    if hosts.is_empty() {
        return Err("no upstream host allowlist: pass --host, --provider, or bind the key under [http.keys] in .locksmith.toml".into());
    }
    if let Some(h) = hosts.iter().find(|h| !valid_host_pattern(h)) {
        return Err(format!("invalid host {h:?}"));
    }
    let placement = placement
        .map(String::from)
        .or_else(|| spec.and_then(|s| s.placement.clone()))
        .or_else(|| p.map(|p| p.placement.clone()))
        .unwrap_or_else(|| "bearer".into());
    let placements = Placement::parse_list(&placement)?;
    let base_url = p
        .map(|p| p.base_url.clone())
        .filter(|u| !u.is_empty())
        .or_else(|| {
            hosts
                .iter()
                .find(|h| !h.starts_with("*."))
                .map(|h| format!("https://{h}"))
        });
    let base_url_env = pick(
        &[],
        spec.map(|s| &s.base_url_env),
        p.map(|p| &p.base_url_env),
    );
    Ok(Resolved {
        provider: p.map(|p| p.id.clone()),
        hosts,
        placements,
        base_url,
        base_url_env,
    })
}

/// `https://api.openai.com/v1` -> `http://127.0.0.1:<port>/h/api.openai.com/v1`.
pub fn relay_url(port: u16, base_url: &str) -> Option<String> {
    let rest = base_url.strip_prefix("https://")?;
    Some(format!("http://127.0.0.1:{port}/h/{rest}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ls_redact::binding::HttpKeySpec;

    #[test]
    fn catalog_is_complete_and_consistent() {
        let all = all();
        assert!(all.len() >= 30, "{} providers", all.len());
        for p in all {
            assert!(!p.hosts.is_empty(), "{}", p.id);
            assert!(p.hosts.iter().all(|h| valid_host_pattern(h)), "{}", p.id);
            Placement::parse_list(&p.placement).unwrap_or_else(|e| panic!("{}: {e}", p.id));
            assert!(
                ["env", "config", "none"].contains(&p.base_url_override.as_str()),
                "{}",
                p.id
            );
            assert!(
                p.base_url.is_empty() || p.base_url.starts_with("https://"),
                "{}",
                p.id
            );
            if p.base_url_override == "env" {
                assert!(!p.base_url_env.is_empty(), "{}", p.id);
            }
        }
        for id in ["stripe", "openai", "anthropic", "github", "gemini"] {
            assert!(get(id).is_some(), "{id}");
        }
    }

    #[test]
    fn resolution_priority() {
        let r = resolve(Some(&HttpKey::Provider("openai".into())), None, &[], None).unwrap();
        assert_eq!(r.hosts, ["api.openai.com"]);
        assert_eq!(r.placements, [Placement::Bearer]);
        assert_eq!(r.base_url_env, ["OPENAI_BASE_URL"]);
        assert_eq!(
            relay_url(7, r.base_url.as_deref().unwrap()).unwrap(),
            "http://127.0.0.1:7/h/api.openai.com/v1"
        );
        let t = HttpKey::Custom(HttpKeySpec {
            provider: Some("stripe".into()),
            hosts: vec!["api.stripe.com".into()],
            placement: Some("basic".into()),
            base_url_env: vec!["MY_BASE".into()],
        });
        let r = resolve(Some(&t), None, &[], None).unwrap();
        assert_eq!(
            (r.placements, r.base_url_env),
            (vec![Placement::Basic], vec!["MY_BASE".to_string()])
        );
        let r = resolve(Some(&t), None, &["API.X.test".into()], Some("query:k")).unwrap();
        assert_eq!(r.hosts, ["api.x.test"]);
        assert_eq!(r.placements, [Placement::Query("k".into())]);
        assert!(resolve(None, None, &[], None).is_err());
        assert!(resolve(None, Some("nope"), &[], None).is_err());
        assert!(resolve(None, None, &["a b".into()], None).is_err());
        let r = resolve(None, None, &["api.x.test".into()], None).unwrap();
        assert_eq!(r.base_url.as_deref(), Some("https://api.x.test"));
    }
}
