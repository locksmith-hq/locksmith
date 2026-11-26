//! Honey token detection in the gateway (t5-honey-tokens group 3, design decisions 3-5).
//!
//! **By reference** (task 3.1): every agent path resolves a secret through
//! [`Decryptor::decrypt`](crate::decrypt::Decryptor::decrypt), which refuses a secret of kind
//! `honey` with the typed [`DecryptError::Honey`](crate::decrypt::DecryptError::Honey) before any
//! unwrap. The path then calls [`record`] with its [`HoneyPath`] and denies with the same fixed
//! `denied` answer as any other refusal, so a caller cannot tell a tripwire from a policy refusal.
//! The MCP `issue_short_lived_credential` tool decrypts nothing, so it asks [`HoneyScan`] whether
//! the secret is a honey token instead (path `delegate`).
//!
//! **By value** (task 3.2): [`HoneyScan`] holds one `aho-corasick` automaton ([`HoneyScanner`])
//! over the org's active (not disabled, minted) honey values in their raw, base64 (standard and
//! URL-safe, at every byte alignment, padded or not) and URL-encoded (reserved bytes only, or
//! every byte; upper and lower hex) forms.
//! The values come from the control plane's scan list (ids and versions only) and are opened with
//! [`Decryptor::decrypt_honey`](crate::decrypt::Decryptor::decrypt_honey); they and every pattern
//! live in [`SecretBytes`] (zeroized on drop; no `Debug`, `Display` or `Clone`). The automaton is
//! rebuilt only when the set of (token, version) pairs changes; [`spawn_refresher`] re-reads the
//! list every [`MAX_CACHE_TTL`], so a new or disabled token takes effect within that time. The
//! relay scans the target URL, every header and the body of each request before its grant check;
//! a match appends `honey.triggered` with path `value_match` and the request is not forwarded.
//! A scan that cannot be loaded refuses the request (fail closed).
//!
//! The `honey.triggered` event ([`HoneyEvent`]) holds ids, a closed path code and the caller's IP
//! address: never the value, a header, a body or a URL. Logs name the token id and the path only.

use std::collections::HashSet;
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;

use aho_corasick::{AhoCorasick, MatchKind};
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use ls_envelope::SecretBytes;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::{AuditError, HoneyEvent};
use crate::decrypt::{BoxFuture, ControlPlane, Decryptor, Internal};
use crate::relay::Relay;
use crate::ttl::MAX_CACHE_TTL;

pub use crate::audit::HoneyPath;

/// Encoded forms are matched only for values at least this long (as in `ls-redact`); shorter
/// values are matched raw. Minted honey values are 20 bytes or more.
const MIN_ENCODED_LEN: usize = ls_redact::MIN_ENCODED_LEN;

/// Largest scan list read (metadata only).
const MAX_LIST_RESPONSE: usize = 1024 * 1024;

/// Append `honey.triggered` for `ev`, retrying a ledger that is briefly unavailable as relay
/// outcomes are. The caller denies whether or not it lands (nothing was decrypted).
pub(crate) async fn record(relay: &Relay, ev: HoneyEvent) {
    tracing::warn!(
        agent.id = %ev.agent_id,
        secret.id = %ev.secret_id,
        honey.path = ev.path.as_str(),
        "honey token used; refused"
    );
    let mut wait = relay.options().outcome_retry_backoff;
    let retries = relay.options().outcome_retries;
    for try_no in 0..=retries {
        match relay.audit().append_honey(ev).await {
            Ok(_) => return,
            Err(AuditError::Rejected) => break,
            Err(AuditError::Unavailable) if try_no < retries => {
                tokio::time::sleep(wait).await;
                wait = wait.saturating_mul(2);
            }
            Err(AuditError::Unavailable) => break,
        }
    }
    tracing::error!(secret.id = %ev.secret_id, honey.path = ev.path.as_str(), "honey.triggered event not appended");
}

/// One honey token as the control plane's scan list names it: ids and flags, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HoneyListItem {
    pub secret_id: Uuid,
    pub disabled: bool,
    /// The version holding the value; `None` before it is minted.
    #[serde(default)]
    pub version: Option<u32>,
}

/// Why the scan list could not be read. Status classes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanError {
    /// The list could not be read.
    ListUnavailable,
    /// An active honey value could not be opened.
    DecryptFailed,
}

/// The org's honey tokens (every one, disabled included), for the scan.
pub trait HoneyListSource: Send + Sync {
    fn honey_tokens(&self) -> BoxFuture<'_, Result<Vec<HoneyListItem>, ScanError>>;
}

#[derive(Deserialize)]
struct ListJson {
    items: Vec<HoneyListItem>,
}

impl HoneyListSource for ControlPlane {
    fn honey_tokens(&self) -> BoxFuture<'_, Result<Vec<HoneyListItem>, ScanError>> {
        Box::pin(async move {
            // The service token alone: the scan list of `GET /internal/v1/honey/tokens`.
            let body = self
                .internal_get("internal/v1/honey/tokens", MAX_LIST_RESPONSE)
                .await
                .map_err(|e: Internal| {
                    tracing::warn!(error = ?e, "honey scan list unavailable");
                    ScanError::ListUnavailable
                })?;
            let list: ListJson =
                serde_json::from_slice(&body).map_err(|_| ScanError::ListUnavailable)?;
            Ok(list.items)
        })
    }
}

/// The stable middle of `base64(zeros(k) ‖ v)`: the characters whose bits all come from `v`, so
/// the pattern matches `v` at byte offset `k (mod 3)` inside any larger base64 text, padded or not.
fn base64_aligned(v: &[u8], k: usize, engine: &impl base64::Engine) -> Option<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; k]);
    buf.extend_from_slice(v);
    let enc = Zeroizing::new(engine.encode(&*buf).into_bytes());
    let start = (4 * k).div_ceil(3);
    let end = (8 * (k + v.len())) / 6;
    (end > start).then(|| Zeroizing::new(enc[start..end].to_vec()))
}

/// Percent-encoding of every byte outside the RFC 3986 unreserved set.
fn percent(v: &[u8], upper: bool) -> Zeroizing<Vec<u8>> {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let hex = if upper { HEX_UPPER } else { HEX_LOWER };
    let mut out = Zeroizing::new(Vec::with_capacity(v.len() * 3));
    for &b in v {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b);
        } else {
            out.extend_from_slice(&[b'%', hex[usize::from(b >> 4)], hex[usize::from(b & 15)]]);
        }
    }
    out
}

/// Percent-encoding of every byte (`%41%4B...`), the form a URL encoder that escapes everything
/// produces.
fn percent_all(v: &[u8], upper: bool) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(v.len() * 3));
    for &b in v {
        let pair = if upper {
            format!("%{b:02X}")
        } else {
            format!("%{b:02x}")
        };
        out.extend_from_slice(pair.as_bytes());
    }
    out
}

/// The forms of one value the scan matches: raw, base64 and URL-encoded.
fn forms(v: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut out = vec![Zeroizing::new(v.to_vec())];
    if v.len() >= MIN_ENCODED_LEN {
        for k in 0..3 {
            out.extend(base64_aligned(v, k, &STANDARD_NO_PAD));
            out.extend(base64_aligned(v, k, &URL_SAFE_NO_PAD));
        }
        out.push(percent(v, true));
        out.push(percent(v, false));
        out.push(percent_all(v, true));
        out.push(percent_all(v, false));
    }
    out.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    out.dedup_by(|a, b| a.as_slice() == b.as_slice());
    out.retain(|p| !p.is_empty());
    out
}

/// One automaton over the active honey values. No `Debug` or `Clone`: it holds the patterns.
pub struct HoneyScanner {
    // Shortcut (as ls-redact): aho-corasick keeps its own, non-zeroized copy of the patterns; it
    // lives only in the gateway, which can open these values anyway.
    ac: Option<AhoCorasick>,
    /// The token each pattern belongs to.
    owners: Vec<Uuid>,
    /// The patterns, kept so they are wiped when the scanner is dropped.
    _patterns: Vec<SecretBytes>,
}

impl HoneyScanner {
    /// Build from (token, value) pairs. An empty set matches nothing.
    pub fn new(values: &[(Uuid, SecretBytes)]) -> Self {
        let mut patterns = Vec::new();
        let mut owners = Vec::new();
        for (id, value) in values {
            for p in forms(value.expose()) {
                patterns.push(SecretBytes::new(p.to_vec()));
                owners.push(*id);
            }
        }
        let ac = (!patterns.is_empty()).then(|| {
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostFirst)
                .build(patterns.iter().map(SecretBytes::expose))
                .expect("honey patterns build")
        });
        Self {
            ac,
            owners,
            _patterns: patterns,
        }
    }

    /// The token whose value (in any form the scan knows) occurs first in `input`.
    pub fn find(&self, input: &[u8]) -> Option<Uuid> {
        let m = self.ac.as_ref()?.find(input)?;
        Some(self.owners[m.pattern().as_usize()])
    }

    /// How many patterns the automaton holds.
    pub fn pattern_count(&self) -> usize {
        self.owners.len()
    }
}

/// One loaded scan: the automaton, the (token, version) set it was built from and every honey
/// token id of the org (disabled ones included).
struct Loaded {
    key: Vec<(Uuid, u32)>,
    honey_ids: HashSet<Uuid>,
    scanner: Arc<HoneyScanner>,
}

/// The org's honey scan, rebuilt when its set of active tokens changes. No `Debug` or `Clone`.
pub struct HoneyScan {
    source: Arc<dyn HoneyListSource>,
    loaded: RwLock<Option<Arc<Loaded>>>,
    /// One refresh at a time.
    refreshing: tokio::sync::Mutex<()>,
}

impl HoneyScan {
    pub fn new(source: Arc<dyn HoneyListSource>) -> Self {
        Self {
            source,
            loaded: RwLock::new(None),
            refreshing: tokio::sync::Mutex::new(()),
        }
    }

    fn current(&self) -> Option<Arc<Loaded>> {
        self.loaded
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Re-read the list; rebuild the automaton only if the active (token, version) set changed.
    /// On failure the previous scan stays in force.
    pub async fn refresh(&self, decryptor: &Decryptor) -> Result<(), ScanError> {
        let _one = self.refreshing.lock().await;
        let items = self.source.honey_tokens().await?;
        let honey_ids: HashSet<Uuid> = items.iter().map(|i| i.secret_id).collect();
        let mut key: Vec<(Uuid, u32)> = items
            .iter()
            .filter(|i| !i.disabled)
            .filter_map(|i| i.version.map(|v| (i.secret_id, v)))
            .collect();
        key.sort_unstable();
        key.dedup();
        let previous = self.current();
        let scanner = match &previous {
            Some(p) if p.key == key => p.scanner.clone(),
            _ => {
                let mut values = Vec::with_capacity(key.len());
                for (id, version) in &key {
                    let value = decryptor.decrypt_honey(*id, *version).await.map_err(|e| {
                        tracing::warn!(secret.id = %id, error = %e, "honey value did not open for the scan");
                        ScanError::DecryptFailed
                    })?;
                    values.push((*id, value));
                }
                let scanner = Arc::new(HoneyScanner::new(&values));
                tracing::info!(
                    tokens = key.len(),
                    patterns = scanner.pattern_count(),
                    "honey scan rebuilt"
                );
                scanner
            }
        };
        *self.loaded.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(Loaded {
            key,
            honey_ids,
            scanner,
        }));
        Ok(())
    }

    /// The loaded scan, loading it first if it never loaded.
    async fn ready(&self, decryptor: &Decryptor) -> Result<Arc<Loaded>, ScanError> {
        if let Some(l) = self.current() {
            return Ok(l);
        }
        self.refresh(decryptor).await?;
        self.current().ok_or(ScanError::ListUnavailable)
    }

    /// The automaton in force (loaded on first use).
    pub async fn scanner(&self, decryptor: &Decryptor) -> Result<Arc<HoneyScanner>, ScanError> {
        Ok(self.ready(decryptor).await?.scanner.clone())
    }

    /// Whether `secret_id` is one of the org's honey tokens (disabled ones included).
    pub async fn is_honey(
        &self,
        decryptor: &Decryptor,
        secret_id: Uuid,
    ) -> Result<bool, ScanError> {
        Ok(self.ready(decryptor).await?.honey_ids.contains(&secret_id))
    }
}

/// Refresh `relay`'s honey scan every `every` until the relay is dropped. A failed refresh keeps
/// the previous scan and is logged (status class only).
pub fn spawn_refresher(relay: &Arc<Relay>, every: Duration) -> Option<tokio::task::JoinHandle<()>> {
    relay.honey_scan()?;
    let weak: Weak<Relay> = Arc::downgrade(relay);
    Some(tokio::spawn(async move {
        loop {
            let Some(relay) = weak.upgrade() else { return };
            if let Some(scan) = relay.honey_scan()
                && let Err(e) = scan.refresh(relay.decryptor()).await
            {
                tracing::warn!(error = ?e, "honey scan refresh failed; the previous scan stays");
            }
            drop(relay);
            tokio::time::sleep(every).await;
        }
    }))
}

/// The default refresh interval: the gateway's cache bound.
pub const REFRESH_EVERY: Duration = MAX_CACHE_TTL;

/// What the relay scans in one request: the target URL, each header name and value, the body.
pub(crate) fn scan_request(
    scanner: &HoneyScanner,
    url: &url::Url,
    headers: &reqwest::header::HeaderMap,
    body: &[u8],
) -> Option<Uuid> {
    scanner
        .find(url.as_str().as_bytes())
        .or_else(|| {
            headers.iter().find_map(|(n, v)| {
                scanner
                    .find(n.as_str().as_bytes())
                    .or_else(|| scanner.find(v.as_bytes()))
            })
        })
        .or_else(|| scanner.find(body))
}

#[cfg(test)]
#[path = "honey_guard_tests.rs"]
mod tests;
