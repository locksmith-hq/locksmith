//! Owner-only honey token reveal (t5-honey-tokens task 2.4), for `smith honey plant`.
//!
//! A person (not an agent) asks the gateway for a honey token's decoy value with their own OIDC
//! access token: `GET /v1/honey-tokens?name=` resolves a name to an id, and
//! `GET /v1/honey-tokens/{id}/value` returns the value as raw bytes. The gateway refuses agent
//! credentials and anyone but the org's owner, and records `honey.revealed` before it decrypts.
//!
//! The value is returned only in a zeroizing buffer; errors are fixed messages with at most the
//! gateway's error slug, never server or transport text.

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{Error, Result, client, error_slug, fail, read_body, transport, uuid_like};

/// One honey token the owner can plant. Metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HoneyToken {
    pub id: String,
    pub name: String,
    pub template: String,
    pub disabled: bool,
}

fn honey_fail(status: reqwest::StatusCode, body: &[u8], what: &str) -> Error {
    let hint = match status.as_u16() {
        401 => " (sign-in not accepted; run `smith login --user`)",
        403 => " (only the org's owner may do this; agent credentials are refused)",
        404 => " (no such honey token)",
        409 => " (not a honey token, disabled, or not minted yet)",
        _ => "",
    };
    fail(&format!(
        "{what} failed: {} {}{hint}",
        status.as_u16(),
        error_slug(body)
    ))
}

/// The org's honey tokens named `name` (`gateway` is a validated endpoint).
pub fn honey_find(gateway: &str, user: &SecretString, name: &str) -> Result<Vec<HoneyToken>> {
    #[derive(Deserialize)]
    struct Refs {
        items: Vec<HoneyToken>,
    }
    let mut url = url::Url::parse(&format!("{gateway}/v1/honey-tokens"))
        .map_err(|_| fail("invalid gateway URL"))?;
    url.query_pairs_mut().append_pair("name", name);
    let resp = client()?
        .get(url)
        .bearer_auth(user.expose_secret())
        .send()
        .map_err(|e| transport(&e))?;
    let status = resp.status();
    let body = read_body(resp)?;
    if !status.is_success() {
        return Err(honey_fail(status, &body, "honey token lookup"));
    }
    let refs: Refs = serde_json::from_slice(&body)
        .map_err(|_| fail("the gateway returned an unusable honey token list"))?;
    Ok(refs.items)
}

/// The decoy value of honey token `id`, in a zeroizing buffer. Never print it.
pub fn honey_value(gateway: &str, user: &SecretString, id: &str) -> Result<Zeroizing<Vec<u8>>> {
    let id = uuid_like(id)?;
    let resp = client()?
        .get(format!("{gateway}/v1/honey-tokens/{id}/value"))
        .bearer_auth(user.expose_secret())
        .send()
        .map_err(|e| transport(&e))?;
    let status = resp.status();
    let body = read_body(resp)?;
    if !status.is_success() {
        return Err(honey_fail(status, &body, "honey value reveal"));
    }
    if body.is_empty() {
        return Err(fail("the gateway returned an empty honey value"));
    }
    Ok(body)
}
