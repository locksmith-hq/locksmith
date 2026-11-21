//! Issuer-side revoke of a hub MCP client's consent (change m1-remote-mcp, task 4.2, owner
//! decision #493 option A).
//!
//! After the control plane marks an `mcp_clients` row revoked, it asks the OIDC issuer (Keycloak)
//! to delete the person's consent for that OAuth client:
//! `DELETE {url}/admin/realms/{realm}/users/{sub}/consents/{client_id}`. Keycloak then also
//! revokes the client's offline tokens, so the client has to ask for consent again. The call
//! authenticates as a dedicated confidential client through the `client_credentials` grant; its
//! service account holds only `realm-management/manage-users`.
//!
//! This is best effort. The database revoke (the `auth_time` rule in [`crate::mcp_tools`]) is the
//! enforcing control, so a failure here never undoes it: the caller logs the static
//! [`IssuerAdminError::reason`] and appends an `mcp.issuer_revoke` event with outcome `error`.
//! Nothing in this module logs or returns a token, the client secret, a response body or the
//! person's subject; errors are labels only.

use std::time::Duration;

use reqwest::{StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};

/// The admin client's settings (`LOCKSMITH_ISSUER_ADMIN_*`). No `Debug`/`Clone`: it holds the
/// client secret.
pub struct IssuerAdminConfig {
    /// The Keycloak server base URL, e.g. `http://localhost:8180`.
    pub url: String,
    pub realm: String,
    pub client_id: String,
    pub client_secret: SecretString,
}

/// Why the issuer call did not complete. A static label per case, never response text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerAdminError {
    /// The client could not be built or a URL could not be formed.
    Setup,
    /// The principal does not belong to the configured issuer, so it has no user id here.
    ForeignPrincipal,
    /// The token request failed (network or non-200).
    Token,
    /// The consent delete failed (network or a status other than 204 or 404).
    Delete,
}

impl IssuerAdminError {
    /// The static audit and log reason.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Setup => "issuer_admin_setup",
            Self::ForeignPrincipal => "issuer_admin_foreign_principal",
            Self::Token => "issuer_admin_token",
            Self::Delete => "issuer_admin_delete",
        }
    }
}

/// Client for the issuer's admin API.
pub struct IssuerAdmin {
    client: reqwest::Client,
    base: Url,
    realm: String,
    client_id: String,
    secret: SecretString,
    /// `{issuer}|`: the prefix of a stored hub principal (`mcp_clients.principal`).
    principal_prefix: String,
}

impl IssuerAdmin {
    /// `issuer` is the OIDC issuer the human tokens carry (`iss`); a principal is
    /// `{issuer}|{sub}` and `sub` is the issuer's user id.
    pub fn new(config: &IssuerAdminConfig, issuer: &str) -> Result<Self, IssuerAdminError> {
        let client = ls_http::builder()
            .map_err(|_| IssuerAdminError::Setup)?
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|_| IssuerAdminError::Setup)?;
        let base = Url::parse(&config.url).map_err(|_| IssuerAdminError::Setup)?;
        Ok(Self {
            client,
            base,
            realm: config.realm.clone(),
            client_id: config.client_id.clone(),
            secret: SecretString::from(config.client_secret.expose_secret().to_owned()),
            principal_prefix: format!("{issuer}|"),
        })
    }

    fn url(&self, segments: &[&str]) -> Result<Url, IssuerAdminError> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| IssuerAdminError::Setup)?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }

    /// A short-lived admin access token (`client_credentials`).
    async fn token(&self) -> Result<SecretString, IssuerAdminError> {
        let url = self.url(&["realms", &self.realm, "protocol", "openid-connect", "token"])?;
        let resp = self
            .client
            .post(url)
            .basic_auth(&self.client_id, Some(self.secret.expose_secret()))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body("grant_type=client_credentials")
            .send()
            .await
            .map_err(|_| IssuerAdminError::Token)?;
        if resp.status() != StatusCode::OK {
            return Err(IssuerAdminError::Token);
        }
        let body = resp.bytes().await.map_err(|_| IssuerAdminError::Token)?;
        if body.len() > 64 * 1024 {
            return Err(IssuerAdminError::Token);
        }
        let v: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| IssuerAdminError::Token)?;
        v.get("access_token")
            .and_then(serde_json::Value::as_str)
            .filter(|t| !t.is_empty())
            .map(|t| SecretString::from(t.to_owned()))
            .ok_or(IssuerAdminError::Token)
    }

    /// Delete the person's consent for `oauth_client` (and with it that client's offline tokens).
    /// `principal` is the stored `{issuer}|{sub}`. A `404` means there was no consent to delete,
    /// which is the state the revoke wants, so it counts as done.
    pub async fn revoke_consent(
        &self,
        principal: &str,
        oauth_client: &str,
    ) -> Result<(), IssuerAdminError> {
        let sub = principal
            .strip_prefix(&self.principal_prefix)
            .filter(|s| !s.is_empty())
            .ok_or(IssuerAdminError::ForeignPrincipal)?;
        let url = self.url(&[
            "admin",
            "realms",
            &self.realm,
            "users",
            sub,
            "consents",
            oauth_client,
        ])?;
        let token = self.token().await?;
        let resp = self
            .client
            .delete(url)
            .bearer_auth(token.expose_secret())
            .send()
            .await
            .map_err(|_| IssuerAdminError::Delete)?;
        match resp.status() {
            StatusCode::NO_CONTENT | StatusCode::OK | StatusCode::NOT_FOUND => Ok(()),
            _ => Err(IssuerAdminError::Delete),
        }
    }
}
