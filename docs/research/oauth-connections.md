# OAuth connections: reuse check and provider facts

Source: research answer on locksmith-roadmap#155 (vendor docs, checked 2026-11-25). Licence, version and date columns come from it; the Decision column is our own judgement, not from the source. Release years marked "probably" were read from GitHub web pages that did not show the year. "Unverified" means not read on a vendor page; do not build on it without a fake-provider test.

## Reuse check

| Name | Latest | Date | Licence | Decision |
|---|---|---|---|---|
| `oauth2` (crate) | 5.0.0 | 2025-01-21 | MIT OR Apache-2.0 | Use for PKCE, authorize URL and code exchange types. |
| `openidconnect` | 4.1.0 | 2026-10-31 | MIT | Reject (our judgement): the registry is plain OAuth 2.0 and most providers here are not OIDC issuers. |
| `yup-oauth2` | 12.1.2 | 2026-01-07 | MIT OR Apache-2.0 | Reject (our judgement): Google-focused, not a multi-provider registry. |
| Nango | v0.72.6 | 2026-11-16 | Elastic License 2.0 (not OSI) | Reject: licence is ELv2, not OSI; also check before any reuse. |
| Ory Hydra | v26.2.0 | 20 Mar (probably 2026) | Apache-2.0 | Reject (our judgement): an OAuth server, not a client of third-party providers. |
| oauth2-proxy | v7.15.6 | 5 Nov (probably 2026) | MIT | Reject (our judgement): a login proxy, not a token store. |
| Keycloak | 26.8.2 | 5 Nov (probably 2026) | Apache-2.0 | Not chosen: identity-brokering features were not checked; the e2e smoke uses it only as a mock provider. |
| Composio | @composio/cli 0.6.3 | 2026 | MIT | Not chosen (our judgement): a third-party broker; not checked for token custody. |
| Arcade | `arcade-ai` 2.3.0 (tombstone for `arcade-mcp`) | 2026-03-12 | MIT | Not chosen (our judgement): same. |

## Providers

| | PKCE S256 | Access token | Refresh | Revoke |
|---|---|---|---|---|
| GitHub App (expiring user tokens) | yes (S256 only) | 8 h | rotates, 6 months | `DELETE https://api.github.com/applications/{client_id}/token` (one token) or `.../grant` (whole authorization), Basic auth, JSON `{"access_token"}`, 204 or 422 |
| GitHub OAuth App | not stated (PKCE is documented for the App section only) | no expiry (inferred) | none (inferred) | same; `read:user` gives the private `/user` profile |
| Google (External app in Testing) | yes: set `S256`, default is `plain` | `expires_in`, about 1 h (unverified) | no rotation (unverified); 7 days in Testing unless only `openid email profile`; 100 per account per client; 6 months unused | `POST https://oauth2.googleapis.com/revoke`, form `token`, 200 |
| Slack (v2 user token) | not documented: treat as unsupported | 12 h with rotation (`xoxe.xoxp-`), otherwise no expiry | opt-in rotation, single use, short grace; lifetime not stated | `POST https://slack.com/api/auth.revoke`, form `token`, `{"ok":true,"revoked":true}` |
| Linear | yes (`plain`, `S256`); secret optional with PKCE | 24 h | 30 days, rotates, same token retryable for 30 min | `POST https://api.linear.app/oauth/revoke`, `token`, 200/400/401 |
| Atlassian 3LO | not documented: treat as unsupported | `expires_in` (1 h unverified) | rotates, 10 min leeway, 90 days inactivity; 365-day cap unconfirmed | none documented (community thread, medium confidence): delete locally, point the user to Connected apps |

## Endpoints

- **GitHub:** authorize `https://github.com/login/oauth/authorize`; token `https://github.com/login/oauth/access_token` (send `Accept: application/json`, else form-encoded); user `GET https://api.github.com/user`; API host `api.github.com`. App permissions are set at registration; `scope` takes only `offline_access`. Refresh needs `client_secret` except for device-flow tokens.
- **Google:** authorize `https://accounts.google.com/o/oauth2/v2/auth` (`access_type=offline`, `prompt=consent` for a fresh refresh token); token `https://oauth2.googleapis.com/token`; user `https://openidconnect.googleapis.com/v1/userinfo`; hosts `*.googleapis.com` (list unverified: pin exact hosts per scope). Minimal scopes: `openid email profile` plus the narrowest `.readonly` scope of the target API.
- **Slack:** authorize `https://slack.com/oauth/v2/authorize?user_scope=...`; token `https://slack.com/api/oauth.v2.access` (user token in `authed_user.access_token`; the code lives 10 min); user `https://slack.com/api/openid.connect.userInfo` with `openid profile email`; host `slack.com`. Always check `ok`; errors are `{"ok":false,"error":...}` (HTTP 200 unverified).
- **Linear:** authorize `https://linear.app/oauth/authorize`; token `https://api.linear.app/oauth/token` (form); scope `read`; API `https://api.linear.app/graphql`, user from the `viewer` query (unverified).
- **Atlassian:** authorize `https://auth.atlassian.com/authorize` (requires `audience=api.atlassian.com` and `prompt=consent`); token `https://auth.atlassian.com/oauth/token`; scopes need `offline_access` for a refresh token and `read:me` for `GET https://api.atlassian.com/me`; sites from `/oauth/token/accessible-resources` (`id` is the `cloudid`); API host `api.atlassian.com`.

## Registry rules that follow

- Per provider record `pkce` (GitHub, Google, Linear only), `rotating_refresh` and `revoke` (Atlassian: none).
- Treat Google refresh tokens in Testing mode as 7-day tokens and say so in the connect UI.
- Handle Slack `ok:false` and `authed_user`, GitHub's `Accept` header, Atlassian `audience` and `cloudid`.
- Unknowns to cover with fakes, not assumptions: PKCE at Slack and Atlassian, Atlassian's 365-day cap, Slack's refresh lifetime, the GitHub App permission `/user` needs, Google's access-token lifetime.

## OSS used

`oauth2` 5.0.0 (released 2025-01-21), MIT OR Apache-2.0. Record this line in `design.md` "OSS used".

Confidence: high for GitHub, Linear and Google endpoints, GitHub/Linear/Slack lifetimes and Google's 7-day Testing limit; medium for Slack user-info scopes and Atlassian having no revoke endpoint.
