//! Upstream credentials: PAT header and GitHub App installation tokens (task 1.3).

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde::Deserialize;
use zeroize::Zeroizing;

/// Upstream credential stored in the vault under a key name. The value is either a plain PAT
/// or JSON `{"app_id":123,"installation_id":456,"private_key":"-----BEGIN RSA PRIVATE KEY-----..."}`.
pub enum Credential {
    Pat(Zeroizing<String>),
    App(AppCreds),
}

pub struct AppCreds {
    pub app_id: u64,
    pub installation_id: u64,
    pub private_key: Zeroizing<String>,
}

#[derive(Deserialize)]
struct AppJson {
    app_id: u64,
    installation_id: u64,
    private_key: String,
}

/// Errors never include the value (serde messages can echo input, so they are not forwarded).
pub fn parse_credential(value: &[u8]) -> Result<Credential, String> {
    let text = Zeroizing::new(
        std::str::from_utf8(value)
            .map_err(|_| "credential is not valid UTF-8".to_string())?
            .trim()
            .to_string(),
    );
    if text.is_empty() {
        return Err("credential is empty".into());
    }
    if text.starts_with('{') {
        let j: AppJson = serde_json::from_str(&text).map_err(|_| {
            "credential looks like JSON but is not a valid GitHub App credential \
             (need app_id, installation_id, private_key)"
                .to_string()
        })?;
        return Ok(Credential::App(AppCreds {
            app_id: j.app_id,
            installation_id: j.installation_id,
            private_key: Zeroizing::new(j.private_key),
        }));
    }
    Ok(Credential::Pat(text))
}

/// `Authorization` header value for a PAT (or any token): `Basic base64("x-access-token:" + t)`.
pub fn pat_header(pat: &str) -> Zeroizing<String> {
    let raw = Zeroizing::new(format!("x-access-token:{pat}"));
    Zeroizing::new(format!("Basic {}", STANDARD.encode(raw.as_bytes())))
}

fn key_pair(pem: &str) -> Result<RsaKeyPair, String> {
    let pkcs8 = pem.contains("BEGIN PRIVATE KEY");
    if !pkcs8 && !pem.contains("BEGIN RSA PRIVATE KEY") {
        return Err("private key is not a PKCS#1 or PKCS#8 RSA PEM".into());
    }
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect();
    let der = Zeroizing::new(
        STANDARD
            .decode(b64)
            .map_err(|_| "private key PEM is not valid base64".to_string())?,
    );
    let kp = if pkcs8 {
        RsaKeyPair::from_pkcs8(&der)
    } else {
        RsaKeyPair::from_der(&der)
    };
    kp.map_err(|_| "private key is not a valid RSA key".to_string())
}

/// RS256 JWT for the App (iat = now-60, exp = now+540, iss = app_id).
pub fn app_jwt(app: &AppCreds, now: i64) -> Result<Zeroizing<String>, String> {
    let kp = key_pair(&app.private_key)?;
    let claims = format!(
        r#"{{"iat":{},"exp":{},"iss":{}}}"#,
        now - 60,
        now + 540,
        app.app_id
    );
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims)
    );
    let mut sig = vec![0u8; kp.public().modulus_len()];
    kp.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        signing_input.as_bytes(),
        &mut sig,
    )
    .map_err(|_| "JWT signing failed".to_string())?;
    Ok(Zeroizing::new(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(sig)
    )))
}

/// Parses `YYYY-MM-DDTHH:MM:SSZ` to unix seconds.
fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20 || b[19] != b'Z' || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (h, mi, sec) = (n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // days from civil (Howard Hinnant)
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + sec)
}

#[derive(Deserialize)]
struct TokenResp {
    token: String,
    expires_at: String,
}

type Entry = (Zeroizing<String>, i64);

/// Per-repository installation-token cache (design D3). Tokens are reused until
/// 5 minutes before `expires_at`.
pub struct TokenCache {
    api: String,
    map: Mutex<HashMap<(u64, String), Entry>>,
}

impl TokenCache {
    pub fn new(api_base: impl Into<String>) -> Self {
        Self {
            api: api_base.into().trim_end_matches('/').to_string(),
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Raw installation token for `repo` ("owner/name"); the repositories filter uses only the
    /// name part.
    pub fn token_for(
        &self,
        app: &AppCreds,
        repo: &str,
        now: i64,
    ) -> Result<Zeroizing<String>, String> {
        let key = (app.installation_id, repo.to_string());
        // Held across the network call so concurrent misses mint once.
        let mut map = self
            .map
            .lock()
            .map_err(|_| "token cache poisoned".to_string())?;
        if let Some((t, exp)) = map.get(&key)
            && now < exp - 300
        {
            return Ok(t.clone());
        }
        let name = repo.rsplit('/').next().unwrap_or(repo);
        let jwt = app_jwt(app, now)?;
        let url = format!(
            "{}/app/installations/{}/access_tokens",
            self.api, app.installation_id
        );
        let body = serde_json::json!({
            "repositories": [name],
            "permissions": {"contents":"write","pull_requests":"write","metadata":"read"}
        });
        let auth = Zeroizing::new(format!("Bearer {}", jwt.as_str()));
        let mut resp = ureq::post(&url)
            .header("Authorization", auth.as_str())
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "locksmith")
            .send_json(body)
            .map_err(|e| match e {
                ureq::Error::StatusCode(c) => format!("GitHub token request failed: HTTP {c}"),
                _ => "GitHub token request failed: transport error".to_string(),
            })?;
        let t: TokenResp = resp
            .body_mut()
            .read_json()
            .map_err(|_| "GitHub token response was not valid".to_string())?;
        let token = Zeroizing::new(t.token);
        let exp = parse_rfc3339(&t.expires_at)
            .ok_or_else(|| "GitHub token response had a bad expires_at".to_string())?;
        map.insert(key, (token.clone(), exp));
        Ok(token)
    }

    /// `Authorization` header value for `repo`.
    pub fn header_for(
        &self,
        app: &AppCreds,
        repo: &str,
        now: i64,
    ) -> Result<Zeroizing<String>, String> {
        Ok(pat_header(&self.token_for(app, repo, now)?))
    }
}

/// Credential -> raw token (the PAT itself, or the installation token).
pub fn upstream_token(
    cred: &Credential,
    cache: &TokenCache,
    repo: &str,
    now: i64,
) -> Result<Zeroizing<String>, String> {
    match cred {
        Credential::Pat(p) => Ok(p.clone()),
        Credential::App(a) => cache.token_for(a, repo, now),
    }
}

/// Credential -> `Authorization` header for one request.
pub fn upstream_header(
    cred: &Credential,
    cache: &TokenCache,
    repo: &str,
    now: i64,
) -> Result<Zeroizing<String>, String> {
    Ok(pat_header(&upstream_token(cred, cache, repo, now)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;

    struct Keys {
        pkcs1: String,
        pkcs8: String,
        pubder: Vec<u8>,
    }

    fn openssl(args: &[&str]) -> bool {
        Command::new("openssl")
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn gen_keys() -> Option<Keys> {
        let dir: PathBuf = std::env::temp_dir().join(format!(
            "ls-gh-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).ok()?;
        let p = |n: &str| dir.join(n).to_string_lossy().into_owned();
        let (raw, k1, k8, pubf) = (p("raw.pem"), p("k1.pem"), p("k8.pem"), p("pub.der"));
        let ok = openssl(&["genrsa", "-out", &raw, "2048"])
            && openssl(&["rsa", "-traditional", "-in", &raw, "-out", &k1])
            && openssl(&["pkcs8", "-topk8", "-nocrypt", "-in", &k1, "-out", &k8])
            && openssl(&[
                "rsa",
                "-in",
                &k1,
                "-RSAPublicKey_out",
                "-outform",
                "DER",
                "-out",
                &pubf,
            ]);
        if !ok {
            println!("openssl unavailable or failed; skipping");
            return None;
        }
        let keys = Keys {
            pkcs1: std::fs::read_to_string(&k1).ok()?,
            pkcs8: std::fs::read_to_string(&k8).ok()?,
            pubder: std::fs::read(&pubf).ok()?,
        };
        let _ = std::fs::remove_dir_all(&dir);
        Some(keys)
    }

    type Seen = Arc<Mutex<Vec<(String, String)>>>; // (request head, body)

    /// Serves one canned token response per request; `expiries` are handed out in order.
    fn mock(expiries: Vec<String>) -> (String, Seen) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen: Seen = Arc::default();
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for (i, conn) in l.incoming().enumerate() {
                let mut c = conn.unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head, body) = loop {
                    let n = c.read(&mut chunk).unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    if let Some(p) = text.find("\r\n\r\n") {
                        let head = text[..p].to_string();
                        let len = head
                            .to_lowercase()
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: ").map(str::to_string))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if text.len() >= p + 4 + len {
                            break (head, text[p + 4..].to_string());
                        }
                    }
                    if n == 0 {
                        break (String::new(), String::new());
                    }
                };
                s2.lock().unwrap().push((head, body));
                let exp = expiries.get(i).cloned().unwrap_or_default();
                let json = format!(r#"{{"token":"ghs_tok{i}","expires_at":"{exp}"}}"#);
                let _ = write!(
                    c,
                    "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
                    json.len()
                );
            }
        });
        (url, seen)
    }

    fn app(key: &str) -> AppCreds {
        AppCreds {
            app_id: 123,
            installation_id: 456,
            private_key: Zeroizing::new(key.to_string()),
        }
    }

    fn b64(h: &str) -> String {
        String::from_utf8(STANDARD.decode(h.strip_prefix("Basic ").unwrap()).unwrap()).unwrap()
    }

    fn iso(t: i64) -> String {
        let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + i64::from(m <= 2);
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            secs / 3600,
            secs % 3600 / 60,
            secs % 60
        )
    }

    #[test]
    fn pat_header_is_basic_x_access_token() {
        assert_eq!(b64(&pat_header("ghp_abc")), "x-access-token:ghp_abc");
    }

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2024-02-29T12:30:45Z"), Some(1_709_209_845));
        assert_eq!(parse_rfc3339("garbage"), None);
        assert_eq!(parse_rfc3339(&iso(1_800_000_123)), Some(1_800_000_123));
    }

    #[test]
    fn parse_credential_variants_and_no_leak() {
        assert!(matches!(
            parse_credential(b"ghp_secretvalue\n"),
            Ok(Credential::Pat(p)) if p.as_str() == "ghp_secretvalue"
        ));
        let ok = br#"{"app_id":1,"installation_id":2,"private_key":"k"}"#;
        assert!(matches!(parse_credential(ok), Ok(Credential::App(a)) if a.installation_id == 2));
        let bad = br#"{"app_id":"SUPERSECRET","installation_id":2}"#;
        let e = parse_credential(bad).err().unwrap();
        assert!(!e.contains("SUPERSECRET"));
        let e = parse_credential(&[0xff, b'S', b'E', b'C']).err().unwrap();
        assert!(!e.contains("SEC"));
        assert!(parse_credential(b"  ").is_err());
    }

    #[test]
    fn jwt_signs_with_both_formats_and_verifies() {
        let Some(k) = gen_keys() else { return };
        for pem in [&k.pkcs1, &k.pkcs8] {
            let jwt = app_jwt(&app(pem), 1_000_000).unwrap();
            let parts: Vec<&str> = jwt.split('.').collect();
            let claims: serde_json::Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
            assert_eq!(claims["iss"], 123);
            assert_eq!(claims["iat"], 1_000_000 - 60);
            assert_eq!(claims["exp"], 1_000_000 + 540);
            let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
            ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                &k.pubder,
            )
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .unwrap();
        }
        assert!(app_jwt(&app("not a key"), 0).is_err());
    }

    #[test]
    fn token_mint_request_cache_and_refresh() {
        let Some(k) = gen_keys() else { return };
        let now = 1_800_000_000;
        // 1st token valid 1h; 2nd expires in 4 min (inside the 5 min margin); 3rd valid.
        let (url, seen) = mock(vec![iso(now + 3600), iso(now + 240), iso(now + 3600)]);
        let cache = TokenCache::new(url);
        let a = app(&k.pkcs1);

        let h1 = cache.header_for(&a, "acme/widgets", now).unwrap();
        assert_eq!(b64(&h1), "x-access-token:ghs_tok0");
        let h2 = cache.header_for(&a, "acme/widgets", now + 10).unwrap();
        assert_eq!(*h1, *h2);
        assert_eq!(seen.lock().unwrap().len(), 1, "second call must hit cache");

        {
            let s = seen.lock().unwrap();
            let (head, body) = &s[0];
            assert!(head.starts_with("POST /app/installations/456/access_tokens"));
            let lower = head.to_lowercase();
            assert!(lower.contains("accept: application/vnd.github+json"));
            assert!(lower.contains("x-github-api-version: 2022-11-28"));
            assert!(lower.contains("user-agent: locksmith"));
            let jwt = head
                .lines()
                .find_map(|l| {
                    l.to_lowercase()
                        .starts_with("authorization: bearer ")
                        .then(|| l[22..].to_string())
                })
                .unwrap();
            let parts: Vec<&str> = jwt.split('.').collect();
            ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                &k.pubder,
            )
            .verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
            )
            .unwrap();
            let v: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(v["repositories"], serde_json::json!(["widgets"]));
            assert_eq!(
                v["permissions"],
                serde_json::json!({"contents":"write","pull_requests":"write","metadata":"read"})
            );
        }

        // Other repo: separate entry (2nd token, expiring in 4 min).
        let h3 = cache.header_for(&a, "acme/other", now).unwrap();
        assert_eq!(b64(&h3), "x-access-token:ghs_tok1");
        // Within-margin token is re-minted.
        let h4 = cache.header_for(&a, "acme/other", now + 1).unwrap();
        assert_eq!(b64(&h4), "x-access-token:ghs_tok2");
        assert_eq!(seen.lock().unwrap().len(), 3);
    }

    #[test]
    fn upstream_token_and_header_dispatch() {
        let Some(k) = gen_keys() else { return };
        let now = 1_800_000_000;
        let (url, seen) = mock(vec![iso(now + 3600)]);
        let cache = TokenCache::new(url);

        let pat = Credential::Pat(Zeroizing::new("ghp_p".into()));
        assert_eq!(*upstream_token(&pat, &cache, "a/b", now).unwrap(), "ghp_p");
        assert_eq!(
            b64(&upstream_header(&pat, &cache, "a/b", now).unwrap()),
            "x-access-token:ghp_p"
        );
        assert_eq!(seen.lock().unwrap().len(), 0, "PAT never calls the API");

        let appc = Credential::App(app(&k.pkcs8));
        assert_eq!(
            *upstream_token(&appc, &cache, "acme/w", now).unwrap(),
            "ghs_tok0"
        );
        assert_eq!(
            b64(&upstream_header(&appc, &cache, "acme/w", now + 5).unwrap()),
            "x-access-token:ghs_tok0"
        );
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn api_error_reports_status_only() {
        let Some(k) = gen_keys() else { return };
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            // Read the whole request first: replying early can reset the client mid-upload.
            let (mut got, mut b) = (Vec::new(), [0u8; 8192]);
            loop {
                let n = c.read(&mut b).unwrap_or(0);
                got.extend_from_slice(&b[..n]);
                let t = String::from_utf8_lossy(&got);
                let done = t.split_once("\r\n\r\n").is_some_and(|(h, body)| {
                    let len = h
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    body.len() >= len
                });
                if n == 0 || done {
                    break;
                }
            }
            let body = "ECHOED-SECRET";
            let _ = write!(
                c,
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        });
        let e = TokenCache::new(url)
            .header_for(&app(&k.pkcs1), "a/b", 1)
            .unwrap_err();
        assert!(e.contains("401") && !e.contains("ECHOED"));
    }
}
