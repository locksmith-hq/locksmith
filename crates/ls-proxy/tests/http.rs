//! HTTP relay end to end against a local echo upstream (plain TCP via the test switch): swap
//! rules, allowlist, placement, response cleansing for every content coding, streaming, and
//! explicit-proxy mode with the name-constrained CA (curl, when installed).

use base64::Engine;
use ls_proxy::http::{
    Attempt, HttpAuthority, HttpGrant, Placement, Upstream, check, host_allowed, new_token, serve,
};
use ls_proxy::{Deny, ca};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const HOST: &str = "api.allowed.test";

/// Built at runtime so no key-shaped literal sits in the source.
fn secret() -> String {
    format!("sk_test_{}_{}", "relay", "Zq81pXv3/Wm+aa")
}

fn token() -> &'static str {
    static T: OnceLock<String> = OnceLock::new();
    T.get_or_init(new_token)
}

struct Fake {
    places: Vec<Placement>,
    blocked: Mutex<Vec<String>>,
    ca: Option<(String, Zeroizing<String>)>,
}

impl HttpAuthority for Fake {
    fn authorize(&self, a: &Attempt<'_>) -> Result<HttpGrant, Deny> {
        if a.token != token() {
            return Err(Deny {
                status: 401,
                message: "unknown token".into(),
            });
        }
        if let Err((rule, message)) = check(&[HOST.to_string()], &self.places, a.host, a.found) {
            self.blocked.lock().unwrap().push(rule.to_string());
            return Err(Deny {
                status: 403,
                message,
            });
        }
        Ok(HttpGrant {
            secret: Zeroizing::new(secret().into_bytes()),
            placements: self.places.clone(),
            label: "API_KEY".into(),
        })
    }
    fn intercept(
        &self,
        host: &str,
        _: SocketAddr,
        _: SocketAddr,
    ) -> Result<Arc<rustls::ServerConfig>, Deny> {
        let deny = |m: &str| Deny {
            status: 403,
            message: m.into(),
        };
        let Some((cert, key)) = &self.ca else {
            return Err(deny("no CA"));
        };
        if !host_allowed(&[HOST.to_string()], host) {
            self.blocked.lock().unwrap().push("connect".into());
            return Err(deny("not enabled"));
        }
        let (chain, k) = ca::leaf(cert, key, host).map_err(|e| deny(&e))?;
        ca::server_config(chain, k).map_err(|e| deny(&e))
    }
}

/// (request line, lowercase headers, body)
type Request = (String, Vec<(String, String)>, Vec<u8>);

/// What the upstream saw.
#[derive(Default)]
struct Seen {
    requests: AtomicUsize,
    last: Mutex<Option<Request>>,
}

fn compress(enc: &str, data: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    match enc {
        "gzip" => {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        "deflate" => {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        "br" => {
            let mut out = Vec::new();
            {
                let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
                w.write_all(data).unwrap();
            }
            out
        }
        "zstd" => {
            ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
        }
        _ => data.to_vec(),
    }
}

fn read_request(s: &mut TcpStream) -> Request {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let mut hs = [httparse::EMPTY_HEADER; 64];
        let mut r = httparse::Request::new(&mut hs);
        if let Ok(httparse::Status::Complete(n)) = r.parse(&buf) {
            let line = format!("{} {}", r.method.unwrap(), r.path.unwrap());
            let h: Vec<(String, String)> = r
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_ascii_lowercase(),
                        String::from_utf8_lossy(h.value).into_owned(),
                    )
                })
                .collect();
            let mut body = buf[n..].to_vec();
            let get = |k: &str| h.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
            if get("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
                while !body.ends_with(b"0\r\n\r\n") {
                    let k = s.read(&mut tmp).unwrap();
                    assert!(k > 0);
                    body.extend_from_slice(&tmp[..k]);
                }
                body = dechunk(&body);
            } else {
                let cl: usize = get("content-length").map_or(0, |v| v.parse().unwrap());
                while body.len() < cl {
                    let k = s.read(&mut tmp).unwrap();
                    assert!(k > 0);
                    body.extend_from_slice(&tmp[..k]);
                }
            }
            return (line, h, body);
        }
        let k = s.read(&mut tmp).unwrap();
        assert!(k > 0, "client closed early");
        buf.extend_from_slice(&tmp[..k]);
    }
}

fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let nl = raw
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("chunk size line");
        let size =
            usize::from_str_radix(std::str::from_utf8(&raw[..nl]).unwrap().trim(), 16).unwrap();
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&raw[nl + 2..nl + 2 + size]);
        raw = &raw[nl + 2 + size + 2..];
    }
}

/// `/echo?enc=<coding>`: reflects Authorization, X-Api-Key, the query and the body, compressed;
/// `/sse`: two events 600 ms apart, the second one carrying the key.
fn upstream(seen: Arc<Seen>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let seen = seen.clone();
            std::thread::spawn(move || {
                let (line, h, body) = read_request(&mut s);
                seen.requests.fetch_add(1, SeqCst);
                *seen.last.lock().unwrap() = Some((line.clone(), h.clone(), body.clone()));
                let get = |k: &str| {
                    h.iter()
                        .find(|(n, _)| n == k)
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default()
                };
                let path = line.split(' ').nth(1).unwrap().to_string();
                if path.ends_with("/sse") {
                    write!(s, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
                    let ev1 = b"data: first\n\n";
                    write!(s, "{:x}\r\n", ev1.len()).unwrap();
                    s.write_all(ev1).unwrap();
                    s.write_all(b"\r\n").unwrap();
                    s.flush().unwrap();
                    std::thread::sleep(Duration::from_millis(600));
                    let ev2 = format!("data: {}\n\n", get("authorization"));
                    write!(s, "{:x}\r\n{ev2}\r\n0\r\n\r\n", ev2.len()).unwrap();
                    return;
                }
                let enc = path
                    .split("enc=")
                    .nth(1)
                    .unwrap_or("")
                    .split('&')
                    .next()
                    .unwrap()
                    .to_string();
                let text = format!(
                    "auth={} key={} line={} body={}",
                    get("authorization"),
                    get("x-api-key"),
                    line,
                    String::from_utf8_lossy(&body)
                );
                // Codings the relay cannot fully undo (gate A3b): stacked in one header, the
                // same coding on two header lines, or a gzip transfer-coding.
                let twice = compress("gzip", &compress("gzip", text.as_bytes()));
                if enc == "te-gzip" {
                    let z = compress("gzip", text.as_bytes());
                    write!(
                        s,
                        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n{:x}\r\n",
                        z.len()
                    )
                    .unwrap();
                    s.write_all(&z).unwrap();
                    s.write_all(b"\r\n0\r\n\r\n").unwrap();
                    return;
                }
                let (payload, ce) = match enc.as_str() {
                    "" => (text.into_bytes(), String::new()),
                    "gzip,gzip" => (twice, "Content-Encoding: gzip, gzip\r\n".into()),
                    "gzip-lines" => (
                        twice,
                        "Content-Encoding: gzip\r\nContent-Encoding: gzip\r\n".into(),
                    ),
                    _ => (
                        compress(&enc, text.as_bytes()),
                        format!("Content-Encoding: {enc}\r\n"),
                    ),
                };
                write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Echo: {}\r\n{ce}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    get("authorization"),
                    payload.len()
                )
                .unwrap();
                s.write_all(&payload).unwrap();
            });
        }
    });
    addr
}

struct Env {
    relay: SocketAddr,
    seen: Arc<Seen>,
    fake: Arc<Fake>,
    upstream: SocketAddr,
}

fn env(places: &[&str], with_ca: bool) -> Env {
    let seen = Arc::new(Seen::default());
    let up = upstream(seen.clone());
    let fake = Arc::new(Fake {
        places: places
            .iter()
            .map(|p| Placement::parse(p).unwrap())
            .collect(),
        blocked: Mutex::default(),
        ca: with_ca.then(|| {
            let c = ca::generate(&[HOST.to_string()]).unwrap();
            (c.cert_pem, c.key_pem)
        }),
    });
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let relay = l.local_addr().unwrap();
    let ups = Arc::new(Upstream {
        insecure_http: vec![(HOST.into(), up), ("evil.example".into(), up)],
    });
    let auth: Arc<dyn HttpAuthority> = fake.clone();
    std::thread::spawn(move || serve(l, auth, ups));
    Env {
        relay,
        seen,
        fake,
        upstream: up,
    }
}

/// Sends `req`; returns (status line, head, de-chunked body).
fn call(e: &Env, req: &str) -> (String, String, String) {
    let mut c = TcpStream::connect(e.relay).unwrap();
    c.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    c.read_to_end(&mut raw).unwrap();
    let i = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("head");
    let head = String::from_utf8_lossy(&raw[..i]).into_owned();
    let mut body = raw[i + 4..].to_vec();
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        body = dechunk(&body);
    }
    let status = head.lines().next().unwrap().to_string();
    (status, head, String::from_utf8_lossy(&body).into_owned())
}

fn get(path: &str, extra: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{extra}\r\n")
}

#[test]
fn bearer_swap_and_every_coding_is_cleansed() {
    let e = env(&["bearer"], false);
    let auth = format!("Authorization: Bearer {}\r\n", token());
    for enc in ["", "gzip", "deflate", "br", "zstd"] {
        let (status, head, body) = call(&e, &get(&format!("/h/{HOST}/v1/echo?enc={enc}"), &auth));
        assert!(status.starts_with("HTTP/1.1 200"), "{enc}: {status}");
        // Upstream got the real key in the Authorization header and nowhere else.
        let (line, h, _) = e.seen.last.lock().unwrap().clone().unwrap();
        assert_eq!(line, format!("GET /v1/echo?enc={enc}"));
        let a = h.iter().find(|(n, _)| n == "authorization").unwrap();
        assert_eq!(a.1, format!("Bearer {}", secret()));
        assert!(h.iter().any(|(n, v)| n == "host" && v == HOST));
        // The client gets the reflection masked, decoded, identity-encoded.
        assert!(
            !body.contains(&secret()) && !head.contains(&secret()),
            "{enc}: {head}\n{body}"
        );
        assert!(
            body.contains("auth=Bearer [REDACTED:API_KEY]"),
            "{enc}: {body}"
        );
        assert!(
            head.contains("X-Echo: Bearer [REDACTED:API_KEY]"),
            "{enc}: {head}"
        );
        assert!(
            !head.to_ascii_lowercase().contains("content-encoding"),
            "{head}"
        );
    }
    assert!(e.fake.blocked.lock().unwrap().is_empty());
}

/// Regression (gate A3b): a body still encoded after the relay's decoding would reach the client
/// unredacted, and the client could decode the key out of it. The relay refuses instead.
#[test]
fn codings_the_relay_cannot_undo_are_refused() {
    let e = env(&["bearer"], false);
    let auth = format!("Authorization: Bearer {}\r\n", token());
    for enc in ["gzip,gzip", "gzip-lines", "te-gzip"] {
        let mut c = TcpStream::connect(e.relay).unwrap();
        c.write_all(get(&format!("/h/{HOST}/v1/echo?enc={enc}"), &auth).as_bytes())
            .unwrap();
        let mut raw = Vec::new();
        c.read_to_end(&mut raw).unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(text.starts_with("HTTP/1.1 502"), "{enc}: {text}");
        // Nothing encoded slipped through either: no gzip member anywhere in the response.
        assert!(!raw.windows(2).any(|w| w == [0x1f, 0x8b]), "{enc}: {text}");
        assert!(!text.contains(&secret()), "{enc}");
    }
}

#[test]
fn wrong_host_is_403_without_contacting_it() {
    let e = env(&["bearer"], false);
    let auth = format!("Authorization: Bearer {}\r\n", token());
    let (status, _, body) = call(&e, &get("/h/evil.example/v1/echo", &auth));
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");
    assert!(body.contains("allowlist"), "{body}");
    assert_eq!(e.seen.requests.load(SeqCst), 0, "upstream was contacted");
    assert_eq!(*e.fake.blocked.lock().unwrap(), ["http_host_not_allowed"]);
    // No token, unknown token, two tokens: refused before anything else.
    let (s, _, _) = call(&e, &get(&format!("/h/{HOST}/x"), ""));
    assert!(s.starts_with("HTTP/1.1 401"), "{s}");
    let other = new_token();
    let (s, _, _) = call(
        &e,
        &get(
            &format!("/h/{HOST}/x"),
            &format!("Authorization: Bearer {other}\r\n"),
        ),
    );
    assert!(s.starts_with("HTTP/1.1 401"), "{s}");
    let two = format!("Authorization: Bearer {}\r\nX-Other: {other}\r\n", token());
    let (s, _, _) = call(&e, &get(&format!("/h/{HOST}/x"), &two));
    assert!(s.starts_with("HTTP/1.1 400"), "{s}");
    let (s, _, _) = call(&e, &get("/nope", &auth));
    assert!(s.starts_with("HTTP/1.1 404"), "{s}");
    assert_eq!(e.seen.requests.load(SeqCst), 0);
}

#[test]
fn wrong_placement_is_refused_and_nothing_swapped() {
    let e = env(&["header:X-Api-Key"], false);
    // The token in Authorization and in the query, but not in X-Api-Key.
    let req = get(
        &format!("/h/{HOST}/v1/echo?key={}", token()),
        &format!("Authorization: Bearer {}\r\n", token()),
    );
    let (status, _, body) = call(&e, &req);
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");
    assert!(body.contains("header:x-api-key"), "{body}");
    assert_eq!(e.seen.requests.load(SeqCst), 0);
    assert_eq!(*e.fake.blocked.lock().unwrap(), ["http_wrong_placement"]);
    // In its placement: swapped there only; the copy in the body is never rewritten.
    let body_in = format!("{{\"echo\":\"{}\"}}", token());
    let req = format!(
        "POST /h/{HOST}/v1/echo HTTP/1.1\r\nHost: x\r\nX-Api-Key: {}\r\nContent-Length: {}\r\n\r\n{body_in}",
        token(),
        body_in.len()
    );
    let (status, _, body) = call(&e, &req);
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let (_, h, b) = e.seen.last.lock().unwrap().clone().unwrap();
    assert!(h.iter().any(|(n, v)| n == "x-api-key" && *v == secret()));
    assert_eq!(String::from_utf8_lossy(&b), body_in, "body was rewritten");
    assert!(
        body.contains("key=[REDACTED:API_KEY]") && !body.contains(&secret()),
        "{body}"
    );
}

#[test]
fn query_and_basic_placements_and_chunked_upload() {
    let e = env(&["query:api_key", "basic"], false);
    let (status, _, body) = call(
        &e,
        &get(&format!("/h/{HOST}/v1/echo?api_key={}&x=1", token()), ""),
    );
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let (line, _, _) = e.seen.last.lock().unwrap().clone().unwrap();
    let enc = secret().replace('/', "%2F").replace('+', "%2B");
    assert_eq!(line, format!("GET /v1/echo?api_key={enc}&x=1"));
    assert!(!body.contains(&secret()) && !body.contains(&enc), "{body}");

    let b64 = base64::engine::general_purpose::STANDARD;
    let basic = b64.encode(format!("{}:", token()));
    let req = format!(
        "POST /h/{HOST}/v1/echo HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {basic}\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"
    );
    let (status, _, body) = call(&e, &req);
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let (_, h, b) = e.seen.last.lock().unwrap().clone().unwrap();
    let want = format!("Basic {}", b64.encode(format!("{}:", secret())));
    assert!(
        h.iter().any(|(n, v)| n == "authorization" && *v == want),
        "{h:?}"
    );
    assert_eq!(b, b"abcde");
    assert!(
        body.contains("auth=[REDACTED:API_KEY]") || body.contains("auth=Basic [REDACTED"),
        "{body}"
    );
    assert!(
        !body.contains(&b64.encode(format!("{}:", secret()))),
        "{body}"
    );
}

#[test]
fn server_sent_events_still_stream() {
    let e = env(&["bearer"], false);
    let mut c = TcpStream::connect(e.relay).unwrap();
    c.write_all(
        get(
            &format!("/h/{HOST}/v1/sse"),
            &format!("Authorization: Bearer {}\r\n", token()),
        )
        .as_bytes(),
    )
    .unwrap();
    let t = Instant::now();
    let mut got = Vec::new();
    let mut tmp = [0u8; 4096];
    while !String::from_utf8_lossy(&got).contains("data: first") {
        let n = c.read(&mut tmp).unwrap();
        assert!(n > 0, "closed before the first event");
        got.extend_from_slice(&tmp[..n]);
    }
    assert!(
        t.elapsed() < Duration::from_millis(500),
        "first event was held back {:?}",
        t.elapsed()
    );
    c.read_to_end(&mut got).unwrap();
    let all = String::from_utf8_lossy(&got);
    assert!(all.contains("data: Bearer [REDACTED:API_KEY]"), "{all}");
    assert!(!all.contains(&secret()));
    assert!(all.ends_with("0\r\n\r\n"), "{all}");
}

fn have_curl() -> bool {
    Command::new("curl")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn curl(args: &[&str]) -> std::process::Output {
    Command::new("curl")
        .args(["-sS", "--max-time", "20"])
        .args(args)
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .env_remove("CURL_CA_BUNDLE")
        .env_remove("SSL_CERT_FILE")
        .output()
        .unwrap()
}

/// A one-shot TLS server presenting a CA-signed leaf for `name`.
fn tls_server(cert: &str, key: &str, name: &str) -> SocketAddr {
    let (chain, k) = ca::leaf(cert, key, name).unwrap();
    let cfg = ca::server_config(chain, k).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
            let mut t = rustls::StreamOwned::new(conn, s);
            let mut b = [0u8; 4096];
            if t.read(&mut b).is_ok() {
                let _ = t.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                let _ = t.flush();
            }
        }
    });
    addr
}

#[test]
fn explicit_proxy_with_name_constrained_ca() {
    if !have_curl() {
        eprintln!("SKIP: curl is not installed");
        return;
    }
    let e = env(&["bearer"], true);
    let (cert, key) = e.fake.ca.clone().unwrap();
    let dir = std::env::temp_dir().join(format!("ls-ca-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca_file = dir.join("ca.pem");
    std::fs::write(&ca_file, &cert).unwrap();
    let ca_path = ca_file.to_str().unwrap();
    let proxy = format!("http://{}", e.relay);
    let auth = format!("Authorization: Bearer {}", token());

    // Enabled host: TLS terminated with a CA leaf, token swapped, response cleansed.
    let o = curl(&[
        "--cacert",
        ca_path,
        "-x",
        &proxy,
        "-H",
        &auth,
        &format!("https://{HOST}/v1/echo?enc=gzip"),
    ]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        o.status.success(),
        "{out} {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(
        out.contains("auth=Bearer [REDACTED:API_KEY]") && !out.contains(&secret()),
        "{out}"
    );
    let (line, h, _) = e.seen.last.lock().unwrap().clone().unwrap();
    assert_eq!(line, "GET /v1/echo?enc=gzip");
    assert!(
        h.iter()
            .any(|(n, v)| n == "authorization" && *v == format!("Bearer {}", secret()))
    );

    // Not enabled: CONNECT refused, no tunnel, upstream untouched.
    let before = e.seen.requests.load(SeqCst);
    let o = curl(&[
        "--cacert",
        ca_path,
        "-x",
        &proxy,
        "-H",
        &auth,
        "https://example.org/",
    ]);
    assert!(!o.status.success());
    assert_eq!(e.seen.requests.load(SeqCst), before);
    assert_eq!(*e.fake.blocked.lock().unwrap(), ["connect"]);

    // Name constraints: a leaf the CA signs for example.org is rejected by curl (OpenSSL)...
    let bad = tls_server(&cert, &key, "example.org");
    let o = curl(&[
        "--cacert",
        ca_path,
        "--resolve",
        &format!("example.org:{}:127.0.0.1", bad.port()),
        &format!("https://example.org:{}/", bad.port()),
    ]);
    assert_eq!(
        o.status.code(),
        Some(60),
        "curl must reject the leaf (peer verification): {}",
        String::from_utf8_lossy(&o.stderr)
    );
    // ...while the same CA's leaf for the enabled host is accepted.
    let good = tls_server(&cert, &key, HOST);
    let o = curl(&[
        "--cacert",
        ca_path,
        "--resolve",
        &format!("{HOST}:{}:127.0.0.1", good.port()),
        &format!("https://{HOST}:{}/", good.port()),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(String::from_utf8_lossy(&o.stdout), "ok");
    let _ = e.upstream;
    let _ = std::fs::remove_dir_all(&dir);
}
