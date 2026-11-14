//! Streaming secret redactor (spec: output-redaction; design: m2-run-and-redact D1, D2).
//!
//! For every active secret we compile the plain value plus its common encodings into one
//! Aho-Corasick automaton and replace any match with `[REDACTED:<LABEL>]`. [`Stream`] does the
//! same over chunked output, so a secret split across writes is still caught.

pub mod doctor;

use aho_corasick::{AhoCorasick, MatchKind};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

/// Values shorter than this only get plain-form matching (encoded forms would false-positive).
pub const MIN_ENCODED_LEN: usize = 8;

/// One secret to redact. `basic_auth_user` adds the `base64("user:" + value)` header form.
pub struct Secret {
    pub label: String,
    pub value: Zeroizing<Vec<u8>>,
    pub basic_auth_user: Option<String>,
}

impl Secret {
    pub fn new(label: impl Into<String>, value: &[u8]) -> Self {
        Self {
            label: label.into(),
            value: Zeroizing::new(value.to_vec()),
            basic_auth_user: None,
        }
    }
}

pub struct Redactor {
    // shortcut: aho-corasick keeps its own (non-zeroized) copy of the patterns; acceptable because
    // the redactor only lives inside the process that already holds the secrets.
    ac: Option<AhoCorasick>,
    patterns: Vec<Zeroizing<Vec<u8>>>,
    labels: Vec<Vec<u8>>, // replacement text per pattern
    max_len: usize,
}

/// The stable middle of `base64(zeros(k) ‖ v)`: only characters whose 6 bits come entirely from
/// `v`, so the pattern matches `v` at byte offset `k (mod 3)` inside any larger base64 stream.
fn base64_aligned(v: &[u8], k: usize, engine: &impl Engine) -> Option<Vec<u8>> {
    let mut buf = Zeroizing::new(vec![0u8; k]);
    buf.extend_from_slice(v);
    let enc = Zeroizing::new(engine.encode(&*buf).into_bytes());
    let start = (4 * k).div_ceil(3); // first char not touching the zero prefix
    let end = (8 * (k + v.len())) / 6; // chars fully inside the data
    (end > start).then(|| enc[start..end].to_vec())
}

fn percent(v: &[u8], upper: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 3);
    for &b in v {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b);
        } else if upper {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        } else {
            out.extend_from_slice(format!("%{b:02x}").as_bytes());
        }
    }
    out
}

fn hex(v: &[u8], upper: bool) -> Vec<u8> {
    v.iter()
        .flat_map(|b| {
            if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
            .into_bytes()
        })
        .collect()
}

/// Every encoded form of one secret value (design D1).
fn forms(s: &Secret) -> Vec<Vec<u8>> {
    let v: &[u8] = &s.value;
    let mut out = vec![v.to_vec()];
    if v.len() < MIN_ENCODED_LEN {
        return out;
    }
    for k in 0..3 {
        out.extend(base64_aligned(v, k, &STANDARD_NO_PAD));
        out.extend(base64_aligned(v, k, &URL_SAFE_NO_PAD));
    }
    out.push(hex(v, false));
    out.push(hex(v, true));
    out.push(percent(v, true));
    out.push(percent(v, false));
    if let Ok(text) = std::str::from_utf8(v) {
        let json = serde_json::to_string(text).expect("string serializes");
        let inner = json.as_bytes()[1..json.len() - 1].to_vec();
        if inner.contains(&b'/') {
            out.push(
                String::from_utf8_lossy(&inner)
                    .replace('/', "\\/")
                    .into_bytes(),
            );
        }
        out.push(inner);
    }
    if let Some(user) = &s.basic_auth_user {
        let mut cred = Zeroizing::new(format!("{user}:").into_bytes());
        cred.extend_from_slice(v);
        out.push(STANDARD_NO_PAD.encode(&*cred).into_bytes());
    }
    out.sort();
    out.dedup();
    out.retain(|p| !p.is_empty());
    out
}

impl Redactor {
    pub fn new(secrets: &[Secret]) -> Self {
        let mut patterns = Vec::new();
        let mut labels = Vec::new();
        for s in secrets {
            for p in forms(s) {
                patterns.push(Zeroizing::new(p));
                labels.push(format!("[REDACTED:{}]", s.label).into_bytes());
            }
        }
        let max_len = patterns.iter().map(|p| p.len()).max().unwrap_or(0);
        let ac = (!patterns.is_empty()).then(|| {
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(patterns.iter().map(|p| p.as_slice()))
                .expect("patterns build")
        });
        Self {
            ac,
            patterns,
            labels,
            max_len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ac.is_none()
    }

    /// Redact a complete buffer.
    pub fn redact_all(&self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        let end = self.emit(input, input.len(), &mut out);
        out.extend_from_slice(&input[end..]);
        out
    }

    /// Write `buf[..cut]` (redacted) into `out`. Matches starting before `cut` are replaced whole,
    /// even if they extend past it. Returns the index where emission actually stopped.
    fn emit(&self, buf: &[u8], cut: usize, out: &mut Vec<u8>) -> usize {
        let mut pos = 0;
        if let Some(ac) = &self.ac {
            for m in ac.find_iter(buf) {
                if m.start() >= cut {
                    break;
                }
                out.extend_from_slice(&buf[pos..m.start()]);
                out.extend_from_slice(&self.labels[m.pattern().as_usize()]);
                pos = m.end();
            }
        }
        if pos < cut {
            let end = utf8_floor(buf, pos, cut);
            out.extend_from_slice(&buf[pos..end]);
            pos = end;
        }
        pos
    }

    /// Length of the longest suffix of `held` that is a proper prefix of some pattern.
    fn pending_prefix_len(&self, held: &[u8]) -> usize {
        let top = held.len().min(self.max_len.saturating_sub(1));
        (1..=top)
            .rev()
            .find(|&k| {
                let suffix = &held[held.len() - k..];
                self.patterns
                    .iter()
                    .any(|p| p.len() > k && p.starts_with(suffix))
            })
            .unwrap_or(0)
    }

    pub fn stream(&self) -> Stream<'_> {
        Stream {
            r: self,
            held: Zeroizing::new(Vec::new()),
        }
    }
}

/// Back `cut` up so it does not split a UTF-8 code point (never below `floor`).
fn utf8_floor(buf: &[u8], floor: usize, cut: usize) -> usize {
    let mut c = cut;
    while c > floor && c < buf.len() && (buf[c] & 0b1100_0000) == 0b1000_0000 && cut - c < 3 {
        c -= 1;
    }
    if c < buf.len() && (buf[c] & 0b1100_0000) == 0b1000_0000 {
        cut
    } else {
        c
    }
}

/// Incremental redaction over chunked output. Bytes that could still be the start of a secret are
/// held back until more data, [`Stream::flush_idle`], or [`Stream::finish`] resolves them.
pub struct Stream<'a> {
    r: &'a Redactor,
    held: Zeroizing<Vec<u8>>,
}

impl Stream<'_> {
    /// Feed a chunk; returns what is safe to show now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.held.extend_from_slice(chunk);
        let carry = self.r.max_len.saturating_sub(1);
        let cut = self.held.len().saturating_sub(carry);
        self.drain_to(cut)
    }

    /// Call when the source has been quiet (~20 ms): emit everything except a trailing partial
    /// match candidate, so prompts without a newline appear promptly.
    pub fn flush_idle(&mut self) -> Vec<u8> {
        let keep = self.r.pending_prefix_len(&self.held);
        let cut = self.held.len() - keep;
        self.drain_to(cut)
    }

    /// End of stream: emit everything (redacted).
    pub fn finish(mut self) -> Vec<u8> {
        let out = self.r.redact_all(&self.held);
        self.held.clear();
        out
    }

    fn drain_to(&mut self, cut: usize) -> Vec<u8> {
        let mut out = Vec::new();
        if cut == 0 {
            return out;
        }
        let used = self.r.emit(&self.held, cut, &mut out);
        self.held.drain(..used);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE};

    const V: &[u8] = b"sk_live_51Hx9/zQ+AbC";

    fn r() -> Redactor {
        let mut s = Secret::new("STRIPE_KEY", V);
        s.basic_auth_user = Some("api".into());
        Redactor::new(&[s])
    }

    fn clean(out: &[u8]) -> bool {
        !out.windows(V.len()).any(|w| w == V)
    }

    #[test]
    fn plain_is_labelled() {
        let out = r().redact_all(b"key=sk_live_51Hx9/zQ+AbC;");
        assert_eq!(out, b"key=[REDACTED:STRIPE_KEY];");
    }

    #[test]
    fn base64_every_offset_and_alphabet() {
        let red = r();
        for prefix in [&b""[..], b"x", b"xy", b"xyz"] {
            for eng in [&STANDARD, &URL_SAFE] {
                let mut data = prefix.to_vec();
                data.extend_from_slice(V);
                data.extend_from_slice(b"tail");
                let enc = eng.encode(&data);
                let out = red.redact_all(enc.as_bytes());
                assert!(
                    String::from_utf8_lossy(&out).contains("[REDACTED:STRIPE_KEY]"),
                    "offset {}",
                    prefix.len()
                );
            }
        }
    }

    #[test]
    fn hex_percent_json_basic() {
        let red = r();
        let cases = [
            hex(V, false),
            hex(V, true),
            percent(V, true),
            serde_json::to_string(std::str::from_utf8(V).unwrap())
                .unwrap()
                .into_bytes(),
            format!(
                "Authorization: Basic {}",
                STANDARD.encode(b"api:sk_live_51Hx9/zQ+AbC")
            )
            .into_bytes(),
        ];
        for c in cases {
            let out = red.redact_all(&c);
            assert!(
                String::from_utf8_lossy(&out).contains("[REDACTED:STRIPE_KEY]"),
                "{}",
                String::from_utf8_lossy(&c)
            );
        }
    }

    #[test]
    fn short_secret_plain_only() {
        let red = Redactor::new(&[Secret::new("PIN", b"1234")]);
        assert_eq!(
            red.redact_all(b"pin 1234 / 31323334"),
            b"pin [REDACTED:PIN] / 31323334"
        );
    }

    #[test]
    fn split_one_byte_at_a_time_with_idle_flushes() {
        let red = r();
        let mut s = red.stream();
        let mut out = Vec::new();
        for b in b"before sk_live_51Hx9/zQ+AbC after" {
            out.extend(s.push(&[*b]));
            out.extend(s.flush_idle());
        }
        out.extend(s.finish());
        assert_eq!(out, b"before [REDACTED:STRIPE_KEY] after");
    }

    #[test]
    fn idle_flush_shows_prompt_promptly() {
        let red = r();
        let mut s = red.stream();
        let mut out = s.push(b"password> ");
        out.extend(s.flush_idle());
        assert_eq!(out, b"password> ");
    }

    #[test]
    fn idle_flush_holds_only_a_possible_secret_prefix() {
        let red = r();
        let mut s = red.stream();
        let mut out = s.push(b"token: sk_li");
        out.extend(s.flush_idle());
        assert_eq!(out, b"token: ");
        out.extend(s.push(b"ve_51Hx9/zQ+AbC!"));
        out.extend(s.finish());
        assert_eq!(out, b"token: [REDACTED:STRIPE_KEY]!");
    }

    #[test]
    fn utf8_passthrough_is_byte_identical() {
        let red = r();
        let text = "héllo 🌍 世界 — ok ✓".repeat(50);
        let mut s = red.stream();
        let mut out = Vec::new();
        for c in text.as_bytes().chunks(7) {
            let o = s.push(c);
            assert!(
                std::str::from_utf8(&o).is_ok(),
                "emitted a split code point"
            );
            out.extend(o);
        }
        out.extend(s.finish());
        assert_eq!(out, text.as_bytes());
    }

    #[test]
    fn no_secrets_is_identity() {
        let red = Redactor::new(&[]);
        assert!(red.is_empty());
        let mut s = red.stream();
        let mut out = s.push(b"abc");
        out.extend(s.finish());
        assert_eq!(out, b"abc");
        assert!(clean(&out));
    }
}
