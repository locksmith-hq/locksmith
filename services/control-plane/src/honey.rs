//! Honey (decoy) value generators (change t5-honey-tokens, design decision 2).
//!
//! Each template yields a value that passes the provider's offline format checks (prefix, length,
//! alphabet, and the CRC32 suffix where the provider has one) but is never valid. Values are
//! built straight into [`SecretBytes`] (zeroized on drop). The generator types have no `Debug`,
//! `Display`, `Clone` or `Serialize`, so a value cannot be printed or logged by accident.

use ls_envelope::SecretBytes;

const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// RFC 4648 base32 alphabet, the one AWS access key ids use after their 4-letter prefix.
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const DIGITS: &[u8; 10] = b"0123456789";

/// The randomness source failed. Carries no detail.
#[derive(Debug)]
pub struct RngError;

/// The decoy formats the core can mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Template {
    AwsAccessKey,
    GithubPat,
    SlackToken,
    GenericApiKey,
}

/// Generate one value for `template`.
pub fn generate(template: Template) -> Result<SecretBytes, RngError> {
    generate_with(template, &mut os_fill)
}

fn os_fill(buf: &mut [u8]) -> Result<(), RngError> {
    getrandom::getrandom(buf).map_err(|_| RngError)
}

/// As [`generate`], with an injectable byte source (tests use a counter).
fn generate_with(
    template: Template,
    fill: &mut dyn FnMut(&mut [u8]) -> Result<(), RngError>,
) -> Result<SecretBytes, RngError> {
    // Sized up front so the buffer never reallocates and leaves stray plaintext copies.
    let mut out: Vec<u8> = Vec::with_capacity(64);
    match template {
        Template::AwsAccessKey => {
            // `AKIA` is the long-term access key prefix; 16 base32 characters follow (20 total).
            out.extend_from_slice(b"AKIA");
            push_random(&mut out, BASE32, 16, fill)?;
        }
        Template::GithubPat => {
            // `ghp_` + 30 random base62 characters + the 6-character base62 CRC32 of those 30.
            out.extend_from_slice(b"ghp_");
            let start = out.len();
            push_random(&mut out, BASE62, 30, fill)?;
            let crc = crc32fast::hash(&out[start..]);
            push_base62(&mut out, crc, 6);
        }
        Template::SlackToken => {
            // `xoxb-<12 digits>-<13 digits>-<24 base62>`: the shape of a bot token.
            out.extend_from_slice(b"xoxb-");
            push_random(&mut out, DIGITS, 12, fill)?;
            out.push(b'-');
            push_random(&mut out, DIGITS, 13, fill)?;
            out.push(b'-');
            push_random(&mut out, BASE62, 24, fill)?;
        }
        Template::GenericApiKey => {
            out.extend_from_slice(b"sk_live_");
            push_random(&mut out, BASE62, 40, fill)?;
        }
    }
    Ok(SecretBytes::new(out))
}

/// Append `n` characters drawn uniformly from `alphabet` (rejection sampling, no modulo bias).
fn push_random(
    out: &mut Vec<u8>,
    alphabet: &[u8],
    n: usize,
    fill: &mut dyn FnMut(&mut [u8]) -> Result<(), RngError>,
) -> Result<(), RngError> {
    // Largest multiple of the alphabet size that fits a byte; bytes at or above it are redrawn.
    let limit = 256 - (256 % alphabet.len());
    let mut chunk = [0u8; 64];
    let mut added = 0;
    while added < n {
        fill(&mut chunk)?;
        for &b in chunk.iter() {
            if usize::from(b) < limit {
                out.push(alphabet[usize::from(b) % alphabet.len()]);
                added += 1;
                if added == n {
                    break;
                }
            }
        }
    }
    chunk.fill(0);
    Ok(())
}

/// Append `value` as `width` base62 digits, most significant first, left-padded with `0`.
fn push_base62(out: &mut Vec<u8>, mut value: u32, width: usize) {
    let mut digits = vec![b'0'; width];
    for slot in digits.iter_mut().rev() {
        *slot = BASE62[(value % 62) as usize];
        value /= 62;
    }
    out.extend_from_slice(&digits);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(t: Template) -> String {
        let v = generate(t).expect("rng");
        String::from_utf8(v.expose().to_vec()).expect("ascii")
    }

    fn all_in(s: &str, alphabet: &[u8]) -> bool {
        s.bytes().all(|b| alphabet.contains(&b))
    }

    #[test]
    fn aws_access_key_format() {
        let s = text(Template::AwsAccessKey);
        assert_eq!(s.len(), 20);
        assert!(s.starts_with("AKIA"));
        assert!(all_in(&s[4..], BASE32));
    }

    #[test]
    fn github_pat_format_and_checksum() {
        let s = text(Template::GithubPat);
        assert_eq!(s.len(), 40);
        assert!(s.starts_with("ghp_"));
        let (body, check) = s[4..].split_at(30);
        assert!(all_in(body, BASE62));
        let mut expect = Vec::new();
        push_base62(&mut expect, crc32fast::hash(body.as_bytes()), 6);
        assert_eq!(check.as_bytes(), expect.as_slice());
    }

    #[test]
    fn base62_encoding_matches_known_value() {
        let mut out = Vec::new();
        push_base62(&mut out, 0, 6);
        assert_eq!(out, b"000000");
        let mut out = Vec::new();
        push_base62(&mut out, 62, 6);
        assert_eq!(out, b"000010");
        let mut out = Vec::new();
        push_base62(&mut out, u32::MAX, 6);
        assert_eq!(out, b"4gfFC3"); // 4294967295 in base62
    }

    #[test]
    fn slack_token_format() {
        let s = text(Template::SlackToken);
        let parts: Vec<&str> = s.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "xoxb");
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 13);
        assert_eq!(parts[3].len(), 24);
        assert!(all_in(parts[1], DIGITS) && all_in(parts[2], DIGITS));
        assert!(all_in(parts[3], BASE62));
    }

    #[test]
    fn generic_api_key_format() {
        let s = text(Template::GenericApiKey);
        assert_eq!(s.len(), 48);
        assert!(s.starts_with("sk_live_"));
        assert!(all_in(&s[8..], BASE62));
    }

    #[test]
    fn values_differ_between_calls() {
        assert_ne!(text(Template::GithubPat), text(Template::GithubPat));
    }

    #[test]
    fn rejection_sampling_skips_biased_bytes() {
        // Alphabet of 62: bytes >= 248 are redrawn. 255 then 0 must yield exactly one char, 'A'... index 0.
        let mut calls = 0u32;
        let mut fill = |b: &mut [u8]| -> Result<(), RngError> {
            calls += 1;
            b.fill(255);
            if calls > 1 {
                b.fill(0);
            }
            Ok(())
        };
        let mut out = Vec::new();
        push_random(&mut out, BASE62, 1, &mut fill).unwrap();
        assert_eq!(out, b"0");
        assert_eq!(calls, 2);
    }

    #[test]
    fn rng_failure_is_an_error() {
        let mut fill = |_: &mut [u8]| -> Result<(), RngError> { Err(RngError) };
        assert!(generate_with(Template::GenericApiKey, &mut fill).is_err());
    }
}
