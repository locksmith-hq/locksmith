//! t5-honey-tokens task 3.4: the cost of the relay's honey value scan on a 1 MiB body with 100
//! active honey tokens (raw, base64 and URL-encoded forms of each in one automaton).
//!
//! Run: `cargo bench -p ls-gateway --bench honey_scan`. Prints the automaton size and build time
//! and p50 / p99 of one full scan of the body, for a body with no honey value (every byte is
//! read) and one with a value at its very end. No value is printed.

use std::time::{Duration, Instant};

use ls_envelope::SecretBytes;
use ls_gateway::honey_guard::HoneyScanner;
use uuid::Uuid;

const TOKENS: usize = 100;
const BODY: usize = 1024 * 1024;
const WARMUP: usize = 20;
const RUNS: usize = 1000;

/// xorshift64*: a fixed, dependency-free byte source.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// `n` characters of `alphabet`.
    fn text(&mut self, alphabet: &[u8], n: usize) -> Vec<u8> {
        (0..n)
            .map(|_| alphabet[(self.next() % alphabet.len() as u64) as usize])
            .collect()
    }
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// A JSON-ish body: printable ASCII with the same alphabet the decoys use, so the automaton sees
/// many partial matches.
fn body(rng: &mut Rng) -> Vec<u8> {
    let alphabet: Vec<u8> = ALNUM.iter().copied().chain(*b" \"{}:,=_-/+").collect();
    rng.text(&alphabet, BODY)
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i]
}

fn measure(scanner: &HoneyScanner, input: &[u8], expect_hit: bool) -> (Duration, Duration) {
    for _ in 0..WARMUP {
        assert_eq!(scanner.find(input).is_some(), expect_hit);
    }
    let mut times = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let t = Instant::now();
        let hit = std::hint::black_box(scanner.find(std::hint::black_box(input)));
        times.push(t.elapsed());
        assert_eq!(hit.is_some(), expect_hit);
    }
    times.sort_unstable();
    (percentile(&times, 0.50), percentile(&times, 0.99))
}

fn main() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    // Decoy-shaped values: an AWS key id prefix plus 16 characters, or a 40-character token.
    let values: Vec<(Uuid, SecretBytes)> = (0..TOKENS)
        .map(|i| {
            let mut v = if i % 2 == 0 {
                b"AKIA".to_vec()
            } else {
                b"ghp_".to_vec()
            };
            v.extend(rng.text(ALNUM, if i % 2 == 0 { 16 } else { 36 }));
            (Uuid::from_u128(i as u128 + 1), SecretBytes::new(v))
        })
        .collect();
    let t = Instant::now();
    let scanner = HoneyScanner::new(&values);
    let build = t.elapsed();

    let clean = body(&mut rng);
    let mut dirty = clean.clone();
    let last = values.last().unwrap().1.expose().to_vec();
    let at = dirty.len() - last.len();
    dirty[at..].copy_from_slice(&last);

    let (p50, p99) = measure(&scanner, &clean, false);
    let (hit50, hit99) = measure(&scanner, &dirty, true);
    println!(
        "honey scan: {TOKENS} tokens, {} patterns, build {:.2} ms",
        scanner.pattern_count(),
        build.as_secs_f64() * 1e3
    );
    println!(
        "1 MiB body, no match:       p50 {:.3} ms  p99 {:.3} ms  ({RUNS} runs)",
        p50.as_secs_f64() * 1e3,
        p99.as_secs_f64() * 1e3
    );
    println!(
        "1 MiB body, match at end:   p50 {:.3} ms  p99 {:.3} ms  ({RUNS} runs)",
        hit50.as_secs_f64() * 1e3,
        hit99.as_secs_f64() * 1e3
    );
}
