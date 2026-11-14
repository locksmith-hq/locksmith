//! Throughput and chunk-latency benchmarks: 100 secrets against a 10 MB log-like buffer.

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ls_redact::{Redactor, Secret};

const BUF_LEN: usize = 10 * 1024 * 1024;
const CHUNK: usize = 4 * 1024;
const SECRET_COUNT: usize = 100;

/// Deterministic LCG; no rand crate needed.
struct Lcg(u64);

impl Lcg {
    fn next_u8(&mut self) -> u8 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 56) as u8
    }
}

fn secrets(rng: &mut Lcg) -> Vec<Secret> {
    (0..SECRET_COUNT)
        .map(|i| {
            let value: Vec<u8> = (0..32).map(|_| rng.next_u8()).collect();
            Secret::new(format!("SECRET_{i:03}"), &value)
        })
        .collect()
}

/// Mostly ASCII log lines; a few secrets embedded at fixed intervals.
fn corpus(secrets: &[Secret], rng: &mut Lcg) -> Vec<u8> {
    let mut buf = Vec::with_capacity(BUF_LEN + 256);
    let mut line_no = 0usize;
    while buf.len() < BUF_LEN {
        line_no += 1;
        let level = ["INFO", "DEBUG", "WARN", "ERROR"][(rng.next_u8() % 4) as usize];
        buf.extend_from_slice(
            format!(
                "2026-11-14T10:{:02}:{:02}Z {level} worker-{} request id={:08x} path=/api/v1/items status=200 took={}ms\n",
                (line_no / 60) % 60,
                line_no % 60,
                rng.next_u8() % 8,
                line_no * 2654435761usize % 0xffff_ffff,
                rng.next_u8() % 200,
            )
            .as_bytes(),
        );
        if line_no.is_multiple_of(2000) {
            let s = &secrets[(line_no / 2000) % secrets.len()];
            buf.extend_from_slice(b"auth token=");
            buf.extend_from_slice(&s.value);
            buf.push(b'\n');
        }
    }
    buf.truncate(BUF_LEN);
    buf
}

fn bench_redact(c: &mut Criterion) {
    let mut rng = Lcg(0x5eed);
    let secs = secrets(&mut rng);
    let buf = corpus(&secs, &mut rng);
    let red = Redactor::new(&secs);

    let mut group = c.benchmark_group("redact");
    group.throughput(Throughput::Bytes(BUF_LEN as u64));
    group.bench_function("redact_all_10mb_100_secrets", |b| {
        b.iter(|| black_box(red.redact_all(black_box(&buf))));
    });
    group.finish();
}

fn bench_stream_chunks(c: &mut Criterion) {
    let mut rng = Lcg(0x5eed);
    let secs = secrets(&mut rng);
    let buf = corpus(&secs, &mut rng);
    let red = Redactor::new(&secs);

    let mut group = c.benchmark_group("redact_stream");
    group.throughput(Throughput::Bytes(BUF_LEN as u64));
    group.bench_function("push_4kib_chunks_10mb", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            let mut samples: Vec<Duration> = Vec::with_capacity(iters as usize * (BUF_LEN / CHUNK));
            for _ in 0..iters {
                let mut s = red.stream();
                for chunk in buf.chunks(CHUNK) {
                    let t = Instant::now();
                    black_box(s.push(black_box(chunk)));
                    let d = t.elapsed();
                    total += d;
                    samples.push(d);
                }
                black_box(s.finish());
            }
            samples.sort();
            let p99 = samples[(samples.len() * 99 / 100).min(samples.len() - 1)];
            let mean = total / samples.len() as u32;
            eprintln!(
                "per-4KiB-chunk push: mean {:?}, p99 {:?}, max {:?} ({} chunks)",
                mean,
                p99,
                samples.last().unwrap(),
                samples.len()
            );
            total
        });
    });
    group.finish();
}

criterion_group!(benches, bench_redact, bench_stream_chunks);
criterion_main!(benches);
