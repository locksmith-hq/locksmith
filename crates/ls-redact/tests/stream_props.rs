//! Property: for any output, any secret placement/encoding, any chunking and any idle-flush
//! schedule, streaming == batch redaction and no secret form survives.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use ls_redact::{Redactor, Secret};
use proptest::prelude::*;

const SECRETS: [(&str, &[u8]); 3] = [
    ("A_KEY", b"fake_test_4eC39HqLyjWDarjtT1zdp7dc"),
    ("DB_PASS", b"p@ss/w0rd+with%chars"),
    ("TOKEN", b"fakegh_16C7e42F292c6912E7710c838347Ae178B4a"),
];

fn encode(v: &[u8], how: u8, pad: &[u8]) -> Vec<u8> {
    let mut data = pad.to_vec();
    data.extend_from_slice(v);
    match how % 5 {
        0 => data,
        1 => STANDARD.encode(&data).into_bytes(),
        2 => URL_SAFE.encode(&data).into_bytes(),
        3 => data
            .iter()
            .flat_map(|b| format!("{b:02x}").into_bytes())
            .collect(),
        _ => serde_json::to_string(&String::from_utf8_lossy(&data))
            .unwrap()
            .into_bytes(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]
    #[test]
    fn streaming_matches_batch_and_never_leaks(
        noise in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..40), 1..6),
        picks in proptest::collection::vec((0usize..3, any::<u8>(), 0usize..3), 1..5),
        chunk_sizes in proptest::collection::vec(1usize..17, 1..64),
        idle_every in 1usize..5,
    ) {
        let secrets: Vec<Secret> = SECRETS.iter().map(|(l, v)| Secret::new(*l, v)).collect();
        let red = Redactor::new(&secrets);
        let mut input = Vec::new();
        for (i, n) in noise.iter().enumerate() {
            input.extend_from_slice(n);
            if let Some((which, how, pad)) = picks.get(i) {
                input.extend(encode(SECRETS[*which].1, *how, &b"xyz"[..*pad]));
            }
        }
        let batch = red.redact_all(&input);

        let mut s = red.stream();
        let mut out = Vec::new();
        let (mut pos, mut i) = (0, 0);
        while pos < input.len() {
            let n = chunk_sizes[i % chunk_sizes.len()].min(input.len() - pos);
            out.extend(s.push(&input[pos..pos + n]));
            if i % idle_every == 0 { out.extend(s.flush_idle()); }
            pos += n; i += 1;
        }
        out.extend(s.finish());
        prop_assert_eq!(&out, &batch);
        for (_, v) in SECRETS {
            prop_assert!(!out.windows(v.len()).any(|w| w == v), "plain secret leaked");
        }
    }
}
