//! Property tests: encoder round trips and verify-walk detection.

use ls_audit::{
    Break, BreakKind, Checkpoint, Encoder, GENESIS, Link, decode, decode_opt, row_hash, verify,
};
use proptest::prelude::*;

#[derive(Debug, Clone)]
enum Field {
    Plain(Vec<u8>),
    Opt(Option<Vec<u8>>),
}

fn field() -> impl Strategy<Value = Field> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..40).prop_map(Field::Plain),
        prop::option::of(prop::collection::vec(any::<u8>(), 0..40)).prop_map(Field::Opt),
    ]
}

fn encode(domain: &[u8], fields: &[Field]) -> Vec<u8> {
    let mut e = Encoder::new(domain);
    for f in fields {
        match f {
            Field::Plain(b) => e.field(b),
            Field::Opt(o) => e.opt_field(o.as_deref()),
        };
    }
    e.finish()
}

/// A valid chain whose rows carry arbitrary payloads.
fn chain(payloads: &[Vec<u8>], stored: bool) -> Vec<Link> {
    let mut prev = GENESIS;
    payloads
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let seq = i as u64 + 1;
            let mut e = Encoder::ledger();
            e.field(&seq.to_be_bytes()).field(p).field(&prev);
            let hash = row_hash(&e.finish(), &[]);
            let l = Link {
                seq,
                prev_hash: prev,
                hash,
                stored_hash: stored.then_some(hash),
            };
            prev = hash;
            l
        })
        .collect()
}

fn payloads() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 0..16), 1..20)
}

proptest! {
    #[test]
    fn encoding_round_trips(
        domain in prop::collection::vec(any::<u8>(), 0..24),
        fields in prop::collection::vec(field(), 0..12),
    ) {
        let bytes = encode(&domain, &fields);
        let got = decode(&domain, &bytes).expect("decodes");
        prop_assert_eq!(got.len(), fields.len());
        for (g, f) in got.iter().zip(&fields) {
            match f {
                Field::Plain(b) => prop_assert_eq!(*g, &b[..]),
                Field::Opt(o) => prop_assert_eq!(decode_opt(g).expect("opt"), o.as_deref()),
            }
        }
    }

    #[test]
    fn encoding_is_injective(
        a in prop::collection::vec(field(), 0..6),
        b in prop::collection::vec(field(), 0..6),
    ) {
        let (ea, eb) = (encode(b"d", &a), encode(b"d", &b));
        if ea == eb {
            prop_assert_eq!(decode(b"d", &ea), decode(b"d", &eb));
        } else {
            prop_assert_ne!(decode(b"d", &ea), decode(b"d", &eb));
        }
    }

    #[test]
    fn intact_chain_verifies_with_its_checkpoints(p in payloads(), stored in any::<bool>()) {
        let c = chain(&p, stored);
        let cps: Vec<Checkpoint> = c.iter().step_by(3).map(|l| Checkpoint { seq: l.seq, hash: l.hash }).collect();
        let w = verify(c.clone(), &cps);
        prop_assert!(w.ok(), "{:?}", w);
        prop_assert_eq!(w.rows, c.len() as u64);
        prop_assert_eq!(w.head, c.last().unwrap().hash);
    }

    #[test]
    fn editing_a_row_breaks_at_or_right_after_it(p in payloads(), idx in any::<prop::sample::Index>(), stored in any::<bool>()) {
        let c = chain(&p, stored);
        let i = idx.index(c.len());
        let mut edited = c.clone();
        // Recompute the hash as a verifier would after the payload changed.
        edited[i].hash[0] ^= 0x80;
        let w = verify(edited, &[]);
        let seq = c[i].seq;
        if stored {
            prop_assert_eq!(w.broken, Some(Break { seq, kind: BreakKind::Hash }));
        } else if i + 1 < c.len() {
            prop_assert_eq!(w.broken, Some(Break { seq: seq + 1, kind: BreakKind::Link }));
        } else {
            // The newest row without a stored hash is caught only by a checkpoint.
            prop_assert_eq!(w.broken, None);
            let cp = Checkpoint { seq, hash: c[i].hash };
            let mut again = c.clone();
            again[i].hash[0] ^= 0x80;
            prop_assert_eq!(verify(again, &[cp]).broken, Some(Break { seq, kind: BreakKind::Checkpoint }));
        }
    }

    #[test]
    fn deleting_a_row_is_detected(p in payloads(), idx in any::<prop::sample::Index>()) {
        let c = chain(&p, true);
        let i = idx.index(c.len());
        let mut cut = c.clone();
        cut.remove(i);
        let cp = Checkpoint { seq: c.last().unwrap().seq, hash: c.last().unwrap().hash };
        let w = verify(cut, &[cp]);
        if i + 1 < c.len() {
            prop_assert_eq!(w.broken, Some(Break { seq: c[i].seq, kind: BreakKind::Sequence }));
        } else {
            prop_assert_eq!(w.broken, None);
            prop_assert_eq!(w.truncated.map(|t| (t.checkpoint_seq, t.last_seq)), Some((cp.seq, cp.seq - 1)));
        }
    }

    #[test]
    fn full_rewrite_is_caught_by_a_checkpoint(p in payloads(), idx in any::<prop::sample::Index>()) {
        // The strongest tamper: rewrite one row and recompute every later hash.
        let c = chain(&p, true);
        let i = idx.index(c.len());
        let mut forged = p.clone();
        forged[i].push(0xff);
        let f = chain(&forged, true);
        prop_assert!(verify(f.clone(), &[]).ok());
        let last = c.last().unwrap();
        let w = verify(f, &[Checkpoint { seq: last.seq, hash: last.hash }]);
        prop_assert_eq!(w.broken, Some(Break { seq: last.seq, kind: BreakKind::Checkpoint }));
    }
}
