//! SCRAM-SHA-256 client (RFC 5802, RFC 7677) without channel binding (`n,,`), as Postgres uses
//! it. Every value derived from the password is zeroized. The server signature is verified, so
//! a fake upstream cannot complete authentication without knowing the verifier.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ring::{digest, hmac, pbkdf2};
use std::num::NonZeroU32;
use zeroize::Zeroizing;

/// Iteration counts above this are refused (a hostile upstream could stall the relay).
const MAX_ITERATIONS: u32 = 10_000_000;

/// Sans-IO SCRAM-SHA-256 client (RFC 7677); the caller moves the bytes. Shared with the gateway (D3).
pub struct Client {
    first_bare: String,
    nonce: String,
    /// Expected server signature, set by [`Client::final_message`].
    server_sig: Option<Zeroizing<Vec<u8>>>,
}

fn hmac256(key: &[u8], msg: &[u8]) -> Zeroizing<Vec<u8>> {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    Zeroizing::new(hmac::sign(&k, msg).as_ref().to_vec())
}

impl Client {
    pub fn new(user: &str) -> Client {
        let raw: [u8; 18] = super::random();
        Self::with_nonce(user, &B64.encode(raw))
    }

    fn with_nonce(user: &str, nonce: &str) -> Client {
        let user = user.replace('=', "=3D").replace(',', "=2C");
        Client {
            first_bare: format!("n={user},r={nonce}"),
            nonce: nonce.into(),
            server_sig: None,
        }
    }

    /// `client-first-message` (gs2 header `n,,`: no channel binding).
    pub fn first_message(&self) -> String {
        format!("n,,{}", self.first_bare)
    }

    /// `client-final-message` for the server's first message.
    pub fn final_message(
        &mut self,
        password: &[u8],
        server_first: &[u8],
    ) -> Result<Zeroizing<String>, String> {
        let sf = std::str::from_utf8(server_first).map_err(|_| "bad SCRAM server message")?;
        let (mut r, mut s, mut i) = (None, None, None);
        for part in sf.split(',') {
            match part.split_at_checked(2) {
                Some(("r=", v)) => r = Some(v),
                Some(("s=", v)) => s = Some(v),
                Some(("i=", v)) => i = Some(v),
                _ => {}
            }
        }
        let (Some(r), Some(s), Some(i)) = (r, s, i) else {
            return Err("bad SCRAM server message".into());
        };
        if !r.starts_with(&self.nonce) || r.len() <= self.nonce.len() {
            return Err("SCRAM server nonce mismatch".into());
        }
        let salt = B64.decode(s).map_err(|_| "bad SCRAM salt")?;
        let iters = i
            .parse::<u32>()
            .ok()
            .filter(|n| *n <= MAX_ITERATIONS)
            .and_then(NonZeroU32::new)
            .ok_or("bad SCRAM iteration count")?;
        let mut salted = Zeroizing::new([0u8; 32]);
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iters,
            &salt,
            password,
            &mut salted[..],
        );
        let client_key = hmac256(&salted[..], b"Client Key");
        let stored_key = Zeroizing::new(
            digest::digest(&digest::SHA256, &client_key)
                .as_ref()
                .to_vec(),
        );
        let without_proof = format!("c=biws,r={r}");
        let auth_msg = format!("{},{sf},{without_proof}", self.first_bare);
        let sig = hmac256(&stored_key, auth_msg.as_bytes());
        let proof: Zeroizing<Vec<u8>> = Zeroizing::new(
            client_key
                .iter()
                .zip(sig.iter())
                .map(|(a, b)| a ^ b)
                .collect(),
        );
        let server_key = hmac256(&salted[..], b"Server Key");
        self.server_sig = Some(hmac256(&server_key, auth_msg.as_bytes()));
        Ok(Zeroizing::new(format!(
            "{without_proof},p={}",
            B64.encode(&*proof)
        )))
    }

    /// Check `server-final-message` (`v=<signature>`).
    pub fn verify(&self, server_final: &[u8]) -> Result<(), String> {
        let want = self.server_sig.as_ref().ok_or("SCRAM out of order")?;
        let sf = std::str::from_utf8(server_final).map_err(|_| "bad SCRAM final message")?;
        let v = sf
            .split(',')
            .find_map(|p| p.strip_prefix("v="))
            .ok_or("SCRAM server rejected the proof")?;
        let got = B64.decode(v).map_err(|_| "bad SCRAM server signature")?;
        // Constant-time compare.
        let diff = got
            .iter()
            .zip(want.iter())
            .fold(0u8, |a, (x, y)| a | (x ^ y));
        if got.len() != want.len() || diff != 0 {
            return Err("SCRAM server signature mismatch (not the expected server)".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7677 section 3 test vector.
    #[test]
    fn rfc7677_vector() {
        let mut c = Client::with_nonce("user", "rOprNGfwEbeRWgbNEkqO");
        assert_eq!(c.first_message(), "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
        let sf = b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let f = c.final_message(b"pencil", sf).unwrap();
        assert_eq!(
            f.as_str(),
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        c.verify(b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
            .unwrap();
        assert!(
            c.verify(b"v=AAAATRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
                .is_err()
        );
        assert!(c.verify(b"e=invalid-proof").is_err());
    }

    #[test]
    fn rejects_foreign_nonce_and_huge_iterations() {
        let mut c = Client::with_nonce("", "abc");
        assert!(c.final_message(b"pw", b"r=xyz123,s=AAAA,i=4096").is_err());
        assert!(c.final_message(b"pw", b"r=abc,s=AAAA,i=4096").is_err());
        assert!(
            c.final_message(b"pw", b"r=abcd,s=AAAA,i=4294967295")
                .is_err()
        );
        assert!(c.final_message(b"pw", b"r=abcd,s=AAAA,i=1").is_ok());
    }
}
