//! `vault.header`: CBOR sidecar holding the KDF parameters and key wraps, HMAC-protected under a
//! key derived from the vault key (checked right after unwrapping it).

use hmac::{Hmac, Mac};
use ls_crypto::SecretKey32;
use ls_crypto::aead::Sealed;
use ls_crypto::kdf::{KdfParams, hkdf, label};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::Write;
use std::path::Path;

use crate::Error;

pub const FORMAT: u32 = 1;
pub const HEADER_FILE: &str = "vault.header";

#[derive(Serialize, Deserialize, Clone)]
pub struct SealedDto {
    nonce: [u8; 12],
    ct: Vec<u8>,
}

impl From<&Sealed> for SealedDto {
    fn from(s: &Sealed) -> Self {
        Self {
            nonce: s.nonce,
            ct: s.ct.clone(),
        }
    }
}

impl SealedDto {
    pub fn to_sealed(&self) -> Sealed {
        Sealed {
            nonce: self.nonce,
            ct: self.ct.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Body {
    pub format: u32,
    pub vault_id: [u8; 16],
    pub vk_version: u32,
    pub kdf: KdfParams,
    pub salt: [u8; 32],
    pub pass_wrap: SealedDto,
    pub recovery_wrap: SealedDto,
    pub created_at: u64,
}

#[derive(Serialize, Deserialize)]
struct File {
    body: Body,
    mac: [u8; 32],
}

fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("CBOR serialization into a Vec cannot fail");
    out
}

fn mac_of(vk: &SecretKey32, body: &Body) -> Hmac<Sha256> {
    let key = hkdf(vk.expose(), label::HEADER_MAC);
    let mut m = Hmac::<Sha256>::new_from_slice(key.expose()).expect("HMAC takes any key length");
    m.update(&cbor(body));
    m
}

pub fn read(dir: &Path) -> Result<(Body, [u8; 32]), Error> {
    let bytes = match std::fs::read(dir.join(HEADER_FILE)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::NotInitialized),
        Err(e) => return Err(e.into()),
    };
    let f: File = ciborium::from_reader(bytes.as_slice())
        .map_err(|_| Error::Header("vault.header is corrupt".into()))?;
    Ok((f.body, f.mac))
}

pub fn verify(vk: &SecretKey32, body: &Body, mac: &[u8; 32]) -> bool {
    mac_of(vk, body).verify_slice(mac).is_ok()
}

/// Atomic replace: write a 0600 temp file, fsync, rename over the header, fsync the directory.
pub fn write(dir: &Path, body: &Body, vk: &SecretKey32) -> Result<(), Error> {
    let mac: [u8; 32] = mac_of(vk, body).finalize().into_bytes().into();
    let bytes = cbor(&File {
        body: body.clone(),
        mac,
    });
    let tmp = dir.join("vault.header.tmp");
    let mut f = ls_platform::fs::PrivateFile::new()
        .truncate(true)
        .open(&tmp)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, dir.join(HEADER_FILE))?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}
