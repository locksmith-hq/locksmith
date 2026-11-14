//! Secret containers. No Debug/Display/Clone/Serialize on purpose: they cannot leak by formatting.

use zeroize::Zeroize;

/// A 256-bit key on the heap (stable address for mlock), zeroized and unlocked on drop.
pub struct SecretKey32 {
    bytes: Box<[u8; 32]>,
    locked: bool,
}

impl SecretKey32 {
    /// Takes ownership and wipes the caller's copy.
    pub fn from_bytes(mut b: [u8; 32]) -> Self {
        let bytes = Box::new(b);
        b.zeroize();
        let locked = ls_platform::mlock(bytes.as_ptr(), 32);
        Self { bytes, locked }
    }

    pub fn random() -> Result<Self, crate::CryptoError> {
        Ok(Self::from_bytes(crate::random_bytes::<32>()?))
    }

    /// Borrow the raw key. Keep the borrow short; never copy it into an unprotected buffer.
    pub fn expose(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// True when the OS honoured the mlock request.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for SecretKey32 {
    fn drop(&mut self) {
        self.bytes.zeroize();
        if self.locked {
            ls_platform::munlock(self.bytes.as_ptr(), 32);
        }
    }
}

/// Variable-length secret (payloads, seeds). Zeroized on drop.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(v: Vec<u8>) -> Self {
        Self(v)
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
