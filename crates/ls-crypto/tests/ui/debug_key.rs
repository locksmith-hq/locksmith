fn main() {
    let k = ls_crypto::SecretKey32::from_bytes([0u8; 32]);
    let _ = format!("{:?}", k);
}
