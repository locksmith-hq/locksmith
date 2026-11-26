fn main() {
    let b = ls_crypto::SecretBytes::new(vec![1, 2, 3]);
    let _s = format!("{b:?}");
}
