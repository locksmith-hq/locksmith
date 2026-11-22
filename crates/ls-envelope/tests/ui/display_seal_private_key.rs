fn requires<T: std::fmt::Display>() {}

fn main() {
    requires::<ls_envelope::SealPrivateKey>();
}
