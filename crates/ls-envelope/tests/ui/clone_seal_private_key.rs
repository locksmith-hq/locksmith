fn requires<T: Clone>() {}

fn main() {
    requires::<ls_envelope::SealPrivateKey>();
}
