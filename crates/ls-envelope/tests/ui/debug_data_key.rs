fn requires<T: std::fmt::Debug>() {}

fn main() {
    requires::<ls_envelope::DataKey>();
}
