//! Envelope secret types must not be printable or cloneable: these snippets must fail to compile.
#[test]
fn secret_types_have_no_debug_display_or_clone() {
    trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
}
