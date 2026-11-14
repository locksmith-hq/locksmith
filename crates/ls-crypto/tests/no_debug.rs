//! Secret types must not be printable: these snippets must fail to compile.
#[test]
fn secret_types_have_no_debug() {
    trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
}
