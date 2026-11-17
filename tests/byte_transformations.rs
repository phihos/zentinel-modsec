use std::borrow::Cow;
use zentinel_modsec::transformations::Transformation;

#[test]
fn custom_text_only_transformations_reject_binary_input() {
    struct TextOnly;
    impl Transformation for TextOnly {
        fn transform<'a>(&self, value: &'a str) -> Cow<'a, str> {
            Cow::Borrowed(value)
        }
        fn name(&self) -> &'static str {
            "custom"
        }
    }
    assert!(TextOnly
        .transform_bytes(b"\xff")
        .unwrap_err()
        .to_string()
        .contains("binary input"));
}
