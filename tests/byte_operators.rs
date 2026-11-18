use zentinel_modsec::operators::{create_operator, Operator, OperatorResult};
use zentinel_modsec::parser::OperatorName;

#[test]
fn byte_comparisons_and_validation_use_original_bytes() {
    for (operator, argument, input, expected) in [
        (OperatorName::Contains, "attack", &b"\xffattack\0"[..], true),
        (OperatorName::BeginsWith, "safe", &b"safe\xff"[..], true),
        (OperatorName::EndsWith, "attack", &b"\xffattack"[..], true),
        (OperatorName::StreQ, "\\xff", &b"\xff"[..], false),
        (OperatorName::Eq, "0", &b"\xff"[..], false),
        (OperatorName::Ne, "normal", &b"\xff"[..], true),
        (OperatorName::ValidateUtf8Encoding, "", &b"\xff"[..], true),
        (
            OperatorName::ValidateUtf8Encoding,
            "",
            &b"\0valid"[..],
            false,
        ),
        (OperatorName::ValidateUrlEncoding, "", &b"\xff%0X"[..], true),
        (
            OperatorName::ValidateUrlEncoding,
            "",
            &b"\xff%FF"[..],
            false,
        ),
        (
            OperatorName::ValidateByteRange,
            "0-255",
            &b"\xff\0"[..],
            false,
        ),
    ] {
        let op = create_operator(operator, argument).unwrap();
        assert_eq!(
            op.execute_bytes(input).unwrap().matched,
            expected,
            "{operator:?}"
        );
    }
}

#[test]
fn custom_text_only_operators_fail_explicitly_on_binary_input() {
    struct TextOnly;
    impl Operator for TextOnly {
        fn execute(&self, _: &str) -> OperatorResult {
            OperatorResult::no_match()
        }
        fn name(&self) -> &'static str {
            "custom"
        }
    }
    assert!(TextOnly
        .execute_bytes(b"\xff")
        .unwrap_err()
        .to_string()
        .contains("binary input"));
}

#[cfg(feature = "libinjection-ffi")]
#[test]
fn native_operators_inspect_binary_values() {
    let op = create_operator(OperatorName::DetectXss, "").unwrap();
    assert!(
        op.execute_bytes(b"\xff\0<script>alert(1)</script>")
            .unwrap()
            .matched
    );
}
