use zentinel_modsec::operators::{create_operator, Operator, OperatorResult};
use zentinel_modsec::parser::OperatorName;

#[test]
fn byte_comparisons_and_validation_use_original_bytes() {
    for (operator, argument, input, expected) in [
        (OperatorName::Contains, "attack", &b"\xffattack\0"[..], true),
        (OperatorName::BeginsWith, "safe", &b"safe\xff"[..], true),
        (OperatorName::EndsWith, "attack", &b"\xffattack"[..], true),
        (OperatorName::StreQ, "\\xff", &b"\xff"[..], false),
        // Pinned Coraza ignores Atoi syntax errors, yielding numeric zero.
        (OperatorName::Eq, "0", &b"\xff"[..], true),
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

#[test]
fn detection_operators_inspect_binary_values() {
    let op = create_operator(OperatorName::DetectXss, "").unwrap();
    assert!(
        op.execute_bytes(b"\xff\0<script>alert(1)</script>")
            .unwrap()
            .matched
    );
}

#[test]
fn static_regex_keeps_match_evidence_across_negation_and_changed_stages() {
    use zentinel_modsec::{variables::ByteCollection, ModSecurity};

    for negated in [false, true] {
        let operator = if negated { "!@rx" } else { "@rx" };
        let rules = format!(
            r#"SecRuleEngine DetectionOnly
SecRule REQUEST_HEADERS:Mode "@rx (sample)" "id:11,phase:1,pass,capture"
SecRule REQUEST_HEADERS:Value "{operator} (draft)(-(42))?" "id:12,phase:1,pass,capture,multiMatch,t:lowercase""#
        );
        let engine = ModSecurity::from_string(&rules).unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/catalog", "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("Mode", "sample").unwrap();
        tx.add_request_header_bytes(b"Value", b"\xffDRAFT-42")
            .unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules(), ["11", "12"]);
        let data = &tx.matched_data()[1];
        if negated {
            assert_eq!(data.value_bytes, b"\xffDRAFT-42");
            assert_eq!(data.matched_portion_bytes, None);
            assert_eq!(tx.tx().get_bytes(b"0"), None);
            assert_eq!(tx.tx().get_bytes(b"1"), None);
        } else {
            assert_eq!(data.value_bytes, b"\xffdraft-42");
            assert_eq!(
                data.matched_portion_bytes.as_deref(),
                Some(b"draft-42".as_slice())
            );
            assert_eq!(tx.tx().get_bytes(b"0"), Some(vec![b"draft-42".as_slice()]));
            assert_eq!(tx.tx().get_bytes(b"3"), Some(vec![b"42".as_slice()]));
        }
    }
}
