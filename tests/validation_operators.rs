use zentinel_modsec::operators::{
    create_operator, Operator, ValidateByteRangeOperator, ValidateUrlEncodingOperator,
    ValidateUtf8EncodingOperator,
};
use zentinel_modsec::parser::OperatorName;
use zentinel_modsec::ModSecurity;

#[test]
fn compiled_ranges_match_the_reference_at_every_byte_boundary() {
    for (spec, ranges) in [
        ("0-255", vec![0..=255]),
        (
            "0, 9, 32-126, 80-150, 255",
            vec![0..=0, 9..=9, 32..=150, 255..=255],
        ),
        ("7-3,+09,254-255", vec![9..=9, 254..=255]),
        ("2-1", vec![]),
    ] {
        let op = create_operator(OperatorName::ValidateByteRange, spec).unwrap();
        assert!(!op.execute_bytes(b"").unwrap().matched);
        for b in 0..=255 {
            let expected = !ranges.iter().any(|r| r.contains(&b));
            let matched = op.execute_bytes(&[b]).unwrap();
            assert_eq!(matched.matched, expected, "{spec} byte {b}");
            assert_eq!(matched.matched_value, expected.then(|| vec![b]));
        }
    }
    let omitted = create_operator(OperatorName::ValidateByteRange, "").unwrap();
    for value in [b"".as_slice(), b"normal"] {
        assert!(omitted.execute_bytes(value).unwrap().matched);
    }
    let op = ValidateByteRangeOperator::try_new("65-90").unwrap();
    assert_eq!(
        op.execute("Az").matched_value.as_deref(),
        Some("invalid byte: 122")
    );
    assert_eq!(
        op.execute_bytes(b"Az").unwrap().matched_value.as_deref(),
        Some(b"Az".as_slice())
    );
}

#[test]
fn malformed_static_rules_fail_at_load_and_dynamic_lists_validate_at_evaluation() {
    for entry in [
        "x", "256", "1-256", "2-3-4", "1-", ",0", "255,", "0,,9", "3 - 4", "%{}", "1,%{}%{",
    ] {
        let rules = format!(r#"SecRule ARGS:x "@validateByteRange {entry}" "id:1,phase:1,pass""#);
        let error = ModSecurity::from_string(&rules).expect_err("invalid config");
        assert!(error.to_string().contains("@validateByteRange"), "{error}");
    }
    let ms = ModSecurity::from_string(
        r#"
SecRule ARGS:x "@validateByteRange %{ARGS.list}" "id:1,phase:1,pass"
"#,
    )
    .unwrap();
    for (uri, matched) in [
        ("/?x=ABC&list=65-90", false),
        ("/?x=abc&list=65-90", true),
        ("/?x=&list=", true),
    ] {
        let mut tx = ms.new_transaction();
        tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules().len(), usize::from(matched), "{uri}");
    }
    let mut tx = ms.new_transaction();
    tx.process_uri("/?x=abc&list=1-500", "GET", "HTTP/1.1")
        .unwrap();
    assert!(tx
        .process_request_headers()
        .unwrap_err()
        .to_string()
        .contains("1-500"));
    let legacy = ValidateByteRangeOperator::new("invalid,65-90");
    assert!(!legacy.execute("ABC").matched);
}

#[test]
fn encoding_validators_agree_on_text_and_keep_binary_validation() {
    for text in ["", "a\0b", "é ☕", "a%20b%2F", "end%", "%x0", "%00%"] {
        for op in [
            &ValidateUtf8EncodingOperator as &dyn Operator,
            &ValidateUrlEncodingOperator,
        ] {
            assert_eq!(
                op.execute(text).matched,
                op.execute_bytes(text.as_bytes()).unwrap().matched
            );
        }
        assert!(!ValidateUtf8EncodingOperator.execute(text).matched);
    }
    assert!(
        ValidateUtf8EncodingOperator
            .execute_bytes(b"\xff")
            .unwrap()
            .matched
    );
    assert!(
        ValidateUrlEncodingOperator
            .execute_bytes(b"\xff%0")
            .unwrap()
            .matched
    );
    assert!(
        !ValidateUrlEncodingOperator
            .execute_bytes(b"\xff%0F")
            .unwrap()
            .matched
    );
}
