use zentinel_modsec::operators::{Operator, RxOperator};

#[test]
fn raw_signature_and_partial_utf8_captures_are_not_unicode_codepoints() {
    let op = RxOperator::new(r"(\xac\xed\x00\x05)").unwrap();
    let result = op.execute_bytes(b"prefix\xac\xed\0\x05suffix").unwrap();
    assert!(result.matched);
    assert_eq!(result.captures, [b"\xac\xed\0\x05".to_vec()]);
    let op = RxOperator::new(r"(\xe2\x80)[\x98\x99]").unwrap();
    let result = op.execute_bytes("‘".as_bytes()).unwrap();
    assert!(result.matched);
    assert_eq!(result.captures, [vec![0xe2, 0x80]]);
}

#[test]
fn unicode_patterns_and_explicit_flag_overrides_keep_their_semantics() {
    let op = RxOperator::new(r"(\p{Greek}+)").unwrap();
    assert!(op.execute("αβ").matched);
    assert!(
        !RxOperator::new(r"(?-s)a.b")
            .unwrap()
            .execute("a\nb")
            .matched
    );
    assert!(RxOperator::new(r"a.b").unwrap().execute("a\nb").matched);
}
