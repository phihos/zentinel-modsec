//! Full, unchanged CRS patterns must remain executable in binary mode.
use zentinel_modsec::{
    operators::{Operator, RxOperator},
    ModSecurity,
};

#[test]
fn binary_braced_escapes_do_not_drop_entire_crs_rule_families() {
    let ms =
        ModSecurity::from_string(include_str!("fixtures/crs-binary-braced-escapes.conf")).unwrap();
    for (payload, expected) in [
        ("$a()", Some("933180")),
        ("$å()", Some("933180")),
        ("$1()", None),
        ("https://2130706433", Some("934120")),
        ("http://①②⑦", Some("934120")),
        ("https://example.com", None),
        ("%u00BCscript%u00BE%u00BC/script%u00BE", Some("941310")),
        ("¼script>¼/script>", Some("941310")),
        ("<script></script>", None),
    ] {
        let uri = format!(
            "/?x={}",
            percent_encoding::utf8_percent_encode(payload, percent_encoding::NON_ALPHANUMERIC)
        );
        let mut tx = ms.new_transaction();
        tx.process_uri(&uri, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        let expected: Vec<String> = expected.into_iter().map(str::to_owned).collect();
        assert_eq!(tx.matched_rules(), expected, "{payload}");
    }
}

#[test]
fn braced_byte_ranges_and_escaped_backslashes_keep_their_grammar() {
    let op = RxOperator::new(r"^[\x7f-\x{ff}]+$").unwrap();
    assert!(op.execute_bytes(b"\x80\xff").unwrap().matched);
    assert!(!op.execute_bytes(b"ASCII").unwrap().matched);
    let op = RxOperator::new(r"^\\x\{ff\}:(\x{ff})$").unwrap();
    assert!(op.execute_bytes(b"\\x{ff}:\xff").unwrap().matched);
    assert_eq!(
        op.execute_bytes(b"\\x{ff}:\xff").unwrap().captures,
        [vec![0xff]]
    );
}
