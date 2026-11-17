use std::borrow::Cow;
use zentinel_modsec::transformations::{EscapeSeqDecode, Transformation};
use zentinel_modsec::ModSecurity;

#[test]
fn c_escapes_decode_quotes_controls_octal_and_exactly_two_hex_digits() {
    let decode = EscapeSeqDecode;
    assert_eq!(decode.transform(r#"\'\"\?\\"#), "'\"?\\");
    assert_eq!(
        decode.transform(r"\a\b\f\n\r\t\v"),
        "\x07\x08\x0c\n\r\t\x0b"
    );
    assert_eq!(decode.transform(r"\101\040\141\400\08"), "A a\0\08");
    assert_eq!(decode.transform(r"\x41\X42\x4Z"), "ABx4Z");
    assert_eq!(decode.transform(r"\q\u0041"), "qu0041");
    assert_eq!(decode.transform("trailing\\"), "trailing\\");
}

#[test]
fn crs_sqlite_quote_escapes_are_visible_to_the_exact_rule() {
    let engine = ModSecurity::from_string(include_str!("fixtures/crs-escape-seq.conf")).unwrap();
    for body in ["code=1;.\\\"shell whoami\n", "code=1;.\\'shell whoami\n"] {
        let mut tx = engine.new_transaction();
        tx.process_uri("/post", "POST", "HTTP/1.1").unwrap();
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
            .unwrap();
        tx.append_request_body(body.as_bytes()).unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        assert!(
            tx.matched_rules().iter().any(|id| id == "932210"),
            "{body:?}"
        );
    }
}

#[test]
fn unchanged_unicode_input_is_borrowed() {
    assert!(matches!(
        EscapeSeqDecode.transform("café"),
        Cow::Borrowed("café")
    ));
}
