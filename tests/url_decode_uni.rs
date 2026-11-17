use zentinel_modsec::transformations::{Transformation, UrlDecodeUni};
use zentinel_modsec::ModSecurity;

#[test]
fn plus_and_percent_are_decoded_in_one_pass() {
    let decode = UrlDecodeUni;
    assert_eq!(decode.transform("a+b%2Bc%252B"), "a b+c%2B");
    assert_eq!(decode.transform("%u002B+%U002b"), "+ +");
    for (input, expected) in [
        ("%+x", "% x"),
        ("%u12+3", "%u12 3"),
        ("%U12xz", "%U12xz"),
        ("%€+", "%€ "),
        ("tail%", "tail%"),
    ] {
        assert_eq!(decode.transform(input), expected, "input={input:?}");
    }
}

#[test]
fn a_second_explicit_decode_sees_a_plus_produced_by_the_first() {
    let first = UrlDecodeUni.transform("cat%2B/etc/passwd");
    assert_eq!(first, "cat+/etc/passwd");
    assert_eq!(UrlDecodeUni.transform(&first), "cat /etc/passwd");
}

#[test]
fn crs_rce_chain_observes_encoded_plus_as_whitespace_after_argument_parsing() {
    // CRS 932200-4: argument parsing decodes %2B, then the rule's
    // urlDecodeUni must decode that literal plus before its whitespace link.
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule ARGS:host "@contains /" "id:932200,phase:2,pass,t:none,t:urlDecodeUni,chain"
SecRule MATCHED_VARS "@rx \s" "t:none,setvar:tx.score=+5""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri(
        "/get?host=www.google.com;c%24%40at%2B%2Fet%24%40c%2Fpas%24%40swd",
        "GET",
        "HTTP/1.1",
    )
    .unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert!(tx.matched_rules().iter().any(|id| id == "932200"));
}
