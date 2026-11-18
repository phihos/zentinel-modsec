//! Binary input must survive acquisition, collections, transforms and captures.
use zentinel_modsec::ModSecurity;

fn request(ms: &ModSecurity, uri: &str, body: &[u8]) -> Vec<String> {
    let mut tx = ms.new_transaction();
    tx.process_uri(uri, "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    tx.matched_rules().to_vec()
}

#[test]
fn invalid_utf8_from_form_and_query_is_not_replaced_before_validation() {
    let ms = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule ARGS|ARGS_NAMES "@validateUtf8Encoding" "id:920250,phase:2,pass""#,
    )
    .unwrap();
    for (uri, body) in [
        ("/", &b"x=\xff\0"[..]),
        ("/?x=%E2%A3", &b""[..]),
        ("/?%FF=value", &b""[..]),
    ] {
        assert_eq!(request(&ms, uri, body), ["920250"], "{uri}");
    }
}

#[test]
fn raw_java_signature_is_detected_in_binary_request_body() {
    let ms = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule REQUEST_BODY|ARGS "@rx \xac\xed\x00\x05" "id:944200,phase:2,pass""#,
    )
    .unwrap();
    assert_eq!(request(&ms, "/", b"test=\xac\xed\0\x05"), ["944200"]);
}

#[test]
fn raw_capture_reaches_tx_and_setvar_macro_without_display_roundtrip() {
    let ms = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule ARGS:x "@rx (\xff)" "id:1,phase:2,pass,capture,setvar:tx.raw=%{tx.1}"
SecRule TX:raw "@rx ^\xff$" "id:2,phase:2,pass"
SecRule TX:raw "@streq \\xff" "id:3,phase:2,pass""#,
    )
    .unwrap();
    assert_eq!(request(&ms, "/?x=%FF", b""), ["1", "2"]);
}

#[test]
fn binary_names_and_literal_escape_text_are_distinct_engine_inputs() {
    use zentinel_modsec::variables::ByteCollection;
    let ms = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule ARGS_NAMES "@rx ^\xff$" "id:1,phase:2,pass"
SecRule &ARGS "@eq 2" "id:2,phase:2,pass""#,
    )
    .unwrap();
    let mut tx = ms.new_transaction();
    tx.process_uri("/?%FF=binary&%5Cxff=literal", "GET", "HTTP/1.1")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2"]);
    assert_eq!(tx.matched_data()[0].value_bytes, b"\xff");
    assert!(tx.tx().get_bytes(b"nothing").is_none());
}

#[test]
fn captured_binary_macros_can_be_operator_arguments_and_binary_tx_keys() {
    use zentinel_modsec::variables::ByteCollection;
    let ms = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule ARGS:x "@rx (\xff)" "id:1,phase:2,pass,capture,setvar:tx.key_%{tx.1}=%{tx.1}"
SecRule ARGS:y "@streq %{tx.1}" "id:2,phase:2,pass""#,
    )
    .unwrap();
    let mut tx = ms.new_transaction();
    tx.process_uri("/?x=%FF&y=%FF", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2"]);
    assert_eq!(tx.tx().get_bytes(b"KEY_\xff"), Some(vec![&b"\xff"[..]]));
    assert!(tx.tx().get_bytes(b"key_\\xff").is_none());
}

#[test]
fn arbitrary_header_and_request_line_bytes_reach_their_variables() {
    let ms = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule REQUEST_HEADERS "@rx \xff" "id:1,phase:1,pass"
SecRule REQUEST_HEADERS_NAMES "@rx \x80" "id:2,phase:1,pass"
SecRule REQUEST_URI_RAW|REQUEST_FILENAME "@rx \xfe" "id:3,phase:1,pass""#,
    )
    .unwrap();
    let mut tx = ms.new_transaction();
    tx.process_uri_bytes(b"/\xfe", b"GET", b"HTTP/1.1").unwrap();
    tx.add_request_header_bytes(b"X-\x80", b"\xff").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2", "3"]);
}

#[test]
fn multimatch_retains_binary_stages_and_revisits_changed_cycles() {
    use zentinel_modsec::variables::ByteCollection;
    let ms=ModSecurity::from_string(r#"SecRuleEngine DetectionOnly
SecRule ARGS:x "@rx (ff|\xff)" "id:1,phase:2,pass,multiMatch,t:hexDecode,t:hexEncode,capture,setvar:tx.count=+1""#).unwrap();
    let mut tx = ms.new_transaction();
    tx.process_uri("/?x=ff", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["1"]);
    assert_eq!(tx.tx().get_bytes(b"count"), Some(vec![&b"3"[..]]));
    assert_eq!(tx.tx().get_bytes(b"1"), Some(vec![&b"ff"[..]]));
}

#[test]
fn invalid_decoded_filename_bytes_observe_absolute_target_and_fragment_rules() {
    let ms = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule REQUEST_FILENAME "@rx ^/\xff$" "id:1,phase:1,pass""#,
    )
    .unwrap();
    for uri in [
        &b"/%FF"[..],
        &b"http://example/%FF"[..],
        &b"/%FF#ignore"[..],
        &b"http://example/\xff#ignore"[..],
    ] {
        let mut tx = ms.new_transaction();
        tx.process_uri_bytes(uri, b"GET", b"HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules(), ["1"], "{uri:?}");
    }
}
