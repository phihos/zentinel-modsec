use zentinel_modsec::variables::RequestData;
use zentinel_modsec::ModSecurity;

#[test]
fn filename_decodes_once_after_query_split_and_preserves_raw_uri() {
    let uri = "/a%3Fb%2Fc%252F+z?arg=a%2Bb";
    let mut request = RequestData::new();
    request.set_uri(uri);
    assert_eq!(request.path, "/a?b/c%2F+z");
    assert_eq!(request.uri, uri);
    assert_eq!(request.uri_raw, uri);
    assert_eq!(request.query_string, "arg=a%2Bb");
}

#[test]
fn absolute_form_and_malformed_paths_have_consistent_fallbacks() {
    let mut request = RequestData::new();
    request.set_uri("http://example.test/a%20b?q=1");
    assert_eq!(request.path, "/a b");
    request.set_uri("/bad%zz%2Fpath");
    assert_eq!(request.path, "/bad%zz%2Fpath");
    request.set_uri("/bad%FF");
    // No replacement character is introduced at this string API boundary.
    assert_eq!(request.path, "/bad%FF");
}

#[test]
fn crs_php_uri_cases_expose_decoded_filename_and_basename() {
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule REQUEST_FILENAME "@rx (?i)\b(?:substr|eval|unpack|array_diff|pg_enter_pipeline_mode|sodium_crypto_aead_chacha20poly1305_ietf_keygen)[\s\x0b]*\(" "id:933160,phase:2,pass,t:none"
SecRule REQUEST_URI_RAW "@contains %28" "id:2,phase:2,pass"
SecRule REQUEST_BASENAME "@contains (" "id:3,phase:2,pass""#,
    )
    .unwrap();
    for uri in [
        "/post/subSTR%28%24x%29",
        "/get/eval%28gzinflate%28str_rot13%28base64_decode%28%22%22%29",
        "/get/eval%28base64_decode%28%27cGFwYWRhcHVwaSwK%27%29",
        "/post/unPACK%28%24x%29",
        "/get/array_diff%20%28",
        "/get/pg_enter_pipeline_mode%20%28",
        "/get/sodium_crypto_aead_chacha20poly1305_ietf_keygen%20%28",
    ] {
        let mut tx = engine.new_transaction();
        tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        for id in ["933160", "2", "3"] {
            assert!(
                tx.matched_rules().iter().any(|actual| actual == id),
                "{uri}: missing {id}"
            );
        }
    }
}

#[test]
fn query_bytes_do_not_change_a_text_path_or_previous_query() {
    use zentinel_modsec::variables::ByteCollection;
    let mut request = RequestData::new();
    request.set_uri("/before?old=1");
    let mut target = "/café?label=".as_bytes().to_vec();
    target.push(0xff);
    request.set_uri_bytes(&target);
    assert_eq!(request.path_bytes(), "/café".as_bytes());
    assert_eq!(request.uri_bytes(), target);
    assert_eq!(request.args_get.get_bytes(b"label").unwrap(), [b"\xff"]);
    assert!(request.args_get.get_bytes(b"old").is_none());
    request.set_uri_bytes(b"/%ff?label=caf\xc3\xa9#fragment");
    assert_eq!(request.path_bytes(), b"/\xff");
    assert_eq!(request.query_bytes(), "label=café".as_bytes());
}
