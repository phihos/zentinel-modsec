use zentinel_modsec::ModSecurity;

fn matched(config: &str, uri: &str) -> Vec<String> {
    let engine = ModSecurity::from_string(config).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.matched_rules().to_vec()
}

#[test]
fn crs_multipart_charset_selects_lowercase_tx_keys_with_uppercase_pattern() {
    let ids = matched(
        r#"SecRuleEngine DetectionOnly
SecAction "id:1,phase:1,pass,setvar:'tx.multipart_headers_content_types_0=text/plain; charset=utf-7'"
SecRule TX:/MULTIPART_HEADERS_CONTENT_TYPES_*/ "@contains utf-7" "id:922110,phase:2,pass""#,
        "/",
    );
    assert!(ids.iter().any(|id| id == "922110"));
}

#[test]
fn tx_regex_folding_preserves_escape_operators_and_explicit_flags() {
    let ids = matched(
        r#"SecRuleEngine DetectionOnly
SecAction "id:1,phase:1,pass,setvar:tx.name=attack"
SecRule TX:/^\D+$/ "@streq attack" "id:2,phase:2,pass"
SecRule TX:/^(?-i:NAME)$/ "@streq attack" "id:3,phase:2,pass"
SecRule TX:/^(?i:NAME)$/ "@streq attack" "id:4,phase:2,pass""#,
        "/",
    );
    assert!(ids.iter().any(|id| id == "2"));
    assert!(!ids.iter().any(|id| id == "3"));
    assert!(ids.iter().any(|id| id == "4"));
}

#[test]
fn tx_regex_exclusions_fold_literals_without_affecting_args_case() {
    let ids = matched(
        r#"SecRuleEngine DetectionOnly
SecAction "id:1,phase:1,pass,setvar:tx.secret_name=attack"
SecRule TX|!TX:/^SECRET_/ "@streq attack" "id:2,phase:2,pass"
SecRule ARGS:/^NAME$/ "@streq attack" "id:3,phase:2,pass"
SecRule ARGS:/^name$/ "@streq attack" "id:4,phase:2,pass""#,
        "/?name=attack",
    );
    assert!(!ids.iter().any(|id| id == "2"));
    assert!(!ids.iter().any(|id| id == "3"));
    assert!(ids.iter().any(|id| id == "4"));
}
