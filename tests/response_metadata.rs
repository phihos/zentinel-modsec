use zentinel_modsec::ModSecurity;

fn inspect(status: u16, protocol: &str) -> Vec<String> {
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule RESPONSE_STATUS "@eq 200" "id:100,phase:3,pass"
SecRule RESPONSE_STATUS "@eq 403" "id:101,phase:3,pass"
SecRule RESPONSE_STATUS "@eq 0" "id:102,phase:3,pass"
SecRule RESPONSE_PROTOCOL "@streq HTTP/2.0" "id:103,phase:3,pass"
SecRule RESPONSE_STATUS "@eq 403" "id:104,phase:4,pass"
SecRule RESPONSE_HEADERS:Content-Type "@contains text/plain" "id:105,phase:3,pass""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.add_response_header("Content-Type", "text/plain")
        .unwrap();
    tx.process_response_headers_with_status(status, protocol)
        .unwrap();
    tx.process_response_body().unwrap();
    tx.matched_rules().to_vec()
}

#[test]
fn response_status_and_protocol_are_visible_in_response_phases() {
    assert_eq!(inspect(403, "HTTP/2.0"), ["101", "103", "105", "104"]);
    assert_eq!(inspect(200, "HTTP/1.1"), ["100", "105"]);
}

#[test]
fn response_metadata_is_transaction_local() {
    let engine = ModSecurity::from_string(
        r#"SecRule RESPONSE_STATUS "@eq 403" "id:1,phase:3,pass"
SecRule RESPONSE_PROTOCOL "@streq HTTP/2.0" "id:2,phase:3,pass""#,
    )
    .unwrap();
    let mut denied = engine.new_transaction();
    denied
        .process_response_headers_with_status(403, "HTTP/2.0")
        .unwrap();
    let mut ok = engine.new_transaction();
    ok.process_response_headers_with_status(200, "HTTP/1.1")
        .unwrap();
    assert_eq!(denied.matched_rules(), ["1", "2"]);
    assert!(ok.matched_rules().is_empty());
}
