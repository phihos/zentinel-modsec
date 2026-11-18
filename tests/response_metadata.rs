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

#[test]
fn final_media_type_governs_response_rules_and_body_inspection() {
    let engine = ModSecurity::from_string(
        r#"
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule RESPONSE_CONTENT_TYPE "@streq text/plain" "id:1,phase:3,pass"
SecRule RESPONSE_HEADERS:Content-Type "@streq text/plain; charset=utf-8" "id:2,phase:3,pass"
SecRule RESPONSE_BODY "@streq hello" "id:3,phase:4,pass"
"#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.add_response_header("Content-Type", "text/html").unwrap();
    tx.add_response_header("Content-Type", "text/plain; charset=utf-8")
        .unwrap();
    tx.process_response_headers().unwrap();
    assert!(tx.response_body_processable());
    tx.write_response_body(b"hello").unwrap();
    tx.process_response_body().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2", "3"]);
}

#[test]
fn cli_checks_phase_two_on_bodyless_requests() {
    use std::{io::Write, process::Command};
    let mut rules = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        rules,
        r#"SecRule REQUEST_METHOD "@streq GET" "id:12,phase:2,deny,status:403""#
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_zentinel-modsec"))
        .args(["test", "--uri", "/", "--rules"])
        .arg(rules.path())
        .output()
        .unwrap();
    assert!(result.status.success(), "{:?}", result);
    assert!(String::from_utf8(result.stdout)
        .unwrap()
        .contains("BLOCKED (Phase 2)"));
}
