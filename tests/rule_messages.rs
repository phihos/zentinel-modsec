use zentinel_modsec::ModSecurity;

#[test]
fn messages_capture_match_time_values_before_later_rules_mutate_tx() {
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecAction "id:1,phase:1,pass,setvar:tx.score=0"
SecRule ARGS:q "@rx ^evil$" "id:100,phase:2,pass,capture,msg:'score=%{tx.score}',logdata:'%{MATCHED_VAR_NAME}=%{tx.0}',setvar:tx.score=+5"
SecAction "id:101,phase:2,pass,setvar:tx.score=99,setvar:tx.0=changed""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.set_record_rule_messages(true);
    tx.process_uri("/?q=evil", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    let message = tx
        .rule_messages()
        .iter()
        .find(|m| m.rule_id == "100")
        .unwrap();
    assert_eq!(message.message.as_deref(), Some(b"score=5".as_slice()));
    assert_eq!(message.logdata.as_deref(), Some(b"ARGS:q=evil".as_slice()));
}

#[test]
fn failed_chains_do_not_emit_messages_and_completed_chains_use_starter_metadata() {
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule ARGS:first "@streq evil" "id:200,phase:2,pass,chain,msg:'completed chain'"
SecRule ARGS:last "@streq complete" "t:none""#,
    )
    .unwrap();
    for (last, completes) in [("incomplete", false), ("complete", true)] {
        let mut tx = engine.new_transaction();
        tx.set_record_rule_messages(true);
        tx.process_uri(&format!("/?first=evil&last={last}"), "GET", "HTTP/1.1")
            .unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx.rule_messages().len(), usize::from(completes));
        if completes {
            assert_eq!(tx.rule_messages()[0].rule_id, "200");
            assert_eq!(
                tx.rule_messages()[0].message.as_deref(),
                Some(b"completed chain".as_slice())
            );
        }
    }
}

#[test]
fn message_macro_values_retain_original_binary_bytes() {
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule ARGS:q "@rx \xff" "id:300,phase:2,pass,capture,msg:'binary',logdata:'%{MATCHED_VAR_NAME}=%{tx.0}'""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.set_record_rule_messages(true);
    tx.process_uri_bytes(b"/?q=%ff", b"GET", b"HTTP/1.1")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(
        tx.rule_messages()[0].logdata.as_deref(),
        Some(b"ARGS:q=\xff".as_slice())
    );
}

#[test]
fn disabling_message_recording_does_not_disable_detection() {
    let engine = ModSecurity::from_string(
        r#"SecRule REQUEST_METHOD "@streq GET" "id:400,phase:1,pass,msg:'request'""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["400"]);
    assert!(tx.rule_messages().is_empty());
}
