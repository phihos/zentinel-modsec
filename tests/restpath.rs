use zentinel_modsec::ModSecurity;

#[test]
fn path_parameters_are_visible_within_the_same_phase_and_in_later_phases() {
    let engine=ModSecurity::from_string(r#"SecRuleEngine DetectionOnly
SecArgumentsLimit 1
SecAction "id:1,phase:1,pass,setvar:tx.0=old"
SecRule REQUEST_URI "@restpath /orders/{Section}/{Item}" "id:2,phase:1,pass,capture,msg:'%{ARGS_PATH.section}/%{ARGS_PATH.Item}/%{tx.0}'"
SecRule ARGS_PATH:item "@streq tea" "id:3,phase:1,pass,msg:'%{MATCHED_VAR_NAME}'"
SecRule ARGS "@pm tea" "id:4,phase:1,pass"
SecRule ARGS_NAMES "@rx ^Section$" "id:5,phase:1,pass"
SecRule &ARGS_PATH "@eq 2" "id:6,phase:1,pass"
SecRule ARGS_COMBINED_SIZE "@eq 0" "id:7,phase:1,pass"
SecRule REQUEST_URI "!@restpath /orders/{Item}" "id:8,phase:1,pass"
SecRule ARGS_PATH:Item "@streq grocery" "id:9,phase:1,pass"
SecAction "id:10,phase:1,pass,msg:'%{ARGS.Item}/%{ARGS_PATH.Item}/%{ARGUMENTS_LIMIT_REACHED}'"
SecRule ARGS_PATH "@streq grocery" "id:11,phase:2,pass""#).unwrap();
    for (uri, expected_ids, last) in [
        (
            "/x/orders/grocery/tea",
            &["1", "2", "3", "4", "5", "6", "7", "9", "10", "11"][..],
            "grocery/grocery/0",
        ),
        (
            "/x/orders/grocery/tea?Item=query",
            &["1", "2", "3", "4", "5", "6", "9", "10", "11"][..],
            "query/grocery/0",
        ),
        (
            "/x/no-route",
            &["1", "7", "8", "10"][..],
            "ARGS.Item/ARGS_PATH.Item/0",
        ),
    ] {
        let mut tx = engine.new_transaction();
        tx.set_record_rule_messages(true);
        tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx.matched_rules(), expected_ids);
        for m in tx.rule_messages() {
            let expected = match m.rule_id.as_str() {
                "2" => "grocery/tea/old",
                "3" => "ARGS_PATH:Item",
                "10" => last,
                _ => continue,
            };
            assert_eq!(m.message.as_deref(), Some(expected.as_bytes()));
        }
    }
}

#[test]
fn repeated_numeric_and_binary_parameters_keep_their_original_values() {
    let engine=ModSecurity::from_string(r#"SecRule REQUEST_URI "@restpath /{1}/{1}/{tag}" "id:1,phase:1,pass,msg:'%{args_path.1}',logdata:'%{args_path.tag}'""#).unwrap();
    let mut tx = engine.new_transaction();
    tx.set_record_rule_messages(true);
    tx.process_uri_bytes(b"/one/two/\xff?tail", b"GET", b"HTTP/1.1")
        .unwrap();
    tx.process_request_headers().unwrap();
    let m = &tx.rule_messages()[0];
    assert_eq!(m.message.as_deref(), Some(b"two".as_slice()));
    assert_eq!(m.logdata.as_deref(), Some(b"\xff".as_slice()));
    assert!(ModSecurity::from_string(
        r#"SecRule REQUEST_URI "@restpath /{a/{b}" "id:2,phase:1,pass""#
    )
    .is_err());
}

#[test]
fn connector_path_arguments_count_duplicates_and_keep_later_values_after_route_matches() {
    let engine = ModSecurity::from_string(r#"SecArgumentsLimit 2
SecRule REQUEST_URI "@restpath /{Item}" "id:1,phase:1,pass"
SecRule &ARGS_PATH:item "@eq 2" "id:2,phase:1,pass"
SecRule ARGS_PATH:item "@streq route" "id:3,phase:1,pass,msg:'%{MATCHED_VAR_NAME}'"
SecRule ARGS_PATH:item "@rx ^\xff$" "id:4,phase:1,pass,msg:'%{MATCHED_VAR_NAME}',logdata:'%{MATCHED_VAR}'"
SecRule ARGUMENTS_LIMIT_REACHED "@streq 1" "id:5,phase:1,pass"
SecRule &ARGS_PATH:extra "@eq 0" "id:6,phase:1,pass""#).unwrap();
    let mut tx = engine.new_transaction();
    tx.set_record_rule_messages(true);
    tx.add_path_argument("ITEM", "first");
    tx.add_path_argument_bytes(b"iTem", b"\xff");
    tx.add_path_argument("extra", "over limit");
    tx.process_uri("/route", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2", "3", "4", "5", "6"]);
    let messages = tx.rule_messages();
    assert_eq!(
        messages[2].message.as_deref(),
        Some(b"ARGS_PATH:Item".as_slice())
    );
    assert_eq!(
        messages[3].message.as_deref(),
        Some(b"ARGS_PATH:iTem".as_slice())
    );
    assert_eq!(messages[3].logdata.as_deref(), Some(b"\xff".as_slice()));
}
