use zentinel_modsec::ModSecurity;

fn matches(config: &str) -> Vec<String> {
    let engine = ModSecurity::from_string(config).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/?color=green", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.matched_rules().to_vec()
}

#[test]
fn skip_after_resumes_at_adjacent_marker_and_never_jumps_back() {
    assert_eq!(
        matches(
            r#"
SecAction "id:1,phase:1,pass,skipAfter:NEXT"
SecMarker NEXT
SecAction "id:2,phase:1,pass"
SecAction "id:3,phase:1,pass,skipAfter:NEXT"
SecAction "id:4,phase:1,pass"
"#
        ),
        ["1", "2", "3"]
    );
}

#[test]
fn removed_unconditional_action_never_initializes_tx() {
    assert_eq!(
        matches(
            r#"
SecAction "id:1,phase:1,pass,setvar:tx.note=green"
SecRule TX:note "@streq green" "id:2,phase:1,pass"
SecAction "id:3,phase:1,pass"
SecRuleRemoveById 1
"#
        ),
        ["3"]
    );
}

#[test]
fn id_target_exclusion_applies_to_anonymous_child_only_in_named_chain() {
    assert_eq!(
        matches(
            r#"
SecAction "id:1,phase:1,pass,ctl:ruleRemoveTargetById=2;ARGS:color"
SecRule REQUEST_METHOD "@streq GET" "id:2,phase:1,pass,chain"
SecRule ARGS:color "@streq green" "t:none"
SecRule REQUEST_METHOD "@streq GET" "id:3,phase:1,pass,chain"
SecRule ARGS:color "@streq green" "t:none"
"#
        ),
        ["1", "3"]
    );
}

#[test]
fn within_matches_partial_and_empty_substrings_in_static_and_binary_arguments() {
    use zentinel_modsec::operators::{compile_operator_bytes, create_operator};
    use zentinel_modsec::parser::{OperatorName, OperatorSpec};

    let text = create_operator(OperatorName::Within, "green,blue").unwrap();
    assert!(text.execute("en,bl").matched);
    assert!(text.execute("").matched);
    assert!(!text.execute("Green").matched);
    let spec = OperatorSpec {
        name: OperatorName::Within,
        argument: "%{tx.palette}".into(),
        negated: false,
    };
    let bytes = compile_operator_bytes(&spec, b"green\xffblue").unwrap();
    assert!(bytes.execute_bytes(b"n\xffb").unwrap().matched);
    assert!(bytes.execute_bytes(b"").unwrap().matched);
}

#[test]
fn numeric_operand_observes_previous_match_actions() {
    let engine = ModSecurity::from_string(
        r#"
SecAction "id:1,phase:1,pass,setvar:tx.next=1"
SecRule ARGS:n "@eq %{tx.next}" "id:2,phase:1,pass,setvar:tx.next=+1,msg:'%{tx.next}'"
SecRule TX:next "@eq 3" "id:3,phase:1,pass"
"#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.set_record_rule_messages(true);
    tx.process_uri("/?n=1&n=2", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2", "3"]);
    assert_eq!(
        tx.rule_messages()
            .iter()
            .find(|message| message.rule_id == "2")
            .unwrap()
            .message
            .as_deref(),
        Some(&b"2"[..])
    );
}

#[test]
fn multimatch_rebinds_between_stages_and_retains_only_the_first_log_snapshot() {
    let engine = ModSecurity::from_string(r#"
SecAction "id:1,phase:1,pass,setvar:tx.next=GREEN"
SecRule ARGS:color "@streq %{tx.next}" "id:2,phase:1,pass,multiMatch,t:lowercase,setvar:tx.next=green,setvar:tx.count=+1,msg:'%{MATCHED_VAR}'"
SecRule TX:count "@eq 2" "id:3,phase:1,pass"
"#).unwrap();
    let mut tx = engine.new_transaction();
    tx.set_record_rule_messages(true);
    tx.process_uri("/?color=GREEN", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2", "3"]);
    assert_eq!(
        tx.rule_messages()
            .iter()
            .find(|message| message.rule_id == "2")
            .unwrap()
            .message
            .as_deref(),
        Some(&b"GREEN"[..])
    );
}

#[test]
fn failed_chain_preserves_nondisruptive_controls_but_defers_disruption() {
    assert_eq!(
        matches(
            r#"
SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,deny,chain,ctl:ruleRemoveById=2"
SecRule ARGS:color "@streq blue" "t:none"
SecAction "id:2,phase:1,pass"
SecAction "id:3,phase:1,pass"
"#
        ),
        ["3"]
    );
}

#[test]
fn subsequent_targets_see_setvar_from_an_earlier_target() {
    assert_eq!(
        matches(
            r#"
SecRule ARGS:color|TX:note "@streq green" "id:1,phase:1,pass,setvar:tx.note=green,setvar:tx.count=+1"
SecRule TX:count "@eq 2" "id:2,phase:1,pass"
"#
        ),
        ["1", "2"]
    );
}

#[test]
fn compiled_tag_dispatch_still_depends_on_this_transactions_controls() {
    let engine = ModSecurity::from_string(
        r#"
SecRule REQUEST_METHOD "@streq POST" "id:1,phase:1,pass,ctl:ruleRemoveByTag=method-check,ctl:ruleRemoveTargetByTag=report;ARGS_GET:color"
SecRule REQUEST_METHOD "@rx ." "id:2,phase:2,pass,tag:method-check"
SecRule REQUEST_METHOD "@rx ." "id:3,phase:2,pass,tag:report,chain"
SecRule ARGS_GET:color "@streq green" "t:none"
SecRule ARGS_GET:color "@streq green" "id:4,phase:2,pass,tag:unrelated"
"#,
    )
    .unwrap();
    for (method, expected) in [
        ("GET", vec!["2", "3", "4"]),
        ("POST", vec!["1", "4"]),
        ("GET", vec!["2", "3", "4"]),
    ] {
        let mut tx = engine.new_transaction();
        tx.process_uri("/?color=green", method, "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx.matched_rules(), expected, "{method}");
    }
}

#[test]
fn empty_collections_preserve_counts_negation_and_chain_effects() {
    let engine = ModSecurity::from_string(
        r#"
SecRule ARGS "!@streq unused" "id:1,phase:1,pass"
SecRule &ARGS "@eq 0" "id:2,phase:1,pass,setvar:tx.note=blue"
SecRule TX:note "@streq blue" "id:3,phase:1,pass,chain,setvar:tx.collected=yes"
SecRule REQUEST_COOKIES "!@streq unused" "t:none"
SecRule ARGS|TX:collected "@streq yes" "id:4,phase:1,pass"
SecRule REQUEST_COOKIES|ARGS:present "@streq " "id:5,phase:1,pass"
"#,
    )
    .unwrap();
    for (uri, expected) in [("/", vec!["2", "4"]), ("/?present=", vec!["1", "5"])] {
        let mut tx = engine.new_transaction();
        tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules(), expected);
    }
}

#[test]
fn phase_body_targets_and_tag_removal_counts_follow_the_current_request() {
    let config = r#"
SecRequestBodyAccess On
SecAction "id:1,phase:1,pass,ctl:ruleRemoveTargetByTag=fields;ARGS_POST:city"
SecRule REQUEST_HEADERS:X-Skip "@streq all" "id:2,phase:1,pass,ctl:ruleRemoveTargetByTag=fields;ARGS_POST"
SecRule &ARGS_POST "@eq 0" "id:3,phase:2,pass,tag:fields"
SecRule &ARGS_POST "@eq 1" "id:4,phase:2,pass,tag:fields"
SecRule ARGS_POST:city "@streq Paris" "id:5,phase:2,pass,tag:other"
SecRule ARGS_POST:name "@streq alex" "id:6,phase:2,pass,tag:fields"
"#;
    let engine = ModSecurity::from_string(config).unwrap();
    for (skip, expected) in [
        ("one", vec!["1", "4", "5", "6"]),
        ("all", vec!["1", "2", "3", "5"]),
    ] {
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
            .unwrap();
        tx.add_request_header("X-Skip", skip).unwrap();
        tx.process_request_headers().unwrap();
        tx.append_request_body(b"city=Paris&name=alex").unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx.matched_rules(), expected);
    }
}
