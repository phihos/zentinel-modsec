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
