//! An operator argument expanded from the request that does not compile must
//! not stop the phase: the rule does not match, negated or not, and later
//! rules still run, as in ModSecurity v3 (operators/rx.cc, #3123).

use zentinel_modsec::ModSecurity;

fn run(pattern_header: &str) -> (bool, Vec<String>) {
    let modsec = ModSecurity::from_string(RULES).expect("rules load");
    let mut tx = modsec.new_transaction();
    tx.process_uri("/?a=attack", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header("X-Pattern", pattern_header).unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body()
        .expect("an expanded argument that does not compile must not end the phase");
    (tx.intervention().is_some(), tx.matched_rules().to_vec())
}

const RULES: &str = r#"
SecRuleEngine On
SecRule ARGS:a "@rx %{request_headers.x-pattern}" "id:1,phase:2,pass,log"
SecRule ARGS:a "!@rx %{request_headers.x-pattern}" "id:2,phase:2,pass,log"
SecRule ARGS:a "@streq attack" "id:3,phase:2,deny,status:403"
"#;

#[test]
fn an_invalid_expanded_pattern_matches_neither_form_and_later_rules_run() {
    let (blocked, matched) = run("(");
    assert!(blocked, "rule 3 must still run and deny: {matched:?}");
    assert!(
        !matched.contains(&"1".to_string()),
        "@rx must not match: {matched:?}"
    );
    assert!(
        !matched.contains(&"2".to_string()),
        "!@rx must not match either: {matched:?}"
    );
}

#[test]
fn a_valid_expanded_pattern_still_matches() {
    let (blocked, matched) = run("att");
    assert!(blocked, "{matched:?}");
    assert!(matched.contains(&"1".to_string()), "{matched:?}");
    assert!(!matched.contains(&"2".to_string()), "{matched:?}");
}
