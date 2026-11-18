//! A chain that fails part-way did not match: it must leave nothing in
//! `matched_rules()` or `matched_data()` (zentinelproxy/zentinel-modsec#59).

use zentinel_modsec::ModSecurity;

/// The shape of CRS 920170: a GET without a body must not report the rule.
const RULE_920170: &str = "SecRuleEngine On\n\
    SecRule REQUEST_METHOD \"@rx ^(?:GET|HEAD)$\" \"id:920170,phase:1,block,chain\"\n\
    SecRule REQUEST_HEADERS:Content-Length \"!@rx ^0?$\" \"setvar:'tx.score=+5'\"";

fn run(rules: &str, headers: &[(&str, &str)]) -> zentinel_modsec::engine::Transaction {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(
        "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "GET",
        "HTTP/1.1",
    )
    .unwrap();
    tx.add_request_header("host", "example.com").unwrap();
    for (name, value) in headers {
        tx.add_request_header(name, value).unwrap();
    }
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx
}

#[test]
fn an_incomplete_chain_is_not_in_matched_rules() {
    let tx = run(RULE_920170, &[]);
    assert!(tx.matched_rules().is_empty(), "{:?}", tx.matched_rules());
}

#[test]
fn an_incomplete_chain_leaves_no_matched_data() {
    let tx = run(RULE_920170, &[]);
    assert!(tx.matched_data().is_empty(), "{:?}", tx.matched_data());
}

#[test]
fn a_complete_chain_reports_every_link_under_the_starters_id() {
    let tx = run(RULE_920170, &[("content-length", "12")]);
    assert_eq!(tx.matched_rules(), ["920170"]);
    let data = tx.matched_data();
    assert_eq!(data.len(), 2, "{data:?}");
    assert!(data.iter().all(|d| d.rule_id.as_deref() == Some("920170")));
    assert_eq!(data[0].variable, "REQUEST_METHOD");
    assert_eq!(data[0].value, "GET");
    assert_eq!(data[1].value, "12");
}

#[test]
fn a_failed_chain_does_not_hide_a_later_rules_data() {
    let rules = format!(
        "{RULE_920170}\n\
         SecRule REQUEST_METHOD \"@streq GET\" \"id:2,phase:1,pass\""
    );
    let tx = run(&rules, &[]);
    assert_eq!(tx.matched_rules(), ["2"]);
    let data = tx.matched_data();
    assert_eq!(data.len(), 1, "{data:?}");
    assert_eq!(data[0].rule_id.as_deref(), Some("2"));
}

#[test]
fn a_three_link_chain_failing_on_the_last_link_leaves_nothing() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_METHOD \"@streq GET\" \"id:3,phase:1,pass,chain\"\n\
        SecRule REQUEST_HEADERS:Host \"@streq example.com\" \"chain\"\n\
        SecRule REQUEST_URI \"@contains nothing-here\"";
    let tx = run(rules, &[]);
    assert!(tx.matched_rules().is_empty());
    assert!(tx.matched_data().is_empty(), "{:?}", tx.matched_data());
}

#[test]
fn concurrent_phase_reads_preserve_starter_link_and_anonymous_ids() {
    let engine = ModSecurity::from_string(
        r#"
SecRule REQUEST_METHOD "@streq GET" "id:0007,phase:1,pass,chain"
SecRule REQUEST_URI "@streq /" "t:none"
SecRule REQUEST_METHOD "@streq GET" "phase:1,pass"
SecRule REQUEST_METHOD "@streq GET" "id:099,phase:2,pass"
"#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| {
                assert_eq!(tx.matched_rules(), ["7"]);
                let ids: Vec<_> = tx
                    .matched_data()
                    .iter()
                    .map(|d| d.rule_id.as_deref())
                    .collect();
                assert_eq!(ids, [Some("7"), Some("7"), None]);
            });
        }
    });
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["7", "99"]);
    assert_eq!(
        tx.matched_data().last().unwrap().rule_id.as_deref(),
        Some("99")
    );
}

#[test]
fn selected_fields_span_a_completed_chain_and_keep_the_first_audit_value_per_link() {
    let engine = ModSecurity::from_string(
        r#"
SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,pass,chain"
SecRule REQUEST_URI "@streq /missing" "t:none"
SecRule ARGS:a|ARGS:b "@streq green" "id:2,phase:1,pass,chain"
SecRule ARGS:b|ARGS:c|ARGS:d "@streq green" "t:none"
"#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.record_matched_fields(3, |name| Some(name));
    tx.process_uri("/?a=green&b=green&c=green&d=green", "GET", "HTTP/1.1")
        .unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(
        tx.matched_fields().collect::<Vec<_>>(),
        [
            (Some("2"), "ARGS:a"),
            (Some("2"), "ARGS:b"),
            (Some("2"), "ARGS:c")
        ]
    );
    assert_eq!(
        tx.matched_data()
            .iter()
            .map(|m| m.variable.as_str())
            .collect::<Vec<_>>(),
        ["ARGS:a", "ARGS:b"]
    );
}

#[test]
fn tagged_markers_update_the_scalar_only_when_executed() {
    assert_header_denials(&[
        (
            r#"SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,pass,skipAfter:SAME"
SecMarker SAME
SecRule REQUEST_METHOD "@streq GET" "id:2,phase:1,deny"
SecMarker SAME"#,
            "2",
        ),
        (
            r#"SecAction "id:1,phase:1,pass,setvar:tx.a=1,setvar:tx.b=1,setvar:tx.c=1,setvar:tx.d=1,setvar:tx.e=1,setvar:tx.f=1,setvar:tx.g=1,setvar:tx.h=1"
SecMarker MIDDLE
SecRule &TX:a "@eq 1" "id:2,phase:1,pass,setvar:tx.z=1"
SecRule MATCHED_VAR_NAME "@streq TX:a" "id:3,phase:1,deny""#,
            "3",
        ),
        (
            r#"SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,pass"
SecRule REQUEST_HEADERS:Missing "@streq green" "id:2,phase:1,pass"
SecMarker BETWEEN
SecRule REQUEST_HEADERS:Missing "@streq blue" "id:3,phase:1,pass"
SecRule MATCHED_VAR_NAME "@streq UNKNOWN" "id:4,phase:1,deny""#,
            "4",
        ),
        (
            r#"SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,pass"
SecMarker MARK
SecRule MATCHED_VAR_NAME "@streq UNKNOWN" "id:2,phase:1,deny""#,
            "2",
        ),
        (
            r#"SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,pass,skipAfter:MARK"
SecMarker BEFORE
SecMarker MARK
SecRule MATCHED_VAR_NAME "@streq REQUEST_METHOD" "id:2,phase:1,deny""#,
            "2",
        ),
        (
            r#"SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,pass,skipAfter:MARK"
SecMarker MARK
SecMarker AFTER
SecRule MATCHED_VAR_NAME "@streq UNKNOWN" "id:2,phase:1,deny""#,
            "2",
        ),
        (
            r#"SecRule REQUEST_METHOD "@streq GET" "id:9,phase:1,deny,chain"
SecMarker MARK
SecRule REQUEST_URI "@streq /missing" "t:none""#,
            "9",
        ),
    ]);
}

#[test]
fn multiphase_matches_coraza_rule_and_chain_field_lifetimes() {
    assert_header_denials(&[
        (
            r#"SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,pass"
SecRule &MATCHED_VARS "@eq 0" "id:2,phase:1,deny""#,
            "2",
        ),
        (
            r#"SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,pass"
SecRule REQUEST_URI "@streq /missing" "id:2,phase:1,pass"
SecRule MATCHED_VAR "@streq GET" "id:3,phase:1,deny""#,
            "3",
        ),
        (
            r#"SecRule REQUEST_METHOD "@streq GET" "id:3,phase:1,deny,chain"
SecRule REQUEST_URI "@streq /home" "chain"
SecRule MATCHED_VARS:REQUEST_METHOD "@streq GET" "t:none""#,
            "3",
        ),
        (
            r#"SecAction "id:4,phase:1,pass,setvar:'tx.name=%{MATCHED_VAR_NAME}'"
SecRule TX:name "@streq UNKNOWN" "id:5,phase:1,deny""#,
            "5",
        ),
        (
            r#"SecRule MATCHED_VAR_NAME "@rx ^$" "id:7,phase:1,deny""#,
            "7",
        ),
    ]);
}

fn assert_header_denials(cases: &[(&str, &str)]) {
    for &(rules, id) in cases {
        let mut tx = tagged_request(rules);
        tx.process_request_headers().unwrap();
        assert!(!tx.matched_rules().iter().any(|id| id == "0"));
        assert_eq!(
            tx.intervention().map(|i| &i.rule_ids[..]),
            Some([id.to_owned()].as_slice()),
            "{rules}"
        );
    }
}

fn tagged_request(rules: &str) -> zentinel_modsec::Transaction {
    let mut parser = zentinel_modsec::parser::Parser::new();
    parser.parse(&format!("SecRuleEngine On\n{rules}")).unwrap();
    let ruleset =
        zentinel_modsec::CompiledRuleset::compile_multiphase(parser.into_directives()).unwrap();
    let mut tx = zentinel_modsec::Transaction::new(ruleset.into(), 403);
    tx.process_uri("/home", "GET", "HTTP/1.1").unwrap();
    tx
}

#[test]
fn a_trailing_marker_updates_the_scalar_for_the_next_phase() {
    let mut tx = tagged_request(
        r#"SecRule MATCHED_VAR_NAME "@streq UNKNOWN" "id:2,phase:2,deny"
SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,pass"
SecMarker TRAIL"#,
    );
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["1"]);
    tx.process_request_body().unwrap();
    assert_eq!(tx.intervention().unwrap().rule_ids, ["2"]);
    assert_eq!(tx.matched_rules(), ["1", "2"]);
}
