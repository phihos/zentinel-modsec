//! Pinned Coraza 3.8.1 phase-5 behavior, including disruptive actions and retries.
use zentinel_modsec::{engine::phase::Phase, variables::Collection, ModSecurity};

#[test]
fn logging_runs_after_denial_can_replace_status_and_continues_after_denial() {
    for initial in ["redirect:https://initial.example.test/", "pass"] {
        let engine = ModSecurity::from_string(&format!(
            r#"SecRuleEngine On
SecAction "id:1,phase:1,{initial}"
SecAction "id:2,phase:5,pass,setvar:tx.runs=+1"
SecAction "id:3,phase:5,deny,setvar:tx.denies=+1"
SecAction "id:4,phase:5,pass,setvar:tx.last=+1""#
        ))
        .unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        for (runs, ids) in [
            ("1", vec!["1", "2", "3", "4"]),
            ("2", vec!["1", "2", "3", "4", "2", "3", "4"]),
        ] {
            tx.process_logging().unwrap();
            assert_eq!(tx.matched_rules(), ids);
            assert_eq!(tx.tx().get("runs"), Some(vec![runs]));
            assert_eq!(tx.tx().get("denies"), Some(vec![runs]));
            assert_eq!(tx.tx().get("last"), Some(vec![runs]));
            let intervention = tx.intervention().unwrap();
            assert_eq!(intervention.status, 403);
            assert_eq!(intervention.phase, Phase::Logging);
            assert_eq!(intervention.rule_ids, ["3"]);
        }
    }
}

#[test]
fn allow_suppresses_logging_but_detection_only_still_records_without_disruption() {
    for (mode, action, ids) in [
        ("On", "allow", vec!["1"]),
        ("DetectionOnly", "deny,status:418", vec!["1", "2", "3"]),
    ] {
        let engine = ModSecurity::from_string(&format!(
            r#"SecRuleEngine {mode}
SecAction "id:1,phase:1,{action}"
SecAction "id:2,phase:5,deny,status:409"
SecAction "id:3,phase:5,pass""#
        ))
        .unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_logging().unwrap();
        assert_eq!(tx.matched_rules(), ids);
        assert!(tx.intervention().is_none());
    }
}

#[test]
fn every_disruptive_logging_outcome_permits_later_logging_rules() {
    for (action, status) in [
        ("block", 403),
        ("drop", 0),
        ("redirect:https://example.test/", 302),
    ] {
        let engine = ModSecurity::from_string(&format!(
            r#"SecRuleEngine On
SecAction "id:1,phase:1,deny,status:418"
SecAction "id:2,phase:5,{action}"
SecAction "id:3,phase:5,pass""#
        ))
        .unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_logging().unwrap();
        assert_eq!(tx.matched_rules(), ["1", "2", "3"]);
        assert_eq!(tx.intervention().unwrap().status, status);
    }
}

#[test]
fn allow_resumes_at_the_phase_selected_by_its_scope() {
    let all_phases = "1 10 20 30 40 50 50";
    let cases = [
        ("On", "allow", 1, "1"),
        ("On", "allow:phase", 1, "1 20 30 40 50 50"),
        ("On", "allow:request", 1, "1 30 40 50 50"),
        ("On", "allow:request", 2, "10 1 30 40 50 50"),
        ("On", "allow:request", 3, "10 20 1 30 40 50 50"),
        ("On", "allow:request", 5, "10 20 30 40 1 50 1 50"),
        ("On", "allow:phase", 5, "10 20 30 40 1 1"),
        ("On", "allow", 5, "10 20 30 40 1"),
        ("DetectionOnly", "allow", 1, all_phases),
        ("DetectionOnly", "allow:phase", 1, all_phases),
        ("DetectionOnly", "allow:request", 1, all_phases),
    ];
    for (mode, action, phase, expected) in cases {
        let engine = ModSecurity::from_string(&format!(
            r#"SecRuleEngine {mode}
SecAction "id:1,phase:{phase},{action},setvar:tx.runs=+1"
SecAction "id:10,phase:1,pass"
SecAction "id:20,phase:2,pass"
SecAction "id:30,phase:3,pass"
SecAction "id:40,phase:4,pass"
SecAction "id:50,phase:5,pass""#
        ))
        .unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/catalog", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        tx.process_response_headers_with_status(200, "HTTP/1.1")
            .unwrap();
        tx.process_response_body().unwrap();
        tx.process_logging().unwrap();
        tx.process_logging().unwrap();
        assert_eq!(
            tx.matched_rules().join(" "),
            expected,
            "{mode} {action} in phase {phase}"
        );
        assert!(tx.intervention().is_none());
        let count = expected
            .split_whitespace()
            .filter(|&id| id == "1")
            .count()
            .to_string();
        assert_eq!(tx.tx().get("runs"), Some(vec![count.as_str()]));
    }
}

#[test]
fn allow_request_waits_for_a_complete_chain_and_is_transaction_local() {
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine On
SecRule REQUEST_URI "@streq /catalog" "id:1,phase:1,allow:request,chain"
SecRule REQUEST_METHOD "@streq GET" "setvar:tx.seen=yes"
SecAction "id:2,phase:1,pass"
SecAction "id:3,phase:2,pass"
SecAction "id:4,phase:3,pass""#,
    )
    .unwrap();
    for (method, ids) in [("GET", vec!["1", "4"]), ("POST", vec!["2", "3", "4"])] {
        let mut tx = engine.new_transaction();
        tx.process_uri("/catalog", method, "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        tx.process_response_headers_with_status(200, "HTTP/1.1")
            .unwrap();
        assert_eq!(tx.matched_rules(), ids);
    }
}
