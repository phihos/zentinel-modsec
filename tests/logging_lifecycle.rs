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
