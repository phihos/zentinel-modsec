use zentinel_modsec::variables::Collection;
use zentinel_modsec::ModSecurity;

#[test]
fn exact_crs_payloads_match_before_destructive_transformations() {
    let engine = ModSecurity::from_string(include_str!("fixtures/crs-multimatch.conf")).unwrap();
    for (uri, id) in [
        (r"/get?arg=..\\pineapple", "930110"),
        (r"/get?a=..;.\.;\.", "930110"),
        ("/get?foo=new+Function+%28", "934100"),
        ("/get?eval=while(!%2B0);", "934160"),
        (
            "/get?test=9999+or+%2F*%2Boptimizer+hint+*%2F+true",
            "942500",
        ),
        (
            "/get?test=9999+or+%2F*+%2Boptimizer+hint+*%2F+true",
            "942500",
        ),
    ] {
        let mut tx = engine.new_transaction();
        tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        assert!(
            tx.matched_rules().iter().any(|actual| actual == id),
            "{uri}: missing {id}"
        );
    }
    let mut tx = engine.new_transaction();
    tx.process_uri("/post", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "multipart/form-data; boundary=B")
        .unwrap();
    tx.append_request_body(b"--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"..\\\\1.7z\"\r\n\r\nBINARYDATA\r\n--B--\r\n").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert!(tx.matched_rules().iter().any(|id| id == "930110"));
}

#[test]
fn changed_stages_run_actions_once_each_and_preserve_captures() {
    let engine = ModSecurity::from_string(r#"SecRuleEngine DetectionOnly
SecRule ARGS:x "@rx (?i)(a)" "id:10,phase:2,pass,multiMatch,t:none,t:lowercase,t:uppercase,t:uppercase,capture,setvar:tx.score=+5""#).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/?x=a", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["10"]);
    assert_eq!(tx.tx().get("score"), Some(vec!["10"]));
    assert_eq!(tx.tx().get("0"), Some(vec!["A"]));
    assert_eq!(tx.tx().get("1"), Some(vec!["A"]));
}

#[test]
fn negation_applies_independently_to_each_stage_and_absence_is_not_a_value() {
    let engine = ModSecurity::from_string(r#"SecRuleEngine DetectionOnly
SecRule ARGS:x "!@contains X" "id:10,phase:2,pass,multiMatch,t:uppercase,setvar:tx.score=+1"
SecRule ARGS:absent "!@contains X" "id:11,phase:2,pass,multiMatch,t:uppercase,setvar:tx.score=+100""#).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/?x=x", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["10"]);
    assert_eq!(tx.tx().get("score"), Some(vec!["1"]));
}

#[test]
fn chain_children_see_all_matching_stages_and_failed_chains_keep_only_local_effects() {
    for (child, expected_score, matched) in [("A", "17", true), ("nope", "10", false)] {
        let engine = ModSecurity::from_string(&format!(r#"SecRuleEngine DetectionOnly
SecRule ARGS:x "@rx (?i)(a)" "id:10,phase:2,pass,multiMatch,t:uppercase,capture,setvar:tx.score=+5,chain"
SecRule MATCHED_VARS "@streq {child}" "t:none,setvar:tx.score=+7""#)).unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/?x=a", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx.matched_rules().iter().any(|id| id == "10"), matched);
        assert_eq!(tx.tx().get("score"), Some(vec![expected_score]));
        assert_eq!(tx.matched_data().is_empty(), !matched);
    }
}

#[test]
fn returning_to_an_earlier_value_after_a_change_is_another_evaluation() {
    let engine = ModSecurity::from_string(r#"SecRuleEngine DetectionOnly
SecRule ARGS:x "@streq a" "id:10,phase:2,pass,multiMatch,t:uppercase,t:lowercase,setvar:tx.score=+1""#).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/?x=a", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.tx().get("score"), Some(vec!["2"]));
}

#[test]
fn multi_match_does_not_overwrite_an_earlier_skip_after_action() {
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule ARGS:x "@streq a" "id:10,phase:2,pass,skipAfter:END,multiMatch"
SecRule ARGS:x "@streq a" "id:11,phase:2,pass"
SecMarker END
SecRule ARGS:x "@streq a" "id:12,phase:2,pass""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/?x=a", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["10", "12"]);
}
