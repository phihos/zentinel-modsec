//! What a match does is worked out once, when the rules load.
//!
//! A rule's `setvar`, `ctl:`, flow and disruptive actions are read from the
//! prepared form on every match, in every transaction. These pin that
//! nothing is used up by a match, that a completed chain still runs the
//! `ctl:` of every link in order and takes its starter's disruptive action,
//! and that a `setvar` leaves the same TX state and the same recorded effect.

use zentinel_modsec::engine::{SetVarChange, SetVarEffect, Transaction};
use zentinel_modsec::variables::Collection;
use zentinel_modsec::ModSecurity;

fn request(engine: &ModSecurity, uri: &str) -> Transaction {
    let mut tx = engine.new_transaction();
    tx.set_record_setvar_effects(true);
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx
}

fn run(rules: &str, uri: &str) -> Transaction {
    let engine = ModSecurity::from_string(rules).expect("rules should load");
    request(&engine, uri)
}

fn tx_var(tx: &Transaction, name: &str) -> String {
    tx.tx()
        .get(name)
        .and_then(|v| v.first().map(|s| s.to_string()))
        .unwrap_or_else(|| "-".to_string())
}

fn effect(rule_id: &str, key: &str, op: SetVarChange) -> SetVarEffect {
    SetVarEffect {
        rule_id: rule_id.to_string(),
        collection: "tx".to_string(),
        key: key.to_string(),
        op,
    }
}

#[test]
fn every_transaction_gets_the_same_actions() {
    let engine = ModSecurity::from_string(
        "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,setvar:'tx.name=abc',setvar:'tx.score=+3',ctl:ruleRemoveById=3,skipAfter:M\"\n\
         SecAction \"id:2,phase:1,pass,nolog\"\n\
         SecMarker M\n\
         SecAction \"id:3,phase:1,pass,nolog\"\n\
         SecRule REQUEST_URI \"@contains old\" \"id:4,phase:2,redirect:https://example.com/new\"",
    )
    .unwrap();
    for _ in 0..3 {
        let tx = request(&engine, "/old");
        assert_eq!(tx.matched_rules(), ["1", "4"]);
        assert_eq!(tx_var(&tx, "name"), "abc");
        assert_eq!(tx_var(&tx, "score"), "3");
        assert_eq!(
            tx.setvar_effects(),
            [
                effect("1", "name", SetVarChange::Set("abc".into())),
                effect("1", "score", SetVarChange::Increment(3)),
            ]
        );
        let intervention = tx.intervention().expect("the redirect intervenes");
        assert_eq!(intervention.url.as_deref(), Some("https://example.com/new"));
    }
}

#[test]
fn a_completed_chain_runs_the_ctl_of_every_link() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains go\" \"id:1,phase:1,pass,nolog,chain,ctl:ruleRemoveById=100\"\n\
        SecRule REQUEST_METHOD \"@streq GET\" \"chain,ctl:ruleRemoveById=101\"\n\
        SecRule REQUEST_PROTOCOL \"@streq HTTP/1.1\" \"ctl:ruleRemoveById=102\"\n\
        SecAction \"id:100,phase:1,pass,nolog\"\n\
        SecAction \"id:101,phase:1,pass,nolog\"\n\
        SecAction \"id:102,phase:1,pass,nolog\"\n\
        SecAction \"id:103,phase:1,pass,nolog\"";
    assert_eq!(run(rules, "/go").matched_rules(), ["1", "103"]);
    // A chain that fails runs none of them, not even the starter's.
    assert_eq!(
        run(rules, "/stop").matched_rules(),
        ["100", "101", "102", "103"]
    );
}

#[test]
fn the_ctl_of_a_chain_runs_starter_first() {
    // ctl:ruleEngine is single-valued, so the later link decides.
    let chain = |first: &str, last: &str| {
        format!(
            "SecRuleEngine On\n\
             SecRule REQUEST_URI \"@contains go\" \"id:1,phase:1,pass,nolog,chain,ctl:ruleEngine={first}\"\n\
             SecRule REQUEST_METHOD \"@streq GET\" \"ctl:ruleEngine={last}\"\n\
             SecAction \"id:2,phase:1,deny\""
        )
    };
    assert!(run(&chain("DetectionOnly", "On"), "/go").has_intervention());
    assert!(!run(&chain("On", "DetectionOnly"), "/go").has_intervention());
}

#[test]
fn a_rules_own_ctl_governs_its_disruptive_action() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains go\" \"id:1,phase:1,deny,ctl:ruleEngine=DetectionOnly\"";
    let tx = run(rules, "/go");
    assert_eq!(tx.matched_rules(), ["1"]);
    assert!(!tx.has_intervention());
}

#[test]
fn a_completed_chain_takes_the_disruptive_action_and_flow_of_its_starter() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains go\" \"id:1,phase:1,deny,chain\"\n\
        SecRule REQUEST_METHOD \"@streq GET\" \"t:none\"\n\
        SecAction \"id:2,phase:1,pass,nolog\"";
    let tx = run(rules, "/go");
    assert_eq!(tx.intervention().map(|i| i.status), Some(403));
    assert_eq!(tx.matched_rules(), ["1"]);

    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains go\" \"id:1,phase:1,pass,nolog,chain,skip:1\"\n\
        SecRule REQUEST_METHOD \"@streq GET\" \"t:none\"\n\
        SecAction \"id:2,phase:1,pass,nolog\"\n\
        SecAction \"id:3,phase:1,pass,nolog\"";
    assert_eq!(run(rules, "/go").matched_rules(), ["1", "3"]);
}

#[test]
fn a_setvar_name_is_recorded_as_written_and_stored_case_insensitively() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@rx (go)\" \"id:1,phase:1,pass,nolog,capture,\
            setvar:'tx.Seen_%{tx.1}=%{tx.0}',setvar:'tx.Total=+2',setvar:'tx.Total=-%{tx.Seen_go}x',\
            setvar:'tx.Gone=1',setvar:'!tx.Gone'\"";
    let tx = run(rules, "/go");
    assert_eq!(tx_var(&tx, "seen_go"), "go");
    assert_eq!(tx_var(&tx, "total"), "2");
    assert_eq!(tx_var(&tx, "gone"), "-");
    assert_eq!(
        tx.setvar_effects(),
        [
            effect("1", "Seen_go", SetVarChange::Set("go".into())),
            effect("1", "Total", SetVarChange::Increment(2)),
            effect("1", "Total", SetVarChange::Decrement(0)),
            effect("1", "Gone", SetVarChange::Set("1".into())),
            effect("1", "Gone", SetVarChange::Delete),
        ]
    );
}

#[test]
fn a_setvar_runs_once_for_every_matched_value() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS \"@rx ^a\" \"id:1,phase:2,pass,nolog,setvar:'tx.hits=+1',setvar:'tx.last=%{MATCHED_VAR}'\"";
    let tx = run(rules, "/?x=a1&y=b2&z=a3");
    assert_eq!(tx_var(&tx, "hits"), "2");
    assert_eq!(tx_var(&tx, "last"), "a3");
}
