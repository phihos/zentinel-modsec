//! What a transaction keeps of the matches it saw: the matched rules, the
//! variable and value each one matched on, `MATCHED_VAR` and its relatives
//! for the rules that follow, captures, and rule messages.

use zentinel_modsec::engine::transaction::{MatchedData, Transaction};
use zentinel_modsec::ModSecurity;

fn transaction(rules: &str, uri: &str) -> Transaction {
    let engine = ModSecurity::from_string(rules).expect("rules load");
    let mut tx = engine.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "shop.example").unwrap();
    tx
}

fn run(rules: &str, uri: &str) -> Transaction {
    let mut tx = transaction(rules, uri);
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx
}

fn entry(rule_id: &str, variable: &str, value: &str, portion: Option<&str>) -> MatchedData {
    MatchedData {
        rule_id: Some(rule_id.to_string()),
        variable: variable.to_string(),
        value: value.to_string(),
        matched_portion: portion.map(str::to_string),
    }
}

fn tx_value(tx: &Transaction, key: &str) -> Option<String> {
    use zentinel_modsec::variables::Collection;
    tx.tx()
        .get(key)
        .and_then(|v| v.first().map(|s| s.to_string()))
}

#[test]
fn each_matching_rule_leaves_its_first_match_in_order() {
    let tx = run(
        r#"
        SecRuleEngine On
        SecRule ARGS "@contains a" "id:1,phase:1,pass,nolog"
        SecRule REQUEST_METHOD "@streq GET" "id:2,phase:1,pass,nolog"
        SecRule ARGS:c "@rx ^(x)(y)$" "id:3,phase:2,pass,nolog"
        SecRule ARGS:b "@streq nothing" "id:4,phase:2,pass,nolog"
        SecRule &ARGS "@eq 3" "id:5,phase:2,pass,nolog"
        "#,
        "/?a=banana&b=avocado&c=xy",
    );
    assert_eq!(tx.matched_rules(), ["1", "2", "3", "5"]);
    assert_eq!(
        tx.matched_data(),
        [
            entry("1", "ARGS:a", "banana", Some("a")),
            entry("2", "REQUEST_METHOD", "GET", Some("GET")),
            entry("3", "ARGS:c", "xy", Some("xy")),
            entry("5", "&Args", "3", Some("3")),
        ]
    );
}

#[test]
fn a_completed_chain_reports_every_link_and_a_failed_one_nothing() {
    let tx = run(
        r#"
        SecRuleEngine On
        SecRule ARGS:a "@streq one" "id:1,phase:2,pass,nolog"
        SecRule ARGS:a "@streq one" "id:2,phase:2,pass,nolog,chain"
            SecRule ARGS:b "@streq two" "chain"
            SecRule ARGS:c "@streq nope"
        SecRule ARGS:b "@streq two" "id:3,phase:2,pass,nolog,chain"
            SecRule ARGS:c "@streq three" "chain"
            SecRule ARGS:a "@contains n"
        SecRule ARGS:c "@streq three" "id:4,phase:2,pass,nolog"
        "#,
        "/?a=one&b=two&c=three",
    );
    assert_eq!(tx.matched_rules(), ["1", "3", "4"]);
    assert_eq!(
        tx.matched_data(),
        [
            entry("1", "ARGS:a", "one", Some("one")),
            entry("3", "ARGS:b", "two", Some("two")),
            entry("3", "ARGS:c", "three", Some("three")),
            entry("3", "ARGS:a", "one", Some("n")),
            entry("4", "ARGS:c", "three", Some("three")),
        ]
    );
}

#[test]
fn matched_vars_hold_every_value_of_the_rule_before() {
    let tx = run(
        r#"
        SecRuleEngine On
        SecRule ARGS "@contains a" "id:1,phase:2,pass,nolog"
        SecRule &MATCHED_VARS "@eq 2" "id:2,phase:2,pass,nolog"
        SecRule ARGS "@contains a" "id:3,phase:2,pass,nolog"
        SecRule MATCHED_VARS_NAMES "@streq ARGS:b" "id:4,phase:2,pass,nolog,setvar:tx.name=%{MATCHED_VAR}"
        SecRule ARGS "@contains a" "id:5,phase:2,pass,nolog"
        SecRule MATCHED_VAR "@streq avocado" "id:6,phase:2,pass,nolog,setvar:tx.last=%{MATCHED_VAR_NAME}"
        SecRule ARGS "@contains a" "id:7,phase:2,pass,nolog"
        SecRule MATCHED_VARS "@contains a" "id:8,phase:2,pass,nolog"
        "#,
        "/?a=banana&b=avocado&c=xy",
    );
    assert_eq!(tx.matched_rules(), ["1", "2", "3", "4", "5", "6", "7", "8"]);
    assert_eq!(tx_value(&tx, "name").as_deref(), Some("ARGS:b"));
    assert_eq!(tx_value(&tx, "last").as_deref(), Some("MATCHED_VAR"));
    // The record keeps the first value of each rule.
    assert_eq!(
        tx.matched_data(),
        [
            entry("1", "ARGS:a", "banana", Some("a")),
            entry("2", "&MatchedVars", "2", Some("2")),
            entry("3", "ARGS:a", "banana", Some("a")),
            entry("4", "MATCHED_VARS_NAMES:ARGS:b", "ARGS:b", Some("ARGS:b")),
            entry("5", "ARGS:a", "banana", Some("a")),
            entry("6", "MATCHED_VAR", "avocado", Some("avocado")),
            entry("7", "ARGS:a", "banana", Some("a")),
            entry("8", "MATCHED_VARS:ARGS:a", "banana", Some("a")),
        ]
    );
}

#[test]
fn a_rule_without_targets_clears_the_matched_variables() {
    let tx = run(
        r#"
        SecRuleEngine On
        SecRule ARGS:a "@streq one" "id:1,phase:2,pass,nolog"
        SecAction "id:2,phase:2,pass,nolog"
        SecRule &MATCHED_VARS "@eq 0" "id:3,phase:2,pass,nolog"
        SecRule MATCHED_VAR "@rx ." "id:4,phase:2,pass,nolog"
        "#,
        "/?a=one",
    );
    assert_eq!(tx.matched_rules(), ["1", "2", "3", "4"]);
    assert_eq!(
        tx.matched_data(),
        [
            entry("1", "ARGS:a", "one", Some("one")),
            entry("3", "&MatchedVars", "0", Some("0")),
            entry("4", "MATCHED_VAR", "0", Some("0")),
        ]
    );
}

#[test]
fn a_failed_chain_leaves_its_last_matching_link_as_the_matched_variable() {
    let tx = run(
        r#"
        SecRuleEngine On
        SecRule ARGS:a "@streq one" "id:1,phase:2,pass,nolog"
        SecRule ARGS:b "@streq two" "id:2,phase:2,pass,nolog,chain"
            SecRule ARGS:a "@streq nope"
        SecRule MATCHED_VAR "@streq two" "id:3,phase:2,pass,nolog,setvar:tx.name=%{MATCHED_VAR_NAME}"
        "#,
        "/?a=one&b=two",
    );
    assert_eq!(tx.matched_rules(), ["1", "3"]);
    assert_eq!(tx_value(&tx, "name").as_deref(), Some("MATCHED_VAR"));
    assert_eq!(
        tx.matched_data(),
        [
            entry("1", "ARGS:a", "one", Some("one")),
            entry("3", "MATCHED_VAR", "two", Some("two")),
        ]
    );
}

#[test]
fn the_records_can_be_read_between_phases_and_again() {
    let mut tx = transaction(
        r#"
        SecRuleEngine On
        SecRule ARGS "@contains a" "id:1,phase:1,pass,nolog"
        SecRule MATCHED_VAR "@streq avocado" "id:2,phase:2,pass,nolog"
        SecRule &MATCHED_VARS "@eq 1" "id:3,phase:2,pass,nolog"
        SecRule ARGS:a "@streq banana" "id:4,phase:5,pass,nolog"
        "#,
        "/?a=banana&b=avocado",
    );
    tx.process_request_headers().unwrap();
    let first = [entry("1", "ARGS:a", "banana", Some("a"))];
    assert_eq!(tx.matched_rules(), ["1"]);
    assert_eq!(tx.matched_data(), first);
    assert_eq!(tx.matched_data(), first);

    // The last value phase 1 matched is still MATCHED_VAR in phase 2.
    tx.process_request_body().unwrap();
    let second = [
        entry("1", "ARGS:a", "banana", Some("a")),
        entry("2", "MATCHED_VAR", "avocado", Some("avocado")),
        entry("3", "&MatchedVars", "1", Some("1")),
    ];
    assert_eq!(tx.matched_rules(), ["1", "2", "3"]);
    assert_eq!(tx.matched_data(), second);

    tx.process_logging().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2", "3", "4"]);
    assert_eq!(tx.matched_data()[..3], second);
    assert_eq!(
        tx.matched_data()[3],
        entry("4", "ARGS:a", "banana", Some("banana"))
    );
    assert_eq!(tx.matched_data().len(), 4);
}

#[test]
fn a_phase_that_ends_early_keeps_the_record_of_the_rule_that_ended_it() {
    let tx = run(
        r#"
        SecRuleEngine On
        SecRule ARGS:a "@streq one" "id:1,phase:2,pass,nolog"
        SecRule ARGS "@contains t" "id:2,phase:2,deny,status:403,msg:'saw %{MATCHED_VAR}',logdata:'%{MATCHED_VAR_NAME}'"
        SecRule ARGS:a "@streq one" "id:3,phase:2,pass,nolog"
        "#,
        "/?a=one&b=two&c=three",
    );
    assert_eq!(tx.matched_rules(), ["1", "2"]);
    assert_eq!(
        tx.matched_data(),
        [
            entry("1", "ARGS:a", "one", Some("one")),
            entry("2", "ARGS:b", "two", Some("t")),
        ]
    );
    // The message is written once every value was seen, so it names the last.
    let message = &tx.messages()[0];
    assert_eq!(message.rule_id.as_deref(), Some("2"));
    assert_eq!(message.msg.as_deref(), Some("saw three"));
    assert_eq!(message.data.as_deref(), Some("ARGS:c"));
    let metadata = &tx.intervention().expect("denied").metadata[0];
    assert_eq!(metadata.msg.as_deref(), Some("saw three"));
    assert_eq!(metadata.logdata.as_deref(), Some("ARGS:c"));
}

#[test]
fn an_allow_keeps_the_record_of_the_rule_that_allowed() {
    let tx = run(
        r#"
        SecRuleEngine On
        SecRule ARGS:a "@streq one" "id:1,phase:1,allow,nolog"
        SecRule ARGS:a "@streq one" "id:2,phase:2,pass,nolog"
        "#,
        "/?a=one",
    );
    assert_eq!(tx.matched_rules(), ["1"]);
    assert_eq!(
        tx.matched_data(),
        [entry("1", "ARGS:a", "one", Some("one"))]
    );
}

#[test]
fn captures_are_those_of_the_last_value_and_reach_the_next_link() {
    let tx = run(
        r#"
        SecRuleEngine On
        SecRule ARGS "@rx ^(\w)(\w+)$" "id:1,phase:2,pass,capture,msg:'whole %{TX.0}',logdata:'%{TX.1}-%{TX.2}',chain"
            SecRule TX:1 "@streq a" "setvar:tx.rest=%{TX.2}"
        "#,
        "/?a=banana&b=avocado",
    );
    assert_eq!(tx.matched_rules(), ["1"]);
    assert_eq!(tx_value(&tx, "rest").as_deref(), Some("vocado"));
    assert_eq!(
        tx.matched_data(),
        [
            entry("1", "ARGS:a", "banana", Some("banana")),
            entry("1", "TX:1", "a", Some("a")),
        ]
    );
    let message = &tx.messages()[0];
    assert_eq!(message.msg.as_deref(), Some("whole avocado"));
    assert_eq!(message.data.as_deref(), Some("a-vocado"));
}

#[test]
fn a_rule_that_logs_leaves_a_message_with_its_metadata() {
    let tx = run(
        r#"
        SecRuleEngine On
        SecRule ARGS:a "@streq one" "id:1,phase:2,pass,rev:'2',ver:'v1',severity:'CRITICAL',tag:'x',tag:'y',msg:'plain',logdata:'%{MATCHED_VAR}'"
        SecRule ARGS:a "@streq one" "id:2,phase:2,pass,nolog,msg:'silent'"
        SecRule ARGS:a "@streq one" "id:3,phase:2,pass"
        "#,
        "/?a=one",
    );
    let messages = tx.messages();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].rule_id.as_deref(), Some("1"));
    assert_eq!(messages[0].rev.as_deref(), Some("2"));
    assert_eq!(messages[0].ver.as_deref(), Some("v1"));
    assert_eq!(messages[0].msg.as_deref(), Some("plain"));
    assert_eq!(messages[0].data.as_deref(), Some("one"));
    assert_eq!(messages[0].tags, ["x", "y"]);
    assert_eq!(messages[1].rule_id.as_deref(), Some("3"));
    assert_eq!(messages[1].msg, None);
}

#[test]
fn a_chain_that_denies_reports_its_links_and_the_message_of_its_starter() {
    let tx = run(
        r#"
        SecRuleEngine On
        SecRule ARGS:a "@streq one" "id:1,phase:2,pass,nolog"
        SecRule ARGS:b "@streq two" "id:2,phase:2,deny,status:403,msg:'chain saw %{MATCHED_VAR}',chain"
            SecRule ARGS "@contains e"
        "#,
        "/?a=one&b=two&c=three",
    );
    assert_eq!(tx.matched_rules(), ["1", "2"]);
    assert_eq!(
        tx.matched_data(),
        [
            entry("1", "ARGS:a", "one", Some("one")),
            entry("2", "ARGS:b", "two", Some("two")),
            entry("2", "ARGS:a", "one", Some("e")),
        ]
    );
    assert_eq!(tx.messages()[0].msg.as_deref(), Some("chain saw three"));
    let metadata = &tx.intervention().expect("denied").metadata[0];
    assert_eq!(metadata.msg.as_deref(), Some("chain saw three"));
}

#[test]
fn a_chain_removed_for_the_transaction_leaves_the_records_around_it_whole() {
    let tx = run(
        r#"
        SecRuleEngine On
        SecRule ARGS:a "@streq one" "id:1,phase:2,pass,nolog,ctl:ruleRemoveById=2"
        SecRule ARGS:b "@streq two" "id:2,phase:2,pass,nolog,chain"
            SecRule ARGS:c "@streq three"
        SecRule ARGS:b "@streq two" "id:3,phase:2,pass,nolog,chain"
            SecRule ARGS:c "@streq nope"
        SecRule MATCHED_VAR "@streq two" "id:4,phase:2,pass,nolog"
        "#,
        "/?a=one&b=two&c=three",
    );
    assert_eq!(tx.matched_rules(), ["1", "4"]);
    assert_eq!(
        tx.matched_data(),
        [
            entry("1", "ARGS:a", "one", Some("one")),
            entry("4", "MATCHED_VAR", "two", Some("two")),
        ]
    );
}

#[test]
fn negated_regex_matches_only_misses_at_each_transformation_stage() {
    let tx = run(
        r#"
        SecRuleEngine On
        SecRule ARGS:a "!@rx ^([A-Z]+)$" "id:1,phase:2,pass,nolog"
        SecRule ARGS:a "!@rx ^([A-Z]+)$" "id:2,phase:2,pass,multiMatch,t:lowercase"
        SecRule ARGS:a "@rx [A-Z]+" "id:3,phase:2,pass"
        "#,
        "/?a=ABC",
    );
    assert_eq!(tx.matched_rules(), ["2", "3"]);
    assert_eq!(
        tx.matched_data(),
        [
            entry("2", "ARGS:a", "abc", None),
            entry("3", "ARGS:a", "ABC", Some("ABC")),
        ]
    );
}
