//! A rule tests its targets in the order they are written, and each target's
//! values in the order the collection holds them. A `&VARIABLE` target takes
//! its place in that order as one value, the count, and a target that resolves
//! to nothing contributes nothing. `ctl:ruleRemoveTargetById` drops values
//! before they are counted or tested.
//!
//! Rule evaluation tests each value as the resolver produces it rather than
//! gathering the values first; these tests pin the order and the edge cases
//! that must not move with it. `setvar` runs once per match
//! (`rule_with_operator.cc`), so appending `MATCHED_VAR_NAME` to a TX
//! variable records every value the operator matched, in order.

use zentinel_modsec::engine::Transaction;
use zentinel_modsec::variables::Collection;
use zentinel_modsec::ModSecurity;

const RECORD: &str = "setvar:'tx.order=%{tx.order} %{MATCHED_VAR_NAME}=%{MATCHED_VAR}'";

fn run(rules: &str) -> Transaction {
    let rules = format!(
        "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,setvar:'tx.order=start'\"\n\
         {rules}"
    );
    let msc = ModSecurity::from_string(&rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri("/p?a=1&b=2", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx
}

fn order(tx: &Transaction) -> String {
    tx.tx()
        .get("order")
        .and_then(|v| v.first().map(|s| s.to_string()))
        .unwrap_or_default()
}

#[test]
fn targets_are_tested_in_written_order_with_counts_in_place() {
    let tx = run(&format!(
        "SecRule REQUEST_METHOD|&ARGS|ARGS_NAMES|REQUEST_HEADERS:X-Absent|ARGS|&REQUEST_HEADERS:X-Absent \
         \"@rx .\" \"id:2,phase:1,pass,{RECORD}\""
    ));
    assert_eq!(
        order(&tx),
        "start REQUEST_METHOD=GET &Args=2 ARGS_NAMES:a=a ARGS_NAMES:b=b \
         ARGS:a=1 ARGS:b=2 &RequestHeaders=0"
    );
    let data = tx.matched_data();
    assert_eq!(data.len(), 1, "{data:?}");
    assert_eq!(data[0].variable, "REQUEST_METHOD");
}

#[test]
fn targets_that_resolve_to_nothing_do_not_match_even_negated() {
    let tx = run(&format!(
        "SecRule REQUEST_HEADERS:X-Absent|REQUEST_COOKIES \"!@rx .\" \"id:2,phase:1,pass,{RECORD}\""
    ));
    assert_eq!(order(&tx), "start");
    assert_eq!(tx.matched_rules(), ["1"]);
}

#[test]
fn a_removed_target_is_neither_tested_nor_counted() {
    let tx = run(&format!(
        "SecAction \"id:2,phase:1,pass,nolog,ctl:ruleRemoveTargetById=3;ARGS:a\"\n\
         SecRule ARGS|&ARGS|ARGS_NAMES \"@rx .\" \"id:3,phase:1,pass,{RECORD}\""
    ));
    assert_eq!(
        order(&tx),
        "start ARGS:b=2 &Args=1 ARGS_NAMES:a=a ARGS_NAMES:b=b"
    );
}

#[test]
fn a_rule_whose_targets_are_all_removed_does_not_match() {
    let tx = run(&format!(
        "SecAction \"id:2,phase:1,pass,nolog,ctl:ruleRemoveTargetById=3;ARGS\"\n\
         SecRule ARGS \"!@rx nothing\" \"id:3,phase:1,pass,{RECORD}\""
    ));
    assert_eq!(order(&tx), "start");
    assert_eq!(tx.matched_rules(), ["1", "2"]);
}

#[test]
fn an_exclusion_applies_to_every_target_of_its_collection() {
    let tx = run(&format!(
        "SecRule ARGS|!ARGS:a|ARGS:/^[ab]$/|ARGS_NAMES|&ARGS|REQUEST_HEADERS:HOST \
         \"@rx .\" \"id:2,phase:1,pass,{RECORD}\""
    ));
    assert_eq!(
        order(&tx),
        "start ARGS:b=2 ARGS:b=2 ARGS_NAMES:a=a ARGS_NAMES:b=b &Args=1 \
         REQUEST_HEADERS:HOST=example.com"
    );
}

#[test]
fn multi_match_reports_the_first_matching_stage_of_each_value() {
    let tx = run(&format!(
        "SecRule ARGS_NAMES|REQUEST_METHOD \"@rx ^(?:A|get)$\" \
         \"id:2,phase:1,pass,t:none,t:uppercase,t:lowercase,multiMatch,{RECORD}\""
    ));
    assert_eq!(order(&tx), "start ARGS_NAMES:a=A REQUEST_METHOD=get");
}

#[test]
fn capture_and_matched_var_hold_the_last_match() {
    let tx = run(&format!(
        "SecRule ARGS|REQUEST_METHOD \"@rx ^(.)\" \"id:2,phase:1,pass,capture,{RECORD}\"\n\
         SecRule MATCHED_VAR|MATCHED_VAR_NAME|TX:1 \"@rx .\" \"id:3,phase:1,pass,{RECORD}\""
    ));
    assert_eq!(
        order(&tx),
        "start ARGS:a=1 ARGS:b=2 REQUEST_METHOD=GET \
         MATCHED_VAR=GET MATCHED_VAR_NAME=REQUEST_METHOD TX:1=G"
    );
}

#[test]
fn a_chain_link_tests_what_the_starter_matched() {
    let tx = run(&format!(
        "SecRule ARGS \"@rx .\" \"id:2,phase:1,pass,chain\"\n\
         SecRule MATCHED_VARS|&MATCHED_VARS_NAMES \"@rx ^2$\" \"{RECORD}\""
    ));
    assert_eq!(
        order(&tx),
        "start MATCHED_VARS:ARGS:b=2 &MatchedVarsNames=2"
    );
}

#[test]
fn an_operand_macro_is_expanded_for_every_value() {
    let tx = run(&format!(
        "SecAction \"id:2,phase:1,pass,nolog,setvar:tx.want=2\"\n\
         SecRule ARGS|&ARGS|REQUEST_HEADERS:X-Absent \"@streq %{{tx.want}}\" \"id:3,phase:1,pass,{RECORD}\""
    ));
    assert_eq!(order(&tx), "start ARGS:b=2 &Args=2");
}

#[test]
fn an_expanded_operand_that_does_not_compile_matches_nothing() {
    let tx = run(&format!(
        "SecAction \"id:2,phase:1,pass,nolog,setvar:'tx.bad=('\"\n\
         SecRule ARGS|&ARGS \"!@rx %{{tx.bad}}\" \"id:3,phase:1,pass,{RECORD}\"\n\
         SecRule REQUEST_HEADERS:X-Absent \"!@rx %{{tx.bad}}\" \"id:4,phase:1,pass,{RECORD}\"\n\
         SecRule REQUEST_METHOD \"@rx .\" \"id:5,phase:1,pass,{RECORD}\""
    ));
    assert_eq!(order(&tx), "start REQUEST_METHOD=GET");
    assert_eq!(tx.matched_rules(), ["1", "2", "5"]);
}
