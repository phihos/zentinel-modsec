//! `status` names the response status of the rule's disruptive action, as in
//! ModSecurity v3, where `deny` answers 403 only when the rule names none.

use zentinel_modsec::ModSecurity;

fn denied_with(rules: &str) -> u16 {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri("/?a=x&b=y", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.intervention()
        .expect("the request should be denied")
        .status
}

#[test]
fn deny_answers_the_status_the_rule_names() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:a \"@streq x\" \"id:1,phase:2,deny,status:418\"\n";
    assert_eq!(denied_with(rules), 418);
}

#[test]
fn the_status_may_come_before_the_disruptive_action() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:a \"@streq x\" \"id:1,phase:2,status:406,deny\"\n";
    assert_eq!(denied_with(rules), 406);
}

#[test]
fn deny_without_a_status_answers_403() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:a \"@streq x\" \"id:1,phase:2,deny\"\n";
    assert_eq!(denied_with(rules), 403);
}

#[test]
fn block_answers_the_status_the_rule_names() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:a \"@streq x\" \"id:1,phase:2,block,status:429\"\n";
    assert_eq!(denied_with(rules), 429);
}

#[test]
fn block_without_a_status_answers_the_default_status() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:a \"@streq x\" \"id:1,phase:2,block\"\n";
    let mut msc = ModSecurity::from_string(rules).unwrap();
    msc.set_default_status(451);
    let mut tx = msc.new_transaction();
    tx.process_uri("/?a=x", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.intervention().unwrap().status, 451);
}

#[test]
fn a_chain_answers_the_status_of_its_starter() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:a \"@streq x\" \"id:1,phase:2,deny,status:418,chain\"\n\
        SecRule ARGS:b \"@streq y\" \"t:none\"\n";
    assert_eq!(denied_with(rules), 418);
}

#[test]
fn a_status_in_phase_1_is_honoured() {
    let rules = "SecRuleEngine On\n\
        SecAction \"id:1,phase:1,deny,status:503\"\n";
    assert_eq!(denied_with(rules), 503);
}

#[test]
fn a_status_on_a_passing_rule_denies_nothing() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:a \"@streq x\" \"id:1,phase:2,pass,status:418\"\n\
        SecRule ARGS:b \"@streq y\" \"id:2,phase:2,deny\"\n";
    assert_eq!(denied_with(rules), 403);
}
