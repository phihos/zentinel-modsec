//! A matched rule's message, its `msg` and `logdata` expanded at the match,
//! as ModSecurity v3 records and logs it (`Transaction::messages`,
//! `RuleMessage::log_line`).

use zentinel_modsec::ModSecurity;

const RULES: &str = r#"SecRuleEngine On
SecRule ARGS:q "@contains attack" "id:10,phase:2,pass,msg:'Attack in %{MATCHED_VAR_NAME}',logdata:'Matched Data: %{MATCHED_VAR}',severity:'CRITICAL',ver:'test/1',tag:'attack-generic',setvar:'tx.score=+5'"
SecRule ARGS:q "@contains attack" "id:11,phase:2,pass,nolog,msg:'Never logged'"
SecRule ARGS:q "@contains benign" "id:12,phase:2,pass,msg:'Not matched'"
SecRule ARGS:q "@contains attack" "id:13,phase:2,pass"
SecRule TX:score "@ge 5" "id:20,phase:2,deny,status:403,msg:'Score exceeded (Total: %{TX.score})'"
"#;

const NOLOG_DENY: &str = r#"SecRuleEngine On
SecRule ARGS:q "@contains attack" "id:30,phase:2,deny,status:403,nolog,msg:'Denied quietly: %{MATCHED_VAR}'"
"#;

fn transaction(uri: &str) -> zentinel_modsec::Transaction {
    let m = ModSecurity::from_string(RULES).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx
}

#[test]
fn each_logging_match_leaves_its_message_expanded() {
    let tx = transaction("/?q=an%20attack%20%22here%22");
    let lines: Vec<String> = tx.messages().iter().map(|m| m.log_line()).collect();
    assert_eq!(
        lines,
        [
            r#"[id "10"] [rev ""] [msg "Attack in ARGS:q"] [data "Matched Data: an attack \x22here\x22"] [severity "2"] [ver "test/1"] [maturity "0"] [accuracy "0"] [tag "attack-generic"]"#,
            r#"[id "13"] [rev ""] [msg ""] [data ""] [severity "0"] [ver ""] [maturity "0"] [accuracy "0"]"#,
            r#"[id "20"] [rev ""] [msg "Score exceeded (Total: 5)"] [data ""] [severity "0"] [ver ""] [maturity "0"] [accuracy "0"]"#,
        ],
        "nolog (11) and a rule that did not match (12) leave none; one without \
         msg or logdata (13) leaves one, as in v3"
    );
}

#[test]
fn the_intervention_carries_the_expanded_message() {
    let tx = transaction("/?q=attack");
    let intervention = tx.intervention().expect("20 denies");
    assert_eq!(intervention.status, 403);
    assert_eq!(
        intervention.metadata[0].msg.as_deref(),
        Some("Score exceeded (Total: 5)"),
        "the intervention's message is expanded too"
    );
    assert!(
        tx.messages()
            .iter()
            .any(|m| m.msg.as_deref() == Some("Score exceeded (Total: 5)")),
        "{:?}",
        tx.messages()
    );
}

#[test]
fn a_clean_request_leaves_no_message() {
    assert!(transaction("/?q=hello").messages().is_empty());
}

#[test]
fn a_nolog_rule_that_denies_logs_nothing_and_still_reports_its_intervention() {
    let m = ModSecurity::from_string(NOLOG_DENY).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.process_uri("/?q=attack", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert!(tx.messages().is_empty(), "{:?}", tx.messages());
    let intervention = tx.intervention().expect("30 denies");
    assert_eq!(
        intervention.metadata[0].msg.as_deref(),
        Some("Denied quietly: attack")
    );
}
