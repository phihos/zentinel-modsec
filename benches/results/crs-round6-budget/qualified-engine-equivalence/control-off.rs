use zentinel_modsec::{ModSecurity,Transaction,variables::ByteCollection};

fn record(case: &str, phase: usize, tx: &Transaction) {
    println!("{case} {phase} ids={:?} data={:?} effects={:?} messages={:?} tx={:?} intervention={:?}",tx.matched_rules(),tx.matched_data(),tx.setvar_effects(),tx.rule_messages(),tx.tx().all_bytes(),tx.intervention());
}

fn main() {
    let cases: &[(&str, &str, &[&str])] = &[
        ("standalone and jump", r#"SecAction "id:1,phase:1,pass,setvar:tx.before=1,ctl:ruleEngine=Off,skipAfter:END"
SecAction "id:2,phase:1,pass"
SecMarker END"#, &["1"]),
        ("unsuccessful control", r#"SecRule REQUEST_METHOD "@streq POST" "id:1,phase:1,pass,ctl:ruleEngine=Off""#, &["91","92","93","94","95"]),
        ("starter stops incomplete chain", r#"SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,pass,chain,setvar:tx.starter=1,ctl:ruleEngine=Off"
SecRule REQUEST_METHOD "@streq GET" "setvar:tx.child=1""#, &[]),
        ("terminal control retains completed match", r#"SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,pass,chain,setvar:tx.starter=1"
SecRule REQUEST_METHOD "@streq GET" "setvar:tx.child=1,ctl:ruleEngine=Off""#, &["1"]),
        ("off then on", r#"SecAction "id:1,phase:1,pass,ctl:ruleEngine=Off,ctl:ruleEngine=On""#, &["1","91","92","93","94","95"]),
        ("on then off", r#"SecAction "id:1,phase:1,pass,ctl:ruleEngine=On,ctl:ruleEngine=Off""#, &["1"]),
        ("disable before disruption in phase 2", r#"SecRule REQUEST_METHOD "@streq GET" "id:1,phase:2,deny,status:418,capture,ctl:ruleEngine=Off""#, &["91","1"]),
        ("disable in phase 5", r#"SecAction "id:1,phase:5,pass,ctl:ruleEngine=Off""#, &["91","92","93","94","1"]),
    ];
    for (name, rules, ids) in cases {
        let mut cfg=format!("SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\n{rules}\n");
        for phase in 1..=5 {
            cfg.push_str(&format!("SecAction \"id:9{phase},phase:{phase},pass,setvar:tx.phase={phase},msg:'phase {phase}'\"\n"));
        }
        let engine=ModSecurity::from_string(&cfg).unwrap();
        for diagnostics in [false,true] {
            let mut tx=engine.new_transaction();
            tx.set_record_rule_messages(diagnostics);
            tx.set_record_setvar_effects(diagnostics);
            tx.process_uri("/case","GET","HTTP/1.1").unwrap();
            tx.process_request_headers().unwrap();record(name,1,&tx);
            tx.process_request_body().unwrap();record(name,2,&tx);
            tx.process_response_headers_with_status(200,"HTTP/1.1").unwrap();record(name,3,&tx);
            tx.process_response_body().unwrap();record(name,4,&tx);
            tx.process_logging().unwrap();record(name,5,&tx);
            assert_eq!(tx.matched_rules(), *ids, "{name}");
            assert!(!tx.has_intervention(), "{name}");
        }
    }
}
