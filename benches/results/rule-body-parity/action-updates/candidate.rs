use std::io::{self, BufRead};
use zentinel_modsec::ModSecurity;
fn main() {
    let rules = r#"SecRuleEngine On
SecRule REQUEST_URI "@rx ^(/ok)$" "id:11,phase:1,pass,msg:'original',log,setvar:tx.first=1"
SecRule REQUEST_URI "@rx ^(/ok)$" "id:12,phase:1,pass,msg:'original2',log,setvar:tx.second=1""#;
    for edit in io::stdin().lock().lines().map(Result::unwrap){
        let config = format!(r#"{rules}
SecRuleUpdateActionById {edit}
SecRule TX:edited "@streq 1" "id:21,phase:2,pass,msg:edited,log"
SecRule TX:1 "@streq /ok" "id:22,phase:2,pass,msg:cap,log""#);
        let Ok(waf) = ModSecurity::from_string(&config) else {println!("{edit} LOAD ERROR"); continue;};
        let mut tx=waf.new_transaction(); tx.set_record_rule_messages(true);
        tx.process_uri("/ok","GET","HTTP/1.1").unwrap(); tx.process_request_headers().unwrap();
        let phase1=tx.matched_rules().join(" ");
        if tx.intervention().is_none(){tx.process_request_body().unwrap();}
        let status=tx.intervention().map_or(0,|i| i.status);
        let msgs=tx.rule_messages().iter().map(|m|String::from_utf8_lossy(m.message.as_deref().unwrap_or_default())).collect::<Vec<_>>().join(" ");
        println!("{edit} status {status} phase1 [{phase1}] all [{}] messages [{msgs}]",tx.matched_rules().join(" "));
    }
}
