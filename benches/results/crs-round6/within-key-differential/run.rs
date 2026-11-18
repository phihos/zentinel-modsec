use zentinel_modsec::ModSecurity;
use zentinel_modsec::variables::ByteCollection;

fn main() {
    let mut total = 0;
    for argument in [r"%{TX.\xff}","%{tx.dot.key}","%{TX.K}","%{tx.İ}","%{tx.}", "%{tx.%{nested}", "%{tx.missing}"] {
        for sign in ["", "!"] {
            for target in ["ARGS:a|ARGS:b","TX:@missing|&ARGS:a","ARGS|MATCHED_VARS","REQUEST_METHOD","&ARGS"] {
                for transforms in ["t:none","t:lowercase","multiMatch,t:lowercase,t:removeWhitespace"] {
                    let source = format!(r#"SecRuleEngine On
SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,pass,capture"
SecRule {target} "{sign}@within {argument}" "id:2,phase:2,pass,{transforms},capture,setvar:tx.WANTED=next,setvar:tx.ä=next,setvar:tx.hits=+1""#);
                    let rules = ModSecurity::from_string(&source).unwrap();
                    for uri in ["/?a=miss&a=skip&a=%FF&a=next&b=next", "/?a=opaque&a=text&b=end&pattern=next", "/?a=Ne+Xt&a=NEXT&b=end", "/"] {
                        let mut tx = rules.new_transaction();
                        tx.tx_mut().set_bytes(&[0xff][..], "opaque");
                        tx.tx_mut().set_bytes(r"\xff", "text");
                        tx.tx_mut().set_bytes("dot.key", "next");
                        tx.tx_mut().set_bytes("K", &[0xff][..]);
                        tx.tx_mut().set_bytes("İ", "end");
                        tx.tx_mut().set_bytes("", "skip");
                        tx.tx_mut().set_bytes("%{nested", "next");
                        tx.set_record_setvar_effects(true);
                        tx.process_uri(uri,"GET","HTTP/1.1").unwrap();
                        tx.process_request_headers().unwrap();
                        tx.process_request_body().unwrap();
                        tx.process_logging().unwrap();
                        println!("{total} {:?} {:?} {:?} {:?}",tx.matched_rules(),tx.matched_data(),tx.setvar_effects(),tx.tx().all_bytes());
                        total+=1;
                    }
                }
            }
        }
    }
    assert_eq!(total,840);
}
