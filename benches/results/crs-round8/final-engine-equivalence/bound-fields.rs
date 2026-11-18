use zentinel_modsec::{ModSecurity,variables::ByteCollection};

fn main() {
    let crs = std::env::args().nth(1).unwrap();
    let cfg=format!("SecRuleEngine On\nSecRequestBodyAccess On\nSecRule ARGS \"@rx (marker[.]ok)$\" \"id:10001001,phase:2,pass,capture,setvar:tx.field_hits=+1\"\nInclude \"{crs}/crs-setup.conf.example\"\nInclude \"{crs}/rules/*.conf\"\n");
    let engine=ModSecurity::from_string(&cfg).unwrap();
    assert_eq!(engine.rule_count(),699);
    for (wide,limit) in [(false,128usize),(true,32usize)] {
        for count in [limit-1,limit,limit+1] {
            let key=if wide {"k".repeat(64)} else {"k".to_string()};
            for last_matches in [false,true] {
                let mut members=Vec::new();
                for i in 0..count {
                    let value=if last_matches && i+1==count {
                        if wide {format!("{}marker.ok","v".repeat(55))} else {"marker.ok".into()}
                    } else if wide {"v".repeat(64)} else {"v".into()};
                    members.push(format!("{key}={value}"));
                }
                let (query,form)=members.split_at(count/2);
                let mut tx=engine.new_transaction();
                tx.set_record_rule_messages(true);tx.set_record_setvar_effects(true);
                tx.process_uri(&format!("/forms?{}",query.join("&")),"POST","HTTP/1.1").unwrap();
                tx.add_request_header("Host","example.test").unwrap();
                tx.add_request_header("User-Agent","Mozilla/5.0").unwrap();
                tx.add_request_header("Accept","application/json").unwrap();
                tx.add_request_header("Content-Type","application/x-www-form-urlencoded").unwrap();
                let body=form.join("&");tx.add_request_header("Content-Length",&body.len().to_string()).unwrap();
                tx.process_request_headers().unwrap();tx.append_request_body(body.as_bytes()).unwrap();tx.process_request_body().unwrap();
                tx.process_response_headers_with_status(200,"HTTP/1.1").unwrap();tx.process_response_body().unwrap();tx.process_logging().unwrap();
                assert_eq!(tx.matched_rules().iter().any(|id|id=="10001001"),last_matches);
                println!("wide={wide} count={count} mark={last_matches} ids={:?} data={:?} intervention={:?} vars={:?} effects={:?} messages={:?}",tx.matched_rules(),tx.matched_data(),tx.intervention(),tx.tx().all_bytes(),tx.setvar_effects(),tx.rule_messages());
            }
        }
    }
}
