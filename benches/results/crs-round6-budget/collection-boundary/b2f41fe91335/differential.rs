
#[cfg(test)]
#[test]
fn full_collections_at_arg_limits() {
    use crate::{CompiledRuleset,engine::{phase::Phase, Transaction}, parser::VariableName,variables::RequestData};
    use std::collections::HashMap;
    use std::sync::Arc;
    type Row=(bool,String,String); // GET, case-preserving name, value
    struct Fixture {request: RequestData, rows: Vec<Row>, cost:usize, late:u8}
    let mut fixtures=Vec::new();
    // All-GET, all-POST and split collections exercise one shared budget.
    for (count,exact) in [(32,None),(33,None),(127,None),(128,None),(129,None),
                          (64,Some(4095)),(64,Some(4096)),(64,Some(4097))] {
        for split in [0,count/2,count] {
            // Bit 0 changes the final value, bit 1 changes the final name.
            for late in 0..4 {
                let mut request=RequestData::new();
                let mut rows=Vec::new();
                let mut cost=0;
                for i in 0..count {
                    let get=i<split;
                    // Repeated folded keys have several independently observed spellings.
                    let mut key=format!("{}{}",if i%2==0{"Key."}else{"kEY."},i%11);
                    let mut value=format!("{}{}",["Book","X.9","42","part/z"][i%4],i%7);
                    if let Some(bytes)=exact {
                        let combined=if i+1==count {bytes-64*(count-1)}else{64};
                        value.extend(std::iter::repeat_n('x',combined-key.len()-value.len()));
                    }
                    if i+1==count && late&1!=0 {value.pop();value.push('!');}
                    if i+1==count && late&2!=0 {key.pop();key.push('!');}
                    cost+=32.max(value.len()+key.len());
                    let collection=if get{&mut request.args_get}else{&mut request.args_post};
                    collection.add_bytes(key.as_str(),value.as_str());
                    rows.push((get,key,value));
                }
                assert_eq!(cost,exact.unwrap_or(count*32));
                fixtures.push(Fixture{request,rows,cost,late});
            }
        }
    }
    let dir=std::env::var("CRS_BENCH_DIR").unwrap();
    let crs=CompiledRuleset::from_string(&format!("SecRuleEngine On\nSecRequestBodyAccess On\nInclude \"{dir}/crs-setup.conf.example\"\nInclude \"{dir}/rules/*.conf\"\n")).unwrap();
    assert_eq!(crs.rule_count(),698);
    let config=r#"SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRule ARGS "@rx .{65}" "id:1001,phase:2,pass"
SecRule ARGS_NAMES "@rx .{65}" "id:1002,phase:2,pass"
SecRule ARGS "@pm !" "id:1011,phase:2,pass"
SecRule ARGS_NAMES "@rx !$" "id:1012,phase:2,pass,t:lowercase,multiMatch"
SecRule ARGS "!@pm no-such-punctuation!" "id:1013,phase:2,pass""#;
    let controls=CompiledRuleset::from_string(config).unwrap();
    let patterns:HashMap<_,_>=PHRASE_CACHE.entries.lock().unwrap().iter().filter_map(|(p,w)|w.upgrade().map(|v|(Arc::as_ptr(&v),p.clone()))).collect();
    enum Ref { Rx(regex::bytes::Regex), Pm(AhoCorasick) }
    impl Ref { fn matches(&self,v:&[u8])->bool {match self {Self::Rx(r)=>r.is_match(v),Self::Pm(p)=>p.find(v).is_some()}}}
    for (suite,rules) in [("CRS",&crs),("controls",&controls)] {
        let(mut discarded,mut member_checks,mut negatives,mut fallback,mut checked_rules)=(0,0,0,0,0);
        for phase in Phase::ALL {
            for (index,rule) in rules.rules_for_phase(phase).iter().enumerate() {
                let reference=if let Some(op)=rule.operator.test_phrase() {
                    Some(Ref::Pm(AhoCorasick::builder().ascii_case_insensitive(true).match_kind(MatchKind::LeftmostLongest).build(&patterns[&op.automaton_address()]).unwrap()))
                }else if rule.operator.compiled_regex().is_some() {
                    let p=&rule.operator_spec.argument;
                    let binary=matches_arbitrary_bytes(p);
                    Some(Ref::Rx(regex::bytes::RegexBuilder::new(&normalize_binary_braced_escapes(p,binary)).unicode(!binary).multi_line(!binary).dot_matches_new_line(!binary).build().unwrap()))
                }else{None};
                checked_rules+=1;
                let slow=rule.transformations.oracle_without_shortcuts();
                for f in &fixtures {
                    let pruned=rules.oracle_args_removed(phase,index,&f.request);
                    if f.cost>4096 {assert!(pruned.is_empty(),"over budget {} {:?}",f.cost,rule.id);fallback+=1;}
                    if suite=="controls" && f.late==0 && matches!(rule.id.as_deref(),Some("1001"|"1002")) {
                        assert_eq!(pruned.len(),usize::from(f.cost<=4096),"field count {}, bytes {}",f.rows.len(),f.cost);
                    }
                    for idx in pruned {
                        discarded+=1;
                        let spec=&rule.variables[idx];
                        let op=reference.as_ref().expect("only positive RX and PM have a width proof");
                        assert!(!rule.operator_negated && !spec.count_mode);
                        for (get,key,value) in &f.rows {
                            use VariableName::*;
                            let raw=match spec.name {
                                Args=>value, ArgsNames=>key,
                                ArgsGet if *get=>value, ArgsGetNames if *get=>key,
                                ArgsPost if !*get=>value, ArgsPostNames if !*get=>key,
                                ArgsGet|ArgsPost|ArgsGetNames|ArgsPostNames=>continue,
                                n=>panic!("unrelated target removed {n:?}"),
                            };
                            // Test even members outside the rule's literal/regex name selector.
                            member_checks+=1;
                            slow.visit_byte_stages(raw.as_bytes(),None,|_,v|{
                                assert!(!op.matches(v),"{suite} {:?} {:?} accepted removed value {:?}",rule.id,spec.name,v);
                                negatives+=1;
                                Ok(None::<()>)
                            }).unwrap();
                        }
                    }
                }
            }
        }
        assert!(discarded>0 && member_checks>0 && fallback>0);
        println!("boundary sweep {suite}: fixtures {}, rules {checked_rules}, removed targets {discarded}, source members checked {member_checks}, unfiltered transformed-stage decisions {negatives}, over-budget rule masks restored {fallback}, differences 0",fixtures.len());
    }
    let fast=Arc::new(controls);
    let mut slow=CompiledRuleset::from_string(config).unwrap();
    slow.disable_argument_widths_for_oracle();
    let slow=Arc::new(slow);
    let(mut late_hits,mut over_late,mut over_cases)=(0,0,0);
    for f in &fixtures {
        let form=|get:bool| f.rows.iter().filter(|r|r.0==get).map(|(_,k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("&");
        let uri=format!("/?{}",form(true));
        let body=form(false);
        let eval=|rules|{
            let mut tx=Transaction::new(rules,403);
            tx.process_uri(&uri,"POST","HTTP/1.1").unwrap();
            tx.add_request_header("Content-Type","application/x-www-form-urlencoded").unwrap();
            tx.process_request_headers().unwrap();
            tx.append_request_body(body.as_bytes()).unwrap();
            tx.process_request_body().unwrap();
            tx
        };
        let optimized=eval(fast.clone());let reference=eval(slow.clone());
        assert_eq!(optimized.matched_rules(),reference.matched_rules());
        assert_eq!(optimized.matched_data(),reference.matched_data());
        if f.cost>4096 {over_cases+=1;}
        for (bit,id) in [(1,"1011"),(2,"1012")] {
            let hit=optimized.matched_rules().iter().any(|r|r==id);
            assert_eq!(hit, f.late&bit!=0);
            if hit {late_hits+=1;if f.cost>4096{over_late+=1;}}
        }
    }
    assert!(over_late>0);
    println!("late matches fixtures {}, over-budget fixtures {over_cases}, last-field positives {late_hits}, over-budget last-field positives {over_late}, matched rule and audit differences 0",fixtures.len());
}
