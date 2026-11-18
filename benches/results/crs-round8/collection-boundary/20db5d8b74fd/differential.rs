
#[cfg(test)]
#[test]
fn full_collections_at_arg_limits() {
    use crate::{CompiledRuleset,engine::{phase::Phase, Transaction}, parser::VariableName,variables::RequestData};
    use std::collections::HashMap;
    use std::sync::Arc;
    audit_incremental_width_mutations();
    type Row=(bool,String,String); // GET, case-preserving name, value
    struct Fixture {request: RequestData, rows: Vec<Row>, cost:usize, late:u8}
    let mut fixtures=Vec::new();
    // Compare complete GET, POST, and split collections across size boundaries.
    for (count,exact) in [(32,None),(33,None),(127,None),(128,None),(129,None),(256,None),(257,None),(384,None),
                          (64,Some(4095)),(64,Some(4096)),(64,Some(4097)),(128,Some(8192)),(128,Some(8193)),(256,Some(16384))] {
        for split in [0,count/2,count] {
            // Bit 0 changes the final value, bit 1 changes the final name.
            for late in 0..4 {
              for warm in [false,true] {
                let mut request=RequestData::new();
                let mut rows=Vec::new();
                let mut cost=0;
                for i in 0..count {
                    if warm && (i==count/2 || i+1==count) {
                        // Read the group before appending the final name/value.
                        let _=request.args_get.argument_widths();let _=request.args_post.argument_widths();
                    }
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
SecRule ARGS "!@pm no-such-punctuation!" "id:1013,phase:2,pass"
SecRule ARGS "@validateByteRange 45-58,65-90,95,97-122" "id:1014,phase:2,pass"
SecRule ARGS_NAMES "@validateByteRange 48-57,65-90,97-122" "id:1015,phase:2,pass,t:lowercase,multiMatch"
SecRule ARGS "@validateByteRange" "id:1016,phase:2,pass"
SecRule ARGS "@validateUrlEncoding" "id:1017,phase:2,pass,t:hexDecode,multiMatch"
SecRule ARGS "@validateUtf8Encoding" "id:1018,phase:2,pass,t:hexDecode,multiMatch"
SecRule ARGS "!@validateUtf8Encoding" "id:1019,phase:2,pass""#;
    let controls=CompiledRuleset::from_string(config).unwrap();
    let patterns:HashMap<_,_>=PHRASE_CACHE.entries.lock().unwrap().iter().filter_map(|(p,w)|w.upgrade().map(|v|(Arc::as_ptr(&v),p.clone()))).collect();
    enum Ref { Rx(regex::bytes::Regex), Pm(AhoCorasick), Range(Vec<std::ops::RangeInclusive<u8>>), Url, Utf8, Any }
    impl Ref { fn matches(&self,v:&[u8])->bool {match self {Self::Rx(r)=>r.is_match(v),Self::Pm(p)=>p.find(v).is_some(),
        Self::Range(ranges)=>v.iter().any(|byte|!ranges.iter().any(|r|r.contains(byte))),
        Self::Url=>v.iter().enumerate().any(|(i,b)|*b==b'%' && !(v.get(i+1).is_some_and(u8::is_ascii_hexdigit) && v.get(i+2).is_some_and(u8::is_ascii_hexdigit))),
        Self::Utf8=>std::str::from_utf8(v).is_err(),Self::Any=>true}}}
    for (suite,rules) in [("CRS",&crs),("controls",&controls)] {
        let(mut discarded,mut member_checks,mut negatives,mut fallback,mut checked_rules)=(0,0,0,0,0);
        let mut above_reference_size_pruned=0;
        for phase in Phase::ALL {
            for (index,rule) in rules.rules_for_phase(phase).iter().enumerate() {
                let reference=if let Some(op)=rule.operator.test_phrase() {
                    Some(Ref::Pm(AhoCorasick::builder().ascii_case_insensitive(true).match_kind(MatchKind::LeftmostLongest).build(&patterns[&op.automaton_address()]).unwrap()))
                }else if rule.operator.compiled_regex().is_some() {
                    let p=&rule.operator_spec.argument;
                    let binary=matches_arbitrary_bytes(p);
                    Some(Ref::Rx(regex::bytes::RegexBuilder::new(&normalize_binary_braced_escapes(p,binary)).unicode(!binary).multi_line(!binary).dot_matches_new_line(!binary).build().unwrap()))
                }else{
                    use crate::parser::OperatorName::*;
                    let arg=&rule.operator_spec.argument;
                    match rule.operator_spec.name {
                        ValidateByteRange if arg.is_empty()=>Some(Ref::Any),
                        ValidateByteRange if !arg.contains("%{")=>Some(Ref::Range(arg.split(',').map(|piece|{
                            let p=piece.trim();
                            let (lo,hi)=p.split_once('-').unwrap_or((p,p));
                            lo.parse().unwrap()..=hi.parse().unwrap()
                        }).collect())),
                        ValidateUrlEncoding=>Some(Ref::Url),ValidateUtf8Encoding=>Some(Ref::Utf8),
                        _=>None,
                    }
                };
                checked_rules+=1;
                let slow=rule.transformations.oracle_without_shortcuts();
                for f in &fixtures {
                    let pruned=rules.oracle_args_removed(phase,index,&f.request);
                    if f.cost>4096 {
                        above_reference_size_pruned+=pruned.len();
                        fallback+=1;
                    }
                    for idx in pruned {
                        discarded+=1;
                        let spec=&rule.variables[idx];
                        let op=reference.as_ref().expect("unexpected operator supplied a width proof");
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
        assert!(above_reference_size_pruned>0, "large collections never exercised the new width path");
        println!("boundary sweep {suite}: fixtures {}, rules {checked_rules}, removed targets {discarded}, source members checked {member_checks}, unfiltered transformed-stage decisions {negatives}, over-4KiB rule masks checked {fallback}, targets pruned over 4KiB {above_reference_size_pruned}, differences 0",fixtures.len());
    }
    let fast=Arc::new(controls);
    let mut slow=CompiledRuleset::from_string(config).unwrap();
    slow.disable_argument_widths_for_oracle();
    let slow=Arc::new(slow);
    let(mut late_hits,mut over_late,mut over_cases,mut over_raw_bytes_late)=(0,0,0,0);
    let mut by_member_count=std::collections::BTreeMap::<usize,usize>::new();
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
            if hit {
                late_hits+=1;
                *by_member_count.entry(f.rows.len()).or_default()+=1;
                if f.cost>4096{over_late+=1;}
                if f.rows.iter().map(|(_,k,v)|k.len()+v.len()).sum::<usize>()>4096{over_raw_bytes_late+=1;}
            }
        }
    }
    assert!(over_late>0 && over_raw_bytes_late>0);
    for count in [129,256,257,384] {assert!(by_member_count[&count]>0);}
    println!("late matches fixtures {}, fixtures above reference 4KiB charged budget {over_cases}, last-field positives {late_hits}, late positives above reference 4KiB charged budget {over_late}, above 4KiB actual name/value bytes {over_raw_bytes_late}, late positives grouped by member count {by_member_count:?}, matched rule and audit differences 0",fixtures.len());
}

#[cfg(test)]
fn audit_incremental_width_mutations() {
    use crate::variables::{ByteCollection, HashMapCollection};
    let mut seed=432193u64;
    let mut next=|| {seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;seed as usize};
    let (mut snapshots,mut comparisons,mut conservative)=(0usize,0usize,0usize);
    let alphabet=[b"word".as_slice(),b"Other",b"dot.ted",b"relative/part",b"x!",b"v",b"",b"zzzzzz",b"\xff",b"Q_U",b"90"];
    let limits=[0,1,2,5,8,16,32,63,64,65];
    let mut check=|collection:&HashMapCollection| {
        let flat=collection.all_bytes_with_names();
        let widths=collection.argument_widths();
        for (i,cached) in widths.iter().enumerate() {
            let items=flat.iter().map(|(_,name,value)|if i==0{*value}else{*name}).collect::<Vec<_>>();
            // Independently scan the original members for each nested-alphabet rule.
            for w in limits {for d in limits.into_iter().filter(|n|*n<=w) {for p in limits.into_iter().filter(|n|*n<=d) {
                let minimum=[w,d,p];
                let expected=minimum.iter().enumerate().any(|(class,&min)| min>0 && items.iter().all(|v|v.len()<usize::from(min) && v.len()<=64 && v.iter().all(|b|b.is_ascii_alphanumeric() || class>=1 && *b==b'.' || class==2 && b"_-/:" .contains(b))));
                let discarded=cached.below(minimum);
                assert!(!discarded || expected,"member dimension {i}, unsound thresholds {minimum:?}");
                conservative+=usize::from(expected && !discarded);
                comparisons+=1;
            }}}
        }
        snapshots+=1;
    };
    for mut collection in [HashMapCollection::default(),crate::variables::RequestData::new().args_get] {
        check(&collection);
        for i in 0..512 {
            let mut key=alphabet[next()%alphabet.len()].to_vec();
            if i%3==0 {key.make_ascii_uppercase();}
            let mut value=alphabet[next()%alphabet.len()].to_vec();
            if i%17==0{value.resize([63,64,65,128][next()%4],b'a');}
            match next()%12{
                0=>collection.clear(),
                1|2=>collection.delete_bytes(&key),
                3|4|5=>collection.set_bytes(key,value),
                6=>{
                    let mut clone=collection.clone();
                    clone.add_bytes(key,value);
                    check(&clone);
                    if i%2==0 {collection=clone;}
                }
                _=>collection.add_bytes(key,value),
            }
            check(&collection);
        }
    }
    println!("boundary sweep mutation snapshots {snapshots}, independently rescanned alphabet/length decisions {comparisons}, cold/warm append, clone, set, delete, clear, safe missed pruning opportunities {conservative}, unsound decisions 0");
}
