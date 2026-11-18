#[cfg(test)]
#[test]
fn crs_phrase_differential() {
    use crate::{CompiledRuleset, engine::phase::Phase};
    use std::collections::{HashMap, HashSet};
    let dir=std::env::var("CRS_BENCH_DIR").unwrap();
    let rules=CompiledRuleset::from_string(&format!(
        "SecRuleEngine On\nSecRequestBodyAccess On\nInclude \"{dir}/crs-setup.conf.example\"\nInclude \"{dir}/rules/*.conf\"\n"
    )).unwrap();
    assert_eq!(rules.rule_count(),698);
    let all:Vec<_>=Phase::ALL.iter().flat_map(|&p|rules.rules_for_phase(p)).filter_map(|r| r.operator.test_phrase().map(|op|(op,&r.operator_spec))).collect();
    let inline=all.iter().filter(|(_,s)|matches!(s.name,crate::parser::OperatorName::Pm)).count();
    let file=all.len()-inline;
    let temp=tempfile::tempdir().unwrap();
    let path=temp.path().join("empty.data");
    std::fs::write(&path,b"# comment\n\n").unwrap();
    let controls=[PmOperator::from_file(path.to_str().unwrap()).unwrap(),
        PmOperator::from_patterns([&b"aBC"[..],b"ab",b"abcD",b"bCD",b"\xff",b":",b"0-0",b"a"].into_iter()).unwrap()];
    let entries:HashMap<_,_>=PHRASE_CACHE.entries.lock().unwrap().iter().filter_map(|(p,w)|w.upgrade().map(|v|(Arc::as_ptr(&v),p.clone()))).collect();
    let mut seed=12328641u64;
    let mut next=||{seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;seed};
    let alphabet=b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_:./ <>\r\n";
    let mut base=vec![vec![],b"aBCDabcdaBCDaBcdaBCd".to_vec()];
    for a in 0..=255 {base.push(vec![a]);for b in 0..=255 {base.push(vec![a,b]);}}
    for n in [63,64,65,128,129]{base.push(vec![b'a';n]);}
    for i in 0..2048 {let len=next() as usize%100;base.push((0..len).map(|_|{let x=next()as usize;match i%3{0=>x as u8,1=>alphabet[x%alphabet.len()],_=>alphabet[x%62]}}).collect());}
    let mut checked=HashSet::new();
    let(mut programs,mut phrases,mut comparisons,mut positive,mut captures,mut rejected)=(0,0,0,0,0,0);
    for pm in all.iter().map(|v|v.0).chain(controls.iter()){
        if !checked.insert(pm.automaton_address()){continue;}
        programs+=1;
        let patterns=&entries[&pm.automaton_address()];phrases+=patterns.len();
        let reference=AhoCorasick::builder().ascii_case_insensitive(true).match_kind(MatchKind::LeftmostLongest).build(patterns).unwrap();
        let mut cases=Vec::new();
        for p in patterns {
            cases.push(p.clone());
            cases.push(p.to_ascii_uppercase());
            cases.push(p.to_ascii_lowercase());
            let mut repeated=p.to_ascii_lowercase();
            repeated.extend_from_slice(&p.to_ascii_uppercase());
            repeated.extend_from_slice(p);
            cases.push(repeated);
        }
        for value in base.iter().chain(&cases) {
            let first=reference.find(value);
            let mut expected_captures=vec![];
            if let Some(first)=first {
                positive+=1;
                let mut start=first.start()+1;
                while start<=value.len() && expected_captures.len()<9{
                    let Some(m)=reference.find(&value[start..]) else{break};
                    expected_captures.push(&value[start+m.start()..start+m.end()]);
                    start+=m.start()+1;
                }
            }
            captures+=expected_captures.len();
            let skip=value.len()<pm.min_len || (value.len()<pm.min_alphanumeric && value.len()<=64 && value.iter().all(u8::is_ascii_alphanumeric));
            if skip {rejected+=1;assert!(first.is_none());}
            for capture in [false,true] {
                let found=pm.execute_rule_bytes(value,capture).unwrap();
                assert_eq!(found.matched,first.is_some());
                assert_eq!(found.matched_value.as_deref(),first.map(|m|&value[m.range()]));
                let expected=if capture {&expected_captures[..]} else {&[]};
                assert!(found.captures.iter().map(Vec::as_slice).eq(expected.iter().copied()));
                comparisons+=1;
            }
        }
    }
    let controls=CompiledRuleset::from_string(r#"SecRuleEngine DetectionOnly
SecRule ARGS|ARGS_NAMES "@pm abc" "id:1,phase:2,pass,t:none,t:lowercase,multiMatch"
SecRule ARGS|ARGS_NAMES "@pm ab" "id:2,phase:2,pass,t:none,t:removeCommentsChar,multiMatch"
SecRule ARGS|ARGS_NAMES "@pm //" "id:3,phase:2,pass,t:none,t:normalizePath,multiMatch"
SecRule ARGS|ARGS_NAMES "@pm a" "id:4,phase:2,pass,t:none,t:hexDecode,multiMatch"
SecRule ARGS|ARGS_NAMES "!@pm toolong" "id:5,phase:2,pass,t:none,t:lowercase"
"#).unwrap();
    let cache:HashMap<_,_>=PHRASE_CACHE.entries.lock().unwrap().iter().filter_map(|(p,w)|w.upgrade().map(|v|(Arc::as_ptr(&v),p.clone()))).collect();
    let token=|v:&[u8]|v.iter().all(|b| b.is_ascii_alphanumeric()||b"_-./:".contains(b));
    for (suite,ruleset) in [("CRS",&rules),("controls",&controls)] {
        let (mut checks,mut words_pruned,mut paths_pruned,mut stage_hits,mut changed_hits,mut changed_word_hits,mut changed_path_hits)=(0,0,0,0,0,0,0);
        let mut by_type=[0;3];
        for phase in Phase::ALL{
            for (index,rule) in ruleset.rules_for_phase(phase).iter().enumerate(){
                let Some(pm)=rule.operator.test_phrase() else {continue;};
                let patterns=&cache[&pm.automaton_address()];
                let reference=AhoCorasick::builder().ascii_case_insensitive(true).match_kind(MatchKind::LeftmostLongest).build(patterns).unwrap();
                let pipeline=rule.transformations.oracle_without_shortcuts();
                let mut custom=vec![b"ABC".to_vec(),b"a--b".to_vec(),b"/".to_vec(),b"61".to_vec(),b"..".to_vec(),b"/a/../b".to_vec()];
                for p in patterns {custom.push(p.to_ascii_uppercase());custom.push(p.to_ascii_lowercase());}
                for input in base.iter().chain(custom.iter()).filter(|v|v.len()<=64&&token(v)){
                    let word=input.iter().all(u8::is_ascii_alphanumeric);
                    let counts=ruleset.oracle_phase_pruned(phase,index,ruleset.oracle_request_collections(phase,input));
                    for (total,n) in by_type.iter_mut().zip(counts){*total+=n;}
                    let pruned=counts.iter().sum::<usize>();
                    if pruned>0 {
                        assert!(!rule.operator_negated);
                        if word {words_pruned+=pruned;}else{paths_pruned+=pruned;}
                    }
                    pipeline.visit_byte_stages(input,None,|stage,v|{
                        let actual=pm.execute_rule_bytes(v,true)?;
                        let hit=reference.find(v).map(|m|&v[m.range()]);
                        assert_eq!(actual.matched_value.as_deref(),hit);
                        if hit.is_some(){
                            assert_eq!(pruned,0,"positive {:?} stage {stage}",rule.id);
                            stage_hits+=1;
                            if input.as_slice()!=v{
                                changed_hits+=1;
                                if word{changed_word_hits+=1;}else{changed_path_hits+=1;}
                            }
                        }
                        checks+=1;Ok(None::<()>)
                    }).unwrap();
                }
            }
        }
        assert!(words_pruned>0 && paths_pruned>0 && changed_hits>0);
        if suite=="controls"{assert!(changed_word_hits>0 && changed_path_hits>0);}
        println!("phase search {suite} actual target pruning [arguments,filename,headers] {by_type:?}");
        println!("phase search {suite}: stages {checks}, pruned word targets {words_pruned}, pruned non-word path targets {paths_pruned}, positive stages {stage_hits}, positive changed stages {changed_hits} (words {changed_word_hits}, paths {changed_path_hits}), mismatches 0");
    }
    println!("CRS rules {}, inline phrase rules {inline}, file-backed phrase rules {file}, distinct live programs plus two controls {programs}, phrases {phrases}, capture-mode comparisons {comparisons}, early rejections {rejected}, matched portions {positive}, ordered captures {captures}, mismatches 0",rules.rule_count());
}
