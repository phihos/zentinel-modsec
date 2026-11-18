
#[cfg(test)]
#[test]
fn full_crs_tx_selectors() {
    use crate::{CompiledRuleset,engine::phase::Phase,parser::{Selection,VariableName,parse_single_variable},variables::{SelectorPrograms,TargetSelection}};
    use std::collections::BTreeSet;
    let dir=std::env::var("CRS_BENCH_DIR").unwrap();
    let rules=CompiledRuleset::from_string(&format!("SecRuleEngine On\nSecRequestBodyAccess On\nInclude \"{dir}/crs-setup.conf.example\"\nInclude \"{dir}/rules/*.conf\"\n")).unwrap();
    assert_eq!(rules.rule_count(),698);
    let mut patterns=BTreeSet::new();
    let mut tx=TxCollection::new();
    for r in Phase::ALL.iter().flat_map(|&ph|rules.rules_for_phase(ph)) {
        for v in &r.variables {
            if v.name!=VariableName::Tx {continue;}
            match &v.selection {
                Some(Selection::Regex(s))=>{patterns.insert(s.clone());},
                Some(Selection::Key(k))=>{tx.set_bytes(k.as_bytes(),k.as_bytes());},
                _=>(),
            }
        }
    }
    let live=patterns.len();
    patterns.extend(["^a","^k","^s","^b_9","^0","^_q","^longprefix","^a_b","^","^A","^a[.]","^a|z","^a$","(?-u:^.)","(?i)^ſ","^K"].map(String::from));
    let mut inputs=vec![vec![],b"A_bc".to_vec(),b"z".to_vec(),"ſ_key".as_bytes().into(),"Key".as_bytes().into(),b"HeAdEr_".to_vec()];
    for a in 0..=255 {inputs.push(vec![a]);for b in 0..=255{inputs.push(vec![a,b]);}}
    let mut seed=12392167u64;
    let mut next=||{seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;seed as usize};
    for pattern in &patterns {
        let text=pattern.strip_prefix('^').unwrap_or(pattern).as_bytes();
        for i in 0..384 {
            let mut k=text[..next()%(text.len()+1)].to_vec();
            if i%3==0{k.make_ascii_uppercase();}
            if i%7==0{k.extend_from_slice("Kſ".as_bytes());}
            k.extend((0..next()%18).map(|_|next() as u8));inputs.push(k);
        }
    }
    for (i,k) in inputs.iter().enumerate(){tx.set_bytes(k.as_slice(),(i as u32).to_le_bytes().as_slice());}
    let rows=tx.all_bytes();
    let (mut comparisons,mut fast,mut hits,mut fast_hits)=(0,0,0,0);
    for p in &patterns{
        let spec=parse_single_variable(&format!("TX:/{p}/")).unwrap();
        let mut programs=SelectorPrograms::default();programs.add(p,spec.name).unwrap();
        let selector=TargetSelection::compile(&spec,&programs);
        let optimized=matches!(&selector.member,MemberSelector::TxAsciiPrefix(_));
        fast+=usize::from(optimized);
        let reference=regex::bytes::RegexBuilder::new(p).case_insensitive(true).build().unwrap();
        let expected=rows.iter().copied().filter(|(k,_)|reference.is_match(k)).map(|(k,v)|(k.to_vec(),v.to_vec())).collect::<Vec<_>>();
        let mut actual=Vec::new();
        tx.visit(&selector.member,|k,v|actual.push((k.to_vec(),v.to_vec())));
        assert_eq!(actual,expected,"selector {p}");
        comparisons+=rows.len();hits+=expected.len();
        if optimized{fast_hits+=expected.len();}
    }
    println!("TX selector actual CRS patterns {live}, total regex patterns {}, compiled ASCII-prefix selectors {fast}, distinct stored keys {}, comparisons {comparisons}, ordered key/value hits {hits}, accelerated hits {fast_hits}, differences 0",patterns.len(),rows.len());
}
