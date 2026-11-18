
#[cfg(test)]
#[test]
fn crs_width_differential() {
    use crate::{CompiledRuleset, engine::phase::Phase};

    let dir = std::env::var("CRS_BENCH_DIR").unwrap();
    let rules = CompiledRuleset::from_string(&format!(
        "SecRuleEngine On\nSecRequestBodyAccess On\nInclude \"{dir}/crs-setup.conf.example\"\nInclude \"{dir}/rules/*.conf\"\n"
    )).unwrap();
    assert_eq!(rules.rule_count(),698);
    let mut values = vec![Vec::new()];
    for a in 0..=255 {
        values.push(vec![a]);
        for b in 0..=255 {
            values.push(vec![a,b]);
        }
    }
    let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:";
    let mut seed = 1234567890u64;
    let mut next = || {seed ^= seed<<13; seed ^= seed>>7; seed ^= seed<<17; seed};
    for i in 0..3072 {
        let len = (next() as usize) % 74;
        values.push((0..len).map(|_| {
            let n = next() as usize;
            if i % 3 == 0 { n as u8 } else { alphabet[n % alphabet.len()] }
        }).collect());
    }
    values.extend(["alpha.beta", "/path/part", "key:value", "shop.example:443/path", "json.items_0.sku", "Catalog"," ", "Books: 42", "A\nB", "K","KΣ","小さな木","_","1-2","en_US"].map(|s|s.as_bytes().to_vec()));
    let(mut comparisons,mut rejected,mut matches,mut captures)=(0,0,0,0);
    let mut programs=std::collections::HashSet::new();
    for rule in Phase::ALL.iter().flat_map(|&p|rules.rules_for_phase(p)) {
        let Some(rx)=rule.operator.compiled_regex() else {continue};
        if !programs.insert(Arc::as_ptr(&rx.compiled)) {continue}
        let pattern=&rule.operator_spec.argument;
        let binary=matches_arbitrary_bytes(pattern);
        let reference=regex::bytes::RegexBuilder::new(&normalize_binary_braced_escapes(pattern,binary))
            .unicode(!binary).multi_line(!binary).dot_matches_new_line(!binary).build().unwrap();

        for v in &values {
            let engine=reference.is_match(v);
            if rx.requirements.rules_out(v) {
                assert!(!engine, "false negative in {:?}, value {:?}", rule.id,v);
                rejected+=1;
            }
            assert_eq!(rx.rule_match(v,false,true).is_some(),!engine);
            let plain=rx.rule_match(v,false,false);
            assert_eq!(plain.is_some(),engine);
            if let Some(plain)=plain {
                assert_eq!(plain.matched_value.as_deref(),reference.find(v).map(|m|m.as_bytes()));
            }
            if engine {
                let base=reference.captures(v).unwrap();
                let got=rx.rule_match(v,true,false).unwrap();
                assert_eq!(base.get(0).unwrap().as_bytes(),got.matched_value.as_deref().unwrap());
                let expected=base.iter().skip(1).map(|m|m.map(|m|m.as_bytes()).unwrap_or_default());
                assert!(expected.eq(got.captures.iter().map(|b|b.as_slice())));
                matches+=1;
                captures+=got.captures.len();
            }
            comparisons+=1;
        }
    }
    println!("CRS rules {}, distinct static RX {}, inputs {}, comparisons {}, prefilter rejections {}, matching portions {}, subgroups {}, mismatches 0",rules.rule_count(),programs.len(),values.len(),comparisons,rejected,matches,captures);
}

#[cfg(test)]
impl RxOperator {
    pub(crate) fn independent_byte_regex(pattern: &str) -> regex::bytes::Regex {
        let binary=matches_arbitrary_bytes(pattern);
        regex::bytes::RegexBuilder::new(&normalize_binary_braced_escapes(pattern,binary))
            .unicode(!binary).multi_line(!binary).dot_matches_new_line(!binary).build().unwrap()
    }
}
