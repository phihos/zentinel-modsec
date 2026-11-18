
#[cfg(test)]
#[test]
fn full_crs_short_transform_equivalence() {
    use crate::{CompiledRuleset,engine::phase::Phase};
    use std::collections::BTreeSet;
    let dir=std::env::var("CRS_BENCH_DIR").unwrap();
    let rules=CompiledRuleset::from_string(&format!("SecRuleEngine On\nSecRequestBodyAccess On\nInclude \"{dir}/crs-setup.conf.example\"\nInclude \"{dir}/rules/*.conf\"\n")).unwrap();
    assert_eq!(rules.rule_count(),698);
    let mut shapes=BTreeSet::<Vec<String>>::new();
    for rule in Phase::ALL.iter().flat_map(|&phase|rules.rules_for_phase(phase)) {
        let p=&rule.transformations;
        if p.byte_triggers.is_some() {
            shapes.insert(p.transformations.iter().map(|s|s.name().to_owned()).collect());
        }
    }
    let live_shapes=shapes.len();
    for name in ["utf8ToUnicode","urlDecode","urlDecodeUni","htmlEntityDecode","jsDecode","cssDecode","escapeSeqDecode","removeNulls","replaceNulls","lowercase","removeWhitespace","compressWhitespace","normalizePath","normalizePathWin","replaceComments","removeComments","removeCommentsChar","cmdLine"]{
        shapes.insert(vec![name.to_string()]);
    }
    let mut inputs=vec![Vec::new(),b"/a/../".to_vec(),b"./b".to_vec(),b"a//b".to_vec(),b"...".to_vec(),b"json.items_0.sku".to_vec(),b"_%26amp;".to_vec(),br"a\b".to_vec(),b"//".to_vec(),b"--".to_vec(),b"--/".to_vec(),b"ABE--C-D".to_vec(),b"A./0../Z".to_vec(),b"Aa".to_vec(),b"AZ09_-.:/".to_vec(),b"/*x*/".to_vec(),b"unclosed /* comment".to_vec(),"Straße à".as_bytes().to_vec()];
    for a in 0..=255 {
        inputs.push(vec![a]);
        for b in 0..=255 {inputs.push(vec![a,b]);}
    }
    let alphabet=b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_/:.-~!&+#%?^;,\\\0\r\n*";
    let mut seed=987654321u64;
    let mut next=||{seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;seed};
    for i in 0..2048 {
        let len=next() as usize%74;
        inputs.push((0..len).map(|_|{let a=next()as usize;if i%3==0{a as u8}else{alphabet[a%alphabet.len()]}}).collect());
    }
    let token=|v:&[u8]| v.iter().all(|b|b.is_ascii_alphanumeric() || b"_-.:/".contains(b));
    let mut changed=0;
    let mut early=0;
    let mut affected=0;
    let mut summary=0;
    for rule in Phase::ALL.iter().flat_map(|&phase|rules.rules_for_phase(phase)) {
        if rule.operator_negated || !rule.transformations.preserves_alphanumeric_width_bounds() {continue;}
        let Some(rx)=rule.operator.compiled_regex() else {continue;};
        affected+=1;
        let oracle=crate::operators::RxOperator::independent_byte_regex(&rule.operator_spec.argument);
        let mut reference=TransformationPipeline::new();
        for t in &rule.transformations.transformations { reference.add(create_transformation(t.name()).unwrap()); }
        for input in &inputs {
            let single=rule.transformations.preserves_token_width_bounds() && rx.rejects_short_token(input);
            let [word,path]=rx.token_minimums();
            let grouped=input.len()<=64 && (
                (input.len()<usize::from(word) && input.iter().all(u8::is_ascii_alphanumeric))
                || (rule.transformations.preserves_token_width_bounds() && input.len()<usize::from(path) && token(input)));
            if !(single || grouped){continue;}
            early+=usize::from(single);summary+=usize::from(grouped);
            let expected=reference.apply_bytes(input).unwrap();
            assert!(!oracle.is_match(&expected));
            assert!(token(input));
            changed += usize::from(expected.as_ref()!=input);
            reference.visit_byte_stages(input,None,|index, stage|{
                let _=index;
                assert!(stage.len()<=input.len() && token(stage));
                if input.iter().all(u8::is_ascii_alphanumeric) {assert!(stage.iter().all(u8::is_ascii_alphanumeric));}
                assert!(!oracle.is_match(stage),"rule {:?} produced matching stage {:?}",rule.id,stage);
                Ok(None::<()>)
            }).unwrap();
        }
    }
    println!("early rejection eligible rules {affected}, early rejections crosschecked {early}, summarized width rejections {summary}, final bytes changed {changed}");
    let mut checks=0;
    let mut stage_visits=0;
    for names in &shapes {
        let fast=TransformationPipeline::from_names(names).unwrap();
        let mut reference=TransformationPipeline::new();
        for name in names {reference.add(create_transformation(name).unwrap());}
        assert!(reference.byte_triggers.is_none());
        for input in &inputs {
            let actual=fast.apply_bytes(input).unwrap();
            let expected=reference.apply_bytes(input).unwrap();
            assert_eq!(actual,expected,"pipeline {names:?} value {input:?}");
            assert_eq!(matches!(actual,Cow::Borrowed(_)),matches!(expected,Cow::Borrowed(_)),"borrowed {names:?} {input:?}");
            let stages=|p:&TransformationPipeline|{
                let mut out=Vec::new();
                p.visit_byte_stages(input,None,|index,b|{
                    out.push((index,b.to_owned()));Ok(None::<()>)
                }).unwrap();
                out
            };
            let visits=stages(&fast);
            assert_eq!(visits,stages(&reference),"multiMatch stages {names:?} {input:?}");
            stage_visits+=visits.len();
            checks+=1;
        }
    }
    println!("live shapes {live_shapes}, including individual stages {}, inputs {}, checked final values and ownership {checks}, checked multiMatch stage visits {stage_visits}, mismatches 0",shapes.len(),inputs.len());
}
