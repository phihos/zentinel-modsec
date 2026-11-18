use std::fmt::Write;
use std::{env, hint::black_box, time::Instant};
use zentinel_modsec::{engine::phase::Phase, variables::ByteCollection, ModSecurity, Transaction};

const RULES: &str = r#"SecRuleEngine On
SecRule ARGS:focus "@rx ^(marker)$" "id:101,phase:1,t:none,capture,deny,status:406,msg:'keyed match'""#;
const FIELDS: usize = 8192;
const CASES: [&str; 3] = ["hit", "miss", "absent"];

fn request_uri(case: &str) -> String {
    let mut uri = String::from("/sparse?");
    for n in 0..FIELDS - 1 {
        write!(&mut uri, "key{n:04}=abcdefgh&").unwrap();
    }
    uri.push_str(match case {
        "hit" => "focus=marker",
        "miss" => "focus=normal",
        _ => "other=marker",
    });
    assert_eq!(uri.bytes().filter(|b| *b == b'&').count() + 1, FIELDS);
    uri
}

fn finish(tx: &mut Transaction) {
    tx.process_request_body().unwrap();
    tx.process_response_headers_with_status(200, "HTTP/1.1")
        .unwrap();
    tx.process_response_body().unwrap();
    tx.process_logging().unwrap();
}

fn main() {
    let mut args = env::args().skip(1);
    let mode = args.next().unwrap();
    let engine = ModSecurity::from_string(RULES).unwrap();
    let rules = engine.ruleset().rules_for_phase(Phase::RequestHeaders);
    assert_eq!(rules.len(), 1);
    let r = &rules[0];
    assert_eq!(r.operator.short_token_minimums(), [6, 6]);
    assert_eq!(r.operator.dotted_token_minimum(), 6);
    assert!(r.transformations.is_empty() && !r.operator_negated);
    if mode == "check" {
        println!("rules=1 fields={FIELDS} minimum_word=6 minimum_dotted=6 minimum_path=6");
        for case in CASES {
            let mut tx = engine.new_transaction();
            tx.set_record_setvar_effects(true);
            tx.set_record_rule_messages(true);
            tx.process_uri(&request_uri(case), "GET", "HTTP/1.1")
                .unwrap();
            tx.process_request_headers().unwrap();
            finish(&mut tx);
            if case == "hit" {
                assert_eq!(tx.matched_rules(), ["101"]);
                assert_eq!(tx.matched_data().len(), 1);
                let m = &tx.matched_data()[0];
                assert_eq!(m.variable_bytes, b"ARGS:focus");
                assert_eq!(m.value_bytes, b"marker");
                assert_eq!(
                    m.matched_portion_bytes.as_deref(),
                    Some(b"marker".as_slice())
                );
                assert_eq!(tx.intervention().unwrap().status, 406);
                assert_eq!(tx.tx().get_bytes(b"1").unwrap(), [b"marker".as_slice()]);
            } else {
                assert!(
                    tx.matched_rules().is_empty()
                        && tx.matched_data().is_empty()
                        && tx.intervention().is_none()
                );
            }
            println!(
                "{case} ids={:?} matches={:?} decision={:?} tx={:?} effects={:?} messages={:?}",
                tx.matched_rules(),
                tx.matched_data(),
                tx.intervention(),
                tx.tx().all_bytes(),
                tx.setvar_effects(),
                tx.rule_messages()
            );
        }
        return;
    }
    let count: usize = args.next().unwrap().parse().unwrap();
    let inputs = CASES.map(request_uri);
    let mut sums = [[0u128; 4]; 3];
    for i in 0..(count + 4) * 3 {
        let case = i % 3;
        let start = Instant::now();
        let mut tx = engine.new_transaction();
        let created = Instant::now();
        tx.process_uri(black_box(&inputs[case]), "GET", "HTTP/1.1")
            .unwrap();
        let parsed = Instant::now();
        tx.process_request_headers().unwrap();
        let inspected = Instant::now();
        finish(&mut tx);
        black_box(tx.has_intervention());
        drop(tx);
        let end = Instant::now();
        if i >= 12 {
            let intervals = [
                created - start,
                parsed - created,
                inspected - parsed,
                end - start,
            ];
            for (sum, span) in sums[case].iter_mut().zip(intervals) {
                *sum += span.as_nanos();
            }
        }
    }
    for (case, sums) in CASES.iter().zip(sums) {
        println!(
            "{case}\t{}\t{}\t{}\t{}",
            sums[0] / count as u128,
            sums[1] / count as u128,
            sums[2] / count as u128,
            sums[3] / count as u128
        );
    }
}
