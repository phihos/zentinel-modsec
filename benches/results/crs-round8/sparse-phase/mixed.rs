use std::{env, fmt::Write, hint::black_box, time::Instant};
use zentinel_modsec::{engine::phase::Phase, ModSecurity};

const COUNT: usize = 8192;
const RULE: &str = r#"SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS:focus "@rx ^(marker)$" "id:101,phase:2,t:none,capture,deny,status:406""#;

fn main() {
    let engine = ModSecurity::from_string(RULE).unwrap();
    let rule = &engine.ruleset().rules_for_phase(Phase::RequestBody)[0];
    assert_eq!(rule.operator.short_token_minimums(), [6, 6]);
    let args: Vec<_> = env::args().collect();
    let check = args[1] == "check";
    let reps = if check { 1 } else { args[2].parse().unwrap() };
    let mut inputs = Vec::new();
    for style in ["plain", "early", "late", "dense"] {
        let mut form = String::new();
        for i in 0..COUNT - 1 {
            let value = if style == "dense" || (style == "early" && i == 0) {
                "abc%64efgh"
            } else {
                "abcdefgh"
            };
            write!(&mut form, "key{i:04}={value}&").unwrap();
        }
        form.push_str(if style == "late" || style == "dense" {
            "focus=mark%65r"
        } else {
            "focus=marker"
        });
        for post in [false, true] {
            inputs.push((
                format!("{}-{style}", if post { "post" } else { "get" }),
                post,
                format!("/sparse?{form}"),
                form.clone(),
            ));
        }
    }
    let mut sums = vec![[0u128; 4]; inputs.len()];
    let warm = if check { 0 } else { 3 };
    for round in 0..reps + warm {
        for i in 0..inputs.len() {
            let (case, post, uri, form) = &inputs[i];
            let start = Instant::now();
            let mut tx = engine.new_transaction();
            let created = Instant::now();
            let parse_start;
            let parse_end;
            if *post {
                tx.process_uri("/sparse", "POST", "HTTP/1.1").unwrap();
                tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
                    .unwrap();
                tx.process_request_headers().unwrap();
                tx.append_request_body(black_box(form.as_bytes())).unwrap();
                parse_start = Instant::now();
                tx.process_request_body().unwrap();
                parse_end = Instant::now();
            } else {
                parse_start = Instant::now();
                tx.process_uri(black_box(uri), "GET", "HTTP/1.1").unwrap();
                parse_end = Instant::now();
                tx.process_request_headers().unwrap();
                tx.process_request_body().unwrap();
            }
            let inspected = Instant::now();
            tx.process_response_headers_with_status(200, "HTTP/1.1")
                .unwrap();
            tx.process_response_body().unwrap();
            tx.process_logging().unwrap();
            if check {
                assert_eq!(tx.matched_rules(), ["101"]);
                assert_eq!(tx.matched_data().len(), 1);
                let m = &tx.matched_data()[0];
                assert_eq!(m.variable_bytes, b"ARGS:focus");
                assert_eq!(m.value_bytes, b"marker");
                assert_eq!(tx.intervention().unwrap().status, 406);
                println!(
                    "{case} {:?} {:?} {:?}",
                    tx.matched_rules(),
                    m,
                    tx.intervention()
                );
            } else {
                black_box(tx.has_intervention());
            }
            drop(tx);
            let end = Instant::now();
            if round >= warm {
                let times = [
                    created - start,
                    parse_end - parse_start,
                    inspected - created,
                    end - start,
                ];
                for (sum, ts) in sums[i].iter_mut().zip(times) {
                    *sum += ts.as_nanos();
                }
            }
        }
    }
    if !check {
        for ((case, _, _, _), times) in inputs.iter().zip(sums) {
            println!(
                "{case}\t{}\t{}\t{}\t{}",
                times[0] / reps as u128,
                times[1] / reps as u128,
                times[2] / reps as u128,
                times[3] / reps as u128
            );
        }
    }
}
