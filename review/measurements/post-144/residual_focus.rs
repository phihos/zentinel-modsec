use std::{hint::black_box, time::Instant};
use zentinel_modsec::ModSecurity;

fn main() {
    let mode = std::env::var("FOCUS").unwrap();
    let reps: u32 = std::env::args().nth(1).unwrap().parse().unwrap();
    for size in [1, 16, 64] {
        let mut rules = String::from("SecRuleEngine On\n");
        let mut uri = String::from("/shop?name=NOTEBOOK");
        match mode.as_str() {
            "regex" => {
                for id in 1..=size {
                    rules += &format!(
                        "SecRule ARGS:name \"!@rx ^([A-Z]+)$\" \"id:{id},phase:1,pass,nolog\"\n"
                    );
                }
            }
            "macro" => {
                rules += "SecAction \"id:1000,phase:1,pass,nolog,setvar:tx.qty=2\"\n";
                for id in 1..=size {
                    rules+=&format!("SecRule ARGS:name \"@streq NOTEBOOK\" \"id:{id},phase:1,pass,nolog,setvar:'tx.total=+%{{tx.qty}}',setvar:'tx.item=product-%{{MATCHED_VAR}}'\"\n");
                }
            }
            "collection" => {
                rules += "SecRule REQUEST_METHOD \"@streq GET\" \"id:1,phase:1,pass,nolog\"\n";
                for n in 0..size {
                    uri += &format!("&field{n}=blue");
                }
            }
            _ => unreachable!(),
        }
        let engine = ModSecurity::from_string(&rules).unwrap();
        let request = || {
            let mut tx = engine.new_transaction();
            tx.process_uri(&uri, "GET", "HTTP/1.1").unwrap();
            tx.process_request_headers().unwrap();
            tx
        };
        let tx = request();
        assert!(tx.intervention().is_none());
        match mode.as_str() {
            "regex" => assert!(tx.matched_rules().is_empty()),
            "macro" => assert_eq!(tx.tx().values("total"), [(size * 2).to_string()]),
            _ => assert_eq!(tx.matched_rules(), ["1"]),
        }
        for _ in 0..256 {
            drop(black_box(request()));
        }
        let t = Instant::now();
        for _ in 0..reps {
            drop(black_box(request()));
        }
        println!(
            "{size} {}",
            t.elapsed().as_secs_f64() * 1e6 / f64::from(reps)
        );
    }
}
