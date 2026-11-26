use std::{hint::black_box, time::Instant};
use zentinel_modsec::ModSecurity;

fn run(name: &str, rules: &str, uri: &str, expected: bool, reps: u32) {
    let engine = ModSecurity::from_string(rules).unwrap();
    let request = || {
        let mut tx = engine.new_transaction();
        tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx
    };
    let first = request();
    if name.starts_with("paths") {
        assert!(first.matched_rules().is_empty());
    } else {
        assert_eq!(
            first.matched_rules().iter().any(|id| id == "65535"),
            expected
        );
    }
    drop(first);
    for _ in 0..128 {
        drop(black_box(request()));
    }
    let t = Instant::now();
    for _ in 0..reps {
        drop(black_box(request()));
    }
    println!(
        "{} {}",
        name,
        t.elapsed().as_secs_f64() * 1e6 / f64::from(reps)
    );
}

fn main() {
    let reps = std::env::args().nth(1).unwrap().parse().unwrap();
    let which = std::env::var("FOCUS").unwrap();
    if which == "tx" {
        for size in [32, 128, 512] {
            let mut rules = String::from("SecRuleEngine On\n");
            for i in 0..size {
                rules += &format!(
                    "SecAction \"id:{},phase:1,pass,nolog,setvar:tx.default_{i}=1\"\n",
                    i + 1
                );
            }
            rules += "SecRule REQUEST_METHOD \"@streq GET\" \"id:65534,phase:1,pass,nolog,setvar:tx.header_color=blue\"\nSecRule TX:/^header_/ \"@streq blue\" \"id:65535,phase:1,pass,nolog\"";
            run(&format!("shared{size}"), &rules, "/shop", true, reps);
        }
    } else if which == "filename" {
        for count in [1, 16, 64] {
            let mut rules = String::from("SecRuleEngine On\n");
            for i in 0..count {
                rules += &format!(
                    "SecRule REQUEST_FILENAME \"@rx [a-z]{{20}}/{i}\" \"id:{},phase:1,pass,nolog,t:lowercase\"\n", i+1);
            }
            run(&format!("paths{count}"), &rules, "/shop", false, reps);
        }
    } else {
        let rules = "SecRuleEngine On\nSecRule REQUEST_URI \"@validateUrlEncoding\" \"id:65535,phase:1,pass,nolog\"";
        for (name, raw, invalid) in [
            ("short", "/shop%20cart".to_owned(), false),
            ("sparse", format!("/{}%20cart", "x".repeat(8192)), false),
            ("dense", format!("/{}", "%20".repeat(2700)), false),
            ("late", format!("/{}%x", "x".repeat(8192)), true),
        ] {
            run(name, rules, &raw, invalid, reps);
        }
    }
}
