use zentinel_modsec::ModSecurity;

fn main() {
    let mut config = String::from("SecRuleEngine On\nSecRequestBodyAccess On\n");
    for phase in 1..=2 {
        for suffix in 1..=4 {
            config.push_str(&format!(r#"SecRule REQUEST_HEADERS:X-Late "@rx ^live$" "id:{phase}{suffix},phase:{phase},pass"
"#));
        }
    }
    let engine = ModSecurity::from_string(&config).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert!(tx.matched_rules().is_empty());
    tx.add_request_header("x-LaTe", "live").unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["21", "22", "23", "24"]);
    println!("phase-1 absent header; phase-2 late header observed by four rules");
}
