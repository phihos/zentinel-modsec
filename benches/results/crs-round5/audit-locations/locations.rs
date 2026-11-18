use std::fmt::Write;
use zentinel_modsec::ModSecurity;

fn main() {
    const RULES: usize = 301;
    let mut source = String::from("SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\nSecResponseBodyMimeType text/plain\n");
    let mut expected = Vec::new();
    for phase in 1..=5 {
        for index in 0..RULES {
            let id = (1000 * phase + index).to_string();
            writeln!(source, "SecRule REQUEST_METHOD \"@streq GET\" \"id:{id},phase:{phase},pass\"").unwrap();
            expected.push(id);
        }
    }
    let rules = ModSecurity::from_string(&source).unwrap();
    for read_early in [false, true] {
        let mut tx = rules.new_transaction();
        tx.process_uri("/audit", "GET", "HTTP/1.1").unwrap();
        tx.add_response_header("Content-Type","text/plain").unwrap();
        for phase in 1..=5 {
            match phase {
                1 => tx.process_request_headers(),
                2 => tx.process_request_body(),
                3 => tx.process_response_headers(),
                4 => { tx.append_response_body(b"x").unwrap(); tx.process_response_body() },
                _ => tx.process_logging(),
            }.unwrap();
            if read_early || phase == 5 {
                let expected = &expected[..RULES * phase];
                assert_eq!(tx.matched_rules(), expected);
                let data = tx.matched_data();
                assert_eq!(data.len(), expected.len());
                for (record, id) in data.iter().zip(expected) {
                    assert_eq!(record.rule_id.as_ref(), Some(id));
                    assert_eq!(record.variable_bytes, b"REQUEST_METHOD");
                    assert_eq!(record.value_bytes, b"GET");
                    assert_eq!(record.matched_portion_bytes.as_deref(), Some(b"GET".as_slice()));
                }
            }
        }
    }
    println!("five phases x {RULES} matching rules, early and late views exact");
}
