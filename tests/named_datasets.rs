use zentinel_modsec::{variables::Collection, ModSecurity};

fn inspect(config: &str, query: &str) -> (Vec<String>, Option<String>) {
    let engine = ModSecurity::from_string(config).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri(&format!("/?q={query}"), "GET", "HTTP/1.1")
        .unwrap();
    tx.process_request_headers().unwrap();
    (
        tx.matched_rules().to_vec(),
        tx.tx().get("0").map(|v| v[0].to_owned()),
    )
}

#[test]
fn dataset_phrases_preserve_records_and_bind_to_prior_definitions() {
    let rules = r#"SecDataset Words `
  # comment
Blue
blue sky
word #keep
`
SecRule ARGS:q "@pmFromDataset Words" "id:1,phase:1,pass,capture"
SecDataset Words green
SecRule ARGS:q "@pmFromDataset Words" "id:2,phase:1,pass,capture""#;
    for line_endings in [rules.to_owned(), rules.replace('\n', "\r\n")] {
        for (query, id, capture) in [
            ("BLUE+SKY", "1", "BLUE SKY"),
            ("word+%23keep", "1", "word #keep"),
            ("GrEeN", "2", "GrEeN"),
        ] {
            let (matches, captured) = inspect(&line_endings, query);
            assert_eq!(matches, [id]);
            assert_eq!(captured.as_deref(), Some(capture));
        }
    }
}

#[test]
fn dataset_ips_skip_invalid_records_and_leave_captures_alone() {
    let rules = r#"SecDataset hosts `
192.0.2.0/24, 2001:db8::8,invalid
198.51.100.1 198.51.100.2
`
SecAction "id:1,phase:1,pass,setvar:tx.0=old"
SecRule ARGS:q "@ipMatchFromDataset hosts" "id:2,phase:1,pass,capture""#;
    for (ip, matched) in [
        ("192.0.2.5", true),
        ("2001:db8::8", true),
        ("198.51.100.1", false),
    ] {
        let (ids, capture) = inspect(rules, ip);
        assert_eq!(ids.contains(&"2".to_owned()), matched);
        assert_eq!(capture.as_deref(), Some("old"));
    }
}

#[test]
fn dataset_names_are_literal_case_sensitive_and_required_before_use() {
    let empty = "SecDataset Empty `\n# skipped\n`\n";
    let rule =
        |op: &str, name: &str| format!("SecRule ARGS:q \"@{op} {name}\" \"id:1,phase:1,pass\"");
    assert!(inspect(
        &format!("{empty}{}", rule("pmFromDataset", "Empty")),
        "Empty"
    )
    .0
    .is_empty());
    let literal = format!(
        "SecDataset %{{tx.name}} entry\n{}",
        rule("pmFromDataset", "%{tx.name}")
    );
    assert_eq!(inspect(&literal, "entry").0, ["1"]);
    for config in [
        format!("{empty}{}", rule("ipMatchFromDataset", "Empty")),
        format!("{empty}{}", rule("pmFromDataset", "empty")),
        format!("{}\n{empty}", rule("pmFromDataset", "Empty")),
        String::from("SecDataset only_name"),
        String::from("SecDataset words `\nunclosed"),
    ] {
        assert!(ModSecurity::from_string(&config).is_err(), "{config}");
    }
}
