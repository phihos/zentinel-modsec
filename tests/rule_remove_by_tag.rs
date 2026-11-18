use zentinel_modsec::{variables::Collection, ModSecurity};

#[test]
fn tag_removal_honors_chain_boundaries_and_ends_with_its_transaction() {
    let engine =
        ModSecurity::from_string(include_str!("fixtures/rule-remove-by-tag.conf")).unwrap();
    for (mode, expected) in [
        (
            "selected",
            vec![
                "1", "2", "3", "4", "6", "7", "9", "12", "15", "17", "20", "22", "19",
            ],
        ),
        (
            "ordinary",
            vec![
                "1", "3", "4", "5", "6", "8", "10", "11", "13", "14", "15", "16", "17", "21", "22",
                "23", "25", "18", "19",
            ],
        ),
    ] {
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("Mode", mode).unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        tx.process_response_headers_with_status(200, "HTTP/1.1")
            .unwrap();
        tx.process_response_body().unwrap();
        tx.process_logging().unwrap();
        assert_eq!(tx.matched_rules(), expected);
        let selected = mode == "selected";
        assert_eq!(tx.tx().get("finished").is_some(), selected);
        assert_eq!(tx.tx().get("skipped_child").is_none(), selected);
        assert_eq!(tx.tx().get("skipped_chain").is_none(), selected);
    }
}

#[test]
fn tag_removal_diagnostics_distinguish_bad_controls_from_supported_tags() {
    use zentinel_modsec::engine::control::unsupported_controls;
    use zentinel_modsec::parser::parse_actions;
    for (ctl, warnings) in [
        ("ruleRemoveByTag=blue", 0),
        ("ruleRemoveByTag=blue;ARGS:/[/", 1),
        ("ruleRemoveByMsg=blue", 1),
    ] {
        let actions = parse_actions(&format!("id:1,ctl:{ctl}")).unwrap();
        assert_eq!(unsupported_controls(&actions).len(), warnings, "{ctl}");
    }
}
