use zentinel_modsec::ModSecurity;

#[test]
fn status_actions_resolve_independently_of_order_and_redirect_whitelist() {
    for (action, status) in [
        ("deny", 403),
        ("deny,status:400", 400),
        ("status:418,deny", 418),
        ("deny,status:0", 403),
        ("redirect:https://example.test/", 302),
        ("redirect:https://example.test/,status:301", 301),
        ("redirect:https://example.test/,status:303", 303),
        ("redirect:https://example.test/,status:307", 307),
        ("redirect:https://example.test/,status:308", 302),
        ("redirect:https://example.test/,status:400", 302),
        ("drop", 0),
        ("drop,status:418", 418),
    ] {
        let engine = ModSecurity::from_string(&format!(
            "SecRuleEngine On\nSecAction \"id:1,phase:1,{action}\" "
        ))
        .unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        let it = tx.intervention().unwrap();
        assert_eq!(it.status, status, "{action}");
        assert_eq!(it.drop_connection, action.starts_with("drop"));
        assert_eq!(
            it.url.as_deref(),
            if action.starts_with("redirect") {
                Some("https://example.test/")
            } else {
                None
            }
        );
    }
}

#[test]
fn chains_keep_starter_status_and_detection_only_does_not_interrupt() {
    for mode in ["On", "DetectionOnly"] {
        let engine = ModSecurity::from_string(&format!(
            r#"SecRuleEngine {mode}
SecDefaultAction "phase:1,deny,status:418"
SecRule ARGS:x "@streq attack" "id:1,phase:1,deny,status:400,chain"
SecRule ARGS:y "@streq yes" "t:none""#
        ))
        .unwrap();
        for (query, matched) in [("/?x=attack&y=yes", true), ("/?x=attack&y=no", false)] {
            let mut tx = engine.new_transaction();
            tx.process_uri(query, "GET", "HTTP/1.1").unwrap();
            tx.process_request_headers().unwrap();
            assert_eq!(tx.intervention().is_some(), matched && mode == "On");
            if let Some(it) = tx.intervention() {
                assert_eq!(it.status, 400);
                assert_eq!(it.rule_ids, ["1"]);
            }
        }
    }
}

#[test]
fn status_parser_reports_invalid_values_in_the_public_u16_domain() {
    for value in ["abc", "-1", "65536", ""] {
        assert!(
            ModSecurity::from_string(&format!("SecAction \"id:1,phase:1,deny,status:{value}\" "))
                .is_err(),
            "{value}"
        );
    }
}
