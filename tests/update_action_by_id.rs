//! Load-order and disruption policy for SecRuleUpdateActionById.
use zentinel_modsec::{variables::Collection, ModSecurity};

const RULE: &str =
    r#"SecRule REQUEST_URI "@streq /catalog" "id:11,phase:1,pass,setvar:tx.seen=+1""#;

#[test]
fn updates_keep_the_last_disruptive_action_and_status_independently() {
    for (edits, expected) in [
        ("deny,status:409", Some(409)),
        ("deny,status:409\nstatus:410", Some(410)),
        ("deny,status:409\npass", None),
        ("status:410,pass\npass,deny", Some(410)),
    ] {
        let mut rules = RULE.to_owned();
        for update in edits.lines() {
            rules.push_str(&format!("\nSecRuleUpdateActionById 11 \"{update}\""));
        }
        let engine = ModSecurity::from_string(&rules).unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/catalog", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.intervention().map(|it| it.status), expected);
        assert_eq!(tx.matched_rules(), ["11"]);
        assert_eq!(tx.tx().get("seen"), Some(vec!["1"]));
    }
}

#[test]
fn updating_the_chain_starter_preserves_the_condition_and_child_actions() {
    let engine = ModSecurity::from_string(
        r#"
SecRule REQUEST_METHOD "@streq GET" "id:13,phase:1,chain,pass"
SecRuleUpdateActionById 13 "deny,status:412"
SecRule REQUEST_URI "@streq /catalog" "setvar:tx.seen=+1"
SecAction "id:15,phase:1,pass""#,
    )
    .unwrap();
    for (path, matches) in [("/catalog", true), ("/archive", false)] {
        let mut tx = engine.new_transaction();
        tx.process_uri(path, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        if matches {
            let denied = tx.intervention().unwrap();
            assert_eq!(denied.status, 412);
            assert_eq!(denied.rule_ids, ["13"]);
            assert_eq!(tx.tx().get("seen"), Some(vec!["1"]));
        } else {
            assert!(tx.intervention().is_none());
            assert_eq!(tx.matched_rules(), ["15"]);
            assert_eq!(tx.tx().get("seen"), None);
        }
    }
}

#[test]
fn updates_respect_declaration_order_and_removals() {
    let update = r#"SecRuleUpdateActionById 11 "deny""#;
    for bad in [
        format!("{update}\n{RULE}"),
        format!("{RULE}\nSecRuleRemoveById 10-12\n{update}"),
        format!("SecRuleRemoveById 11\n{RULE}\n{update}"),
        format!("{RULE}\n{RULE}\n{update}"),
    ] {
        assert!(ModSecurity::from_string(&bad).is_err(), "{bad}");
    }
    let engine =
        ModSecurity::from_string(&format!("{RULE}\n{update}\nSecRuleRemoveById 11")).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/catalog", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert!(tx.matched_rules().is_empty());
}

#[test]
fn unimplemented_actions_and_ambiguous_lists_reject_the_entire_configuration() {
    for update in [
        r#"11 "pass,nolog""#,
        r#"11 "phase:2""#,
        r#"11 "setvar:tx.mark=1""#,
        r#"11 "deny:extra""#,
        r#"11 "deny, status:410""#,
        r#"11 "status:x""#,
        r#"11 """#,
        r#"11 "deny,""#,
        r#"11 "deny" "pass""#,
        r#"0 "deny""#,
        r#"11-15 "deny""#,
        r#"11 13 "deny""#,
    ] {
        let rules = format!("{RULE}\nSecRuleUpdateActionById {update}");
        assert!(ModSecurity::from_string(&rules).is_err(), "{update}");
    }
}

#[test]
fn updates_require_a_complete_chain_of_conditional_rules() {
    let update = r#"SecRuleUpdateActionById 11 "deny""#;
    for chain in [
        r#"SecRule REQUEST_URI "@streq /catalog" "id:11,phase:1,pass,chain""#,
        r#"SecAction "id:11,phase:1,pass,chain"
SecRule REQUEST_METHOD "@streq GET" "setvar:tx.seen=1""#,
        r#"SecRule REQUEST_METHOD "@streq GET" "id:11,phase:1,chain,pass"
SecAction "setvar:tx.seen=1""#,
    ] {
        assert!(
            ModSecurity::from_string(&format!("{chain}\n{update}")).is_err(),
            "{chain}"
        );
    }
}
