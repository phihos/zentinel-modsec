//! Tag exclusions follow Coraza 3.8.1's case-sensitive tag matching.
use zentinel_modsec::ModSecurity;

fn matches(ms: &ModSecurity, uri: &str) -> Vec<String> {
    let mut tx = ms.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.matched_rules().to_vec()
}

const RULES: &str = r#"
SecRuleEngine DetectionOnly
SecRule ARGS "@contains secret" "id:10,phase:2,pass,tag:'attack-sqli',tag:'OWASP_CRS'"
SecRule ARGS "@contains secret" "id:11,phase:2,pass,tag:'attack-sqli'"
SecRule ARGS "@contains secret" "id:12,phase:2,pass,tag:'attack-xss'"
"#;

#[test]
fn configure_time_exclusion_selects_all_and_only_matching_tags() {
    let ms = ModSecurity::from_string(&format!(
        "{RULES}\nSecRuleUpdateTargetByTag attack-sqli \"!ARGS:password\""
    ))
    .unwrap();
    assert_eq!(matches(&ms, "/?password=secret"), ["12"]);
    assert_eq!(matches(&ms, "/?other=secret"), ["10", "11", "12"]);
}

#[test]
fn tag_matching_is_exact_and_case_sensitive() {
    for tag in ["attack-SQLi", "sqli", "attack-.*"] {
        let ms = ModSecurity::from_string(&format!(
            "{RULES}\nSecRuleUpdateTargetByTag {tag} \"!ARGS:password\""
        ))
        .unwrap();
        assert_eq!(matches(&ms, "/?password=secret"), ["10", "11", "12"]);
    }
}

#[test]
fn configure_time_additions_replacements_and_regex_exclusions() {
    let ms = ModSecurity::from_string(
        r#"
SecRuleEngine DetectionOnly
SecRule ARGS:old "@contains secret" "id:10,phase:2,pass,tag:'attack-sqli'"
SecRuleUpdateTargetByTag "attack-sqli" "ARGS:new" "ARGS:old"
SecRuleUpdateTargetByTag attack-sqli "ARGS"
SecRuleUpdateTargetByTag attack-sqli "!ARGS:/^token_/"
"#,
    )
    .unwrap();
    // ARGS was appended, so old remains inspected through that collection.
    assert_eq!(matches(&ms, "/?new=secret"), ["10"]);
    assert_eq!(matches(&ms, "/?token_123=secret"), Vec::<String>::new());
    assert_eq!(matches(&ms, "/?other=secret"), ["10"]);
    let replaced = ModSecurity::from_string(
        r#"
SecRule ARGS:old "@contains secret" "id:10,phase:2,pass,tag:'attack-sqli'"
SecRuleUpdateTargetByTag attack-sqli "ARGS:new" "ARGS:old"
"#,
    )
    .unwrap();
    assert!(matches(&replaced, "/?old=secret").is_empty());
    assert_eq!(matches(&replaced, "/?new=secret"), ["10"]);
}

#[test]
fn runtime_exclusion_is_conditional_and_transaction_local() {
    let ms = ModSecurity::from_string(&format!(r#"
SecRule REQUEST_URI "@beginsWith /login" "id:1,phase:1,pass,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:password"
{RULES}
"#)).unwrap();
    assert_eq!(matches(&ms, "/login?password=secret"), ["1", "12"]);
    assert_eq!(matches(&ms, "/login?other=secret"), ["1", "10", "11", "12"]);
    assert_eq!(matches(&ms, "/other?password=secret"), ["10", "11", "12"]);
}

#[test]
fn runtime_tag_exclusions_propagate_to_chain_children() {
    let ms = ModSecurity::from_string(r#"
SecRuleEngine DetectionOnly
SecRule REQUEST_URI "@beginsWith /api" "id:1,phase:1,pass,ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS_GET:json.content"
SecRule REQUEST_METHOD "@streq GET" "id:2,phase:1,pass,tag:'OWASP_CRS',chain"
SecRule ARGS_GET "@contains attack" ""
"#).unwrap();
    assert_eq!(matches(&ms, "/api?json.content=attack"), ["1"]);
    assert_eq!(matches(&ms, "/api?other=attack"), ["1", "2"]);
    assert_eq!(matches(&ms, "/other?json.content=attack"), ["2"]);
}

#[test]
fn runtime_tag_exclusion_matches_regex_against_folded_member_names() {
    let ms = ModSecurity::from_string(&format!(
        r#"
SecAction "id:1,phase:1,pass,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:/^token_/"
{RULES}
"#
    ))
    .unwrap();
    assert_eq!(matches(&ms, "/?token_123=secret"), ["1", "12"]);
    assert_eq!(matches(&ms, "/?Token_123=secret"), ["1", "12"]);
}

#[test]
fn invalid_configure_time_targets_fail_loading() {
    for target in ["!TYPO:password", "!ARGS:/[/"] {
        assert!(
            ModSecurity::from_string(&format!(
                "{RULES}\nSecRuleUpdateTargetByTag attack-sqli \"{target}\""
            ))
            .is_err(),
            "invalid target {target}"
        );
    }
}

#[test]
fn runtime_tag_match_is_exact_and_case_sensitive() {
    for tag in ["attack-SQLi", "sqli", "attack-.*"] {
        let ms = ModSecurity::from_string(&format!(
            r#"
SecAction "id:1,phase:1,pass,ctl:ruleRemoveTargetByTag={tag};ARGS:password"
{RULES}
"#
        ))
        .unwrap();
        assert_eq!(matches(&ms, "/?password=secret"), ["1", "10", "11", "12"]);
    }
}

#[test]
fn malformed_runtime_targets_are_reported_as_unsupported_at_load() {
    use zentinel_modsec::engine::control::unsupported_controls;
    use zentinel_modsec::parser::parse_actions;
    for value in [
        "attack-sqli",
        ";ARGS:x",
        "attack-sqli;TYPO:x",
        "attack-sqli;ARGS:/[/",
        "attack-sqli;&ARGS:x",
        "attack-sqli;ARGS:x|ARGS:y",
    ] {
        let actions = parse_actions(&format!("id:1,ctl:ruleRemoveTargetByTag={value}")).unwrap();
        assert_eq!(unsupported_controls(&actions).len(), 1, "{value}");
    }
}

#[test]
fn excluding_every_scalar_target_does_not_invert_a_negated_operator() {
    let ms = ModSecurity::from_string(
        r#"
SecRuleEngine DetectionOnly
SecAction "id:1,phase:1,pass,ctl:ruleRemoveTargetByTag=attack-sqli;REQUEST_URI"
SecRule REQUEST_URI "!@contains impossible" "id:2,phase:1,pass,tag:'attack-sqli'"
"#,
    )
    .unwrap();
    assert_eq!(matches(&ms, "/"), ["1"]);
}

#[test]
fn mixed_id_and_tag_updates_keep_directive_order() {
    let ms = ModSecurity::from_string(
        r#"
SecRule ARGS:old "@contains secret" "id:10,phase:2,pass,tag:'attack-sqli'"
SecRuleUpdateTargetByTag attack-sqli "ARGS:middle" "ARGS:old"
SecRuleUpdateTargetById 10 "ARGS:new" "ARGS:middle"
"#,
    )
    .unwrap();
    assert!(matches(&ms, "/?old=secret&middle=secret").is_empty());
    assert_eq!(matches(&ms, "/?new=secret"), ["10"]);
}
