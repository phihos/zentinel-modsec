//! Which values `ctl:ruleRemoveTargetById` and `ctl:ruleRemoveTargetByTag`
//! take from a rule, and which they leave.
//!
//! A removal names one variable. It can only take values of a target with that
//! variable, so a rule's other targets are inspected as if the removal were not
//! there. CRS 941010 puts this on almost every request: it removes
//! `REQUEST_FILENAME` from the rules tagged `xss-perf-disable`, whose other
//! targets (`ARGS`, the cookies, a few headers) must still be tested.

use zentinel_modsec::ModSecurity;

/// The header every request of these tests may carry.
const HEADER: &str = "X-Probe";

/// Whether rule 10 matched for a GET of `uri`, optionally with [`HEADER`] set.
fn rule_10_matches(rules: &str, uri: &str, header: Option<&str>) -> bool {
    let msc = ModSecurity::from_string(&format!("SecRuleEngine On\n{rules}")).expect("rules load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    if let Some(value) = header {
        tx.add_request_header(HEADER, value).unwrap();
    }
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.matched_rules().iter().any(|id| id == "10")
}

/// A phase 1 `SecAction` issuing `ctl`, followed by `rule` (which is rule 10).
fn with_ctl(ctl: &str, rule: &str) -> String {
    format!("SecAction \"id:1,phase:1,pass,nolog,ctl:{ctl}\"\n{rule}")
}

const ARGS_OR_HEADER: &str =
    r#"SecRule ARGS|REQUEST_HEADERS:X-Probe "@contains evil" "id:10,phase:2,pass,tag:'probe'""#;

#[test]
fn removing_a_collection_by_id_leaves_the_rule_its_other_targets() {
    let rules = with_ctl("ruleRemoveTargetById=10;ARGS", ARGS_OR_HEADER);
    assert!(!rule_10_matches(&rules, "/?a=evil", None));
    assert!(rule_10_matches(&rules, "/?a=ok", Some("evil")));
}

#[test]
fn removing_a_collection_by_tag_leaves_the_rule_its_other_targets() {
    let rules = with_ctl("ruleRemoveTargetByTag=probe;ARGS", ARGS_OR_HEADER);
    assert!(!rule_10_matches(&rules, "/?a=evil", None));
    assert!(rule_10_matches(&rules, "/?a=ok", Some("evil")));
}

#[test]
fn removing_one_key_leaves_the_other_keys_of_the_collection() {
    for ctl in [
        "ruleRemoveTargetById=10;ARGS:foo",
        "ruleRemoveTargetByTag=probe;ARGS:foo",
    ] {
        let rules = with_ctl(ctl, ARGS_OR_HEADER);
        assert!(!rule_10_matches(&rules, "/?foo=evil", None), "{ctl}");
        assert!(rule_10_matches(&rules, "/?bar=evil", None), "{ctl}");
        assert!(
            rule_10_matches(&rules, "/?foo=evil&bar=evil", None),
            "{ctl}"
        );
        assert!(rule_10_matches(&rules, "/?foo=evil", Some("evil")), "{ctl}");
    }
}

#[test]
fn a_removed_key_is_taken_from_a_regex_key_selection() {
    let rule = r#"SecRule ARGS:/^f/ "@contains evil" "id:10,phase:2,pass,tag:'probe'""#;
    for ctl in [
        "ruleRemoveTargetById=10;ARGS:foo",
        "ruleRemoveTargetByTag=probe;ARGS:foo",
    ] {
        let rules = with_ctl(ctl, rule);
        assert!(!rule_10_matches(&rules, "/?foo=evil", None), "{ctl}");
        assert!(rule_10_matches(&rules, "/?fab=evil", None), "{ctl}");
        assert!(!rule_10_matches(&rules, "/?bar=evil", None), "{ctl}");
    }
}

#[test]
fn a_removal_of_a_variable_the_rule_does_not_target_changes_nothing() {
    // The shape CRS 941010 leaves behind for a rule without REQUEST_FILENAME.
    for ctl in [
        "ruleRemoveTargetById=10;REQUEST_FILENAME",
        "ruleRemoveTargetByTag=probe;REQUEST_FILENAME",
    ] {
        let rules = with_ctl(ctl, ARGS_OR_HEADER);
        assert!(rule_10_matches(&rules, "/?a=evil", None), "{ctl}");
        assert!(rule_10_matches(&rules, "/?a=ok", Some("evil")), "{ctl}");
        assert!(!rule_10_matches(&rules, "/evil?a=ok", Some("ok")), "{ctl}");
    }
}

#[test]
fn a_removed_scalar_leaves_the_collections_beside_it() {
    // CRS 941010 and a rule tagged `xss-perf-disable`.
    let rule = r#"SecRule REQUEST_FILENAME|ARGS|REQUEST_HEADERS:X-Probe "@contains evil" "id:10,phase:2,pass,tag:'probe'""#;
    for ctl in [
        "ruleRemoveTargetById=10;REQUEST_FILENAME",
        "ruleRemoveTargetByTag=probe;REQUEST_FILENAME",
    ] {
        let rules = with_ctl(ctl, rule);
        assert!(!rule_10_matches(&rules, "/evil?a=ok", None), "{ctl}");
        assert!(rule_10_matches(&rules, "/evil?a=evil", None), "{ctl}");
        assert!(rule_10_matches(&rules, "/ok?a=ok", Some("evil")), "{ctl}");
    }
    assert!(rule_10_matches(rule, "/evil?a=ok", None));
}

#[test]
fn argument_keys_compare_exactly_and_header_keys_without_case() {
    let upper_arg = with_ctl("ruleRemoveTargetById=10;ARGS:FOO", ARGS_OR_HEADER);
    assert!(rule_10_matches(&upper_arg, "/?foo=evil", None));
    assert!(!rule_10_matches(&upper_arg, "/?FOO=evil", None));

    for ctl in [
        "ruleRemoveTargetById=10;REQUEST_HEADERS:x-probe",
        "ruleRemoveTargetByTag=probe;REQUEST_HEADERS:X-PROBE",
    ] {
        let rules = with_ctl(ctl, ARGS_OR_HEADER);
        assert!(!rule_10_matches(&rules, "/?a=ok", Some("evil")), "{ctl}");
        assert!(rule_10_matches(&rules, "/?a=evil", Some("evil")), "{ctl}");
    }
}

#[test]
fn a_tag_removal_applies_only_to_rules_carrying_the_tag() {
    let rules = with_ctl("ruleRemoveTargetByTag=other;ARGS", ARGS_OR_HEADER);
    assert!(rule_10_matches(&rules, "/?a=evil", None));
    let rules = with_ctl("ruleRemoveTargetByTag=PROBE;ARGS", ARGS_OR_HEADER);
    assert!(rule_10_matches(&rules, "/?a=evil", None));
}

#[test]
fn a_removal_applies_to_rules_evaluated_after_it() {
    // Issued in phase 2 ahead of the rule: applies. Issued behind it: does not.
    let ahead = format!(
        "SecAction \"id:1,phase:2,pass,nolog,ctl:ruleRemoveTargetById=10;ARGS\"\n{ARGS_OR_HEADER}"
    );
    assert!(!rule_10_matches(&ahead, "/?a=evil", None));
    let behind = format!(
        "{ARGS_OR_HEADER}\nSecAction \"id:1,phase:2,pass,nolog,ctl:ruleRemoveTargetById=10;ARGS\""
    );
    assert!(rule_10_matches(&behind, "/?a=evil", None));
}

#[test]
fn id_and_tag_removals_of_different_variables_combine() {
    let rules = format!(
        "SecAction \"id:1,phase:1,pass,nolog,ctl:ruleRemoveTargetById=10;ARGS:a\"\n\
         SecAction \"id:2,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=probe;REQUEST_HEADERS:X-Probe\"\n\
         {ARGS_OR_HEADER}"
    );
    assert!(!rule_10_matches(&rules, "/?a=evil", Some("evil")));
    assert!(rule_10_matches(&rules, "/?b=evil", Some("evil")));
}

#[test]
fn a_removal_adds_to_the_exclusions_the_rule_itself_declares() {
    let rule = r#"SecRule ARGS|!ARGS:x|REQUEST_HEADERS:X-Probe "@contains evil" "id:10,phase:2,pass,tag:'probe'""#;
    for ctl in [
        "ruleRemoveTargetById=10;ARGS:y",
        "ruleRemoveTargetByTag=probe;ARGS:y",
        // A removal of another variable leaves the rule's own exclusion alone.
        "ruleRemoveTargetByTag=probe;REQUEST_FILENAME",
    ] {
        let rules = with_ctl(ctl, rule);
        let removes_y = ctl.ends_with("ARGS:y");
        assert!(!rule_10_matches(&rules, "/?x=evil", None), "{ctl}");
        assert_eq!(
            rule_10_matches(&rules, "/?y=evil", None),
            !removes_y,
            "{ctl}"
        );
        assert!(rule_10_matches(&rules, "/?z=evil", None), "{ctl}");
    }
}

#[test]
fn a_count_leaves_out_removed_values_only_of_its_own_variable() {
    let two_args = r#"SecRule &ARGS "@eq 2" "id:10,phase:2,pass,tag:'probe'""#;
    let one_arg = r#"SecRule &ARGS "@eq 1" "id:10,phase:2,pass,tag:'probe'""#;
    let none = r#"SecRule &ARGS "@eq 0" "id:10,phase:2,pass,tag:'probe'""#;
    let uri = "/?foo=1&bar=2";
    for ctl in [
        "ruleRemoveTargetById=10;ARGS:foo",
        "ruleRemoveTargetByTag=probe;ARGS:foo",
    ] {
        assert!(rule_10_matches(&with_ctl(ctl, one_arg), uri, None), "{ctl}");
        assert!(
            !rule_10_matches(&with_ctl(ctl, two_args), uri, None),
            "{ctl}"
        );
    }
    for ctl in [
        "ruleRemoveTargetById=10;ARGS",
        "ruleRemoveTargetByTag=probe;ARGS",
    ] {
        assert!(rule_10_matches(&with_ctl(ctl, none), uri, None), "{ctl}");
    }
    for ctl in [
        "ruleRemoveTargetById=10;REQUEST_FILENAME",
        "ruleRemoveTargetByTag=probe;ARGS_NAMES",
    ] {
        assert!(
            rule_10_matches(&with_ctl(ctl, two_args), uri, None),
            "{ctl}"
        );
    }
}

#[test]
fn a_removed_value_is_left_out_at_every_multi_match_stage() {
    let rule = r#"SecRule ARGS|REQUEST_FILENAME "@contains evil" "id:10,phase:2,pass,multiMatch,t:none,t:urlDecodeUni,t:lowercase,tag:'probe'""#;
    for ctl in [
        "ruleRemoveTargetById=10;ARGS:foo",
        "ruleRemoveTargetByTag=probe;ARGS:foo",
    ] {
        let rules = with_ctl(ctl, rule);
        assert!(!rule_10_matches(&rules, "/?foo=EVIL", None), "{ctl}");
        assert!(rule_10_matches(&rules, "/?bar=EVIL", None), "{ctl}");
        assert!(rule_10_matches(&rules, "/EVIL?foo=EVIL", None), "{ctl}");
    }
    let rules = with_ctl("ruleRemoveTargetByTag=probe;REQUEST_FILENAME", rule);
    assert!(!rule_10_matches(&rules, "/EVIL?foo=ok", None));
    assert!(rule_10_matches(&rules, "/EVIL?foo=EVIL", None));
}
