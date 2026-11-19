//! Accepted limitations must be visible before any request is processed.
use std::io::Write;
use std::sync::{Arc, Mutex};
use zentinel_modsec::ModSecurity;

#[derive(Clone)]
struct Log(Arc<Mutex<Vec<u8>>>);
impl Write for Log {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn load_logs(config: &str) -> (ModSecurity, String) {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let writer = Log(bytes.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || writer.clone())
        .finish();
    let engine =
        tracing::subscriber::with_default(subscriber, || ModSecurity::from_string(config).unwrap());
    let log = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
    (engine, log)
}

#[test]
fn placeholder_operators_report_the_affected_rule_at_load() {
    for operator in [
        "verifyCC",
        "verifySSN",
        "verifyCPF",
        "validateHash",
        "validateDTD",
        "rbl",
        "geoLookup",
        "gsbLookup",
        "inspectFile",
        "fuzzyHash",
        "rsub",
    ] {
        let (_, log) = load_logs(&format!(
            r#"SecRule ARGS "@{operator} example" "id:101,phase:2,pass""#
        ));
        assert!(
            log.contains("operator") && log.contains("rule_ids=101"),
            "{operator}: {log}"
        );
    }
}

#[test]
fn strmatch_and_geo_preserve_capture_slots() {
    use zentinel_modsec::variables::Collection;
    let (engine, log) = load_logs(
        r#"
SecAction "id:1,phase:1,pass,setvar:tx.0=prior,setvar:tx.needle=ET"
SecRule REQUEST_METHOD "@strmatch %{tx.needle}" "id:2,phase:1,pass,capture"
SecRule REQUEST_METHOD "@strmatch et" "id:3,phase:1,pass"
SecRule REQUEST_METHOD "@geoLookup" "id:4,phase:1,pass,capture"
SecRule REQUEST_METHOD "!@geoLookup" "id:5,phase:1,pass""#,
    );
    assert!(log.contains("leaves GEO empty") && log.contains("rule_ids=4"));
    assert!(!log.contains("StrMatch"));
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2", "4"]);
    assert_eq!(tx.tx().get("0"), Some(vec!["prior"]));
}

#[test]
fn ignored_transformations_are_reported_with_rule_ids() {
    for transform in ["parityEven7bit", "parityOdd7bit", "parityZero7bit"] {
        let (_, log) = load_logs(&format!(
            r#"SecRule ARGS "@contains attack" "id:103,phase:2,pass,t:{transform}""#
        ));
        assert!(
            log.contains("transformation") && log.contains("rule_ids=103"),
            "{transform}: {log}"
        );
    }
}

#[test]
fn ignored_actions_on_chain_children_name_the_chain_starter() {
    for action in [
        "initcol:ip=%{REMOTE_ADDR}",
        "setuid:user",
        "setsid:session",
        "expirevar:ip.x=10",
        "deprecatevar:ip.x=1/10",
        "exec:/bin/false",
        "prepend:text",
        "append:text",
        "sanitiseMatched",
        "proxy:example",
        "pause:10",
        "xmlns:x=http://example.com",
        "auditlog",
        "noauditlog",
        "log",
        "nolog",
    ] {
        let (_, log) = load_logs(&format!(
            r#"
SecRule REQUEST_METHOD "@streq GET" "id:104,phase:1,pass,chain"
SecRule ARGS "@contains attack" "{action}"
"#
        ));
        assert!(
            log.contains("action") && log.contains("rule_ids=104"),
            "{action}: {log}"
        );
        assert!(!log.contains("rule_ids=(no id)"), "{action}: {log}");
    }
}

#[test]
fn ignored_unknown_directives_name_ruleset_ids() {
    for directive in ["SecCollectionTimeout 1234", "SecUnknownExample On"] {
        let (_, log) = load_logs(&format!(
            r#"
{directive}
SecRule ARGS "@contains attack" "id:105,phase:2,pass"
SecRule ARGS "@contains attack" "id:106,phase:2,pass"
"#
        ));
        assert!(log.contains("rule_ids=105,106"), "{directive}: {log}");
    }
}

#[test]
fn mixed_supported_and_unsupported_targets_do_not_hide_the_gap() {
    let (_, log) = load_logs(r#"SecRule ARGS|TIME_EPOCH "@contains attack" "id:107,phase:2,pass""#);
    assert!(
        log.contains("TimeEpoch") && log.contains("rule_ids=107"),
        "{log}"
    );
}

#[test]
fn unsupported_macro_sources_name_the_affected_rule() {
    for config in [
        r#"SecRule ARGS "@contains %{rule.msg}" "id:108,phase:2,pass""#,
        r#"SecAction "id:108,phase:1,pass,setvar:tx.source=%{SESSION.member}""#,
        r#"SecAction "id:108,phase:1,pass,msg:'%{SESSION.member}'""#,
        r#"SecAction "id:108,phase:1,pass,logdata:'%{rule.msg}'""#,
    ] {
        let (_, log) = load_logs(config);
        assert!(
            log.contains("macro") && log.contains("rule_ids=108"),
            "{log}"
        );
    }
}

#[test]
fn supported_semantics_and_component_metadata_do_not_warn() {
    let (_, log) = load_logs(
        r#"
SecComponentSignature "example"
SecRule REQUEST_METHOD "@streq %{ReQuEsT_MeThOd}" "id:101,phase:1,pass,msg:'%{ARGS}',logdata:'%{ARGS_NAMES.item}',setvar:tx.source=%{REMOTE_ADDR},setvar:tx.copy=%{custom_name}"
SecAction "id:107,phase:2,allow:phase"
SecAction "id:108,phase:2,allow:request"
SecRule ARGS "@contains attack" "id:109,phase:2,pass,t:lowercase,setvar:tx.score=+1"
"#,
    );
    assert!(log.is_empty(), "{log}");
}

#[test]
fn supported_multi_match_does_not_warn_and_keeps_the_initial_match() {
    let (engine, log) =
        load_logs(r#"SecRule ARGS:x "@contains x" "id:1,phase:2,pass,multiMatch,t:uppercase""#);
    assert!(log.is_empty(), "{log}");
    let mut tx = engine.new_transaction();
    tx.process_uri("/?x=x", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["1"]);
}

#[test]
fn unsupported_sanitization_actions_already_fail_loading() {
    for action in [
        "sanitiseArg:x",
        "sanitiseRequestHeader:X-Test",
        "sanitiseResponseHeader:X-Test",
    ] {
        assert!(
            ModSecurity::from_string(&format!(r#"SecAction "id:110,phase:1,pass,{action}""#))
                .is_err()
        );
    }
}

#[test]
fn known_unsupported_controls_warn_only_during_loading() {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let writer = Log(bytes.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let engine =
            ModSecurity::from_string(r#"SecAction "id:111,phase:1,pass,ctl:auditLogParts=+Z""#)
                .unwrap();
        let loaded = bytes.lock().unwrap().clone();
        assert!(String::from_utf8_lossy(&loaded).contains("rule_ids=111"));
        for _ in 0..3 {
            let mut tx = engine.new_transaction();
            tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
            tx.process_request_headers().unwrap();
            tx.process_request_body().unwrap();
        }
        assert_eq!(
            *bytes.lock().unwrap(),
            loaded,
            "known limitations must not log per request"
        );
    });
}

#[test]
fn supported_action_update_does_not_warn() {
    let (_, log) = load_logs(
        r#"
SecRule ARGS "@contains attack" "id:112,phase:2,pass"
SecRuleUpdateActionById 112 "deny,status:403"
"#,
    );
    assert!(log.is_empty(), "{log}");
}

#[test]
fn invalid_variable_regexes_warn_before_evaluation() {
    for variables in ["ARGS:/[/", "ARGS|!ARGS:/[/"] {
        let (_, log) = load_logs(&format!(
            r#"SecRule {variables} "@contains attack" "id:113,phase:2,pass""#
        ));
        assert!(
            log.contains("variable-regex") && log.contains("rule_ids=113"),
            "{log}"
        );
    }
}

#[test]
fn malformed_id_target_controls_warn_before_evaluation() {
    for target in [
        "112;TYPO:key",
        "112;ARGS:/^key/",
        "112;&ARGS:key",
        "wrong;ARGS:key",
    ] {
        let (_, log) = load_logs(&format!(
            r#"SecAction "id:114,phase:1,pass,ctl:ruleRemoveTargetById={target}""#
        ));
        assert!(
            log.contains("ruleRemoveTargetById") && log.contains("rule_ids=114"),
            "{log}"
        );
    }
}

#[test]
fn oversized_variable_regex_programs_warn_at_load_even_with_negation() {
    // Valid syntax, but the Unicode character class repeated this many times
    // exceeds regex::Regex's default compiled program limit.
    let pattern = r"\w{100000}";
    assert!(matches!(
        regex::Regex::new(pattern),
        Err(regex::Error::CompiledTooBig(_))
    ));
    for variables in [
        format!("ARGS:/{pattern}/"),
        format!("ARGS|!ARGS:/{pattern}/"),
    ] {
        for operator in ["@contains attack", "!@contains attack"] {
            let (_, log) = load_logs(&format!(
                r#"SecRule {variables} "{operator}" "id:115,phase:2,pass""#
            ));
            assert!(
                log.contains("variable-regex") && log.contains("rule_ids=115"),
                "{variables}, {operator}: {log}"
            );
        }
    }
}

#[test]
fn supported_argument_macros_do_not_warn_and_read_present_values() {
    let (engine, log) = load_logs(
        r#"SecAction "id:1,phase:1,pass,setvar:tx.charset=%{ARGS._charset_}"
SecRule TX:charset "@streq utf-8" "id:2,phase:1,pass""#,
    );
    assert!(log.is_empty(), "{log}");
    let mut tx = engine.new_transaction();
    tx.process_uri("/?_charset_=utf-8", "GET", "HTTP/1.1")
        .unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2"]);
}

#[test]
fn supported_body_policy_does_not_warn_and_enforces_access() {
    let (engine, log) = load_logs(
        r#"SecRequestBodyAccess Off
SecResponseBodyAccess Off
SecRequestBodyLimit 4
SecResponseBodyLimit 4
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyLimitAction Reject
SecResponseBodyMimeType text/plain
SecRule ARGS_POST:x "@contains attack" "id:201,phase:2,pass""#,
    );
    assert!(log.is_empty(), "{log}");
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.write_request_body(b"x=attack").unwrap().consumed, 0);
    tx.process_request_body().unwrap();
    assert!(tx.matched_rules().is_empty());
}

#[test]
fn byte_only_selector_is_validated_in_the_runtime_dialect() {
    let (engine, log) =
        load_logs(r#"SecRule ARGS:/(?-u:^\xFF$)/ "@streq sample" "id:121,phase:1,pass""#);
    assert!(!log.contains("variable-regex"), "{log}");
    let mut tx = engine.new_transaction();
    tx.process_uri("/?%FF=sample", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["121"]);
}
