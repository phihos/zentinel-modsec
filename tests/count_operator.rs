//! Regression tests for the `&` (count) variable operator.
//!
//! Before the fix, `VariableSpec.count_mode` (the `&` prefix) was parsed but
//! never consulted during evaluation, so `SecRule &TX:x "@eq 0"` compared the
//! variable's *value* instead of its *count*. That broke stock OWASP CRS v4:
//! `901160`'s `&TX:allowed_methods "@eq 0"` never fired, `tx.allowed_methods`
//! stayed unset, and `911100`'s `!@within %{tx.allowed_methods}` then blocked
//! every request — including a plain `GET /`. See issue #12.

use zentinel_modsec::ModSecurity;

/// Load `rules`, run a plain `GET /` through phase 1, and report whether an
/// intervention (block/deny) fired.
fn blocked(rules: &str) -> bool {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.has_intervention()
}

#[test]
fn count_of_unset_var_is_zero() {
    // count of an UNSET var is 0 → `@eq 0` matches → deny fires
    assert!(blocked(
        "SecRuleEngine On\n\
         SecRule &TX:x \"@eq 0\" \"id:1,phase:1,deny\""
    ));
}

#[test]
fn count_of_var_set_once_is_one() {
    // count of a var SET once is 1 → `@eq 1` matches → deny fires
    assert!(blocked(
        "SecRuleEngine On\n\
         SecAction \"id:5,phase:1,pass,nolog,setvar:tx.x=v\"\n\
         SecRule &TX:x \"@eq 1\" \"id:1,phase:1,deny\""
    ));
}

#[test]
fn count_of_unset_var_does_not_equal_one() {
    // count 0 `@eq 1` must NOT match → no deny (guards the negative direction)
    assert!(!blocked(
        "SecRuleEngine On\n\
         SecRule &TX:x \"@eq 1\" \"id:1,phase:1,deny\""
    ));
}

#[test]
fn crs_style_method_enforcement_allows_get() {
    // The CRS default-init idiom: `901160`'s `&TX:allowed_methods "@eq 0"` must
    // fire so `tx.allowed_methods` gets set, so `911100` must NOT block a GET.
    assert!(!blocked(
        "SecRuleEngine On\n\
         SecRule &TX:allowed_methods \"@eq 0\" \"id:901160,phase:1,pass,nolog,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS'\"\n\
         SecRule REQUEST_METHOD \"!@within %{tx.allowed_methods}\" \"id:911100,phase:1,deny\""
    ));
}

#[test]
fn counted_duplicate_names_preserve_multimatch_captures_and_dynamic_operands() {
    use zentinel_modsec::variables::Collection;

    let engine = ModSecurity::from_string(
        r#"SecRuleEngine On
SecRule &REQUEST_HEADERS:X-Report "@rx ^(.+)$" "id:10,phase:1,pass,capture,multiMatch,t:hexEncode,setvar:tx.visits=+1"
SecRule &REQUEST_HEADERS:X-Report "@streq %{tx.0}" "id:11,phase:1,pass,t:hexEncode"
"#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    for _ in 0..12 {
        tx.add_request_header("X-Report", "page").unwrap();
    }
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["10", "11"]);
    assert_eq!(tx.tx().get("0"), Some(vec!["3132"]));
    assert_eq!(tx.tx().get("1"), Some(vec!["3132"]));
    assert_eq!(tx.tx().get("visits"), Some(vec!["2"]));
    assert_eq!(tx.matched_data()[0].variable, "REQUEST_HEADERS:x-report");
    assert_eq!(tx.matched_data()[0].value_bytes, b"12");
}
