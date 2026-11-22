//! A `%{...}` macro expands any variable the engine resolves, as libmodsecurity
//! does: a member of any collection (`%{ARGS._method}`, CRS 920650) and a bare
//! variable name (`%{REQUEST_METHOD}`), not only TX and request headers.

use zentinel_modsec::ModSecurity;

fn matched(rules: &str, method: &str, uri: &str) -> Vec<String> {
    let m = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.process_uri(uri, method, "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.matched_rules().to_vec()
}

#[test]
fn a_member_of_any_collection_expands() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:a \"@streq %{ARGS.b}\" \"id:1,phase:2,pass\"\n";
    assert_eq!(matched(rules, "GET", "/?a=x&b=x"), ["1"]);
    assert!(matched(rules, "GET", "/?a=x&b=y").is_empty());
}

#[test]
fn a_bare_variable_name_expands_to_the_variable() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:m \"@streq %{REQUEST_METHOD}\" \"id:1,phase:2,pass\"\n";
    assert_eq!(matched(rules, "POST", "/?m=POST"), ["1"]);
    assert!(matched(rules, "POST", "/?m=GET").is_empty());
}

/// CRS 920650 compares the method an override names with the request's.
#[test]
fn a_method_override_is_compared_with_the_request_method() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:_method \"!@streq %{REQUEST_METHOD}\" \"id:1,phase:2,pass\"\n";
    assert_eq!(matched(rules, "POST", "/?_method=DELETE"), ["1"]);
    assert!(matched(rules, "POST", "/?_method=POST").is_empty());
}

#[test]
fn a_bare_name_that_is_no_variable_still_reads_tx() {
    let rules = "SecRuleEngine On\n\
        SecAction \"id:9,phase:1,pass,nolog,setvar:tx.expected=yes\"\n\
        SecRule ARGS:v \"@streq %{expected}\" \"id:1,phase:2,pass\"\n";
    assert_eq!(matched(rules, "GET", "/?v=yes"), ["9", "1"]);
    assert_eq!(matched(rules, "GET", "/?v=no"), ["9"]);
}
