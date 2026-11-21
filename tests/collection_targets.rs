//! Which values a collection target resolves to, and in which order.
//!
//! Targets read the request's collections and TX in place rather than from a
//! copied list, so the selections are pinned here through what a rule
//! matched: a whole collection in insertion order with repeated keys, `ARGS`
//! as the query string followed by the body, a key, a `/regex/`, the `*_NAMES`
//! forms, and header and TX keys matched case-insensitively.

use zentinel_modsec::variables::Collection;
use zentinel_modsec::{ModSecurity, Transaction};

/// Run `target` against a request and return every value it resolved to, as
/// `name=value;`, in order.
fn resolved(target: &str) -> String {
    let rules = format!(
        "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,setvar:'tx.Alpha=1',setvar:'tx.beta=2',setvar:'tx.alps=3'\"\n\
         SecRule {target} \"@unconditionalMatch\" \"id:2,phase:2,pass,nolog,\
            setvar:'tx.seen=%{{tx.seen}}%{{MATCHED_VAR_NAME}}=%{{MATCHED_VAR}};'\""
    );
    let engine = ModSecurity::from_string(&rules).expect("rules load");
    let mut tx = engine.new_transaction();
    tx.process_uri("/p?b=1&a=2&b=3&Ab=4", "POST", "HTTP/1.1")
        .unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header("X-Dup", "one").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.add_request_header("x-dup", "two").unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(b"a=5&c=6").unwrap();
    tx.process_request_body().unwrap();
    seen(&tx)
}

fn seen(tx: &Transaction) -> String {
    tx.tx()
        .get("seen")
        .and_then(|v| v.first().map(|s| s.to_string()))
        .unwrap_or_default()
}

#[test]
fn a_whole_collection_is_read_in_insertion_order_with_repeated_keys() {
    assert_eq!(
        resolved("ARGS_GET"),
        "ARGS_GET:b=1;ARGS_GET:b=3;ARGS_GET:a=2;ARGS_GET:Ab=4;"
    );
    assert_eq!(resolved("ARGS_POST"), "ARGS_POST:a=5;ARGS_POST:c=6;");
}

#[test]
fn args_is_the_query_string_followed_by_the_body() {
    assert_eq!(
        resolved("ARGS"),
        "ARGS:b=1;ARGS:b=3;ARGS:a=2;ARGS:Ab=4;ARGS:a=5;ARGS:c=6;"
    );
    assert_eq!(resolved("ARGS:a"), "ARGS:a=2;ARGS:a=5;");
    assert_eq!(resolved("ARGS:/^[ac]$/"), "ARGS:a=2;ARGS:a=5;ARGS:c=6;");
}

#[test]
fn a_key_selects_its_values_and_argument_names_are_case_sensitive() {
    assert_eq!(resolved("ARGS_GET:b"), "ARGS_GET:b=1;ARGS_GET:b=3;");
    assert_eq!(resolved("ARGS_GET:ab"), "");
    assert_eq!(resolved("ARGS_GET:Ab"), "ARGS_GET:Ab=4;");
    assert_eq!(resolved("ARGS_GET:missing"), "");
}

#[test]
fn a_regex_selects_by_key() {
    assert_eq!(resolved("ARGS_GET:/^[aA]/"), "ARGS_GET:a=2;ARGS_GET:Ab=4;");
    assert_eq!(resolved("ARGS_GET:/^z/"), "");
    // A pattern that does not compile selects nothing.
    assert_eq!(resolved("ARGS_GET:/(/"), "");
}

#[test]
fn names_collections_give_one_entry_per_stored_value() {
    assert_eq!(
        resolved("ARGS_NAMES"),
        "ARGS_NAMES:b=b;ARGS_NAMES:b=b;ARGS_NAMES:a=a;ARGS_NAMES:Ab=Ab;ARGS_NAMES:a=a;ARGS_NAMES:c=c;"
    );
    assert_eq!(
        resolved("ARGS_GET_NAMES:/^[aA]/"),
        "ARGS_GET_NAMES:a=a;ARGS_GET_NAMES:Ab=Ab;"
    );
    assert_eq!(resolved("ARGS_GET_NAMES:/(/"), "");
    // A key selection on a names collection ignores case.
    assert_eq!(resolved("ARGS_GET_NAMES:AB"), "ARGS_GET_NAMES:Ab=Ab;");
}

#[test]
fn header_keys_are_matched_case_insensitively_and_named_as_written() {
    assert_eq!(
        resolved("REQUEST_HEADERS:X-DUP"),
        "REQUEST_HEADERS:X-DUP=one;REQUEST_HEADERS:X-DUP=two;"
    );
    assert_eq!(
        resolved("REQUEST_HEADERS:/^x-/"),
        "REQUEST_HEADERS:x-dup=one;REQUEST_HEADERS:x-dup=two;"
    );
}

#[test]
fn tx_keys_are_matched_case_insensitively_and_listed_lowercased() {
    assert_eq!(resolved("TX:ALPHA"), "TX:ALPHA=1;");
    assert_eq!(resolved("TX:missing"), "");
    assert_eq!(resolved("TX:/^al/"), "TX:alpha=1;TX:alps=3;");
    assert_eq!(resolved("TX:/^Al/"), "TX:alpha=1;TX:alps=3;");
    assert_eq!(resolved("&TX:/^al/"), "&Tx=2;");
}

#[test]
fn a_macro_reads_the_first_value_of_a_tx_variable_and_of_a_header() {
    let rules = "SecRuleEngine On\n\
        SecAction \"id:1,phase:1,pass,nolog,setvar:'tx.Limit=7'\"\n\
        SecRule REQUEST_URI \"@unconditionalMatch\" \"id:2,phase:1,pass,nolog,\
            setvar:'tx.seen=%{tx.LIMIT}/%{tx.missing}/%{request_headers.X-Dup}/%{request_headers.missing}'\"\n\
        SecRule ARGS:n \"@eq %{tx.limit}\" \"id:3,phase:1,pass,nolog\"";
    let engine = ModSecurity::from_string(rules).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/?n=7", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("X-Dup", "one").unwrap();
    tx.add_request_header("x-dup", "two").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(seen(&tx), "7//one/");
    assert_eq!(tx.matched_rules(), ["1", "2", "3"]);
}
