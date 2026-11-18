use zentinel_modsec::variables::Collection;
use zentinel_modsec::ModSecurity;

#[test]
fn crs_method_and_multipart_charset_macros_read_arguments() {
    let engine = load_with_request_body(
        r#"SecRuleEngine DetectionOnly
SecAction "id:1,phase:2,pass,setvar:'tx.charset=|%{ARGS._charset_}|'"
SecRule TX:charset "@streq |utf-8|" "id:922100,phase:2,pass"
SecRule REQUEST_METHOD "@streq %{ARGS._method}" "id:920650,phase:2,pass""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/?_charset_=utf-8&_method=GET", "GET", "HTTP/1.1")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "922100", "920650"]);
}

#[test]
fn merged_args_use_first_value_in_get_then_post_order_with_folded_keys() {
    let engine = load_with_request_body(r#"SecRuleEngine DetectionOnly
SecAction "id:1,phase:2,pass,setvar:tx.merged=%{ARGS.foo},setvar:tx.get=%{args_get.foo},setvar:tx.post=%{ArGs_PoSt.foo},setvar:tx.upper=%{ARGS.Foo}""#).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/?foo=first&foo=second&Foo=upper", "POST", "HTTP/1.1")
        .unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.append_request_body(b"foo=third").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    for (key, value) in [
        ("merged", "first"),
        ("get", "first"),
        ("post", "third"),
        ("upper", "first"),
    ] {
        assert_eq!(tx.tx().get(key), Some(vec![value]));
    }
}

#[test]
fn a_known_but_absent_argument_preserves_the_macro_token_text() {
    // Coraza's macro token contains the collection/key text without %{...}.
    let engine =
        load_with_request_body(r#"SecAction "id:1,phase:1,pass,setvar:tx.missing=%{ARGS.absent}""#)
            .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.tx().get("missing"), Some(vec!["ARGS.absent"]));
}

// These positive body fixtures explicitly request inspection; the engine's
// bare defaults match Coraza and leave body access off.
fn load_with_request_body(config: &str) -> zentinel_modsec::Result<ModSecurity> {
    ModSecurity::from_string(&format!("SecRequestBodyAccess On\n{config}"))
}
