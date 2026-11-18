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

#[test]
fn missing_and_empty_keyed_macros_agree_in_operators_actions_and_messages() {
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecAction "id:1,phase:1,pass,setvar:'tx.void=%{REQUEST_HEADERS.X-Empty}',setvar:'tx.values=%{Tx.MiSsInG}|%{rEqUeSt_HeAdErS.X-MiSs}|%{TX.VOID}|%{ReQuEsT_HeAdErS.X-EMPty}'"
SecRule ARGS:whole "@streq %{Tx.MiSsInG}" "id:2,phase:1,pass,log,msg:'%{Tx.MiSsInG}|%{rEqUeSt_HeAdErS.X-MiSs}|%{TX.VOID}|%{ReQuEsT_HeAdErS.X-EMPty}',logdata:'%{MATCHED_VAR}'"
SecRule ARGS:part "@within %{Tx.MiSsInG}" "id:3,phase:1,pass"
SecRule ARGS:part "@within %{Tx.Void}" "id:4,phase:1,pass"
SecRule TX:values "@streq Tx.MiSsInG|rEqUeSt_HeAdErS.X-MiSs||" "id:5,phase:1,pass"
SecRule ARGS:header "@streq %{rEqUeSt_HeAdErS.X-MiSs}" "id:6,phase:1,pass"
SecRule TX:values "@streq %{Tx.VoId}Tx.MiSsInG|rEqUeSt_HeAdErS.X-MiSs||%{ReQuEsT_HeAdErS.X-EMPty}" "id:7,phase:1,pass"
SecRule ARGS:empty_part "@within %{Tx.Void}" "id:8,phase:1,pass""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.set_record_rule_messages(true);
    tx.process_uri(
        "/?whole=Tx.MiSsInG&part=MiSs&header=rEqUeSt_HeAdErS.X-MiSs&empty_part=Void",
        "GET",
        "HTTP/1.1",
    )
    .unwrap();
    tx.add_request_header("X-Empty", "").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2", "3", "5", "6", "7"]);
    let message = tx
        .rule_messages()
        .iter()
        .find(|m| m.rule_id == "2")
        .unwrap();
    assert_eq!(
        message.message.as_deref(),
        Some(b"Tx.MiSsInG|rEqUeSt_HeAdErS.X-MiSs||".as_slice())
    );
    assert_eq!(message.logdata.as_deref(), Some(b"Tx.MiSsInG".as_slice()));
}

// These positive body fixtures explicitly request inspection; the engine's
// bare defaults match Coraza and leave body access off.
fn load_with_request_body(config: &str) -> zentinel_modsec::Result<ModSecurity> {
    ModSecurity::from_string(&format!("SecRequestBodyAccess On\n{config}"))
}
