//! Compare TX writes with pinned Coraza v3.8.1 after whole-value macro expansion.
use zentinel_modsec::engine::Transaction;
use zentinel_modsec::ModSecurity;

/// Run `rules` against a request for `uri`.
fn run(rules: &str, uri: &str) -> Transaction {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx
}

fn tx_var(tx: &Transaction, name: &str) -> String {
    use zentinel_modsec::variables::Collection;
    tx.tx()
        .get(name)
        .and_then(|v| v.first().map(|s| s.to_string()))
        .unwrap_or_else(|| "-".to_string())
}

/// Rules that capture `capture` from the URI into `TX:0`, start `tx.n` at 10,
/// then run `setvar` on it.
fn with_capture(capture: &str, setvar: &str) -> String {
    format!(
        "SecRuleEngine On\n\
         SecRule REQUEST_URI \"@rx {capture}\" \"id:1,phase:1,pass,nolog,capture,setvar:tx.n=10\"\n\
         SecRule REQUEST_URI \"@rx {capture}\" \"id:2,phase:1,pass,nolog,capture,setvar:{setvar}\""
    )
}

#[test]
fn a_captured_negative_number_is_subtracted() {
    let rules = with_capture("-7$", "tx.n=%{tx.0}");
    assert_eq!(tx_var(&run(&rules, "/x-7"), "n"), "3");
}

#[test]
fn a_captured_positive_number_is_added() {
    let rules = with_capture("[+]7$", "tx.n=%{tx.0}");
    assert_eq!(tx_var(&run(&rules, "/x+7"), "n"), "17");
}

#[test]
fn add_and_subtract_macros_still_do_arithmetic() {
    // The sign of the operand is the operand's own: 10 + (-7), 10 - (-7).
    let add = with_capture("-7$", "tx.n=+%{tx.0}");
    assert_eq!(tx_var(&run(&add, "/x-7"), "n"), "3");
    let sub = with_capture("-7$", "tx.n=-%{tx.0}");
    assert_eq!(tx_var(&run(&sub, "/x-7"), "n"), "17");
    // And an unsigned operand, the CRS shape.
    let add = with_capture("7$", "tx.n=+%{tx.0}");
    assert_eq!(tx_var(&run(&add, "/x7"), "n"), "17");
    let sub = with_capture("7$", "tx.n=-%{tx.0}");
    assert_eq!(tx_var(&run(&sub, "/x7"), "n"), "3");
}

#[test]
fn a_literal_sign_is_unchanged() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@rx x\" \"id:1,phase:1,pass,nolog,setvar:tx.a=10,setvar:tx.a=+5,setvar:tx.b=10,setvar:tx.b=-5,setvar:tx.c=-5\"";
    let tx = run(rules, "/x");
    assert_eq!(tx_var(&tx, "a"), "15");
    assert_eq!(tx_var(&tx, "b"), "5");
    // `=-5` on an unset variable subtracts from 0, it does not assign -5.
    assert_eq!(tx_var(&tx, "c"), "-5");
}

#[test]
fn a_nonnumeric_signed_operand_is_stored_verbatim() {
    let add = with_capture("abc$", "tx.n=+%{tx.0}");
    assert_eq!(tx_var(&run(&add, "/xabc"), "n"), "+abc");
    let sub = with_capture("abc$", "tx.n=-%{tx.0}");
    assert_eq!(tx_var(&run(&sub, "/xabc"), "n"), "-abc");
    // As an assignment the text is kept as it is.
    let set = with_capture("abc$", "tx.n=%{tx.0}");
    assert_eq!(tx_var(&run(&set, "/xabc"), "n"), "abc");
}

#[test]
fn arithmetic_requires_the_entire_expanded_operand_to_be_numeric() {
    let add = with_capture("5abc$", "tx.n=+%{tx.0}");
    assert_eq!(tx_var(&run(&add, "/x5abc"), "n"), "+5abc");
    // The operand may also be built from macros and text.
    let sub = with_capture("[0-9]+", "tx.n=-%{tx.0}0");
    assert_eq!(tx_var(&run(&sub, "/x3"), "n"), "-20");
}

#[test]
fn a_missing_tx_operand_keeps_the_destination() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@rx x\" \"id:1,phase:1,pass,nolog,setvar:tx.n=10,setvar:tx.n=+%{tx.nosuch},setvar:tx.m=10,setvar:tx.m=-%{tx.nosuch}\"";
    let tx = run(rules, "/x");
    assert_eq!(tx_var(&tx, "n"), "10");
    assert_eq!(tx_var(&tx, "m"), "10");
}

#[test]
fn the_crs_score_shape_is_unchanged() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@rx x\" \"id:1,phase:1,pass,nolog,setvar:tx.critical_anomaly_score=5,setvar:tx.score=+%{tx.critical_anomaly_score},setvar:tx.score=+%{tx.critical_anomaly_score}\"";
    assert_eq!(tx_var(&run(rules, "/x"), "score"), "10");
}

#[test]
fn capture_clears_the_slots_the_match_did_not_fill() {
    // The first rule fills TX:1 and TX:2, the second only TX:1. In
    // libmodsecurity v3 TX:2 would keep the first rule's value
    // (`operators/rx.cc:104-113` stores, and never removes); this engine
    // clears it, so a later rule cannot read a leftover.
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@rx (a)(b)\" \"id:1,phase:1,pass,nolog,capture\"\n\
        SecRule REQUEST_URI \"@rx (a)\" \"id:2,phase:1,pass,nolog,capture,setvar:tx.one=%{tx.1},setvar:tx.two=%{tx.2}\"";
    let tx = run(rules, "/ab");
    assert_eq!(tx_var(&tx, "one"), "a");
    assert_eq!(tx_var(&tx, "two"), "tx.2");
}

#[test]
fn captures_clear_numeric_keys_written_through_the_public_tx_collection() {
    use zentinel_modsec::variables::{ByteCollection, MutableCollection};

    let engine = ModSecurity::from_string(
        r#"SecRule REQUEST_METHOD "@rx (GET)" "id:1,phase:1,pass,capture""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.tx_mut().set("9".into(), "old".into());
    tx.tx_mut().increment_bytes(b"7", 1);
    tx.tx_mut().set_bytes(&b"01"[..], "keep");
    tx.tx_mut().set_bytes(&b"7x"[..], "also keep");
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(
        tx.tx().all_bytes(),
        [
            (&b"01"[..], &b"keep"[..]),
            (b"7x", b"also keep"),
            (b"0", b"GET"),
            (b"1", b"GET")
        ]
    );
}

#[test]
fn only_nonempty_tx_destinations_load() {
    for action in [
        "ip.count=1",
        "!session.count",
        "count=1",
        "tx.=1",
        "tx.   =1",
        "tx.count=",
        "tx.count",
    ] {
        let rule = format!(r#"SecAction "id:10,phase:1,pass,setvar:'{action}'""#);
        assert!(ModSecurity::from_string(&rule).is_err(), "{action}");
    }
    use zentinel_modsec::{
        engine::CompiledRuleset,
        parser::{Action, DataAction, Directive, Parser},
    };
    let mut parser = Parser::new();
    parser
        .parse(r#"SecAction "id:1,phase:1,pass,setvar:tx.count=1""#)
        .unwrap();
    let mut directives = parser.into_directives();
    let Directive::SecAction(rule) = &mut directives[0] else {
        unreachable!()
    };
    let Some(Action::Data(DataAction::SetVar(write))) = rule.actions.last_mut() else {
        unreachable!()
    };
    write.collection = "ip".into();
    assert!(CompiledRuleset::compile(directives).is_err());
}

#[test]
fn plain_decimal_bytes_and_nonnumeric_prior_values_survive_replay() {
    use zentinel_modsec::variables::ByteCollection;
    let rules = r#"SecAction "id:1,phase:1,pass,setvar:tx.a=0003,setvar:tx.pad=0003,setvar:tx.word=green,setvar:tx.overflow=9223372036854775808,setvar:tx.empty=alpha,setvar:tx.f=1,setvar:tx.g=1,setvar:tx.h=1"
SecAction "id:2,phase:1,pass,setvar:tx.copy=%{tx.a},setvar:tx.a=+2,setvar:tx.word=-3,setvar:tx.overflow=+1,setvar:tx.literal=+1x,setvar:tx.missing=-%{tx.unknown},setvar:tx.saved=%{tx.unknown},setvar:tx.zero=+,setvar:tx.empty=+3""#;
    let engine = ModSecurity::from_string(rules).unwrap();
    for recording in [false, true] {
        let mut tx = engine.new_transaction();
        tx.set_record_setvar_effects(recording);
        tx.process_request_headers().unwrap();
        for (key, value) in [
            ("a", "5"),
            ("pad", "0003"),
            ("word", "green"),
            ("copy", "0003"),
            ("overflow", "9223372036854775808"),
            ("literal", "+1x"),
            ("saved", "tx.unknown"),
            ("zero", "0"),
            ("empty", "alpha"),
        ] {
            assert_eq!(
                tx.tx().get_bytes(key.as_bytes()),
                Some(vec![value.as_bytes()]),
                "{key}"
            );
        }
        assert!(tx.tx().get_bytes(b"missing").is_none());
        assert!(!tx
            .setvar_effects()
            .iter()
            .any(|effect| effect.rule_id == "2"
                && ["missing", "word", "overflow", "empty"].contains(&effect.key.as_str())));
    }
}

#[test]
fn signed_macro_copies_follow_prior_arithmetic_after_default_replay() {
    let rules = r#"SecAction "id:1,phase:1,pass,setvar:tx.operand=+green,setvar:tx.x=10,setvar:tx.a=1,setvar:tx.b=1,setvar:tx.c=1,setvar:tx.d=1,setvar:tx.e=1,setvar:tx.f=1"
SecAction "id:2,phase:1,pass,setvar:tx.text=%{tx.operand},setvar:tx.operand=5,setvar:tx.operand=-8,setvar:tx.x=%{tx.operand}""#;
    let engine = ModSecurity::from_string(rules).unwrap();
    for recording in [false, true] {
        let mut tx = engine.new_transaction();
        tx.set_record_setvar_effects(recording);
        tx.process_request_headers().unwrap();
        assert_eq!(tx_var(&tx, "text"), "+green");
        assert_eq!(tx_var(&tx, "x"), "7");
    }
}
