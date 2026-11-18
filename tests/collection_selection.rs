use zentinel_modsec::ModSecurity;

#[test]
fn named_argument_selection_matches_the_pinned_reference() {
    // Coraza 3.8.1 default named maps, including its direct literal lookup for
    // ARGS_NAMES and folded exception matching. Preserve duplicate arrival order.
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule &ARGS:NaMe "@eq 3" "id:101,phase:1,pass,log"
SecRule &ARGS_NAMES:NaMe "@eq 3" "id:102,phase:1,pass,log"
SecRule &ARGS_NAMES:name "@eq 3" "id:103,phase:1,pass,log"
SecRule &ARGS:/^NAME$/ "@eq 0" "id:104,phase:1,pass,log"
SecRule &ARGS:/^name$/ "@eq 3" "id:105,phase:1,pass,log"
SecRule &ARGS|!ARGS:/^name$/ "@eq 1" "id:106,phase:1,pass,log"
SecRule &ARGS|!ARGS:NAME "@eq 1" "id:107,phase:1,pass,log"
SecAction "id:108,phase:1,pass,setvar:tx.first=%{ARGS.NAME}"
SecRule TX:first "@streq one" "id:109,phase:1,pass,log"
SecAction "id:110,phase:1,pass,ctl:ruleRemoveTargetByTag=example;ARGS:/^name$/"
SecRule &ARGS "@eq 1" "id:111,phase:1,pass,log,tag:example"
SecRule ARGS_NAMES:name "@streq NaMe" "id:112,phase:1,pass,log""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri(
        "/?Name=one&other=four&name=two&NaMe=three",
        "GET",
        "HTTP/1.1",
    )
    .unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(
        tx.matched_rules(),
        ["101", "103", "104", "105", "106", "107", "108", "109", "110", "111", "112"]
    );
}

#[test]
fn named_values_keep_unicode_spelling_and_lookup_order_in_text_and_bytes() {
    use zentinel_modsec::parser::{Selection, VariableName, VariableSpec};
    use zentinel_modsec::variables::{RequestData, ResponseData, TxCollection, VariableResolver};
    let mut req = RequestData::new();
    req.set_uri("/?Ärger=first&ärger=second");
    let response = ResponseData::new();
    let tx = TxCollection::new();
    let resolver = VariableResolver::new(&req, &response, &tx, None, &[], &[]);
    let spec = VariableSpec {
        name: VariableName::Args,
        selection: Some(Selection::Key("ÄRGER".into())),
        count_mode: false,
        exclusions: vec![],
    };
    assert_eq!(
        resolver.resolve(&spec),
        vec![
            ("ARGS:Ärger".into(), "first".into()),
            ("ARGS:ärger".into(), "second".into())
        ]
    );
    let mut excluded = spec.clone();
    excluded.exclusions.push("ARGS:Ärger".into());
    assert!(resolver.resolve_bytes(&excluded).is_empty());
}
