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

#[test]
fn nonargument_maps_and_json_count_metadata_match_the_pinned_reference() {
    let engine = ModSecurity::from_string(r#"SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecAction "id:200,phase:1,pass,setvar:'tx.ÜBER=cart',ctl:requestBodyProcessor=JSON"
SecRule TX:über "@streq cart" "id:201,phase:1,pass,log"
SecRule &REQUEST_COOKIES:THEME "@eq 2" "id:203,phase:1,pass,log,setvar:'tx.observed=%{MATCHED_VAR_NAME}'"
SecRule TX:observed "@streq REQUEST_COOKIES:theme" "id:204,phase:1,pass,log"
SecRule REQUEST_COOKIES_NAMES:THEME "@streq ThEmE" "id:205,phase:1,pass,log"
SecRule REQUEST_HEADERS:/^X-PROBE$/ "@streq green" "id:206,phase:1,pass,log"
SecRule REQUEST_HEADERS_NAMES:X-Probe "@streq X-Probe" "id:207,phase:1,pass,log"
SecRule ARGS:json.TITLE "@streq Bee" "id:208,phase:2,pass,log"
SecRule ARGS_POST:json.title "@streq Orange" "id:209,phase:2,pass,log"
SecRule ARGS_POST:json.title "@streq one" "id:210,phase:2,pass,log"
SecRule ARGS_NAMES:json.title "@streq json.TiTlE" "id:211,phase:2,pass,log"
SecRule &ARGS_POST:json.TITLE "@eq 2" "id:212,phase:2,pass,log,setvar:'tx.post_count_name=%{MATCHED_VAR_NAME}'"
SecRule TX:post_count_name "@streq ARGS_POST:json.TITLE" "id:213,phase:2,pass,log"
SecRule &ARGS_GET "@eq 0" "id:214,phase:2,pass,log,setvar:'tx.get_count_name=%{MATCHED_VAR_NAME}'"
SecRule TX:get_count_name "@streq ARGS_GET" "id:215,phase:2,pass,log"
SecRule RESPONSE_HEADERS_NAMES:X-Color "@streq X-Color" "id:216,phase:3,pass,log"
SecRule RESPONSE_CONTENT_TYPE "@streq text/plain" "id:217,phase:3,pass,log"
SecRule &REQUEST_HEADERS:/^X-PROBE$/ "@eq 1" "id:218,phase:1,pass,log,setvar:'tx.rx_name=%{MATCHED_VAR_NAME}'"
SecRule TX:rx_name "@streq REQUEST_HEADERS:/^x-probe$/" "id:219,phase:1,pass,log"
"#).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/json")
        .unwrap();
    tx.add_request_header("X-Probe", "green").unwrap();
    tx.add_request_header("Cookie", "ThEmE=light; theme=dark")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(br#"{"Title":"Bee","TiTlE":"Orange"}"#)
        .unwrap();
    tx.process_request_body().unwrap();
    tx.add_response_header("X-Color", "green").unwrap();
    tx.add_response_header("Content-Type", "text/plain; charset=utf-8")
        .unwrap();
    tx.process_response_headers_with_status(200, "HTTP/1.1")
        .unwrap();
    assert_eq!(
        tx.matched_rules(),
        [
            "200", "201", "203", "204", "205", "206", "207", "218", "219", "208", "209", "211",
            "212", "213", "214", "215", "216", "217"
        ]
    );
}

#[test]
fn tx_text_and_byte_access_share_unicode_lookup_and_arithmetic() {
    use zentinel_modsec::variables::{ByteCollection, Collection, MutableCollection, TxCollection};
    let mut tx = TxCollection::new();
    tx.set("ÜBER".into(), "4".into());
    assert_eq!(tx.count_key("Über"), 1);
    assert_eq!(tx.get_bytes("über".as_bytes()), Some(vec![b"4".as_slice()]));
    tx.increment("ÜbEr", 2);
    tx.increment_bytes("über".as_bytes(), 1);
    assert_eq!(tx.get("ÜBER"), Some(vec!["7"]));
    tx.delete_bytes("üBER".as_bytes());
    assert_eq!(tx.count(), 0);
}
