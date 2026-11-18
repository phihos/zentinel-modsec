use zentinel_modsec::ModSecurity;

#[test]
fn supported_forms_share_one_transaction_id() {
    let engine = ModSecurity::from_string(
        r#"SecRule UNIQUE_ID "@streq %{unique_id}" "id:1,phase:1,pass,msg:'%{UNIQUE_ID}'""#,
    )
    .unwrap();
    let mut explicit = engine.new_transaction_with_id("  connector-17  ");
    let mut generated = engine.new_transaction();
    let mut blank = engine.new_transaction_with_id(" \t ");
    assert_eq!(explicit.id(), "connector-17");
    for tx in [&generated, &blank] {
        assert_eq!(tx.id().len(), 19);
        assert!(tx.id().bytes().all(|b| b.is_ascii_alphabetic()));
    }
    assert_ne!(generated.id(), blank.id());
    for tx in [&mut explicit, &mut generated, &mut blank] {
        tx.set_record_rule_messages(true);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules(), ["1"]);
        assert_eq!(
            tx.rule_messages()[0].message.as_deref(),
            Some(tx.id().as_bytes())
        );
    }
}

#[test]
fn fixed_ids_select_both_sides_of_crs_fractional_sampling() {
    // The sampling calculation and exclusion from CRS 4.25.0 rules 901410 and 901450.
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine On
SecAction "id:1,phase:1,pass,setvar:tx.sampling_percentage=50"
SecRule UNIQUE_ID "@rx ^[a-f]*([0-9])[a-f]*([0-9])" "id:901410,phase:1,pass,capture,t:sha1,t:hexEncode,setvar:'tx.sampling_rnd100=%{TX.1}%{TX.2}'"
SecRule TX:sampling_rnd100 "!@lt %{tx.sampling_percentage}" "id:901450,phase:1,pass,ctl:ruleRemoveByTag=OWASP_CRS"
SecRule REQUEST_METHOD "@streq GET" "id:2,phase:1,deny,tag:OWASP_CRS""#,
    )
    .unwrap();
    for (id, inspected) in [("request-a", true), ("request-b", false)] {
        let mut tx = engine.new_transaction_with_id(id);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(tx.matched_rules().iter().any(|r| r == "901410"));
        assert_eq!(tx.intervention().is_some(), inspected);
    }
}
