use zentinel_modsec::ModSecurity;

#[test]
fn source_names_follow_the_member_that_matched_and_preserve_the_observed_spelling() {
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS "@streq query" "id:1,phase:2,pass"
SecRule ARGS "@streq body" "id:2,phase:2,pass"
SecRule ARGS_NAMES "@streq oRder" "id:3,phase:2,pass"
SecRule ARGS "@streq route" "id:4,phase:2,pass"
SecRule &ARGS "@eq 3" "id:6,phase:2,pass"
SecRule ARGS|!ARGS:order "@streq body" "id:7,phase:2,pass""#,
    )
    .unwrap();

    for (enabled, expected) in [
        (
            false,
            [
                "ARGS:Order",
                "ARGS:oRder",
                "ARGS_NAMES:oRder",
                "ARGS:Order",
                "ARGS",
            ],
        ),
        (
            true,
            [
                "ARGS_GET:Order",
                "ARGS_POST:oRder",
                "ARGS_POST_NAMES:oRder",
                "ARGS_PATH:Order",
                "ARGS",
            ],
        ),
    ] {
        let mut tx = engine.new_transaction();
        tx.set_source_qualified_argument_names(enabled);
        tx.process_uri("/shop?Order=query", "POST", "HTTP/1.1")
            .unwrap();
        tx.add_path_argument("Order", "route");
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
            .unwrap();
        tx.process_request_headers().unwrap();
        tx.write_request_body(b"oRder=body").unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx.matched_rules(), ["1", "2", "3", "4", "6"]);
        let names: Vec<_> = tx
            .matched_data()
            .iter()
            .map(|m| m.variable.as_str())
            .collect();
        assert_eq!(names, expected);
    }
}

#[test]
fn identical_keys_in_different_sources_use_the_first_matching_value() {
    let engine = ModSecurity::from_string(
        r#"SecRequestBodyAccess On
SecRule ARGS:label "@streq books" "id:10,phase:2,pass""#,
    )
    .unwrap();
    for (query, post, expected) in [
        ("books", "books", "ARGS_GET:label"),
        ("other", "books", "ARGS_POST:label"),
    ] {
        let mut tx = engine.new_transaction();
        tx.set_source_qualified_argument_names(true);
        tx.process_uri(&format!("/?label={query}"), "POST", "HTTP/1.1")
            .unwrap();
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
            .unwrap();
        tx.process_request_headers().unwrap();
        tx.write_request_body(format!("label={post}").as_bytes())
            .unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx.matched_data()[0].variable, expected);
    }
}

#[test]
fn decoded_json_keys_retain_the_post_source() {
    let engine = ModSecurity::from_string(
        r#"SecRequestBodyAccess On
SecAction "id:19,phase:1,pass,ctl:requestBodyProcessor=JSON"
SecRule ARGS "@streq books" "id:20,phase:2,pass""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.set_source_qualified_argument_names(true);
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/json")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.write_request_body(br#"{"Label":"books"}"#).unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(
        tx.matched_data().last().unwrap().variable,
        "ARGS_POST:json.Label"
    );
}
