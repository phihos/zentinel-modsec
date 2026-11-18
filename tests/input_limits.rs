use zentinel_modsec::variables::Collection;
use zentinel_modsec::ModSecurity;

fn observations(config: &str, query: &str, media_type: &str, body: &[u8]) -> Vec<String> {
    let config = format!("SecRequestBodyAccess On\n{config}");
    let engine = ModSecurity::from_string(&config).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri(&format!("/?{query}"), "POST", "HTTP/1.1")
        .unwrap();
    tx.add_request_header("Content-Type", media_type).unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    tx.matched_rules().iter().map(ToString::to_string).collect()
}

#[test]
fn argument_policy_counts_nonempty_pairs_and_repeated_values_independently_per_collection() {
    let rules = r#"SecArgumentsLimit 2
SecRule ARGUMENTS_LIMIT_REACHED "@eq 0" "id:10,phase:1,pass"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:11,phase:1,pass"
SecRule &ARGS_GET:x "@eq 2" "id:12,phase:1,pass"
SecRule ARGS_POST:x "@streq V%" "id:13,phase:2,pass"
SecRule ARGS_POST:x "@streq dropped" "id:14,phase:2,pass"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:15,phase:2,pass""#;
    let form = "application/x-www-form-urlencoded";
    assert_eq!(
        observations(rules, "x=1&X=2&&", form, b"x=V%&%78=two&&"),
        ["10", "12", "13"]
    );
    assert_eq!(
        observations(rules, "x=1&X=2&&", form, b"x=V%&=empty&&x=dropped"),
        ["10", "12", "13", "15"]
    );
    assert_eq!(
        observations(rules, "x=1&X=2&bare", form, b"x=V%"),
        ["11", "12", "13", "15"]
    );
    let long = format!("x={}&X=2&bare", "a".repeat(1100));
    assert_eq!(observations(rules, &long, form, b""), ["11", "12", "15"]);
}

#[test]
fn json_truncation_preserves_complete_prefix_and_checks_tail_syntax_and_depth() {
    let rules = r#"SecArgumentsLimit 2
SecRequestBodyJsonDepthLimit 2
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:20,phase:2,pass"
SecRule REQBODY_ERROR "@eq 1" "id:21,phase:2,pass"
SecRule &ARGS_POST:json.keep "@eq 2" "id:22,phase:2,pass"
SecRule ARGS_POST:json.late "@streq 3" "id:23,phase:2,pass"
SecRule ARGS_POST:json "@streq 2" "id:24,phase:2,pass""#;
    let json = "application/json";
    assert_eq!(
        observations(rules, "", json, br#"{"keep":1,"KEEP":2}"#),
        ["22"]
    );
    assert_eq!(
        observations(rules, "", json, br#"{"keep":1,"KEEP":2,"late":3}"#),
        ["20", "22"]
    );
    assert_eq!(
        observations(rules, "", json, br#"{"keep":1,"KEEP":2,"late":[[]]}"#),
        ["20", "21", "22"]
    );
    assert_eq!(
        observations(rules, "", json, br#"{"keep":1,"KEEP":2,"late":!}"#),
        ["21", "22"]
    );
    assert_eq!(observations(rules, "", json, b"[1,2]"), ["24"]);
    assert_eq!(observations(rules, "", json, b"[1,2,3]"), ["20"]);
    for body in [b"[1,2,]".as_slice(), b"[1,2,"] {
        assert_eq!(observations(rules, "", json, body), ["21", "24"]);
    }
}

#[test]
fn multipart_retains_all_parts_as_in_the_pinned_processor() {
    let rules = r#"SecArgumentsLimit 1
SecRule &ARGS_POST:x "@eq 2" "id:30,phase:2,pass"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 0" "id:31,phase:2,pass""#;
    let body = b"--form\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\na\r\n--form\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nb\r\n--form--\r\n";
    assert_eq!(
        observations(rules, "", "multipart/form-data; boundary=form", body),
        ["30", "31"]
    );
}

#[test]
fn configured_depth_limits_apply_without_recursing_on_the_thread_stack() {
    let config = r#"SecRequestBodyJsonDepthLimit 20000
SecResponseBodyJsonDepthLimit 7
SecRule REQBODY_ERROR "@eq 0" "id:40,phase:2,pass""#;
    let engine = ModSecurity::from_string(config).unwrap();
    assert_eq!(engine.ruleset().body_config().response_json_depth_limit, 7);
    // Empty objects add no flattened metadata or leaves.
    for (depth, expected) in [(20000, vec!["40"]), (20001, vec![])] {
        let document = format!(
            "{}{{}}{}",
            "{\"a\":".repeat(depth - 1),
            "}".repeat(depth - 1)
        );
        assert_eq!(
            observations(config, "", "application/json", document.as_bytes()),
            expected
        );
    }
}

#[test]
fn directives_reject_invalid_values_and_limit_flag_expands_in_macros() {
    for name in [
        "SecArgumentsLimit",
        "SecRequestBodyJsonDepthLimit",
        "SecResponseBodyJsonDepthLimit",
    ] {
        for bad in ["", "-1", "0", "unknown", "2 3", "9000000000000000000000000"] {
            assert!(ModSecurity::from_string(&format!("{name} {bad}")).is_err());
        }
    }
    let msc = ModSecurity::from_string(
        r#"SecArgumentsLimit 1
SecAction "id:1,phase:1,pass,setvar:'tx.limit=%{ARGUMENTS_LIMIT_REACHED}'""#,
    )
    .unwrap();
    for (query, value) in [("a", "0"), ("a&a", "1")] {
        let mut tx = msc.new_transaction();
        tx.process_uri(&format!("/?{query}"), "GET", "HTTP/1.1")
            .unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.tx().get("limit").unwrap(), [value]);
    }
}
