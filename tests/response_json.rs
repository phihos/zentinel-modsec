use std::fs;
use tempfile::tempdir;
use zentinel_modsec::variables::Collection;
use zentinel_modsec::ModSecurity;

#[test]
fn phase_three_selects_json_and_response_schema_takes_precedence() {
    let root = tempdir().unwrap();
    fs::write(
        root.path().join("reply.json"),
        r#"{"type":"object","required":["ok"],"properties":{"ok":{"const":true}}}"#,
    )
    .unwrap();
    let config = root.path().join("policy.conf");
    fs::write(
        &config,
        r#"SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType application/json
SecAction "id:10,phase:3,pass,ctl:responseBodyProcessor=json"
SecRule RES_BODY_PROCESSOR "@streq JSON" "id:11,phase:3,pass"
SecRule RESPONSE_ARGS:json.title "@streq Book" "id:12,phase:4,pass,setvar:tx.title=%{response_args.json.TITLE}"
SecRule &RESPONSE_ARGS:json.title "@eq 2" "id:13,phase:4,pass"
SecRule RESPONSE_BODY "@validateSchema reply.json" "id:14,phase:4,pass"
SecRule RESPONSE_CONTENT_LENGTH "@rx ^$" "id:15,phase:4,pass"
SecRule RESPONSE_BODY "@rx ^$" "id:16,phase:4,pass"
SecRule RES_BODY_ERROR "@streq 1" "id:17,phase:4,pass""#,
    )
    .unwrap();
    let engine = ModSecurity::from_file(config.to_str().unwrap()).unwrap();
    for (media, body, expected, stored) in [
        (
            "application/json",
            r#"{"title":"Book","Title":"Other","ok":true}"#,
            vec!["10", "11", "12", "13", "15", "16"],
            true,
        ),
        (
            "application/json",
            r#"{"ok":false}"#,
            vec!["10", "11", "14", "15", "16"],
            true,
        ),
        (
            "application/json",
            r#"{"title":"Book","bad":"#,
            vec!["10", "11", "12", "14", "15", "16", "17"],
            false,
        ),
        (
            "application/json",
            "",
            vec!["10", "11", "14", "15", "16", "17"],
            false,
        ),
        (
            "text/plain",
            r#"{"ok":true}"#,
            vec!["10", "11", "14", "15", "16"],
            false,
        ),
    ] {
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
        tx.add_request_header("Content-Type", "application/json")
            .unwrap();
        tx.process_request_headers().unwrap();
        tx.append_request_body(br#"{"ok":false}"#).unwrap();
        tx.process_request_body().unwrap();
        tx.add_response_header("Content-Type", media).unwrap();
        tx.process_response_headers_with_status(200, "HTTP/1.1")
            .unwrap();
        tx.append_response_body(body.as_bytes()).unwrap();
        tx.process_response_body().unwrap();
        tx.process_response_body().unwrap();
        if expected.contains(&"12") {
            assert_eq!(tx.tx().get("title").unwrap(), ["Book"]);
        }
        assert_eq!(tx.matched_rules(), expected, "{media} {body}");
        assert_eq!(
            tx.tx().get("json_response_body"),
            stored.then(|| vec![body])
        );
    }
}

#[test]
fn response_depth_and_argument_controls_leave_partial_fields_visible() {
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecResponseBodyAccess On
SecResponseBodyMimeType application/json
SecResponseBodyJsonDepthLimit 1
SecArgumentsLimit 1
SecAction "id:1,phase:3,pass,ctl:responseBodyProcessor=JSON"
SecRule RESPONSE_ARGS:json.a "@streq 1" "id:2,phase:4,pass"
SecRule RESPONSE_ARGS:json.b "@streq 2" "id:3,phase:4,pass"
SecRule ARGUMENTS_LIMIT_REACHED "@streq 1" "id:4,phase:4,pass"
SecRule RES_BODY_PROCESSOR_ERROR_MSG "@rx ." "id:5,phase:4,pass"
SecRule RES_BODY_ERROR_MSG "@beginsWith JSON:" "id:6,phase:4,pass""#,
    )
    .unwrap();
    for (body, ids) in [
        (r#"{"a":1,"b":2}"#, vec!["1", "2", "4"]),
        (r#"{"a":1,"b":{"c":2}}"#, vec!["1", "2", "4", "5", "6"]),
    ] {
        let mut tx = engine.new_transaction();
        tx.add_response_header("Content-Type", "application/json")
            .unwrap();
        tx.process_response_headers_with_status(200, "HTTP/1.1")
            .unwrap();
        tx.append_response_body(body.as_bytes()).unwrap();
        tx.process_response_body().unwrap();
        assert_eq!(tx.matched_rules(), ids);
    }
}

#[test]
fn response_json_requires_access_and_selection_before_phase_four() {
    let policy = r#"SecResponseBodyAccess ACCESS
SecResponseBodyMimeType application/json
SecAction "id:1,phase:PHASE,pass,ctl:responseBodyProcessor=JSON"
SecRule RESPONSE_ARGS:json.name "@streq book" "id:2,phase:4,pass"
SecRule RES_BODY_PROCESSOR "@streq JSON" "id:3,phase:4,pass"
SecRule RESPONSE_BODY "@contains book" "id:4,phase:4,pass""#;
    for (access, phase, ids) in [("Off", "3", vec!["1", "3"]), ("On", "4", vec!["1", "4"])] {
        let engine =
            ModSecurity::from_string(&policy.replace("ACCESS", access).replace("PHASE", phase))
                .unwrap();
        let mut tx = engine.new_transaction();
        tx.add_response_header("Content-Type", "application/json")
            .unwrap();
        tx.process_response_headers_with_status(200, "HTTP/1.1")
            .unwrap();
        tx.append_response_body(br#"{"name":"book"}"#).unwrap();
        tx.process_response_body().unwrap();
        assert_eq!(tx.matched_rules(), ids);
    }
}
