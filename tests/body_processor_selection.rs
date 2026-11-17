//! Pinned Coraza 3.8.1 processor selection and forceRequestBodyVariable.
use zentinel_modsec::{engine::Transaction, ModSecurity};

fn run(config: &str, content_type: Option<&str>, body: &[u8]) -> Transaction {
    let engine = load_with_request_body(config).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    if let Some(content_type) = content_type {
        tx.add_request_header("Content-Type", content_type).unwrap();
    }
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    tx
}

const TARGETS: &str = r#"
SecRuleEngine DetectionOnly
SecRule ARGS:key "@streq value" "id:10,phase:2,pass"
SecRule REQUEST_BODY "@contains key=value" "id:11,phase:2,pass"
SecRule REQUEST_BODY_LENGTH "@gt 0" "id:12,phase:2,pass"
SecRule REQBODY_PROCESSOR "@streq URLENCODED" "id:13,phase:2,pass"
SecRule REQBODY_PROCESSOR "@streq RAW" "id:14,phase:2,pass"
"#;

#[test]
fn unknown_or_missing_type_does_not_implicitly_parse_a_form() {
    for content_type in [
        None,
        Some(""),
        Some("text/plain"),
        Some("application/unknown"),
    ] {
        let tx = run(TARGETS, content_type, b"key=value");
        assert!(
            tx.matched_rules().is_empty(),
            "{content_type:?}: {:?}",
            tx.matched_rules()
        );
    }
}

#[test]
fn force_body_variable_uses_urlencoded_for_unknown_types_as_in_coraza_3_8_1() {
    let config =
        format!("SecAction \"id:1,phase:1,pass,ctl:forceRequestBodyVariable=On\"\n{TARGETS}");
    for content_type in [
        None,
        Some(""),
        Some("text/plain"),
        Some("application/unknown"),
    ] {
        let tx = run(&config, content_type, b"key=value");
        assert_eq!(
            tx.matched_rules(),
            ["1", "10", "11", "12", "13"],
            "{content_type:?}"
        );
    }
}

#[test]
fn explicit_raw_processor_exposes_bytes_without_inventing_form_arguments() {
    let config = format!("SecAction \"id:1,phase:1,pass,ctl:requestBodyProcessor=RAW\"\n{TARGETS}");
    let tx = run(&config, None, b"key=value");
    assert_eq!(tx.matched_rules(), ["1", "11", "12", "14"]);
}

#[test]
fn force_off_cancels_a_previous_force_on() {
    let config = format!("SecAction \"id:1,phase:1,pass,ctl:forceRequestBodyVariable=On,ctl:forceRequestBodyVariable=Off\"\n{TARGETS}");
    assert_eq!(run(&config, None, b"key=value").matched_rules(), ["1"]);
}

#[test]
fn forcing_body_variable_does_not_replace_a_structured_processor() {
    let config = format!(
        r#"
SecAction "id:1,phase:1,pass,ctl:forceRequestBodyVariable=On,ctl:requestBodyProcessor=XML"
{TARGETS}
SecRule XML:/* "@streq key=value" "id:15,phase:2,pass"
"#
    );
    assert_eq!(
        run(&config, None, b"<x>key=value</x>").matched_rules(),
        ["1", "15"]
    );
}

#[test]
fn crs_920640_missing_content_type_cases_observe_forced_body_length() {
    // Unmodified operators and selection of CRS 901340/920640. Bodies include
    // 920640-1's JSON request and the text/form shapes in -6/-7/-8/-10.
    let config = r#"
SecRuleEngine DetectionOnly
SecRule REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)" "id:901340,phase:1,pass,ctl:forceRequestBodyVariable=On"
SecRule REQUEST_BODY_LENGTH "@gt 0" "id:920640,phase:2,pass,t:none,chain"
SecRule &REQUEST_HEADERS:Content-Type "@eq 0" "t:none"
"#;
    for body in [
        br#"{"id_order":"select(sleep(10));"}"#.as_slice(),
        b"hello world",
        b"key=value",
        b"single",
    ] {
        assert!(
            run(config, None, body)
                .matched_rules()
                .iter()
                .any(|id| id == "920640"),
            "{body:?}"
        );
    }
    assert!(!run(config, None, b"")
        .matched_rules()
        .iter()
        .any(|id| id == "920640"));
    assert!(
        !run(config, Some("application/json"), br#"{"key":"value"}"#)
            .matched_rules()
            .iter()
            .any(|id| id == "920640")
    );
}

#[test]
fn explicitly_selected_processor_is_visible_before_empty_body_processing() {
    let engine = load_with_request_body(
        r#"SecRuleEngine DetectionOnly
SecAction "id:10,phase:1,pass,ctl:requestBodyProcessor=JSON"
SecRule REQBODY_PROCESSOR "@streq JSON" "id:11,phase:1,pass"
SecRule REQBODY_PROCESSOR "@streq JSON" "id:12,phase:2,pass,skip:1"
SecRule ARGS "@contains alert" "id:13,phase:2,pass""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/?testarg=alert", "POST", "HTTP/1.1")
        .unwrap();
    tx.add_request_header("Content-Type", "application/json")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["10", "11", "12"]);
}

// These positive body fixtures explicitly request inspection; the engine's
// bare defaults match Coraza and leave body access off.
fn load_with_request_body(config: &str) -> zentinel_modsec::Result<ModSecurity> {
    ModSecurity::from_string(&format!("SecRequestBodyAccess On\n{config}"))
}

#[test]
fn first_content_type_selects_form_processor_before_phase_one_even_when_empty() {
    for (first, second, expected) in [
        ("application/x-www-form-urlencoded", None, "URLENCODED"),
        (
            "\u{a0}Application/X-WWW-Form-Urlencoded; charset=UTF-8",
            Some("multipart/form-data; boundary=x"),
            "URLENCODED",
        ),
        (
            "multipart/form-data; boundary=x",
            Some("application/x-www-form-urlencoded"),
            "MULTIPART",
        ),
        ("text/plain", Some("application/x-www-form-urlencoded"), ""),
        ("application/json", None, ""),
    ] {
        let engine = load_with_request_body(&format!(
            r#"SecRule REQBODY_PROCESSOR "@streq {expected}" "id:1,phase:1,pass"
SecRule REQBODY_PROCESSOR "@streq {expected}" "id:2,phase:2,pass""#
        ))
        .unwrap();
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
        tx.add_request_header("Content-Type", first).unwrap();
        if let Some(second) = second {
            tx.add_request_header("content-type", second).unwrap();
        }
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx.matched_rules(), ["1", "2"], "{first:?}");
    }
}

#[test]
fn explicit_phase_one_ctl_overrides_the_automatic_header_processor() {
    let engine = load_with_request_body(r#"SecRule REQBODY_PROCESSOR "@streq URLENCODED" "id:1,phase:1,pass,ctl:requestBodyProcessor=JSON"
SecRule REQBODY_PROCESSOR "@streq JSON" "id:2,phase:1,pass"
SecRule REQBODY_PROCESSOR "@streq JSON" "id:3,phase:2,pass""#).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2", "3"]);
}

#[test]
fn opaque_content_type_suffix_does_not_hide_a_form_processor() {
    let engine = load_with_request_body(
        r#"SecRule REQBODY_PROCESSOR "@streq URLENCODED" "id:1,phase:1,pass"
SecRule ARGS_POST:x "@streq attack" "id:2,phase:2,pass""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header_bytes(
        b"Content-Type",
        b"\xc2\xa0application/x-www-form-urlencoded\xff",
    )
    .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(b"x=attack").unwrap();
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2"]);
}
