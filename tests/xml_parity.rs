//! Coraza 3.8.1's XML contract: values in XML, markup is not HTTP arguments.
use zentinel_modsec::{engine::Transaction, ModSecurity};

fn transaction(rules: &str, uri: &str, content_type: &str, body: &[u8]) -> Transaction {
    let engine = ModSecurity::from_string(rules).unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri(uri, "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", content_type).unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    tx
}

const JAVA: &str = r#"SecRuleEngine DetectionOnly
SecRule ARGS|ARGS_NAMES|REQUEST_BODY|XML:/*|XML://@* "@rx java\.lang\.(?:runtime|processbuilder)" "id:944100,phase:2,pass,t:lowercase,setvar:tx.hits=+1""#;

#[test]
fn crs_944100_element_and_attribute_names_do_not_trigger_value_detection() {
    for body in [
        r#"<xml><java.lang.Runtime attribute_name="attribute_value">value</java.lang.Runtime></xml>"#,
        r#"<xml><element java.lang.Runtime="attribute_value">element_value</element></xml>"#,
        r#"<xml><java.lang.ProcessBuilder attribute_name="attribute_value">value</java.lang.ProcessBuilder></xml>"#,
        r#"<xml><element java.lang.ProcessBuilder="attribute_value">element_value</element></xml>"#,
    ] {
        let tx = transaction(JAVA, "/", "application/xml", body.as_bytes());
        assert!(
            tx.matched_rules().is_empty(),
            "{body}: {:?}",
            tx.matched_rules()
        );
    }
}

#[test]
fn actual_xml_values_are_inspected_once_without_duplicate_argument_or_raw_body_exposure() {
    use zentinel_modsec::variables::Collection;
    for body in [
        "<xml><element>java.lang.Runtime</element></xml>",
        r#"<xml><element a="java.lang.Runtime"/></xml>"#,
    ] {
        let tx = transaction(JAVA, "/", "application/xml", body.as_bytes());
        assert_eq!(tx.matched_rules(), ["944100"]);
        assert_eq!(tx.tx().get("hits"), Some(vec!["1"]));
    }
}

#[test]
fn namespace_declaration_values_remain_visible_to_xml_attribute_rules() {
    let tx = transaction(
        JAVA,
        "/",
        "application/xml",
        br#"<xml xmlns:p="java.lang.Runtime"><element>value</element></xml>"#,
    );
    assert_eq!(tx.matched_rules(), ["944100"]);
}

#[test]
fn xml_markup_does_not_create_arguments_but_real_query_arguments_remain() {
    let rules = r#"SecRuleEngine DetectionOnly
SecRule ARGS "@streq attack" "id:1,phase:2,pass"
SecRule ARGS_NAMES "@contains java.lang.Runtime" "id:2,phase:2,pass"
SecRule XML:/* "@streq value" "id:3,phase:2,pass""#;
    let tx = transaction(
        rules,
        "/?real=attack",
        "application/xml",
        b"<java.lang.Runtime>value</java.lang.Runtime>",
    );
    assert_eq!(tx.matched_rules(), ["1", "3"]);
}

#[test]
fn form_argument_names_cannot_impersonate_xml_storage() {
    let rules = r#"SecRuleEngine DetectionOnly
SecRule XML:/*|XML://@* "@contains attack" "id:1,phase:2,pass""#;
    let tx = transaction(
        rules,
        "/",
        "application/x-www-form-urlencoded",
        b"xml.a=attack&xml.a.%40id=attack",
    );
    assert!(tx.matched_rules().is_empty());
}

#[test]
fn xml_keeps_raw_acquired_bytes_without_exposing_them_as_request_body() {
    use zentinel_modsec::variables::RequestData;
    let body = b"<xml>value</xml>";
    let mut request = RequestData::new();
    request.append_body(body);
    request.parse_xml_body().unwrap();
    assert_eq!(request.body, body);
    let tx = transaction(
        r#"SecRule REQUEST_BODY "@contains <xml>" "id:1,phase:2,pass""#,
        "/",
        "application/xml",
        body,
    );
    assert!(tx.matched_rules().is_empty());
}

#[test]
fn public_body_is_empty_and_length_is_zero_for_structured_processors() {
    let rules = r#"SecRuleEngine DetectionOnly
SecRule REQUEST_BODY "@rx ^$" "id:1,phase:2,pass"
SecRule REQUEST_BODY_LENGTH "@streq 0" "id:2,phase:2,pass"
SecRule &REQUEST_BODY "@eq 1" "id:3,phase:2,pass"
SecRule &REQUEST_BODY_LENGTH "@eq 1" "id:4,phase:2,pass""#;
    for (content_type, body) in [
        ("application/xml", b"<x>value</x>".as_slice()),
        ("application/json", br#"{"x":"value"}"#.as_slice()),
        (
            "multipart/form-data; boundary=B",
            b"--B\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nvalue\r\n--B--\r\n"
                .as_slice(),
        ),
    ] {
        let tx = transaction(rules, "/", content_type, body);
        assert_eq!(tx.matched_rules(), ["1", "2", "3", "4"], "{content_type}");
    }
    let tx = transaction(rules, "/", "application/x-www-form-urlencoded", b"x=value");
    assert_eq!(tx.matched_rules(), ["3", "4"]);
}
