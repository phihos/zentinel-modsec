//! Differential cases checked against Coraza 3.8.1's encoding/xml processor.
use zentinel_modsec::variables::{Collection, RequestData};

fn parsed(body: &[u8]) -> (RequestData, Result<(), String>) {
    let mut request = RequestData::new();
    request.append_body(body);
    let result = request.parse_xml_body();
    (request, result)
}

fn text_values(body: &[u8]) -> Vec<String> {
    let (request, result) = parsed(body);
    result.unwrap();
    request
        .xml
        .get("/*")
        .unwrap_or_default()
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[test]
fn empty_elements_do_not_leave_open_parser_state() {
    for body in [
        b"<a/>".as_slice(),
        b"<a><empty/><b>value</b></a>".as_slice(),
    ] {
        let (request, result) = parsed(body);
        assert!(result.is_ok(), "{result:?}");
        assert!(request.body_error.is_none());
    }
}

#[test]
fn truncated_text_is_inspected_without_waiting_for_an_end_tag() {
    assert_eq!(text_values(b"<a><b>attack"), ["attack"]);
    assert_eq!(text_values(b"<a>attack<!--"), ["attack"]);
    assert!(text_values(b"<a q=\"unfinished").is_empty());
}

#[test]
fn text_tokens_follow_markup_and_cdata_boundaries() {
    assert_eq!(
        text_values(b"before<a>left<b>inside</b>right<![CDATA[cdata]]>tail<!--x-->last</a>after"),
        ["before", "left", "inside", "right", "cdata", "tail", "last", "after"]
    );
}

#[test]
fn adjacent_text_and_entity_fragments_stay_in_one_token() {
    assert_eq!(
        text_values(b"<a>UNION&#32;SELECT&amp;x</a>"),
        ["UNION SELECT&x"]
    );
}

#[test]
fn mismatched_ancestor_closures_are_tolerated_but_unrelated_end_tags_fail() {
    assert_eq!(text_values(b"<a><b>attack</a>"), ["attack"]);
    let (request, result) = parsed(b"<a>attack</unrelated>");
    assert!(result.is_err());
    assert!(request.body_error.is_some());
    assert_eq!(request.xml.count(), 0);
}

#[test]
fn custom_entity_literals_remain_inspectable_and_suppressed_content_is_an_error() {
    for (body, expected) in [
        (
            br#"<!DOCTYPE d [<!ENTITY p "secret">]><d>&p;</d>"#.as_slice(),
            "&p;",
        ),
        (b"<a>x&unknown;y</a>".as_slice(), "x&unknown;y"),
    ] {
        let (request, result) = parsed(body);
        assert!(
            result.is_err(),
            "the existing hidden-content protection must remain"
        );
        assert!(request.body_error.is_some());
        assert_eq!(request.xml.get("/*"), Some(vec![expected]));
        assert!(!request
            .xml
            .all()
            .iter()
            .any(|(_, value)| value.contains("secret")));
    }
    assert_eq!(text_values(b"<a>a&b</a>"), ["a&b"]);
}

#[test]
fn html4_named_entities_match_the_reference_without_html5_overdecoding() {
    assert_eq!(
        text_values(b"<a>x&nbsp;y&copy;z&lang;</a>"),
        ["x\u{a0}y\u{a9}z\u{2329}"]
    );
    let (request, result) = parsed(b"<a>&NotEqualTilde;</a>");
    assert!(result.is_err());
    assert_eq!(request.xml.get("/*"), Some(vec!["&NotEqualTilde;"]));
}

#[test]
fn unquoted_and_duplicate_attribute_values_remain_inspected() {
    for (body, expected) in [
        (b"<a q=attack/>".as_slice(), vec!["attack"]),
        (
            br#"<a q="attack" q="second"/>"#.as_slice(),
            vec!["attack", "second"],
        ),
    ] {
        let (request, result) = parsed(body);
        result.unwrap();
        assert_eq!(request.xml.get("//@*"), Some(expected));
    }
}

#[test]
fn numeric_null_illegal_controls_and_invalid_utf8_are_visible_errors() {
    for body in [
        b"<a>attack&#0;</a>".as_slice(),
        b"<a>&#1;</a>".as_slice(),
        b"<a>\xff</a>".as_slice(),
    ] {
        let (request, result) = parsed(body);
        assert!(result.is_err(), "{body:?}");
        assert!(request.body_error.is_some());
        assert_eq!(request.xml.count(), 0);
    }
}

#[test]
fn html_autoclose_elements_do_not_require_an_end_tag() {
    assert_eq!(
        text_values(b"<a>left<br>right<img>tail</a>"),
        ["left", "right", "tail"]
    );
}

#[test]
fn unsupported_declared_encodings_are_reported_instead_of_decoded_as_utf8() {
    let (request, result) = parsed(br#"<?xml version="1.0" encoding="ISO-8859-1"?><a>value</a>"#);
    assert!(result.is_err());
    assert!(request.body_error.is_some());
}

#[test]
fn a_bare_ampersand_in_an_attribute_does_not_swallow_a_later_reference() {
    let (request, result) = parsed(br#"<a q="a&bare &amp;tail" bool empty=""/>"#);
    result.unwrap();
    assert_eq!(
        request.xml.get("//@*"),
        Some(vec!["a&bare &tail", "bool", ""])
    );
}
