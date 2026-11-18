use zentinel_modsec::{
    variables::{
        ByteCollection, Collection, HashMapCollection, MutableCollection, RequestData, ResponseData,
    },
    ModSecurity,
};

#[test]
fn duplicate_request_headers_preserve_each_original_name_and_fold_lookup() {
    let ms=ModSecurity::from_string(r#"SecRuleEngine DetectionOnly
SecRule REQUEST_HEADERS:x-demo "@contains attack" "id:10,phase:1,pass,setvar:tx.last=%{MATCHED_VAR_NAME}"
SecRule REQUEST_HEADERS:/^X-DEMO$/ "@contains attack" "id:11,phase:1,pass"
SecRule REQUEST_HEADERS:/^\D+-\D+$/ "@contains attack" "id:12,phase:1,pass"
SecRule REQUEST_HEADERS:/(?-i)^x-demo$/ "@contains attack" "id:13,phase:1,pass"
SecRule REQUEST_HEADERS:/(?-i)^X-Demo$/ "@contains attack" "id:14,phase:1,pass"
SecRule REQUEST_HEADERS_NAMES "@streq X-Demo" "id:15,phase:1,pass""#).unwrap();
    let mut tx = ms.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("X-Demo", "attack-one").unwrap();
    tx.add_request_header("x-DeMo", "attack-two").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["10", "11", "12", "13", "15"]);
    assert_eq!(tx.matched_data()[0].variable, "REQUEST_HEADERS:X-Demo");
    assert_eq!(
        tx.tx().get_bytes(b"last"),
        Some(vec![&b"REQUEST_HEADERS:x-DeMo"[..]])
    );
}

#[test]
fn response_header_names_and_match_names_preserve_the_received_spelling() {
    let ms = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule RESPONSE_HEADERS:x-demo "@contains attack" "id:20,phase:3,pass"
SecRule RESPONSE_HEADERS:/^X-DEMO$/ "@contains attack" "id:21,phase:3,pass"
SecRule RESPONSE_HEADERS_NAMES "@streq X-Demo" "id:22,phase:3,pass""#,
    )
    .unwrap();
    let mut tx = ms.new_transaction();
    tx.add_response_header("X-Demo", "attack").unwrap();
    tx.add_response_header("x-DeMo", "other").unwrap();
    tx.add_response_header_bytes(b"Content-TYPE", b"text/plain")
        .unwrap();
    let mut response = ResponseData::new();
    response.add_header_bytes(b"Content-TYPE", b"text/plain");
    assert_eq!(response.content_type, "text/plain");
    tx.process_response_headers_with_status(200, "HTTP/1.1")
        .unwrap();
    assert_eq!(tx.matched_rules(), ["20", "21", "22"]);
    assert_eq!(
        tx.matched_data()[0].variable_bytes,
        b"RESPONSE_HEADERS:X-Demo"
    );
}

#[test]
fn header_exclusions_still_fold_keys_without_excluding_other_headers() {
    let ms = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecAction "id:1,phase:1,pass,ctl:ruleRemoveTargetById=10;REQUEST_HEADERS:X-DEMO,ctl:ruleRemoveTargetByTag=demo;REQUEST_HEADERS:/(?-i)^x-demo$/"
SecRule REQUEST_HEADERS "@contains attack" "id:10,phase:1,pass"
SecRule REQUEST_HEADERS "@contains attack" "id:11,phase:1,pass"
SecRule REQUEST_HEADERS "@contains attack" "id:12,phase:1,pass,tag:demo"
SecRuleUpdateTargetById 11 "!REQUEST_HEADERS:/(?-i)^x-demo$/""#,
    )
    .unwrap();
    for (other, expected) in [(false, vec!["1"]), (true, vec!["1", "10", "11", "12"])] {
        let mut tx = ms.new_transaction();
        tx.add_request_header("X-Demo", "attack").unwrap();
        tx.add_request_header("x-DeMo", "attack").unwrap();
        if other {
            tx.add_request_header("X-Other", "attack").unwrap();
        }
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules(), expected);
    }
}

#[test]
fn raw_name_alignment_survives_set_append_delete_and_binary_names() {
    let mut headers = RequestData::new();
    headers.add_header("X-Demo", "one");
    headers.add_header("x-DeMo", "two");
    assert_eq!(headers.headers.get("x-demo"), Some(vec!["one", "two"]));
    assert_eq!(
        headers.headers.all(),
        vec![("X-Demo", "one"), ("x-DeMo", "two")]
    );
    headers.headers.set("x-demo".into(), "replacement".into());
    headers.add_header("X-DEMO", "third");
    assert_eq!(
        headers.headers.all(),
        vec![("x-demo", "replacement"), ("X-DEMO", "third")]
    );
    headers.headers.delete("x-demo");
    headers.add_header_bytes(b"X-\xff", b"value");
    assert_eq!(
        headers.headers.all_bytes_with_names(),
        vec![(&b"x-\xff"[..], &b"X-\xff"[..], &b"value"[..])]
    );
    // Ordinary case-sensitive collections retain distinct binary/literal keys.
    let mut args = HashMapCollection::new();
    args.add_bytes(&b"\xff"[..], "binary");
    args.add("\\xff".into(), "literal".into());
    assert_eq!(args.count(), 2);
}
