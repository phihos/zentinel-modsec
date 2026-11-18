use zentinel_modsec::ModSecurity;

#[test]
fn binary_macro_argument_comparisons_report_the_matched_portion() {
    let ms = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule ARGS:x "@rx (\xff)" "id:1,phase:2,pass,capture"
SecRule ARGS:y "@contains %{tx.1}" "id:2,phase:2,pass""#,
    )
    .unwrap();
    let mut tx = ms.new_transaction();
    tx.process_uri("/?x=%FF&y=pre%FFpost", "GET", "HTTP/1.1")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    let entry = tx
        .matched_data()
        .iter()
        .find(|entry| entry.rule_id.as_deref() == Some("2"))
        .unwrap();
    assert_eq!(entry.value_bytes, b"pre\xffpost");
    assert_eq!(entry.matched_portion_bytes, Some(vec![0xff]));
}

#[test]
fn dynamic_within_rebinds_after_a_binary_match_for_later_members_and_targets() {
    use zentinel_modsec::variables::ByteCollection;

    let engine = ModSecurity::from_string(
        r#"SecRuleEngine On
SecRule ARGS:a|ARGS:b "@within %{TX.Wanted}" "id:1,phase:2,pass,capture,setvar:tx.hits=+1,setvar:tx.wanted=next"
SecRule ARGS:b "!@within %{TX.missing}" "id:2,phase:2,pass""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.tx_mut().set_bytes("wanted", &[0xff][..]);
    tx.process_uri("/?a=miss&a=skip&a=%FF&a=next&b=next", "GET", "HTTP/1.1")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();

    assert_eq!(tx.matched_rules(), ["1", "2"]);
    assert_eq!(tx.tx().get_bytes(b"hits"), Some(vec![b"3".as_slice()]));
    assert_eq!(tx.tx().get_bytes(b"0"), Some(vec![b"next".as_slice()]));
    let matches = tx.matched_data();
    assert_eq!(matches[0].value_bytes, [0xff]);
    assert_eq!(
        matches[0].matched_portion_bytes.as_deref(),
        Some(&[0xff][..])
    );
    assert_eq!(matches[1].matched_portion_bytes, None);
}
