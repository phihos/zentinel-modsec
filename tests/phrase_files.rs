use std::fs;
use zentinel_modsec::variables::ByteCollection;
use zentinel_modsec::ModSecurity;

#[test]
fn nested_includes_resolve_each_list_at_its_declaring_rule_and_load_it_once() {
    let dir = tempfile::tempdir().unwrap();
    let child = dir.path().join("child");
    fs::create_dir(&child).unwrap();
    fs::write(child.join("list.data"), "short\nshort blue\n").unwrap();
    fs::write(
        child.join("rules.conf"),
        r#"SecRule ARGS:q "@pMf list.data" "id:1,phase:1,pass,capture""#,
    )
    .unwrap();
    let filename = "v%{TX.tenant}.data";
    let list = dir.path().join(filename);
    fs::write(&list, "# internal addresses\n192.0.2.8,2001:db8::/64\n").unwrap();
    let conf = dir.path().join("root.conf");
    fs::write(
        &conf,
        format!(
            r#"Include child/rules.conf
SecRule REMOTE_ADDR "@IpMatchF {filename}" "id:2,phase:1,pass"
SecRule ARGS:q "@pmFromFile child/list.data" "id:3,phase:1,pass"
SecRule REMOTE_ADDR "@ipMatchFromFile {filename}" "id:4,phase:1,pass"
"#
        ),
    )
    .unwrap();
    let engine = ModSecurity::from_file(conf.to_str().unwrap()).unwrap();
    fs::remove_file(list).unwrap();
    fs::remove_file(child.join("list.data")).unwrap();
    for addr in ["192.0.2.8", "2001:db8::a"] {
        let mut tx = engine.new_transaction();
        tx.set_client_addr(addr, 1234);
        tx.process_uri("/?q=SHORT+Blue%FFsHoRt", "GET", "HTTP/1.1")
            .unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules(), ["1", "2", "3", "4"]);
        assert_eq!(tx.tx().get_bytes(b"0").unwrap(), [b"SHORT Blue".as_slice()]);
        assert_eq!(tx.tx().get_bytes(b"1").unwrap(), [b"sHoRt".as_slice()]);
        assert_eq!(
            tx.matched_data()[0].matched_portion_bytes.as_deref(),
            Some(b"SHORT Blue".as_slice())
        );
    }
}

#[test]
fn missing_literal_includes_and_data_files_reject_the_load() {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("rules.conf");
    for directive in [
        "Include missing.data",
        r#"SecRule ARGS "@pmf missing.data" "id:1,pass""#,
        r#"SecRule ARGS "@ipMatchF missing.data" "id:1,pass""#,
    ] {
        fs::write(&conf, directive).unwrap();
        let error = ModSecurity::from_file(conf.to_str().unwrap())
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains(dir.path().join("missing.data").to_str().unwrap()),
            "{error}"
        );
    }
}

#[test]
fn capture_uses_the_leftmost_longest_occurrences_and_limits_slots_to_ten() {
    let engine =
        ModSecurity::from_string(r#"SecRule ARGS:q "@pm b abc" "id:1,phase:1,pass,capture""#)
            .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/?q=aBcbbBbbbbbbb", "GET", "HTTP/1.1")
        .unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.tx().get_bytes(b"0").unwrap(), [b"aBc".as_slice()]);
    assert_eq!(tx.tx().get_bytes(b"3").unwrap(), [b"B".as_slice()]);
    assert_eq!(tx.tx().get_bytes(b"9").unwrap(), [b"b".as_slice()]);
    assert!(tx.tx().get_bytes(b"10").is_none());
}

#[test]
fn binary_macro_operand_uses_the_same_phrase_order_and_capture_bytes() {
    let engine = ModSecurity::from_string(
        r#"SecRule ARGS:q "@pm %{ARGS.words}" "id:1,phase:1,pass,capture""#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/?q=%FEaBC%80&words=b+abc+%80", "GET", "HTTP/1.1")
        .unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.tx().get_bytes(b"0").unwrap(), [b"aBC".as_slice()]);
    assert_eq!(tx.tx().get_bytes(b"1").unwrap(), [&[0x80u8][..]]);
}
