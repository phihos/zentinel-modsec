use zentinel_modsec::ModSecurity;

#[test]
fn filename_width_uses_the_decoded_path_and_preserves_transformed_matches() {
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule REQUEST_FILENAME "@rx ^(/a)$" "id:1,phase:1,pass,capture"
SecRule REQUEST_FILENAME "@rx ^(?-u:/\xFF)$" "id:2,phase:1,pass"
SecRule REQUEST_FILENAME "@pm //" "id:3,phase:1,pass,t:normalizePath,multiMatch"
SecRule REQUEST_FILENAME "@rx ^(/ascii)$" "id:4,phase:1,pass,t:lowercase,multiMatch,capture"
SecRule REQUEST_FILENAME "!@pm longword" "id:5,phase:1,pass""#,
    )
    .unwrap();
    for (uri, expected) in [
        ("/%61?long=sum", vec!["1", "5"]),
        ("/%ff", vec!["2", "5"]),
        ("/", vec!["3", "5"]),
        ("/ASC%49I", vec!["4", "5"]),
    ] {
        let mut tx = engine.new_transaction();
        tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules(), expected, "{uri}");
    }
}
