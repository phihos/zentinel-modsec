use zentinel_modsec::variables::Collection;
use zentinel_modsec::ModSecurity;

#[test]
fn dotted_bounds_preserve_matches_at_each_transformation_stage() {
    let engine = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRule ARGS:q "@rx ^(abcde|a[.]b|/)$" "id:1,phase:1,pass,t:lowercase,multiMatch,capture"
SecRule ARGS:q "@pm abcde a.b /" "id:2,phase:1,pass,t:lowercase,multiMatch"
SecRule ARGS:q "@rx ^$" "id:3,phase:1,pass,t:normalizePath"
SecRule ARGS:q "@rx ^[.][.]$" "id:4,phase:1,pass,t:normalizePath"
SecRule ARGS:q "@rx ^a$" "id:5,phase:1,pass,t:normalizePath"
SecRule ARGS:q "@pm //" "id:6,phase:1,pass,t:normalizePath"
SecRule ARGS:q "@rx ^!$" "id:7,phase:1,pass,t:hexDecode"
SecRule ARGS:q "@pm !" "id:8,phase:1,pass,t:hexDecode""#,
    )
    .unwrap();
    for (input, expected) in [
        ("a.", &[][..]),
        ("A.B", &["1", "2"]),
        (".", &["3"]),
        ("..", &["4"]),
        ("./a", &["2", "5"]),
        ("/", &["1", "2", "6"]),
        ("21", &["7", "8"]),
    ] {
        let mut tx = engine.new_transaction();
        tx.process_uri(&format!("/?q={input}"), "GET", "HTTP/1.1")
            .unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules(), expected, "{input}");
        if input == "A.B" {
            assert_eq!(tx.tx().get("1"), Some(vec!["a.b"]));
            assert_eq!(tx.matched_data()[0].value_bytes, b"a.b");
        }
    }
}
