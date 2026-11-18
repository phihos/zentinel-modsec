use zentinel_modsec::variables::Collection;
use zentinel_modsec::ModSecurity;

#[test]
fn candidate_positions_are_preserved_and_the_eleventh_candidate_is_ignored() {
    let waf = ModSecurity::from_string(
        r#"
SecAction "id:1,phase:1,pass,setvar:tx.0=old"
SecRule REQUEST_HEADERS:Example "@validateNid cl [0-9Kk.-]+" "id:2,phase:1,pass,capture"
SecRule REQUEST_HEADERS:More "@validateNid cl [0-9Kk.-]+" "id:3,phase:1,pass"
SecRule REQUEST_HEADERS:Other "@validateNid us [0-9-]+" "id:4,phase:1,pass""#,
    )
    .unwrap();
    let mut tx = waf.new_transaction();
    tx.add_request_header("Example", "16100407-2 16100407-3 10727393-K")
        .unwrap();
    tx.add_request_header("More", &format!("{} 10727393-K", "1 ".repeat(10)))
        .unwrap();
    tx.add_request_header("Other", "000-12-3456 123-45-6789 200-01-0001")
        .unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2", "4"]);
    assert_eq!(tx.tx().get("0"), Some(vec!["old"]));
    assert_eq!(tx.tx().get("1"), Some(vec!["16100407-3"]));
    assert_eq!(tx.tx().get("2"), Some(vec!["10727393-K"]));
}

#[test]
fn unknown_country_missing_pattern_and_invalid_pattern_fail_rule_loading() {
    for spec in ["us", "US [0-9]+", "cl (", "zz .*"] {
        assert!(ModSecurity::from_string(&format!(
            r#"SecRule ARGS "@validateNid {spec}" "id:1,phase:1,pass""#
        ))
        .is_err());
    }
}
