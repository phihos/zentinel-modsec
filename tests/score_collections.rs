use zentinel_modsec::{
    variables::{Collection, MutableCollection},
    ModSecurity,
};

#[test]
fn phase_completion_preserves_rule_owned_category_scores() {
    let ms = ModSecurity::from_string(
        r#"SecRuleEngine On
SecAction "id:1,phase:1,pass,setvar:tx.sql_injection_score=7,setvar:tx.xss_score=9"
SecRule TX:sql_injection_score "@eq 7" "id:2,phase:2,pass,setvar:tx.xss_score=+2""#,
    )
    .unwrap();
    let mut tx = ms.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.tx().get("sql_injection_score"), Some(vec!["7"]));
    assert_eq!(tx.tx().get("xss_score"), Some(vec!["9"]));
    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2"]);
    assert_eq!(tx.tx().get("xss_score"), Some(vec!["11"]));
}

#[test]
fn phases_do_not_create_unconfigured_scoring_variables() {
    let ms = ModSecurity::from_string(r#"SecAction "id:1,phase:1,pass""#).unwrap();
    let mut tx = ms.new_transaction();
    tx.process_request_headers().unwrap();
    for name in [
        "anomaly_score",
        "sql_injection_score",
        "xss_score",
        "rfi_score",
        "lfi_score",
        "rce_score",
        "php_injection_score",
        "session_fixation_score",
    ] {
        assert_eq!(tx.tx().get(name), None, "unexpected {name}");
    }
}

#[test]
fn legacy_score_accessor_reads_the_current_tx_value() {
    let ms = ModSecurity::from_string("").unwrap();
    let mut tx = ms.new_transaction();
    tx.tx_mut().set("anomaly_score".into(), "8".into());
    assert_eq!(tx.anomaly_score(), 8);
    tx.tx_mut().delete("anomaly_score");
    assert_eq!(tx.anomaly_score(), 0);
}
