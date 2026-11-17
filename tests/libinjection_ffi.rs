//! Regression cases for upstream libinjection semantics, selected by the feature.
#![cfg(feature = "libinjection-ffi")]

use zentinel_modsec::{libinjection, ModSecurity};

#[test]
fn quoted_numeric_sqli_is_detected() {
    // CRS 942100: the Rust approximation misses this double-quoted context.
    assert!(libinjection::is_sqli(r#"-1839" or "1"="2"#));
    assert!(libinjection::sqli_fingerprint(r#"-1839" or "1"="2"#).is_some());
}

#[test]
fn ordinary_path_is_not_sqli() {
    assert!(!libinjection::is_sqli("/update-assets"));
    assert!(!libinjection::is_sqli("Please update the table tomorrow"));
}

#[test]
fn html_parser_distinguishes_text_and_attributes() {
    assert!(!libinjection::is_xss("javascript:alert(1)"));
    assert!(!libinjection::is_xss("<p>Normal paragraph</p>"));
    assert!(libinjection::is_xss("<img src=x onerror=alert(1)>"));
    assert!(libinjection::is_xss("<a href='javascript:alert(1)'>"));
}

#[test]
fn length_aware_bridge_does_not_truncate_at_nul() {
    assert!(!libinjection::is_sqli(""));
    assert!(!libinjection::is_xss(""));
    assert!(libinjection::is_xss("\0<script>alert(1)</script>"));
    assert!(libinjection::is_xss("🙂\0<script>alert(1)</script>"));
}

#[test]
fn operators_use_the_selected_backend() {
    let ms = ModSecurity::from_string(
        r#"
SecRuleEngine DetectionOnly
SecRule ARGS "@detectSQLi" "id:942100,phase:2,pass,capture"
SecRule ARGS "@detectXSS" "id:941100,phase:2,pass"
"#,
    )
    .unwrap();
    for (uri, expected) in [
        ("/?x=-1839%22%20or%20%221%22=%222", vec!["942100"]),
        ("/?next=/update-assets", vec![]),
        ("/?x=javascript:alert(1)", vec![]),
        ("/?x=%3Cscript%3Ealert(1)%3C/script%3E", vec!["941100"]),
    ] {
        let mut tx = ms.new_transaction();
        tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx.matched_rules(), expected.as_slice(), "{uri}");
    }
}

#[test]
fn parallel_calls_keep_fingerprints_private() {
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..100 {
                    assert!(libinjection::is_sqli(r#"-1839" or "1"="2"#));
                    assert!(!libinjection::is_sqli("/update-assets"));
                    assert!(libinjection::is_xss("<svg onload=alert(1)>"));
                }
            });
        }
    });
}
