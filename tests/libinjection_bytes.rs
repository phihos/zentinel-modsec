//! Both detectors accept the original bytes without UTF-8 replacement.
use zentinel_modsec::libinjection;

#[test]
fn selected_backend_inspects_arbitrary_bytes_after_nul_and_invalid_utf8() {
    assert!(
        libinjection::detect_xss_bytes(b"\xff\x00<script>alert(1)</script>")
            .unwrap()
            .is_injection
    );
    assert!(
        libinjection::detect_sqli_bytes(b"-1839\" or \"1\"=\"2\xff")
            .unwrap()
            .is_injection
    );
    assert!(
        !libinjection::detect_sqli_bytes(b"/update-assets\xff\x00")
            .unwrap()
            .is_injection
    );
    assert!(
        !libinjection::detect_xss_bytes(b"plain\xff\x00text")
            .unwrap()
            .is_injection
    );
}

#[test]
fn both_backends_complete_binary_inspection_and_continue_the_phase() {
    let engine = zentinel_modsec::ModSecurity::from_string(
        r#"
SecRule ARGS:q "@detectXSS" "id:1,phase:1,pass"
SecRule ARGS:q "@detectSQLi" "id:2,phase:1,pass"
SecRule ARGS:q "@endsWith blue" "id:3,phase:1,pass"
"#,
    )
    .unwrap();
    let mut tx = engine.new_transaction();
    tx.process_uri("/?q=plain%ff%00blue", "GET", "HTTP/1.1")
        .unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["3"]);
}

#[test]
fn selected_backend_checks_raw_bytes() {
    for input in [&b"\xff<script>"[..], &b"<script>"[..]] {
        assert!(libinjection::detect_xss_bytes(input).unwrap().is_injection);
    }
}
