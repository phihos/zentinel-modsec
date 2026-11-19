//! Regression cases for upstream libinjection semantics, shared by the Rust and C backends.

use zentinel_modsec::{libinjection, ModSecurity};

#[test]
fn quoted_numeric_sqli_is_detected() {
    // CRS 942100: the legacy heuristic misses this double-quoted context.
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

#[cfg(feature = "libinjection-ffi")]
mod differential {
    use super::libinjection;
    use std::{fs, path::PathBuf};

    fn agrees(input: &[u8]) -> bool {
        let sql = libinjection::rust::detect_sqli_bytes(input);
        let reference = libinjection::detect_sqli_bytes(input).unwrap();
        let xss = libinjection::rust::detect_xss_bytes(input);
        let html = libinjection::detect_xss_bytes(input).unwrap();
        sql.is_injection == reference.is_injection
            && sql.fingerprint == reference.fingerprint
            && xss.is_injection == html.is_injection
            && xss.fingerprint == html.fingerprint
    }

    #[test]
    fn all_short_byte_inputs() {
        assert!(agrees(b""));
        for first in 0..=u8::MAX {
            assert!(agrees(&[first]), "single byte {first}");
            for second in 0..=u8::MAX {
                assert!(agrees(&[first, second]), "byte pair {first}/{second}");
            }
        }
    }

    #[test]
    #[ignore = "requires the libinjection v4.0.2 data directory"]
    fn upstream_dataset() {
        let dir = PathBuf::from(
            std::env::var_os("LIBINJECTION_DATA_DIR").expect("LIBINJECTION_DATA_DIR"),
        );
        let mut count = 0;
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|ext| ext != "txt") {
                continue;
            }
            for (line, raw) in fs::read(&path).unwrap().split(|&b| b == b'\n').enumerate() {
                let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
                if raw.is_empty() || raw.starts_with(b"#") {
                    continue;
                }
                let form: Vec<_> = raw
                    .iter()
                    .map(|&b| if b == b'+' { b' ' } else { b })
                    .collect();
                let input: Vec<_> = percent_encoding::percent_decode(&form).collect();
                assert!(agrees(&input), "{} line {}", path.display(), line + 1);
                count += 1;
            }
        }
        assert_eq!(count, 167_646, "libinjection v4.0.2 upstream corpus size");
    }
}

#[test]
fn namespace_declarations_match_the_entire_attribute_name() {
    for (markup, expected) in [
        (r#"<doc xmlns:meta="urn:example"/>"#, false),
        (r#"<doc xmlns="urn:example"/>"#, true),
        (
            r#"<doc xmlns:meta="urn:example" style="color: red"/>"#,
            true,
        ),
    ] {
        assert_eq!(libinjection::is_xss(markup), expected, "{markup}");
    }
}
