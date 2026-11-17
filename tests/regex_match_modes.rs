use zentinel_modsec::operators::{Operator, RxOperator};
use zentinel_modsec::ModSecurity;

#[test]
fn rx_defaults_enable_dotall_and_multiline() {
    let operator = RxOperator::new("^a.*b$").unwrap();
    assert!(operator.execute("prefix\na\nb\nsuffix").matched);
}

#[test]
fn explicit_global_and_scoped_flags_override_default_modes() {
    let input = "prefix\na\nb\nsuffix";
    for pattern in ["(?-s)^a.*b$", "(?-m)^a.*b$", "(?-sm:^a.*b$)"] {
        assert!(
            !RxOperator::new(pattern).unwrap().execute(input).matched,
            "{pattern}"
        );
    }
    assert!(
        RxOperator::new("(?sm)^a.*b$")
            .unwrap()
            .execute(input)
            .matched
    );
    assert!(
        RxOperator::new("(?s-m)^a.*b$")
            .unwrap()
            .execute("a\nb")
            .matched
    );
    assert!(
        !RxOperator::new("(?s-m)^a.*b$")
            .unwrap()
            .execute(input)
            .matched
    );
}

#[test]
fn different_inline_modes_remain_isolated_in_the_shared_cache() {
    let ordinary = RxOperator::new("^mode-a.*mode-b$").unwrap();
    let disabled = RxOperator::new("(?-sm)^mode-a.*mode-b$").unwrap();
    let repeated = RxOperator::new("^mode-a.*mode-b$").unwrap();
    let input = "prefix\nmode-a\nmode-b\nsuffix";
    assert!(ordinary.execute(input).matched);
    assert!(!disabled.execute(input).matched);
    assert!(repeated.execute(input).matched);
}

#[test]
fn exact_crs_php_comment_and_sql_newline_cases_match() {
    let engine =
        ModSecurity::from_string(include_str!("fixtures/crs-regex-defaults.conf")).unwrap();
    for (method, uri, body, id) in [
        (
            "GET",
            "/get?foo=exec%09%2f%2afoo%0d%0abar%2a%2f%09%20%28%29",
            "",
            "933160",
        ),
        ("POST", "/post", "var=newline%0A%5C' and 1", "942522"),
    ] {
        let mut tx = engine.new_transaction();
        tx.process_uri(uri, method, "HTTP/1.1").unwrap();
        if !body.is_empty() {
            tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
                .unwrap();
            tx.append_request_body(body.as_bytes()).unwrap();
        }
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        assert!(
            tx.matched_rules().iter().any(|actual| actual == id),
            "missing {id}"
        );
    }
}
