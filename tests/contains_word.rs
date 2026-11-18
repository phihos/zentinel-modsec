//! ModSecurity v3 @containsWord compatibility (Coraza 3.8.1 has no implementation).
use zentinel_modsec::operators::{compile_operator_bytes, create_operator};
use zentinel_modsec::parser::{OperatorName, OperatorSpec};
use zentinel_modsec::ModSecurity;

#[test]
fn literal_and_expanded_words_reject_adjacent_ascii_letters() {
    let spec = OperatorSpec {
        name: OperatorName::ContainsWord,
        negated: false,
        argument: "%{tx.word}".into(),
    };
    for (needle, input, matches) in [
        ("", b"".as_slice(), true),
        ("", b"report", true),
        ("report", b"", false),
        ("report", b"reports", false),
        ("report", b"xreport", false),
        ("report", b"xreporty", false),
        ("report", b"reports/report", true),
        ("report", b"Report", false),
        ("report", b"2report_3", true),
        ("report", b"(report)", true),
        ("report", b"\0report\xff", true),
        ("report", b"\xc3\xa9report\xc3\xa9", true),
        ("--", b"x---", true), // A later overlapping occurrence is eligible.
    ] {
        for op in [
            create_operator(OperatorName::ContainsWord, needle).unwrap(),
            compile_operator_bytes(&spec, needle.as_bytes()).unwrap(),
        ] {
            let result = op.execute_bytes(input).unwrap();
            assert_eq!(result.matched, matches, "{needle:?} in {input:?}");
            assert_eq!(
                result.matched_value.as_deref(),
                matches.then_some(needle.as_bytes())
            );
            if let Ok(text) = std::str::from_utf8(input) {
                assert_eq!(
                    op.execute(text).matched_value.as_deref(),
                    matches.then_some(needle)
                );
            }
        }
    }
}

#[test]
fn dynamic_binary_word_uses_original_bytes_and_exposes_the_matching_portion() {
    let engine = ModSecurity::from_string(
        r#"SecAction "id:1,phase:1,pass,setvar:tx.word=%{ARGS_GET.word}"
SecRule ARGS_GET:text "@containsWord %{tx.word}" "id:2,phase:2,pass""#,
    )
    .unwrap();
    for (uri, expected) in [
        ("/?word=%ff&text=x%ffy", None),
        ("/?word=%ff&text=x%ffy_%ff.", Some(b"\xff".as_slice())),
        ("/?word=&text=example", Some(b"".as_slice())),
    ] {
        let mut tx = engine.new_transaction();
        tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        let entry = tx
            .matched_data()
            .iter()
            .find(|d| d.rule_id.as_deref() == Some("2"));
        assert_eq!(
            entry.and_then(|d| d.matched_portion_bytes.as_deref()),
            expected
        );
    }
}

#[test]
fn literal_empty_and_negated_rules_preserve_match_decisions() {
    let engine = ModSecurity::from_string(
        r#"SecRule ARGS:q "@containsWord" "id:1,phase:2,pass"
SecRule ARGS:q "!@containsWord label" "id:2,phase:2,pass"
SecRule ARGS:q "@containsWord label" "id:3,phase:2,pass""#,
    )
    .unwrap();
    for (uri, id) in [("/?q=relabeled", "2"), ("/?q=label_2", "3")] {
        let mut tx = engine.new_transaction();
        tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx.matched_rules(), ["1", id]);
        assert_eq!(
            tx.matched_data()[0].matched_portion_bytes.as_deref(),
            Some(b"".as_slice())
        );
    }
}
