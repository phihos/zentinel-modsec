//! Cross-phase flow in Coraza's tagged evaluator.
use zentinel_modsec::{parser::Parser, CompiledRuleset, ModSecurity};

#[test]
fn skip_after_resumes_at_an_earlier_marker_on_the_next_phase() {
    for (marker, expected_status) in [("SecMarker before", Some(409)), ("", None)] {
        let mut parser = Parser::new();
        parser
            .parse(&format!(
                r#"
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS_POST:a "@streq green" "id:10501,phase:2,deny,status:412"
{marker}
SecRule REQUEST_METHOD "@streq POST" "id:10502,phase:1,pass,skipAfter:before"
SecRule ARGS_POST:b "@streq green" "id:10503,phase:2,deny,status:409"
"#
            ))
            .unwrap();
        let rules = CompiledRuleset::compile_multiphase(parser.into_directives()).unwrap();
        let mut tx = ModSecurity::new(rules).new_transaction();
        tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
            .unwrap();
        tx.process_request_headers().unwrap();
        tx.append_request_body(b"a=green&b=green").unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx.intervention().map(|i| i.status), expected_status);
    }
}
