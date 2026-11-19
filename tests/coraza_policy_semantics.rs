use zentinel_modsec::{
    engine::ruleset::{CompileOptions, CompiledRuleset},
    parser::{Directive, Parser},
    ModSecurity,
};

fn compile(source: &str) -> zentinel_modsec::Result<CompiledRuleset> {
    let mut parser = Parser::new();
    parser.parse(source)?;
    CompiledRuleset::compile_with_options(parser.into_directives(), CompileOptions::CORAZA_SPOA)
}

#[test]
fn default_actions_are_validated_when_a_following_rule_uses_the_default_table() {
    let action = r#"SecAction "phase:1,id:2,pass""#;
    for invalid in [
        "phase:1,pass,t:lowercase",
        "phase:1,pass,t:none",
        "phase:1,pass,id:1",
        "pass",
        "phase:1",
        "phase:1,pass\nSecDefaultAction phase:1,deny",
    ] {
        let default = format!("SecDefaultAction {invalid}");
        assert!(compile(&default).is_ok(), "{invalid}");
        assert!(
            compile(&format!("{default}\n{action}")).is_err(),
            "{invalid}"
        );
    }
    assert!(compile(&format!(
        "SecDefaultAction phase:1,deny,status:418\n{action}"
    ))
    .is_ok());
}

#[test]
fn component_signatures_keep_coraza_argument_values_and_order() {
    assert!(compile("SecComponentSignature").is_err());
    let mut parser = Parser::new();
    parser.parse("SecComponentSignature \"catalog/1 (test)\"\nSecComponentSignature catalog/2 test\nSecComponentSignature \"\"").unwrap();
    let signatures: Vec<_> = parser
        .into_directives()
        .into_iter()
        .map(|d| {
            let Directive::SecComponentSignature(s) = d else {
                panic!("missing signature")
            };
            s
        })
        .collect();
    assert_eq!(signatures, ["catalog/1 (test)", "catalog/2 test", "\"\""]);
}

#[test]
fn normalized_uri_and_original_request_target_are_independently_available() {
    let rules = compile(
        r#"
            SecRule REQUEST_URI "@streq %{REQUEST_HEADERS.Expected}" "phase:1,id:10,pass,chain"
            SecRule REQUEST_URI_RAW "@streq %{REQUEST_HEADERS.Raw}" "chain"
            SecRule REQUEST_LINE "@streq %{REQUEST_HEADERS.Line}" "setvar:tx.ok=1"
            SecRule TX:ok "@streq 1" "phase:1,id:11,deny"
        "#,
    )
    .unwrap();
    let waf = ModSecurity::new(rules);
    for (raw, normalized) in [
        ("/catalog/café", "/catalog/caf%C3%A9"),
        ("/catalog/caf%C3%A9", "/catalog/caf%C3%A9"),
        ("/a![]/b?q=café#fragment", "/a![]/b?q=café"),
        ("/a%2fb/café?q=café", "/a/b/caf%C3%A9?q=café"),
        ("/bad%escape/café", "/bad%escape/café"),
        ("/a b?x=y", "/a%20b?x=y"),
        ("HTTP://example.org/café", "http://example.org/caf%C3%A9"),
        ("https:/café", "https:/caf%C3%A9"),
        ("*", "*"),
        ("HTTP:opaque", "http:opaque"),
    ] {
        let mut tx = waf.new_transaction();
        tx.process_uri(raw, "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("Expected", normalized).unwrap();
        tx.add_request_header("Raw", raw).unwrap();
        tx.add_request_header("Line", &format!("GET {raw} HTTP/1.1"))
            .unwrap();
        tx.process_request_headers().unwrap();
        assert!(tx.has_intervention(), "{raw}");
    }
}
