use zentinel_modsec::{
    engine::ruleset::{CompileOptions, CompiledRuleset},
    parser::Parser,
    ModSecurity,
};

fn run(pattern: &str, value: &str, options: CompileOptions) -> bool {
    let mut parser = Parser::new();
    parser
        .parse(&format!(
            r#"
        SecAction "id:1,phase:1,pass,setvar:tx.pattern=blue"
        SecRule REQUEST_HEADERS:Color "@rx {pattern}" "id:2,phase:1,deny"
    "#
        ))
        .unwrap();
    let rules = CompiledRuleset::compile_with_options(parser.into_directives(), options).unwrap();
    let mut tx = ModSecurity::new(rules).new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Color", value).unwrap();
    tx.process_request_headers().unwrap();
    tx.has_intervention()
}

#[test]
fn tagged_text_anchors_and_dotall() {
    let tagged = CompileOptions::CORAZA_SPOA;
    let value = "red\nblue\ngreen";
    assert!(!run("^blue$", value, tagged));
    assert!(run("(?m)^blue$", value, tagged));
    assert!(run("^red.*green$", value, tagged));
    assert!(run("^blue$", value, CompileOptions::default()));
}

#[test]
fn coraza_compiles_regex_operands_literally() {
    let tagged = CompileOptions::CORAZA_SPOA;
    assert!(run("^%{tx.pattern}$", "%{tx.pattern}", tagged));
    assert!(!run("^%{tx.pattern}$", "blue", tagged));
    assert!(run("^%{2}$", "%%", tagged));
    let native = CompileOptions::default();
    assert!(run("^%{tx.pattern}$", "red\nblue\ngreen", native));
    assert!(!run(
        "^%{tx.pattern}$",
        "red\nblue\ngreen",
        CompileOptions {
            no_regex_multiline: true,
            ..native
        }
    ));
}
