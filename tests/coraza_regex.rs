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

#[test]
fn coraza_accepts_literal_braces_alongside_regex_syntax() {
    let tagged = CompileOptions::CORAZA_SPOA;
    for (pattern, value) in [
        ("^G[E]T{ok}$", "GET{ok}"),
        ("^c{01}$", "c{01}"),
        ("^cat{z$", "cat{z"),
        (r"^\x{41}{field}$", "A{field}"),
        ("^[{}]$", "{"),
        ("^c{2,3}$", "ccc"),
        ("^cat{2,}$", "catt"),
    ] {
        assert!(run(pattern, value, tagged), "{pattern}");
    }
    assert!(!run("^c{2,3}$", "c", tagged));
}

#[test]
fn word_assertions_use_ascii_boundaries_in_unicode_patterns() {
    let options = CompileOptions::CORAZA_SPOA;
    for (pattern, value, expected) in [
        (r"\bword\b", "éwordλ", true),
        (r"\bword\b", "sword", false),
        (r"\Bword", "éword", false),
        (r"\Bword", "_word", true),
        (r"^\p{Greek}+\bword$", "λword", true),
        (r"^\\\\bword$", r"\bword", true),
    ] {
        assert_eq!(run(pattern, value, options), expected, "{pattern} {value}");
    }
}
