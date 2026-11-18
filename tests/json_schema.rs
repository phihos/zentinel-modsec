use std::fs;
use tempfile::tempdir;
use zentinel_modsec::ModSecurity;

const SCHEMA: &str = r##"{"type":"object","required":["count"],"properties":{"count":{"$ref":"#/$defs/count"}},"$defs":{"count":{"type":"integer","minimum":1}}}"##;

#[test]
fn schemas_validate_target_bytes_or_json_captured_in_the_current_phase() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("policy.conf");
    fs::write(dir.path().join("payload.json"), SCHEMA).unwrap();
    fs::write(
        &config,
        r#"SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRule ARGS:q "@validateSchema payload.json" "id:1,phase:1,pass"
SecRule ARGS:q "@validateSchema payload.json" "id:2,phase:2,pass"
SecRule ARGS:q "!@validateSchema payload.json" "id:3,phase:2,pass""#,
    )
    .unwrap();
    let engine = ModSecurity::from_file(config.to_str().unwrap()).unwrap();
    fs::remove_file(dir.path().join("payload.json")).unwrap();
    for (q, body, expected) in [
        ("42", r#"{"count":2}"#, &["1", "3"][..]),
        ("", r#"{"count":0}"#, &["2"][..]),
        ("null", r#"{"count":"two"}"#, &["1", "2"][..]),
        ("", "", &["3"][..]),
        ("ordinary", "", &["1", "2"][..]),
    ] {
        let mut tx = engine.new_transaction();
        tx.process_uri(&format!("/?q={q}"), "POST", "HTTP/1.1")
            .unwrap();
        tx.add_request_header("Content-Type", "application/json")
            .unwrap();
        tx.process_request_headers().unwrap();
        tx.append_request_body(body.as_bytes()).unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx.matched_rules(), expected, "q={q:?} body={body:?}");
    }
}

#[test]
fn schema_files_and_references_stay_under_the_rule_directory() {
    let parent = tempdir().unwrap();
    let root = parent.path().join("policy");
    fs::create_dir(&root).unwrap();
    let config = root.join("policy.conf");
    let load = |path: &str| {
        fs::write(
            &config,
            format!(r#"SecRule ARGS "@validateSchema {path}" "id:1,phase:1,pass""#),
        )
        .unwrap();
        ModSecurity::from_file(config.to_str().unwrap())
    };
    fs::write(root.join("companion.json"), r#"{"type":"integer"}"#).unwrap();
    fs::write(root.join("local.json"), r#"{"$ref":"companion.json"}"#).unwrap();
    let mut tx = load("local.json").unwrap().new_transaction();
    tx.process_uri("/?a=one", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(tx.matched_rules(), ["1"]);
    fs::write(parent.path().join("outside.json"), "true").unwrap();
    for reference in [
        "../outside.json",
        "https://example.invalid/schema.json",
        "missing.json",
    ] {
        fs::write(
            root.join("local.json"),
            serde_json::json!({"$ref": reference}).to_string(),
        )
        .unwrap();
        assert!(load("local.json").is_err(), "{reference}");
    }
    fs::write(root.join("bad.json"), "{").unwrap();
    fs::write(root.join("bad-type.json"), r#"{"type":5}"#).unwrap();
    for path in [
        "../outside.json",
        "missing.json",
        "bad.json",
        "bad-type.json",
        "sample.xsd",
    ] {
        assert!(load(path).is_err(), "{path}");
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(parent.path().join("outside.json"), root.join("link.json"))
            .unwrap();
        assert!(load("link.json").is_err());
    }
}

#[test]
fn unconstrained_schema_accepts_deep_json_and_still_checks_raw_syntax() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("all.json"), "true").unwrap();
    let rule = dir.path().join("policy.conf");
    fs::write(
        &rule,
        r#"SecRule ARGS:q "@validateSchema all.json" "id:1,phase:1,pass""#,
    )
    .unwrap();
    let ms = ModSecurity::from_file(rule.to_str().unwrap()).unwrap();
    for (scalar, violation) in [
        (r#"{"k":"a\"b","n":45}"#, false),
        ("2e400", true),
        ("malformed", true),
    ] {
        let value = format!("{}{scalar}{}", "[".repeat(160), "]".repeat(160));
        let mut tx = ms.new_transaction();
        tx.process_uri(&format!("/?q={value}"), "GET", "HTTP/1.1")
            .unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(!tx.matched_rules().is_empty(), violation, "{scalar}");
    }
}

#[test]
fn compound_schemas_inspect_nested_fields_and_validate_the_discarded_tail() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("manifest.json"),
        r##"{
        "$defs":{"entry":{"type":"object","required":["kind","detail"],"properties":{
            "kind":{"enum":["book","album"]},
            "detail":{"anyOf":[{"const":{"label":[]}},{"type":"array","minItems":1}]}
        }}},
        "type":"object","required":["entries"],
        "properties":{"entries":{"type":"array","items":{"$ref":"#/$defs/entry"}}}
    }"##,
    )
    .unwrap();
    let rule = dir.path().join("policy.conf");
    fs::write(
        &rule,
        r#"SecRule ARGS:q "@validateSchema manifest.json" "id:1,phase:1,pass""#,
    )
    .unwrap();
    let engine = ModSecurity::from_file(rule.to_str().unwrap()).unwrap();
    let deep = format!("{}42{}", "[".repeat(240), "]".repeat(240));
    let out_of_range = format!("{}2e400{}", "[".repeat(240), "]".repeat(240));
    for (kind, detail, invalid) in [
        ("book", deep.clone(), false),
        ("unknown", deep.clone(), true),
        ("album", out_of_range, true),
        ("book", format!(r#"{{"label":{deep}}}"#), true),
        ("book", format!("{deep}X"), true),
        ("book", "[]".to_owned(), true),
    ] {
        let doc =
            format!(r#"{{"metadata":{deep},"entries":[{{"kind":"{kind}","detail":{detail}}}]}}"#);
        let mut tx = engine.new_transaction();
        tx.process_uri(&format!("/?q={doc}"), "GET", "HTTP/1.1")
            .unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(!tx.matched_rules().is_empty(), invalid, "{kind} {detail}");
    }
}

#[test]
fn deep_unique_items_compare_whole_values() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("distinct.json"),
        r#"{"type":"array","uniqueItems":true}"#,
    )
    .unwrap();
    let rule = dir.path().join("policy.conf");
    fs::write(
        &rule,
        r#"SecRule ARGS:q "@validateSchema distinct.json" "id:1,phase:1,pass""#,
    )
    .unwrap();
    let engine = ModSecurity::from_file(rule.to_str().unwrap()).unwrap();
    for (first, second, violation) in [
        ("1", "2", false),
        ("1", "1", true),
        ("1", "1.0", true),
        (r#"{"a":1,"b":"x"}"#, r#"{"b":"\u0078","a":1.0}"#, true),
        (r#"{"a":0,"a":1}"#, r#"{"a":1}"#, true),
        (r#"{"a":1}"#, r#"{"b":1}"#, false),
        ("-0.0", "0", true),
    ] {
        let nest = |value| format!("{}{value}{}", "[".repeat(160), "]".repeat(160));
        let doc = format!("[{},{}]", nest(first), nest(second));
        let mut tx = engine.new_transaction();
        tx.process_uri(&format!("/?q={doc}"), "GET", "HTTP/1.1")
            .unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(
            !tx.matched_rules().is_empty(),
            violation,
            "{first} vs {second}"
        );
    }
}
