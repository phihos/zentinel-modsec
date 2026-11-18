use serde_json::json;
use std::fs;
use tempfile::tempdir;
use zentinel_modsec::ModSecurity;

fn check(schema: serde_json::Value) {
    let dir = tempdir().unwrap();
    let rule = dir.path().join("policy.conf");
    fs::write(dir.path().join("schema.json"), schema.to_string()).unwrap();
    fs::write(
        &rule,
        r#"SecRule REQUEST_HEADERS:Sample "@validateSchema schema.json" "id:1,phase:1,pass""#,
    )
    .unwrap();
    let engine = ModSecurity::from_file(rule.to_str().unwrap()).unwrap();
    for depth in [0, 160] {
        for (value, violation) in [("42", false), (r#""text""#, true)] {
            let doc = format!(
                r#"{{"v":{value},"tail":{}0{}}}"#,
                "[".repeat(depth),
                "]".repeat(depth)
            );
            let mut tx = engine.new_transaction();
            tx.add_request_header("Sample", &doc).unwrap();
            tx.process_request_headers().unwrap();
            assert_eq!(
                !tx.matched_rules().is_empty(),
                violation,
                "{schema} at {depth}"
            );
        }
    }
}

#[test]
fn pointers_reach_legacy_ids_with_fragments_at_any_instance_depth() {
    for draft in ["04", "06", "07"] {
        let id = if draft == "04" { "id" } else { "$id" };
        for child_id in ["file:///schemas/root.json#named", "root.json#named"] {
            check(json!({
                "$schema":format!("http://json-schema.org/draft-{draft}/schema#"),
                (id):"file:///schemas/root.json",
                "definitions":{
                    "amount":{"type":"string"},
                    "leaf":{(id):child_id,
                        "definitions":{"amount":{"type":"integer"}},
                        "allOf":[{"$ref":"#/definitions/amount"}]
                    }
                },
                "properties":{"v":{"$ref":"#/definitions/leaf"}}
            }));
        }
    }
}

#[test]
fn a_standard_vocabulary_declaration_preserves_deep_instance_checks() {
    for draft in ["2019-09", "2020-12"] {
        let base = format!("https://json-schema.org/draft/{draft}");
        check(json!({
            "$schema": format!("{base}/schema"),
            "$vocabulary":{(format!("{base}/vocab/core")):true,(format!("{base}/vocab/validation")):false},
            "properties":{"v":{"type":"integer"}}
        }));
    }
}
