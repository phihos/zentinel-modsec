use std::fs;
use tempfile::tempdir;
use zentinel_modsec::ModSecurity;

const SCHEMA: &str = r##"{
  "type":"object",
  "properties":{"loose":{"$ref":"urn:local:tree"},"strict":{"$ref":"urn:local:strict"}},
  "$defs":{
    "tree":{"$id":"urn:local:tree","$dynamicAnchor":"node","type":"object",
      "properties":{"child":{"$dynamicRef":"#node"}}},
    "strict":{"$id":"urn:local:strict","$dynamicAnchor":"node","$ref":"urn:local:tree",
      "required":["checked"]}
  }
}"##;

#[test]
fn the_same_tree_uses_the_anchor_selected_by_its_entry_path() {
    let dir = tempdir().unwrap();
    let rule = dir.path().join("policy.conf");
    fs::write(dir.path().join("schema.json"), SCHEMA).unwrap();
    fs::write(
        &rule,
        r#"SecRule REQUEST_HEADERS:Sample "@validateSchema schema.json" "id:1,phase:1,pass""#,
    )
    .unwrap();
    let engine = ModSecurity::from_file(rule.to_str().unwrap()).unwrap();
    for depth in [2, 160] {
        for (entry, leaf, violation) in [
            ("loose", "{}", false),
            ("loose", "42", true),
            ("strict", r#"{"checked":true}"#, false),
            ("strict", "{}", true),
        ] {
            let tree = format!(
                "{}{leaf}{}",
                r#"{"checked":true,"child":"#.repeat(depth),
                "}".repeat(depth)
            );
            let document = format!(r#"{{"{entry}":{tree}}}"#);
            let mut tx = engine.new_transaction();
            tx.add_request_header("Sample", &document).unwrap();
            tx.process_request_headers().unwrap();
            assert_eq!(
                !tx.matched_rules().is_empty(),
                violation,
                "{entry} {leaf} at depth {depth}"
            );
        }
    }
}
