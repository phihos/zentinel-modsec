//! Local documents keep their retrieval URL and their declared resource ID.
use std::{fs, path::Path};
use tempfile::tempdir;
use zentinel_modsec::ModSecurity;

const A: &str = r##"{"$id":"scopes/a-resource.json","$ref":"#/$defs/node",
    "$defs":{"node":{"type":"object","required":["tag"],"properties":{
        "tag":{"const":"A"},"next":{"$ref":"b.json#node"}}}}}"##;
const B: &str = r##"{"$defs":{"entry":{"$anchor":"node","type":"object","required":["tag"],
    "properties":{"tag":{"const":"B"},"next":{"$ref":"../a.json#/$defs/node"}}}}}"##;

fn write_policy(root: &Path) -> std::path::PathBuf {
    fs::create_dir_all(root.join("nested/scopes")).unwrap();
    fs::write(root.join("entry.json"), r#"{"$ref":"nested/a.json"}"#).unwrap();
    fs::write(root.join("nested/a.json"), A).unwrap();
    fs::write(root.join("nested/scopes/b.json"), B).unwrap();
    let config = root.join("policy.conf");
    fs::write(
        &config,
        r#"SecRule REQUEST_HEADERS:Document "@validateSchema entry.json" "id:1,phase:1,pass""#,
    )
    .unwrap();
    config
}

fn nested(depth: usize, valid: bool) -> String {
    let mut data = String::new();
    for i in 0..depth {
        let tag = if i % 2 == 0 { "A" } else { "B" };
        let tag = if i + 1 == depth && !valid {
            "wrong"
        } else {
            tag
        };
        data.push_str(&format!(r#"{{"tag":"{tag}""#));
        if i + 1 != depth {
            data.push_str(r#","next":"#);
        }
    }
    data.extend(std::iter::repeat_n('}', depth));
    data
}

#[test]
fn file_scopes_anchors_and_mutual_references_survive_source_removal() {
    let dir = tempdir().unwrap();
    let config = write_policy(dir.path());
    let rules = ModSecurity::from_file(config.to_str().unwrap()).unwrap();
    fs::remove_dir_all(dir.path().join("nested")).unwrap();
    fs::remove_file(dir.path().join("entry.json")).unwrap();
    assert_alternating_tags(&rules);
}

#[test]
fn companion_documents_inherit_the_configured_draft_for_legacy_ids() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let config = write_policy(root);
    fs::write(
        root.join("entry.json"),
        r##"{"$schema":"http://json-schema.org/draft-04/schema#","$ref":"nested/a.json"}"##,
    )
    .unwrap();
    fs::write(
        root.join("nested/a.json"),
        r#"{"id":"scopes/a-id.json","type":"object","required":["tag"],
            "properties":{"tag":{"enum":["A"]},"next":{"$ref":"b.json"}}}"#,
    )
    .unwrap();
    fs::write(
        root.join("nested/scopes/b.json"),
        r#"{"type":"object","required":["tag"],
            "properties":{"tag":{"enum":["B"]},"next":{"$ref":"../a.json"}}}"#,
    )
    .unwrap();
    let rules = ModSecurity::from_file(config.to_str().unwrap()).unwrap();
    assert_alternating_tags(&rules);
}

fn assert_alternating_tags(rules: &ModSecurity) {
    for depth in [1, 2, 3, 4, 192] {
        for valid in [true, false] {
            let mut tx = rules.new_transaction();
            tx.add_request_header("Document", &nested(depth, valid))
                .unwrap();
            tx.process_request_headers().unwrap();
            assert_eq!(
                tx.matched_rules().is_empty(),
                valid,
                "depth={depth} valid={valid}"
            );
        }
    }
}

#[test]
fn transitive_file_references_are_confined_to_the_rule_directory() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("rules");
    let config = write_policy(&root);
    fs::write(dir.path().join("schema.json"), "true").unwrap();
    for reference in [
        "../../../schema.json",
        "https://example.invalid/schema.json",
    ] {
        fs::write(
            root.join("nested/scopes/b.json"),
            serde_json::json!({"$anchor":"node","$ref":reference}).to_string(),
        )
        .unwrap();
        assert!(
            ModSecurity::from_file(config.to_str().unwrap()).is_err(),
            "{reference}"
        );
    }
}
