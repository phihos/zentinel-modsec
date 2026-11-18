//! Conformance against the OWASP CRS regression corpus.
//!
//! The corpus is ~5,000 request/expectation pairs maintained upstream, one file
//! per rule, asserting **which rule IDs appear in the log** for a given request.
//! go-ftw drives it against a live server and reads the audit log; this drives
//! the same YAML directly against the engine, which is fast enough to run on
//! every push and precise enough to catch a rule that stops matching.
//!
//! # What this measures, and what it does not
//!
//! The corpus runs in the configuration upstream documents for it
//! (`tests/regression/README.md`, rule 900005): **`DetectionOnly` at paranoia
//! level 4**. That is deliberate on their part and important to understand
//! here: in detection-only mode `block` never blocks, the paranoia gates never
//! fire, and the anomaly score never reaches 949110. So this measures whether
//! individual rules *match*. It says nothing about whether the WAF *decides*
//! correctly.
//!
//! That distinction is not academic. A set of defects that made a stock CRS
//! deployment deny 100% of requests — including `GET /` — moved this number by
//! 23 out of 5,033, because none of the machinery they broke runs in this
//! configuration. A green corpus is not evidence that the WAF works.
//!
//! `stock_crs_blocks_attacks_and_passes_ordinary_traffic` covers the other
//! half: real blocking mode, default paranoia, asserting on the decision.
//! Both are needed. Neither substitutes for the other.
//!
//! # Running
//!
//! ```text
//! mkdir -p test-rules
//! git clone https://github.com/coreruleset/coreruleset.git test-rules/crs
//! git -C test-rules/crs checkout 30cb436   # the commit CI pins
//! cp test-rules/crs/crs-setup.conf.example test-rules/crs/crs-setup.conf
//! cargo test --test crs_conformance -- --nocapture
//! ```
//!
//! CI checks every stage against the backend-specific outcome for its pinned
//! CRS revision. A missing file or stage, a changed rule-ID expectation result,
//! and an engine callback error all fail the gate.
//!
//! `CRS_DIR` overrides the location. `SKIP_CRS_CONFORMANCE=1` skips these tests
//! when the corpus is not present — CI's unit-test job sets it, because the
//! dedicated `conformance` jobs fetch the corpus and run release builds for
//! the heuristic and FFI backends. Those jobs must never set
//! it: a gate that can silently not run is not a gate.
//!
//! Absence of the checkout is otherwise a failure rather than a skip, with
//! instructions — these tests previously existed in a form that returned early
//! when the fixture was missing, and went years without running.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zentinel_modsec::ModSecurity;

// --- corpus schema (only the fields this harness uses) ---------------------

#[derive(Deserialize)]
struct TestFile {
    tests: Vec<Test>,
}
#[derive(Deserialize)]
struct Test {
    test_id: u64,
    stages: Vec<Stage>,
}
#[derive(Deserialize)]
struct Stage {
    input: Input,
    #[serde(default)]
    output: Output,
}
#[derive(Deserialize, Default)]
struct Input {
    #[serde(default)]
    dest_addr: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, Scalar>,
    #[serde(default)]
    data: Option<Scalar>,
    #[serde(default)]
    encoded_request: Option<String>,
    #[serde(default)]
    autocomplete_headers: Option<bool>,
}
#[derive(Deserialize, Default)]
struct Output {
    #[serde(default)]
    log: Option<Log>,
}
#[derive(Deserialize, Default)]
struct Log {
    #[serde(default)]
    expect_ids: Vec<Scalar>,
    #[serde(default)]
    no_expect_ids: Vec<Scalar>,
}

/// YAML scalars appear as strings or numbers; `data` may be a block sequence.
#[derive(Deserialize)]
#[serde(untagged)]
enum Scalar {
    Text(String),
    Number(serde_yaml::Number),
    Bool(bool),
    Parts(Vec<Scalar>),
}

fn scalar(value: &Scalar) -> String {
    match value {
        Scalar::Text(s) => s.clone(),
        Scalar::Number(n) => n.to_string(),
        Scalar::Bool(b) => b.to_string(),
        Scalar::Parts(items) => items.iter().map(scalar).collect(),
    }
}

// --- fixture ---------------------------------------------------------------

fn crs_dir() -> Option<PathBuf> {
    if std::env::var_os("SKIP_CRS_CONFORMANCE").is_some() {
        return None;
    }
    let dir = std::env::var("CRS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("test-rules/crs"));
    assert!(
        dir.join("crs-setup.conf").is_file(),
        "OWASP CRS checkout not found at {}.\n\
         Fetch it with:\n  \
           mkdir -p test-rules\n  \
           git clone --depth 1 https://github.com/coreruleset/coreruleset.git test-rules/crs\n  \
           cp test-rules/crs/crs-setup.conf.example test-rules/crs/crs-setup.conf\n\
         CRS_DIR overrides the location; SKIP_CRS_CONFORMANCE=1 skips these \
         tests locally. CI must not set it.",
        dir.display()
    );
    Some(dir)
}

// Recommended phase-1 selectors, installed before CRS reads REQBODY_PROCESSOR.
const REQUEST_PROCESSORS: &str = r#"SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \
     "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" \
     "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_HEADERS:Content-Type "^application/[a-z0-9.-]+[+]json" \
     "id:'200006',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON""#;

/// The configuration the corpus documents for itself: detection-only, paranoia
/// 4, and the size limits its tests assume. Detection-only matters beyond
/// blocking — in blocking mode the first disruptive rule ends the phase, so
/// later rules a test expects would never be recorded.
const FTW_SETUP: &str = r#"SecAction "id:900005,phase:1,nolog,pass,\
    ctl:ruleEngine=DetectionOnly,\
    ctl:ruleRemoveById=910000,\
    setvar:tx.blocking_paranoia_level=4,\
    setvar:tx.crs_validate_utf8_encoding=1,\
    setvar:tx.arg_name_length=100,\
    setvar:tx.arg_length=400,\
    setvar:tx.total_arg_length=64000,\
    setvar:tx.max_num_args=255,\
    setvar:tx.max_file_size=64100,\
    setvar:tx.combined_file_sizes=65535""#;

fn load(dir: &Path, extra: &str) -> ModSecurity {
    let dir = std::fs::canonicalize(dir).expect("CRS dir");
    let d = dir.display();
    // Include directives rather than spliced file contents: CRS `.data` paths
    // are relative to the rule file naming them.
    let cfg = format!(
        "{REQUEST_PROCESSORS}\nSecRuleEngine On\nSecRequestBodyAccess On\n\
         Include \"{d}/crs-setup.conf\"\n{extra}\nInclude \"{d}/rules/*.conf\"\n"
    );
    ModSecurity::from_string(&cfg).expect("CRS should load")
}

/// Drive one corpus stage and return the rule IDs that matched.
fn run_stage(m: &ModSecurity, input: &Input) -> Result<Vec<String>, String> {
    let mut tx = m.new_transaction();
    let uri = input.uri.clone().unwrap_or_else(|| "/".into());
    let method = input.method.clone().unwrap_or_else(|| "GET".into());
    let version = input.version.clone().unwrap_or_else(|| "HTTP/1.1".into());
    tx.process_uri(&uri, &method, &version)
        .map_err(|e| format!("URI: {e}"))?;

    let has = |n: &str| input.headers.keys().any(|k| k.eq_ignore_ascii_case(n));
    for (k, v) in &input.headers {
        tx.add_request_header(k, &scalar(v))
            .map_err(|e| format!("request header: {e}"))?;
    }
    let body = input.data.as_ref().map(scalar).unwrap_or_default();
    // go-ftw fills these in unless a test opts out.
    if input.autocomplete_headers.unwrap_or(true) {
        if !has("Host") {
            let host = input
                .dest_addr
                .clone()
                .unwrap_or_else(|| "localhost".into());
            tx.add_request_header("Host", &host)
                .map_err(|e| format!("auto header: {e}"))?;
        }
        if !has("User-Agent") {
            tx.add_request_header("User-Agent", "go-ftw")
                .map_err(|e| format!("auto header: {e}"))?;
        }
        if !has("Accept") {
            tx.add_request_header("Accept", "*/*")
                .map_err(|e| format!("auto header: {e}"))?;
        }
        if !body.is_empty() && !has("Content-Length") {
            tx.add_request_header("Content-Length", &body.len().to_string())
                .map_err(|e| format!("auto header: {e}"))?;
        }
    }
    tx.process_request_headers()
        .map_err(|e| format!("phase 1: {e}"))?;
    if !body.is_empty() {
        tx.append_request_body(body.as_bytes())
            .map_err(|e| format!("body write: {e}"))?;
    }
    tx.process_request_body()
        .map_err(|e| format!("phase 2: {e}"))?;
    Ok(tx.matched_rules().to_vec())
}

// --- the gate --------------------------------------------------------------

#[test]
fn crs_regression_corpus() {
    let Some(dir) = crs_dir() else { return };
    let m = load(&dir, FTW_SETUP);

    let root = dir.join("tests/regression/tests");
    let mut report = BTreeMap::new();
    let mut callbacks = Vec::new();
    for entry in walkdir::WalkDir::new(&root) {
        let entry = entry.expect("walk pinned corpus");
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "yaml" && e != "yml") {
            continue;
        }
        let file = path.strip_prefix(&root).unwrap().to_str().unwrap();
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {file}: {e}"));
        if text
            .lines()
            .all(|line| line.trim().is_empty() || line.trim_start().starts_with('#'))
        {
            report.insert(format!("{file}#-"), "comment-only".into());
            continue;
        }
        let parsed = serde_yaml::from_str::<TestFile>(&text)
            .unwrap_or_else(|e| panic!("decode {file}: {e}"));
        assert!(!parsed.tests.is_empty(), "no tests in {file}");
        for test in parsed.tests {
            assert!(
                !test.stages.is_empty(),
                "no stages for {file}#{}",
                test.test_id
            );
            for (index, stage) in test.stages.iter().enumerate() {
                let id = format!("{file}#{}.{}", test.test_id, index + 1);
                let status = if stage.input.encoded_request.is_some() {
                    "skip-encoded".into()
                } else if let Some(log) = stage
                    .output
                    .log
                    .as_ref()
                    .filter(|log| !(log.expect_ids.is_empty() && log.no_expect_ids.is_empty()))
                {
                    match run_stage(&m, &stage.input) {
                        Ok(ids) => {
                            let mut differences = Vec::new();
                            for wanted in log.expect_ids.iter().map(scalar) {
                                if !ids.contains(&wanted) {
                                    differences.push(format!("missing:{wanted}"));
                                }
                            }
                            for rejected in log.no_expect_ids.iter().map(scalar) {
                                if ids.contains(&rejected) {
                                    differences.push(format!("unexpected:{rejected}"));
                                }
                            }
                            if differences.is_empty() {
                                "pass".into()
                            } else {
                                differences.join(",")
                            }
                        }
                        Err(error) => {
                            callbacks.push(format!("{id} {error}"));
                            format!("error:{error}")
                        }
                    }
                } else {
                    "skip-no-rule-ids".into()
                };
                assert!(
                    report.insert(id.clone(), status).is_none(),
                    "duplicate stage {id}"
                );
            }
        }
    }
    if let Some(path) = std::env::var_os("CRS_STAGE_REPORT") {
        let report = report
            .iter()
            .map(|(id, status)| format!("{id}\t{status}\n"))
            .collect::<String>();
        std::fs::write(path, report).expect("write stage report");
    }
    assert!(
        callbacks.is_empty(),
        "incomplete callbacks:\n{}",
        callbacks.join("\n")
    );
    let expected = expected_outcomes();
    let changes = outcome_changes(&expected, &report);
    let stages = report
        .values()
        .filter(|status| *status != "comment-only")
        .count();
    let skipped = report
        .values()
        .filter(|status| status.starts_with("skip-"))
        .count();
    let passed = report.values().filter(|status| *status == "pass").count();
    println!(
        "{passed}/{} stages passed, {skipped} skipped, {stages} total",
        stages - skipped
    );
    assert!(
        changes.is_empty(),
        "pinned stage outcomes changed:\n{}",
        changes.join("\n")
    );
}

/// The fixture groups outcomes by path. Each row records a shared result or
/// separate Rust/FFI results if the backends differ. Even unsupported stages
/// retain their identities and a reason.
fn expected_outcomes() -> BTreeMap<String, String> {
    let mut expected = BTreeMap::new();
    let mut file = "";
    for line in include_str!("fixtures/crs-native-outcomes.tsv").lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(path) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            file = path;
            continue;
        }
        let mut fields = line.split('\t');
        let stage = fields.next().expect("stage");
        let heuristic = fields.next().expect("Rust outcome");
        let ffi = fields.next().unwrap_or(heuristic);
        assert!(
            !file.is_empty() && fields.next().is_none(),
            "invalid manifest line {line}"
        );
        let outcome = if cfg!(feature = "libinjection-ffi") {
            ffi
        } else {
            heuristic
        };
        let id = format!("{file}#{stage}");
        assert!(
            expected.insert(id.clone(), outcome.to_owned()).is_none(),
            "duplicate expected stage {id}"
        );
    }
    expected
}

fn outcome_changes(
    expected: &BTreeMap<String, String>,
    actual: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut changes = Vec::new();
    for (id, old) in expected {
        match actual.get(id) {
            None => changes.push(format!("{id}: missing from corpus")),
            Some(new) if old != new => changes.push(format!("{id}: {old} -> {new}")),
            _ => {}
        }
    }
    for (id, new) in actual {
        if !expected.contains_key(id) {
            changes.push(format!("{id}: new stage ({new})"));
        }
    }
    changes
}

#[test]
fn equal_totals_cannot_hide_changed_or_replaced_stages() {
    let expected = BTreeMap::from([
        ("a".into(), "pass".into()),
        ("b".into(), "missing:42".into()),
        ("c".into(), "skip-encoded".into()),
    ]);
    let actual = BTreeMap::from([
        ("a".into(), "missing:42".into()),
        ("b".into(), "pass".into()),
        ("d".into(), "skip-encoded".into()),
    ]);
    assert_eq!(
        outcome_changes(&expected, &actual),
        [
            "a: pass -> missing:42",
            "b: missing:42 -> pass",
            "c: missing from corpus",
            "d: new stage (skip-encoded)",
        ]
    );
}

// --- the half the corpus cannot see ----------------------------------------

#[test]
fn stock_crs_blocks_attacks_and_passes_ordinary_traffic() {
    // Real blocking mode, default paranoia — the configuration an operator
    // actually deploys, and the one the corpus above is blind to.
    let Some(dir) = crs_dir() else { return };
    let m = load(&dir, "");

    let ue = "application/x-www-form-urlencoded";
    let xml = "application/xml";
    // name, should_block, method, uri, content-type, body
    type Case = (
        &'static str,
        bool,
        &'static str,
        &'static str,
        &'static str,
        &'static [u8],
    );
    let cases: &[Case] = &[
        ("GET /", false, "GET", "/", "", b""),
        ("static page", false, "GET", "/index.html", "", b""),
        ("health check", false, "GET", "/api/v1/health", "", b""),
        ("pdf download", false, "GET", "/docs/report.pdf", "", b""),
        (
            "ordinary query",
            false,
            "GET",
            "/search?q=blue+widgets&page=2",
            "",
            b"",
        ),
        (
            "form post",
            false,
            "POST",
            "/api/orders",
            ue,
            b"item=widget&qty=3",
        ),
        (
            "xml post",
            false,
            "POST",
            "/api/orders",
            xml,
            br#"<order><item id="7">widget</item></order>"#,
        ),
        (
            "SQLi in query",
            true,
            "GET",
            "/u?id=1'+UNION+SELECT+password+FROM+users--+",
            "",
            b"",
        ),
        (
            "SQLi in form",
            true,
            "POST",
            "/u",
            ue,
            b"q=1' UNION SELECT password FROM users-- ",
        ),
        (
            "SQLi in XML",
            true,
            "POST",
            "/u",
            xml,
            br#"<o><q>1' UNION SELECT password FROM users-- </q></o>"#,
        ),
        (
            "XSS in query",
            true,
            "GET",
            "/s?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "",
            b"",
        ),
        (
            "LFI in query",
            true,
            "GET",
            "/f?p=../../../../etc/passwd",
            "",
            b"",
        ),
        // Detected only by rules whose anomaly score sits on the last link of
        // a chain (920170, 920420): invisible while that `setvar` did not run.
        ("GET with a body", true, "GET", "/", "text/plain", b"hi"),
        (
            "unknown Content-Type",
            true,
            "POST",
            "/",
            "my-new-content-type",
            b"hi=test",
        ),
    ];

    let mut wrong = Vec::new();
    for (name, should_block, method, uri, ct, body) in cases {
        let mut tx = m.new_transaction();
        tx.process_uri(uri, method, "HTTP/1.1").unwrap();
        tx.add_request_header("Host", "example.com").unwrap();
        tx.add_request_header(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
        )
        .unwrap();
        tx.add_request_header("Accept", "text/html,application/xhtml+xml")
            .unwrap();
        tx.add_request_header("Accept-Language", "en-US,en;q=0.9")
            .unwrap();
        tx.add_request_header("Accept-Encoding", "gzip, deflate")
            .unwrap();
        tx.add_request_header("Connection", "keep-alive").unwrap();
        if !ct.is_empty() {
            tx.add_request_header("Content-Type", ct).unwrap();
            tx.add_request_header("Content-Length", &body.len().to_string())
                .unwrap();
        }
        tx.process_request_headers().unwrap();
        if !body.is_empty() {
            tx.append_request_body(body).unwrap();
        }
        tx.process_request_body().unwrap();

        let blocked = tx.has_intervention();
        let ids = tx
            .intervention()
            .map(|i| i.rule_ids.clone())
            .unwrap_or_default();
        println!("{name:<18} blocked={blocked:<6} {ids:?}");
        if blocked != *should_block {
            wrong.push(format!(
                "{name}: expected {}, got {blocked} {ids:?}",
                if *should_block { "a block" } else { "no block" }
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "stock CRS behaved wrongly:\n  {}",
        wrong.join("\n  ")
    );
}

/// Drive the upstream Apache internal-request exception (905110), including
/// its anonymous final link, followed by tagged and untagged sentinel rules.
#[test]
fn crs_internal_request_exception_removes_only_tagged_rules() {
    let Some(dir) = crs_dir() else { return };
    let exceptions =
        std::fs::canonicalize(dir.join("rules/REQUEST-905-COMMON-EXCEPTIONS.conf")).unwrap();
    let engine = ModSecurity::from_string(&format!(
        r#"
SecRuleEngine On
Include "{}"
SecAction "id:1,phase:1,pass,tag:OWASP_CRS"
SecAction "id:2,phase:1,pass"
SecAction "id:3,phase:4,pass,tag:OWASP_CRS"
SecAction "id:4,phase:4,pass"
"#,
        exceptions.display()
    ))
    .unwrap();
    for (addr, expected) in [
        ("127.0.0.1", vec!["905110", "2", "4"]),
        ("192.0.2.1", vec!["1", "2", "3", "4"]),
    ] {
        let mut tx = engine.new_transaction();
        tx.set_client_addr(addr, 42300);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("Host", "localhost").unwrap();
        tx.add_request_header("User-Agent", "Apache (internal dummy connection)")
            .unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        tx.process_response_headers_with_status(200, "HTTP/1.1")
            .unwrap();
        tx.process_response_body().unwrap();
        tx.process_logging().unwrap();
        assert_eq!(tx.matched_rules(), expected);
    }
}
