//! Accepted limitations must be visible before any request is processed.
use std::io::Write;
use std::sync::{Arc, Mutex};
use zentinel_modsec::ModSecurity;

#[derive(Clone)]
struct Log(Arc<Mutex<Vec<u8>>>);
impl Write for Log {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn load_logs(config: &str) -> (ModSecurity, String) {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let writer = Log(bytes.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || writer.clone())
        .finish();
    let engine =
        tracing::subscriber::with_default(subscriber, || ModSecurity::from_string(config).unwrap());
    let log = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
    (engine, log)
}

#[test]
fn placeholder_operators_report_the_affected_rule_at_load() {
    for operator in [
        "verifyCC",
        "verifySSN",
        "verifyCPF",
        "validateHash",
        "validateDTD",
        "validateSchema",
        "rbl",
        "geoLookup",
        "gsbLookup",
        "inspectFile",
        "fuzzyHash",
        "rsub",
    ] {
        let (_, log) = load_logs(&format!(
            r#"SecRule ARGS "@{operator} example" "id:101,phase:2,pass""#
        ));
        assert!(
            log.contains("operator") && log.contains("rule_ids=101"),
            "{operator}: {log}"
        );
    }
}

#[test]
fn approximated_operators_report_the_affected_rule_at_load() {
    for operator in ["containsWord", "strmatch", "pmf", "ipMatchF"] {
        let argument = if operator == "ipMatchF" {
            "127.0.0.1"
        } else {
            "example"
        };
        let (_, log) = load_logs(&format!(
            r#"SecRule ARGS "@{operator} {argument}" "id:102,phase:2,pass""#
        ));
        assert!(
            log.contains("operator") && log.contains("rule_ids=102"),
            "{operator}: {log}"
        );
    }
}

#[test]
fn ignored_transformations_are_reported_with_rule_ids() {
    for transform in ["parityEven7bit", "parityOdd7bit", "parityZero7bit"] {
        let (_, log) = load_logs(&format!(
            r#"SecRule ARGS "@contains attack" "id:103,phase:2,pass,t:{transform}""#
        ));
        assert!(
            log.contains("transformation") && log.contains("rule_ids=103"),
            "{transform}: {log}"
        );
    }
}

