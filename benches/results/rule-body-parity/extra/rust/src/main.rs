use serde_json::{json, Value};
use std::{env, fs, path::Path};
use zentinel_modsec::ModSecurity;

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
fn files(dir: &Path) -> Vec<String> {
    let mut out: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|p| hex(&fs::read(p.unwrap().path()).unwrap()))
        .collect();
    out.sort();
    out
}
fn evaluate(f: &Value) -> Value {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    let mut out = json!({"name":f["name"],"loaded":false,"matches":[],"Files":[],"Remaining":[]});
    let rules = f["rules"]
        .as_str()
        .unwrap()
        .replace("{DIR}", path.to_str().unwrap());
    let Ok(mut waf) = ModSecurity::from_string(&format!("SecRuleEngine DetectionOnly\n{rules}"))
    else {
        return out;
    };
    out["loaded"] = json!(true);
    waf.set_autodetect_structured_request_bodies(false);
    let mut tx = waf.new_transaction();
    tx.set_record_rule_messages(true);
    tx.process_uri(f["URI"].as_str().unwrap_or("/"), "GET", "HTTP/1.1")
        .unwrap();
    for a in f["PathArgs"].as_array().into_iter().flatten() {
        tx.add_path_argument(a[0].as_str().unwrap(), a[1].as_str().unwrap());
    }
    for h in f["headers"].as_array().into_iter().flatten() {
        tx.add_request_header(h[0].as_str().unwrap(), h[1].as_str().unwrap())
            .unwrap()
    }
    tx.process_request_headers().unwrap();
    if let Some(body) = f["body"].as_str() {
        tx.write_request_body(body.as_bytes()).unwrap();
    }
    tx.process_request_body().unwrap();
    tx.process_logging().unwrap();
    let upload = f["upload"].as_bool().unwrap_or(false);
    let matches: Vec<_> = tx
        .rule_messages()
        .iter()
        .map(|m| {
            let msg = std::str::from_utf8(m.message.as_deref().unwrap_or_default()).unwrap();
            let text = if upload && !msg.is_empty() {
                let tmp = Path::new(msg);
                assert_eq!(tmp.parent(), Some(path));
                hex(&fs::read(tmp).unwrap())
            } else {
                msg.to_owned()
            };
            format!("{}={text}", m.rule_id)
        })
        .collect();
    out["matches"] = json!(matches);
    if upload {
        out["Files"] = json!(files(path))
    }
    drop(tx);
    if upload {
        out["Remaining"] = json!(files(path))
    }
    out
}
fn main() {
    let input = fs::read(env::args().nth(1).unwrap()).unwrap();
    let cases: Vec<Value> = serde_json::from_slice(&input).unwrap();
    let results: Vec<_> = cases.iter().map(evaluate).collect();
    println!("{}", serde_json::to_string_pretty(&results).unwrap())
}
