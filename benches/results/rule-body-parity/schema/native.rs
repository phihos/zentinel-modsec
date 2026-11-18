use std::{env, fs, path::PathBuf};
use zentinel_modsec::ModSecurity;
fn main() {
    let input = fs::read_to_string(env::args().nth(1).unwrap()).unwrap();
    let dir = PathBuf::from(env::args().nth(2).unwrap());
    let config = dir.join("policy.conf");
    fs::write(&config, "SecRuleEngine DetectionOnly\nSecRule ARGS:q \"@validateSchema schema.json\" \"id:1,phase:1,pass,log\"").unwrap();
    for line in input.lines() {
        let [label, schema, doc] = serde_json::from_str::<[String; 3]>(line).unwrap();
        fs::write(dir.join("schema.json"), schema).unwrap();
        let engine = ModSecurity::from_file(config.to_str().unwrap()).unwrap();
        let mut tx = engine.new_transaction();
        let uri = format!(
            "/?q={}",
            url::form_urlencoded::byte_serialize(doc.as_bytes()).collect::<String>()
        );
        tx.process_uri(&uri, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        println!("{label} violation={}", !tx.matched_rules().is_empty());
    }
}
