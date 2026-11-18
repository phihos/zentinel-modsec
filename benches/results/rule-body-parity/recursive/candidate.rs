use std::{env, fs, path::Path, thread};
use zentinel_modsec::ModSecurity;
fn main() {
    let args: Vec<_> = env::args().collect();
    for line in fs::read_to_string(&args[1]).unwrap().lines() {
        let (name, schema, doc, _): (String, String, String, bool) =
            serde_json::from_str(line).unwrap();
        let dir = Path::new(&args[2]);
        fs::write(dir.join("schema.json"), schema).unwrap();
        let config = dir.join("rules.conf");
        fs::write(&config, "SecRuleEngine DetectionOnly\nSecRule REQUEST_HEADERS:Sample \"@validateSchema schema.json\" \"id:1,phase:1,pass\"").unwrap();
        let engine = ModSecurity::from_file(config.to_str().unwrap()).unwrap();
        let matched = thread::Builder::new()
            .stack_size(1024 * 1024)
            .spawn(move || {
                let mut tx = engine.new_transaction();
                tx.add_request_header("Sample", &doc).unwrap();
                tx.process_request_headers().unwrap();
                !tx.matched_rules().is_empty()
            })
            .unwrap()
            .join()
            .unwrap();
        println!("{name} {matched}");
    }
}
