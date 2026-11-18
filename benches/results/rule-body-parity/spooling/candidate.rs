use std::{env, fs, path::PathBuf};
use zentinel_modsec::ModSecurity;
fn backing() -> bool {
    let scratch = PathBuf::from(env::var_os("TMPDIR").unwrap());
    fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
        .any(|file| file.starts_with(&scratch))
}
fn main() {
    let waf = ModSecurity::from_string(
        r#"SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRequestBodyLimit 16
SecRequestBodyInMemoryLimit 3
SecRule ARGS_POST:x "@streq abcdef" "id:1,phase:2,pass""#,
    )
    .unwrap();
    let mut tx = waf.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();
    for chunk in ["x=a", "bc", "def"] {
        let r = tx.write_request_body(chunk.as_bytes()).unwrap();
        println!("consumed={} file={}", r.consumed, backing());
    }
    tx.process_request_body().unwrap();
    for rule in tx.matched_rules() {
        println!("phase2={rule}");
    }
    drop(tx);
    println!("closed={}", !backing());
}
