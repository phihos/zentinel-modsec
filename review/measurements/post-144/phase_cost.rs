use std::{hint::black_box, path::Path, process::Command};
use zentinel_modsec::{engine::Transaction, ModSecurity};

const CRS_COMMIT: &str = "aabf675fcfc5e489b424b844e6c9f1b39802df69";

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed in {}",
        dir.display()
    );
    String::from_utf8(output.stdout).unwrap()
}

fn inspect(
    engine: &ModSecurity,
    method: &str,
    uri: &str,
    content_type: &str,
    body: &[u8],
) -> Transaction {
    let mut tx = engine.new_transaction();
    tx.set_client_addr("127.0.0.1", 40000);
    tx.set_server_addr("127.0.0.1", 443);
    tx.process_uri(uri, method, "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "shop.example").unwrap();
    tx.add_request_header("User-Agent", "Mozilla/5.0").unwrap();
    tx.add_request_header("Accept", "*/*").unwrap();
    if !body.is_empty() {
        tx.add_request_header("Content-Type", content_type).unwrap();
        tx.add_request_header("Content-Length", &body.len().to_string())
            .unwrap();
    }
    tx.process_request_headers().unwrap();
    if !body.is_empty() {
        tx.append_request_body(body).unwrap();
    }
    tx.process_request_body().unwrap();
    tx.process_logging().unwrap();
    tx
}

fn main() {
    let Some(dir) = std::env::var_os("CRS_BENCH_DIR") else {
        return;
    };
    let dir = Path::new(&dir).canonicalize().expect("OWASP CRS checkout");
    assert_eq!(
        git(&dir, &["rev-parse", "HEAD"]).trim(),
        CRS_COMMIT,
        "expected CRS 4.25.0"
    );
    let changes = git(
        &dir,
        &[
            "status",
            "--porcelain",
            "--",
            "rules",
            "crs-setup.conf.example",
        ],
    );
    assert!(changes.is_empty(), "modified CRS inputs: {changes}");
    let d = dir.display();
    let engine = ModSecurity::from_string(&format!(
        "SecRuleEngine On\nSecRequestBodyAccess On\nInclude \"{d}/crs-setup.conf.example\"\nInclude \"{d}/rules/*.conf\"\n"
    )).expect("load all OWASP CRS rules");
    assert_eq!(engine.rule_count(), 698);
    let denied = inspect(&engine, "PATCH", "/cart", "", b"");
    assert!(denied.intervention().is_some());
    assert!(denied.matched_rules().iter().any(|id| id == "911100"));

    let reps: usize = std::env::args().nth(1).unwrap().parse().unwrap();
    for (name, method, uri, ctype, body) in [
        ("get", "GET", "/products?category=books", "", ""),
        (
            "form",
            "POST",
            "/checkout",
            "application/x-www-form-urlencoded",
            "item=notebook&qty=2",
        ),
        (
            "json",
            "POST",
            "/api/cart",
            "application/json",
            r#"{"items":[{"sku":"notebook","qty":2}]}"#,
        ),
    ] {
        for _ in 0..256 {
            drop(black_box(inspect(
                &engine,
                method,
                uri,
                ctype,
                body.as_bytes(),
            )));
        }
        let mut totals = [0u128; 5];
        for _ in 0..reps {
            let t0 = std::time::Instant::now();
            let mut tx = engine.new_transaction();
            tx.set_client_addr("127.0.0.1", 40000);
            tx.set_server_addr("127.0.0.1", 443);
            tx.process_uri(uri, method, "HTTP/1.1").unwrap();
            tx.add_request_header("Host", "shop.example").unwrap();
            tx.add_request_header("User-Agent", "Mozilla/5.0").unwrap();
            tx.add_request_header("Accept", "*/*").unwrap();
            if !body.is_empty() {
                tx.add_request_header("Content-Type", ctype).unwrap();
                tx.add_request_header("Content-Length", &body.len().to_string())
                    .unwrap();
            }
            let t1 = std::time::Instant::now();
            tx.process_request_headers().unwrap();
            let t2 = std::time::Instant::now();
            if !body.is_empty() {
                tx.append_request_body(body.as_bytes()).unwrap();
            }
            tx.process_request_body().unwrap();
            let t3 = std::time::Instant::now();
            tx.process_logging().unwrap();
            let t4 = std::time::Instant::now();
            drop(black_box(tx));
            let t5 = std::time::Instant::now();
            for (total, (start, end)) in
                totals
                    .iter_mut()
                    .zip([(t0, t1), (t1, t2), (t2, t3), (t3, t4), (t4, t5)])
            {
                *total += (end - start).as_nanos();
            }
        }
        for (k, t) in ["setup", "headers", "body", "logging", "drop"]
            .iter()
            .zip(totals)
        {
            println!("{name}-{k} {}", t as f64 / reps as f64 / 1000.);
        }
    }
}
