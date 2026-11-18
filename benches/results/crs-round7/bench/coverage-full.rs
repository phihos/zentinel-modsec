use criterion::Criterion;
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
    if uri == "/many-headers" {
        for index in 0..33 {
            tx.add_request_header(&format!("X-Trace-{index}"), "value").unwrap();
        }
    }
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

pub fn requests(c: &mut Criterion) {
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

    let mut group = c.benchmark_group("full_crs");
    for (name, method, uri, content_type, body) in [
        ("get", "PATCH", "/cart", "", b"".as_slice()),
        ("form", "GET", "/many-headers", "", b"".as_slice()),
        ("json", "POST", "/upload", "multipart/form-data; boundary=example",
            b"--example\r\nContent-Disposition: form-data; name=\"document\"; filename=\"note.txt\"\r\nContent-Type: text/plain\r\n\r\nhello world\r\n--example--\r\n".as_slice()),
    ] {
        let request = || inspect(&engine, method, uri, content_type, body);
        let tx = request();
        if method == "PATCH" {
            assert!(tx.intervention().is_some());
            assert!(tx.matched_rules().iter().any(|id| id == "911100"));
        } else {
            assert!(tx.intervention().is_none(), "{name} was blocked: {:?}", tx.matched_rules());
            for expected in ["900990", "949059", "980099"] {
                assert!(tx.matched_rules().iter().any(|id| id == expected));
            }
        }
        group.bench_function(name, |b| b.iter(|| drop(black_box(request()))));
    }
}
