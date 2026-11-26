use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, Ordering};
static TRACK: AtomicBool = AtomicBool::new(false);
struct Count;
#[global_allocator]
static ALLOC: Count = Count;
extern "C" {
    fn backtrace(buffer: *mut usize, size: i32) -> i32;
    fn write(fd: i32, buf: *const usize, size: usize) -> isize;
}
fn trace(n: usize) {
    if TRACK.swap(false, Ordering::Relaxed) {
        let mut rec = [0usize; 34];
        rec[0] = n;
        unsafe {
            rec[1] = backtrace(rec[2..].as_mut_ptr(), 32) as usize;
            write(2, rec.as_ptr(), std::mem::size_of_val(&rec));
        }
        TRACK.store(true, Ordering::Relaxed);
    }
}
unsafe impl GlobalAlloc for Count {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        trace(l.size());
        System.alloc(l)
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        trace(l.size());
        System.alloc_zeroed(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        trace(n);
        System.realloc(p, l, n)
    }
}
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

    let reps: u32 = std::env::args().nth(1).unwrap().parse().unwrap();
    for (name, method, uri, content_type, body) in [
        ("get", "GET", "/products?category=books", "", b"".as_slice()),
        (
            "form",
            "POST",
            "/checkout",
            "application/x-www-form-urlencoded",
            b"item=notebook&qty=2",
        ),
        (
            "json",
            "POST",
            "/api/cart",
            "application/json",
            br#"{"items":[{"sku":"notebook","qty":2}]}"#,
        ),
    ] {
        let reads = std::env::var("READ").unwrap_or_default();
        let request = || {
            let tx = inspect(&engine, method, uri, content_type, body);
            if reads == "end" {
                black_box(tx.matched_data());
            }
            tx
        };
        let tx = request();
        assert!(tx.intervention().is_none(), "{name} was blocked");
        for expected in ["900990", "949059", "980099"] {
            assert!(
                tx.matched_rules().iter().any(|id| id == expected),
                "{name} missed {expected}"
            );
        }
        if name == "json" {
            assert!(
                tx.matched_rules().iter().any(|id| id == "920539"),
                "JSON processor was inactive"
            );
        }
        if std::env::var("ONLY").is_ok_and(|n| n != name) {
            continue;
        }
        for _ in 0..256 {
            drop(black_box(request()));
        }
        let t = std::time::Instant::now();
        std::fs::copy("/proc/self/maps", std::env::var("TRACE_MAP").unwrap()).unwrap();
        TRACK.store(true, Ordering::Relaxed);
        drop(black_box(request()));
        TRACK.store(false, Ordering::Relaxed);
        println!(
            "{} {}",
            name,
            t.elapsed().as_secs_f64() * 1e6 / f64::from(reps)
        );
    }
}
