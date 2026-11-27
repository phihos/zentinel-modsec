//! Train a release profile or time three full CRS request lifecycles.
use std::{hint::black_box, path::Path};
use zentinel_modsec::ModSecurity;
#[path = "../benches/modsec_bench/crs_workload.rs"]
mod workload;
use workload::inspect;

fn train(engine: &ModSecurity) {
    for i in 0_u32..12_000 {
        let (method, uri, kind, body) = match i % 6 {
            0 | 1 => ("GET", "/inventory?color=green&size=medium", "", ""),
            2 => (
                "POST",
                "/account",
                "application/x-www-form-urlencoded",
                "name=Alex&active=true",
            ),
            3 => (
                "POST",
                "/v1/order",
                "application/json",
                r#"{"order":{"id":19,"paid":true}}"#,
            ),
            4 => ("GET", "/status", "", ""),
            _ => ("PATCH", "/inventory", "", ""),
        };
        let tx = inspect(engine, method, uri, kind, body.as_bytes());
        if i % 3 == 0 {
            black_box(tx.matched_data());
        }
        black_box(tx);
    }
}

fn main() {
    let dir =
        std::env::var_os("CRS_BENCH_DIR").expect("set CRS_BENCH_DIR to the CRS 4.25.0 checkout");
    let engine = workload::load(Path::new(&dir));
    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .expect("expected train or a positive request count");
    if mode == "train" {
        assert!(args.next().is_none(), "train takes no additional arguments");
        train(&engine);
        return;
    }
    let reps: u32 = mode.parse().expect("expected a positive request count");
    assert!(reps > 0);
    let read_matched_data = match args.next().as_deref() {
        None => false,
        Some("--read-matched-data") => true,
        Some(arg) => panic!("unknown option {arg}"),
    };
    assert!(args.next().is_none(), "unexpected extra arguments");
    for (name, method, uri, content_type, body) in workload::FIXTURES {
        let request = || {
            let tx = inspect(&engine, method, uri, content_type, body);
            if read_matched_data {
                black_box(tx.matched_data());
            }
            tx
        };
        workload::check(name, &request());
        for _ in 0..256 {
            drop(black_box(request()));
        }
        let t = std::time::Instant::now();
        for _ in 0..reps {
            drop(black_box(request()));
        }
        println!(
            "{} {}",
            name,
            t.elapsed().as_secs_f64() * 1e6 / f64::from(reps)
        );
    }
}
