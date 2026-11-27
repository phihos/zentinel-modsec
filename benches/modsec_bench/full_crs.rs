use criterion::Criterion;
use std::{hint::black_box, path::Path};
#[path = "crs_workload.rs"]
mod workload;

pub fn requests(c: &mut Criterion) {
    let Some(dir) = std::env::var_os("CRS_BENCH_DIR") else {
        return;
    };
    let engine = workload::load(Path::new(&dir));
    let mut group = c.benchmark_group("full_crs");
    for (name, method, uri, content_type, body) in workload::FIXTURES {
        let request = || workload::inspect(&engine, method, uri, content_type, body);
        workload::check(name, &request());
        group.bench_function(name, |b| b.iter(|| drop(black_box(request()))));
    }
}
