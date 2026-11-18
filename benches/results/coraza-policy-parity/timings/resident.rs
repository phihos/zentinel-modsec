extern crate self as criterion;
use std::io::{self, BufRead};
#[repr(C)] struct Timespec { sec: i64, nsec: i64 }
unsafe extern "C" { fn clock_gettime(clock: i32, result: *mut Timespec) -> i32; }
fn thread_ns() -> u64 {
    let mut t = Timespec {sec: 0, nsec: 0};
    assert_eq!(unsafe {clock_gettime(3, &mut t)}, 0);
    (t.sec * 1_000_000_000 + t.nsec) as u64
}
pub struct Criterion { workload: String }
impl Criterion {
    fn benchmark_group(&mut self, _: &str) -> &mut Self { self }
    fn bench_function(&mut self, name: &str, mut f: impl FnMut(&mut Self)) {
        if self.workload == name { f(self); }
    }
    fn iter<T>(&mut self, mut request: impl FnMut() -> T) {
        println!("ready {}", self.workload);
        for line in io::stdin().lock().lines() {
            let line = line.unwrap();
            let count: usize = line.trim().parse().unwrap();
            let start = std::time::Instant::now(); let cpu = thread_ns();
            for _ in 0..count { std::hint::black_box(request()); }
            println!("{} {}", start.elapsed().as_nanos(), thread_ns()-cpu);
        }
    }
}
mod crs { include!(env!("FULL_CRS_SOURCE")); }
fn main() { crs::requests(&mut Criterion { workload: std::env::args().nth(1).unwrap() }); }
