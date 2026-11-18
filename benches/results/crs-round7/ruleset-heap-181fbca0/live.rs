use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use zentinel_modsec::ModSecurity;

struct Count;
static LIVE: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Count {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() { LIVE.fetch_add(layout.size(), Relaxed); }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Relaxed);
        unsafe { System.dealloc(p, layout) }
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, n: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, layout, n) };
        if !q.is_null() {
            LIVE.fetch_add(n, Relaxed);
            LIVE.fetch_sub(layout.size(), Relaxed);
        }
        q
    }
}
#[global_allocator]
static COUNTER: Count = Count;

fn main() {
    let d = std::env::var("CRS_BENCH_DIR").unwrap();
    let config = format!("SecRuleEngine On\nSecRequestBodyAccess On\nInclude \"{d}/crs-setup.conf.example\"\nInclude \"{d}/rules/*.conf\"\n");
    let initial = LIVE.load(Relaxed);
    let engine = ModSecurity::from_string(&config).unwrap();
    assert_eq!(engine.rule_count(), 698);
    let loaded = LIVE.load(Relaxed);
    drop(engine);
    let dropped = LIVE.load(Relaxed);
    println!("{} {} {}", loaded - initial, loaded - dropped, dropped - initial);
}
