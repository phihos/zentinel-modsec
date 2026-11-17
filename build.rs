fn main() {
    #[cfg(feature = "libinjection-ffi")]
    {
        let dir = "vendor/libinjection";
        println!("cargo:rerun-if-changed={dir}");
        cc::Build::new()
            .include(dir)
            .file(format!("{dir}/libinjection_sqli.c"))
            .file(format!("{dir}/libinjection_xss.c"))
            .file(format!("{dir}/libinjection_html5.c"))
            .warnings(true)
            .compile("zentinel_libinjection");
    }
}
