fn main() {
    println!("cargo:rerun-if-changed=exports.def");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let definition = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
            .join("exports.def");
        println!("cargo:rustc-link-arg-cdylib=/DEF:{}", definition.display());
    }
}
