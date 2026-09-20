fn main() {
    assert_eq!(
        std::env::var("CARGO_CFG_TARGET_OS").as_deref(),
        Ok("macos"),
        "MAC-001 requires macOS"
    );
    let mut native = cc::Build::new();
    if std::env::var_os("CARGO_FEATURE_READ_ONLY_DOWNLOADS").is_some() {
        native.define("SP_READ_ONLY", None);
    }
    native
        .file("native/macos.m")
        .file("native/window.m")
        .flag("-fobjc-arc")
        .flag("-mmacosx-version-min=13.0")
        .compile("cleanup_native");
    println!("cargo:rustc-link-lib=framework=AppKit");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rerun-if-changed=native/macos.m");
    println!("cargo:rerun-if-changed=native/window.m");
}
