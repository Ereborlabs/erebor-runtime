fn main() -> Result<(), std::io::Error> {
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rustc-env=ARAPHOR_NATIVE_TARGET={}",
        std::env::var("TARGET").map_err(std::io::Error::other)?
    );
    Ok(())
}
