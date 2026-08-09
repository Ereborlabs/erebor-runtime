use std::env;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

fn main() {
    if let Err(error) = build_bpf() {
        eprintln!("failed to build erebor-interceptor BPF object: {error:?}");
        std::process::exit(1);
    }
}

fn build_bpf() -> Result<(), Box<dyn std::error::Error>> {
    let crate_root =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "CARGO_MANIFEST_DIR is not set")
        })?);
    let repository_root = crate_root.join("../..");
    let bpf_root = repository_root.join("bpf/erebor-interceptor");
    let source = bpf_root.join("programs/identity.bpf.c");
    let object = PathBuf::from(
        env::var_os("OUT_DIR")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "OUT_DIR is not set"))?,
    )
    .join("erebor-interceptor.bpf.o");

    for path in [
        &source,
        &bpf_root.join("programs/identity_maps.h"),
        &bpf_root.join("include/erebor_interceptor_abi.h"),
        &bpf_root.join("include/linux_uapi.h"),
        &bpf_root.join("include/vmlinux.h"),
        &bpf_root.join("include/vmlinux_generated_x86.h"),
        &bpf_root.join("include/vmlinux_generated_arm64.h"),
        &bpf_root.join("include/vmlinux_generated_arm.h"),
        &bpf_root.join("include/vmlinux_generated_riscv.h"),
    ] {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let clang_args = vec![
        OsString::from("-D__BPF__"),
        OsString::from("-Wall"),
        OsString::from("-Werror"),
        OsString::from("-I"),
        bpf_root.join("include").into_os_string(),
        OsString::from("-I"),
        bpf_root.join("programs").into_os_string(),
        OsString::from(format!(
            "-fdebug-prefix-map={}=/src",
            repository_root.display()
        )),
        OsString::from("-fdebug-compilation-dir=/src"),
    ];
    SkeletonBuilder::new()
        .source(&source)
        .obj(&object)
        .clang_args(clang_args)
        .build()?;
    println!(
        "cargo:rustc-env=EREBOR_INTERCEPTOR_BPF_OBJECT={}",
        object.display()
    );
    Ok(())
}
