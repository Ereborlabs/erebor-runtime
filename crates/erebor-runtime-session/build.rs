use std::process::Command;
use std::{
    env,
    path::{Path, PathBuf},
    process,
};

fn main() {
    println!("cargo:rerun-if-changed=src/os/linux/process_guard.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/interception.rs");

    let out_dir = match env::var("OUT_DIR") {
        Ok(out_dir) => PathBuf::from(out_dir),
        Err(error) => {
            eprintln!("OUT_DIR is not set by Cargo: {error}");
            process::exit(1);
        }
    };
    compile_standalone_binary(
        "Linux process guard",
        "src/os/linux/process_guard.rs",
        &out_dir.join("erebor-linux-process-guard"),
    );
}

fn compile_standalone_binary(name: &str, source: &str, output: &Path) {
    let Some(output) = output.to_str() else {
        eprintln!("Cargo OUT_DIR path is not valid UTF-8 for {name} build");
        process::exit(1);
    };
    let status = match Command::new("rustc")
        .args([
            "--edition=2021",
            "-C",
            "opt-level=2",
            "-C",
            "target-feature=+crt-static",
            "-C",
            "panic=abort",
            "-o",
            output,
            source,
        ])
        .status()
    {
        Ok(status) => status,
        Err(error) => {
            eprintln!("failed to invoke rustc for {name}: {error}");
            process::exit(1);
        }
    };

    if !status.success() {
        eprintln!("failed to compile {name}");
        process::exit(1);
    }
}
