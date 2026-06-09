use std::process::Command;
use std::{env, path::PathBuf, process};

fn main() {
    println!("cargo:rerun-if-changed=src/docker_process_guard.c");

    let out_dir = match env::var("OUT_DIR") {
        Ok(out_dir) => PathBuf::from(out_dir),
        Err(error) => {
            eprintln!("OUT_DIR is not set by Cargo: {error}");
            process::exit(1);
        }
    };
    let guard = out_dir.join("erebor-docker-process-guard");
    let Some(guard) = guard.to_str() else {
        eprintln!("Cargo OUT_DIR path is not valid UTF-8 for guard build");
        process::exit(1);
    };
    let status = match Command::new("cc")
        .args([
            "-static",
            "-O2",
            "-Wall",
            "-Wextra",
            "-o",
            guard,
            "src/docker_process_guard.c",
        ])
        .status()
    {
        Ok(status) => status,
        Err(error) => {
            eprintln!("failed to invoke cc for Docker process guard: {error}");
            process::exit(1);
        }
    };

    if !status.success() {
        eprintln!("failed to compile Docker process guard");
        process::exit(1);
    }
}
