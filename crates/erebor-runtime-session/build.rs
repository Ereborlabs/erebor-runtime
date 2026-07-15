use std::process::Command;
use std::{
    env,
    path::{Path, PathBuf},
    process,
};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(erebor_runtime_ipc_contract_tests)");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/audit.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/broker.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/cgroup.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/exec_observer.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/file_interception.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/interception.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/interception/audit.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/interception/broker.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/interception/executable.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/interception/handlers.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/memory.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/rules.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/status.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/sys.rs");
    println!("cargo:rerun-if-changed=src/os/linux/process_guard/trace.rs");
    println!("cargo:rerun-if-changed=../erebor-runtime-ipc/src/standalone/mod.rs");
    println!("cargo:rerun-if-changed=../erebor-runtime-ipc/src/standalone/codec.rs");
    println!("cargo:rerun-if-changed=../erebor-runtime-ipc/src/standalone/decision.rs");
    println!("cargo:rerun-if-changed=../erebor-runtime-ipc/src/standalone/envelope.rs");
    println!("cargo:rerun-if-changed=../erebor-runtime-ipc/src/standalone/file.rs");
    println!("cargo:rerun-if-changed=../erebor-runtime-ipc/src/standalone/request.rs");

    let out_dir = match env::var("OUT_DIR") {
        Ok(out_dir) => PathBuf::from(out_dir),
        Err(error) => {
            eprintln!("OUT_DIR is not set by Cargo: {error}");
            process::exit(1);
        }
    };
    let process_guard = out_dir.join("erebor-linux-process-guard");
    compile_standalone_binary(
        "Linux process guard",
        "src/os/linux/process_guard.rs",
        &process_guard,
    );
    println!(
        "cargo:rustc-env=EREBOR_BUILD_LINUX_PROCESS_GUARD={}",
        process_guard.display()
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
