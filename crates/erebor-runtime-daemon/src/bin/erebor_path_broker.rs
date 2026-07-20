fn main() {
    if let Err(error) = erebor_runtime_daemon::run_path_broker() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
