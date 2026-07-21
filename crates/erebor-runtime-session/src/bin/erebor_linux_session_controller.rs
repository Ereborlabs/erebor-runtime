fn main() {
    if let Err(error) = erebor_runtime_session::run_linux_session_controller() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
