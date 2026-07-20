fn main() {
    if let Err(error) = erebor_runtime_session::run_session_helper() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
