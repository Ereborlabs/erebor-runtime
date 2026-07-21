fn main() {
    if let Err(error) = erebor_runtime_session::run_docker_session_controller() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
