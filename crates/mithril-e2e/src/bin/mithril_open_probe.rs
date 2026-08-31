use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;
use std::thread;
use std::time::Duration;

struct OpenProbe {
    path: PathBuf,
    pid_file: Option<PathBuf>,
    release_file: Option<PathBuf>,
    hold_after_success: bool,
}

impl OpenProbe {
    fn parse() -> Option<Self> {
        let arguments = env::args_os().skip(1).collect::<Vec<_>>();
        match arguments.as_slice() {
            [path] => Some(Self {
                path: PathBuf::from(path),
                pid_file: None,
                release_file: None,
                hold_after_success: false,
            }),
            [pid_flag, pid_file, release_flag, release_file, path]
                if pid_flag == "--pid-file" && release_flag == "--release-file" =>
            {
                Some(Self {
                    path: PathBuf::from(path),
                    pid_file: Some(PathBuf::from(pid_file)),
                    release_file: Some(PathBuf::from(release_file)),
                    hold_after_success: true,
                })
            }
            _ => None,
        }
    }

    fn run(&self) -> bool {
        if let (Some(pid_file), Some(release_file)) = (&self.pid_file, &self.release_file) {
            let Ok(release) = fs::File::open(release_file) else {
                return false;
            };
            if let Some(parent) = pid_file.parent() {
                if fs::create_dir_all(parent).is_err() {
                    return false;
                }
            }
            if fs::write(pid_file, format!("{}\n", process::id())).is_err() {
                return false;
            }
            while !release.metadata().is_ok_and(|metadata| metadata.len() > 0) {
                thread::sleep(Duration::from_millis(10));
            }
        }
        let succeeded = fs::File::open(&self.path).is_ok();
        if succeeded && self.hold_after_success {
            // A held success must not issue another filesystem operation.
            loop {
                thread::park();
            }
        }
        succeeded
    }
}

fn main() {
    let succeeded = OpenProbe::parse().is_some_and(|probe| probe.run());
    process::exit(i32::from(!succeeded));
}
