pub(super) fn normalize_request_path(cwd: &str, path: &str) -> String {
    let input = if path.starts_with('/') || cwd.is_empty() {
        path.to_owned()
    } else {
        format!("{cwd}/{path}")
    };
    let absolute = input.starts_with('/');
    let mut parts = Vec::new();

    for part in input.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push(part);
                }
            }
            _ => parts.push(part),
        }
    }

    match (absolute, parts.is_empty()) {
        (true, true) => String::from("/"),
        (true, false) => format!("/{}", parts.join("/")),
        (false, true) => String::from("."),
        (false, false) => parts.join("/"),
    }
}
