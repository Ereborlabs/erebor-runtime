use std::path::PathBuf;

pub(super) struct SessionRegistryPath;

impl SessionRegistryPath {
    pub(super) fn safe_dir_name(session_id: &str) -> String {
        session_id
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                    character
                } else {
                    '_'
                }
            })
            .collect()
    }

    pub(super) fn absolute_root(root: PathBuf) -> PathBuf {
        if root.is_absolute() {
            return root;
        }
        match std::env::current_dir() {
            Ok(current_dir) => current_dir.join(root),
            Err(_error) => root,
        }
    }
}
