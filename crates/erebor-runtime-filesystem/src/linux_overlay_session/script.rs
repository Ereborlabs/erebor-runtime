use super::plan::LinuxOverlayVolumeMount;

const CHILD_ARG: &str = "--erebor-overlay-child";

pub(super) struct LinuxOverlayWrapperScript<'a> {
    mounts: &'a [LinuxOverlayVolumeMount],
}

impl<'a> LinuxOverlayWrapperScript<'a> {
    pub(super) const fn new(mounts: &'a [LinuxOverlayVolumeMount]) -> Self {
        Self { mounts }
    }

    pub(super) fn render(&self) -> String {
        let mut script = String::from("#!/bin/sh\nset -eu\n\n");
        self.push_identity_functions(&mut script);
        script.push_str(&format!("if [ \"${{1:-}}\" = '{}' ]; then\n", CHILD_ARG));
        script.push_str("  shift\n  cleanup() {\n    set +e\n");
        for mount in self.mounts.iter().rev() {
            self.push_cleanup(&mut script, mount);
        }
        script.push_str("  }\n  trap cleanup EXIT INT TERM\n");
        script.push_str("  prepare_session_identity\n");
        for mount in self.mounts {
            self.push_mount_commands(&mut script, mount);
        }
        script.push_str("  set +e\n  run_session_command \"$@\"\n");
        script.push_str("  status=$?\n  set -e\n  exit \"$status\"\nfi\n\n");
        script.push_str("command -v unshare >/dev/null 2>&1\n");
        script.push_str("command -v mount >/dev/null 2>&1\n");
        script.push_str("command -v umount >/dev/null 2>&1\n");
        script.push_str("if [ \"$(id -u)\" != \"0\" ] && ");
        script
            .push_str("unshare -U --map-current-user --keep-caps -m true >/dev/null 2>&1; then\n");
        script.push_str(&format!(
            "  exec unshare -U --map-current-user --keep-caps -m --propagation private -- \"$0\" '{}' \"$@\"\n",
            CHILD_ARG
        ));
        script.push_str("fi\n");
        script.push_str(&format!(
            "exec unshare -m --propagation private -- \"$0\" '{}' \"$@\"\n",
            CHILD_ARG
        ));
        script
    }

    fn push_cleanup(&self, script: &mut String, mount: &LinuxOverlayVolumeMount) {
        for path in [
            &mount.session_path,
            &mount.host_path,
            &mount.merged_path,
            &mount.lower_ro_path,
        ] {
            script.push_str(&format!(
                "    umount {} >/dev/null 2>&1 || true\n",
                Self::sh(path)
            ));
        }
    }

    fn push_mount_commands(&self, script: &mut String, mount: &LinuxOverlayVolumeMount) {
        script.push_str(&format!(
            "  mount --bind {} {}\n",
            Self::sh(&mount.host_path),
            Self::sh(&mount.lower_ro_path)
        ));
        script.push_str(&format!(
            "  mount -o remount,bind,ro {}\n",
            Self::sh(&mount.lower_ro_path)
        ));
        script.push_str(&format!(
            "  mount -t overlay overlay -o {} {}\n",
            Self::sh(&format!(
                "lowerdir={},upperdir={},workdir={}",
                mount.lower_ro_path, mount.upper_path, mount.workdir_path
            )),
            Self::sh(&mount.merged_path)
        ));
        script.push_str(&format!(
            "  mount --bind {} {}\n",
            Self::sh(&mount.mask_path),
            Self::sh(&mount.host_path)
        ));
        script.push_str(&format!(
            "  mount -o remount,bind,ro {}\n",
            Self::sh(&mount.host_path)
        ));
        script.push_str(&format!(
            "  mount --bind {} {}\n",
            Self::sh(&mount.merged_path),
            Self::sh(&mount.session_path)
        ));
        if mount.read_only {
            script.push_str(&format!(
                "  mount -o remount,bind,ro {}\n",
                Self::sh(&mount.session_path)
            ));
        }
    }

    fn push_identity_functions(&self, script: &mut String) {
        script.push_str(
            r#"
prepare_session_identity() {
  session_uid="$(id -u)"
  session_gid="$(id -g)"
  if [ "$session_uid" != "0" ]; then
    return 0
  fi

  session_uid="${EREBOR_SESSION_UID:-${SUDO_UID:-}}"
  session_gid="${EREBOR_SESSION_GID:-${SUDO_GID:-}}"
  if [ -z "$session_uid" ] || [ -z "$session_gid" ] || [ "$session_uid" = "0" ]; then
    echo "erebor filesystem overlay refused to run the session command as root" >&2
    exit 126
  fi
  command -v setpriv >/dev/null 2>&1 || {
    echo "erebor filesystem overlay requires setpriv to drop root before session command" >&2
    exit 126
  }
}

run_session_command() {
  current_uid="$(id -u)"
  if [ "$current_uid" = "0" ]; then
    setpriv --reuid "$session_uid" --regid "$session_gid" --init-groups -- "$@"
    return $?
  fi
  "$@"
}

"#,
        );
    }

    fn sh(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}
