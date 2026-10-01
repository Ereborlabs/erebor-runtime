use std::{
    fs::File,
    os::fd::AsRawFd as _,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use snafu::{ensure, ResultExt as _};

use crate::error::{CommandSnafu, InvalidInputSnafu, IoSnafu};
use crate::Result;

pub(super) struct NetworkRewriteOwner {
    namespace: File,
    path: PathBuf,
    table: String,
    active: bool,
}

impl NetworkRewriteOwner {
    pub(super) fn install(pid: u32, port: u16) -> Result<Self> {
        let path = PathBuf::from(format!("/proc/{pid}/ns/net"));
        let namespace = File::open(&path).context(IoSnafu { path: &path })?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|source| {
                InvalidInputSnafu {
                    path: &path,
                    reason: format!("the system clock is invalid: {source}"),
                }
                .build()
            })?
            .as_nanos();
        let mut owner = Self {
            namespace,
            path,
            table: format!("mithril_net_{}_{}", std::process::id(), stamp),
            active: false,
        };
        owner.run(&["add", "table", "ip", &owner.table])?;
        owner.active = true;
        if let Err(source) = owner.configure(port) {
            if let Err(cleanup) = owner.remove() {
                return CommandSnafu {
                    program: "nft",
                    reason: format!("{source}; cleanup failed: {cleanup}"),
                }
                .fail();
            }
            return Err(source);
        }
        Ok(owner)
    }

    fn configure(&self, port: u16) -> Result<()> {
        self.run(&[
            "add",
            "chain",
            "ip",
            &self.table,
            "output",
            "{ type nat hook output priority dstnat; policy accept; }",
        ])?;
        let port = port.to_string();
        let target = format!("127.0.0.4:{port}");
        for source in ["198.18.0.1", "198.18.0.2"] {
            self.run(&[
                "add",
                "rule",
                "ip",
                &self.table,
                "output",
                "ip",
                "daddr",
                source,
                "tcp",
                "dport",
                &port,
                "dnat",
                "to",
                &target,
            ])?;
        }
        Ok(())
    }

    fn run(&self, args: &[&str]) -> Result<()> {
        let output = Command::new("nsenter")
            .arg(format!(
                "--net=/proc/{}/fd/{}",
                std::process::id(),
                self.namespace.as_raw_fd()
            ))
            .args(["--", "nft"])
            .args(args)
            .output()
            .context(IoSnafu {
                path: Path::new("nsenter"),
            })?;
        ensure!(
            output.status.success(),
            CommandSnafu {
                program: "nsenter nft",
                reason: format!(
                    "{}: {:?}: {}; stderr: {}",
                    self.path.display(),
                    args,
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            }
        );
        Ok(())
    }

    pub(super) fn cleanup(mut self) -> Result<()> {
        self.remove()
    }

    fn remove(&mut self) -> Result<()> {
        if self.active {
            self.run(&["delete", "table", "ip", &self.table])?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for NetworkRewriteOwner {
    fn drop(&mut self) {
        let _result = self.remove();
    }
}

#[cfg(test)]
mod tests {
    use super::NetworkRewriteOwner;

    #[test]
    #[ignore = "requires Linux CAP_NET_ADMIN and nft"]
    fn rewrite_cleanup_is_idempotent() -> crate::Result<()> {
        let mut rewrite = NetworkRewriteOwner::install(std::process::id(), 19110)?;
        rewrite.run(&["list", "table", "ip", &rewrite.table])?;
        rewrite.remove()?;
        rewrite.remove()?;
        assert!(rewrite
            .run(&["list", "table", "ip", &rewrite.table])
            .is_err());
        rewrite.cleanup()
    }
}
