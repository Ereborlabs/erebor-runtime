use std::fs;
use std::path::{Path, PathBuf};

use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::Result;

pub struct Phase1Packaging {
    root: PathBuf,
}

impl Phase1Packaging {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn verify(&self) -> Result<()> {
        let dockerfile = self.read("packaging/mithril/Dockerfile")?;
        let daemonset = self.read("packaging/mithril/helm/templates/daemonset.yaml")?;
        let chart = self.read("packaging/mithril/helm/Chart.yaml")?;

        ensure!(
            dockerfile
                .contains("cargo build --locked --release -p mithril-node -p mithril-control")
                && dockerfile.contains("gawk")
                && dockerfile.contains("protobuf-compiler")
                && !dockerfile.contains("erebor-interceptor.bpf.o")
                && !dockerfile.contains("feasibility.bpf.c")
                && !dockerfile.contains("clang -g -O2 -target bpf"),
            InvalidInputSnafu {
                path: self.root.join("packaging/mithril/Dockerfile"),
                reason: "development image is missing a required binary/tool or duplicates the embedded BPF object",
            }
        );
        ensure!(
            daemonset.matches("- name: mithril-node\n").count() == 1
                && daemonset.contains("hostPID: true")
                && daemonset.contains("privileged: true"),
            InvalidInputSnafu {
                path: self
                    .root
                    .join("packaging/mithril/helm/templates/daemonset.yaml"),
                reason: "DaemonSet must contain exactly one privileged node container",
            }
        );
        for mount in ["/sys/fs/bpf", "/sys/kernel/btf", "/sys/fs/cgroup"] {
            ensure!(
                daemonset.contains(mount),
                InvalidInputSnafu {
                    path: self
                        .root
                        .join("packaging/mithril/helm/templates/daemonset.yaml"),
                    reason: format!("DaemonSet is missing host mount `{mount}`"),
                }
            );
        }
        ensure!(
            daemonset.contains("containerRuntimeSocket") && daemonset.contains("type: Socket"),
            InvalidInputSnafu {
                path: self
                    .root
                    .join("packaging/mithril/helm/templates/daemonset.yaml"),
                reason: "DaemonSet is missing the read-only CRI socket mount",
            }
        );
        ensure!(
            chart.contains("name: mithril"),
            InvalidInputSnafu {
                path: self.root.join("packaging/mithril/helm/Chart.yaml"),
                reason: "Helm chart metadata is missing",
            }
        );
        Ok(())
    }

    fn read(&self, relative: &str) -> Result<String> {
        let path = self.root.join(Path::new(relative));
        fs::read_to_string(&path).context(IoSnafu { path })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::Phase1Packaging;

    #[test]
    fn development_package_has_one_privileged_node_container_and_required_mounts(
    ) -> crate::Result<()> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        Phase1Packaging::new(root).verify()
    }
}
