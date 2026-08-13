use std::fs;
use std::path::{Path, PathBuf};

use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::Result;

pub struct NodePackaging {
    root: PathBuf,
}

impl NodePackaging {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn verify(&self) -> Result<()> {
        let dockerfile = read(&self.root, "packaging/mithril/Dockerfile")?;
        let daemonset = read(
            &self.root,
            "packaging/mithril/helm/templates/daemonset.yaml",
        )?;
        let chart = read(&self.root, "packaging/mithril/helm/Chart.yaml")?;

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
}

pub struct VmTestHarness {
    root: PathBuf,
}

impl VmTestHarness {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn verify(&self) -> Result<()> {
        let run = read(&self.root, "crates/mithril-e2e/harness/vm/run.sh")?;
        let provider = read(
            &self.root,
            "crates/mithril-e2e/harness/vm/providers/libvirt.sh",
        )?;

        ensure!(
            run.contains("cargo build --locked -p mithril-e2e")
                && run.matches(" physical-probe").count() == 4
                && run.contains("physical-probe --protect")
                && run.contains("trap cleanup EXIT")
                && run.contains("$work_directory/known_hosts")
                && run.contains("destroy \"$vm_name\"")
                && run.contains("verify_absent()")
                && run.matches("verify_absent \"").count() >= 10,
            InvalidInputSnafu {
                path: self.root.join("crates/mithril-e2e/harness/vm/run.sh"),
                reason: "VM test flow must build both probes, run the identity, observation, and enforcement probes, and verify cleanup",
            }
        );
        for command in ["create", "wait", "put", "get", "run", "destroy"] {
            ensure!(
                provider.contains(&format!("  {command})")),
                InvalidInputSnafu {
                    path: self
                        .root
                        .join("crates/mithril-e2e/harness/vm/providers/libvirt.sh"),
                    reason: format!("libvirt provider is missing `{command}`"),
                }
            );
        }
        ensure!(
            provider.contains("sha256sum --check \"$image_checksum\"")
                && provider.contains("download=$work_directory/$image_name")
                && provider.contains("mv -- \"$download\" \"$base_image\"")
                && provider.contains("grep -qw bpf /sys/kernel/security/lsm")
                && provider.contains("refusing to destroy an unexpected domain")
                && provider.contains("refusing cleanup without a domain ownership record")
                && provider.contains("refusing cleanup of a domain with a different UUID"),
            InvalidInputSnafu {
                path: self
                    .root
                    .join("crates/mithril-e2e/harness/vm/providers/libvirt.sh"),
                reason: "libvirt provider must verify its image and guest and scope destruction",
            }
        );
        Ok(())
    }
}

fn read(root: &Path, relative: &str) -> Result<String> {
    let path = root.join(relative);
    fs::read_to_string(&path).context(IoSnafu { path })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{NodePackaging, VmTestHarness};

    #[test]
    fn development_package_has_one_privileged_node_container_and_required_mounts(
    ) -> crate::Result<()> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        NodePackaging::new(root).verify()
    }

    #[test]
    fn vm_harness_runs_all_physical_probes_and_owns_cleanup() -> crate::Result<()> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        VmTestHarness::new(root).verify()
    }
}
