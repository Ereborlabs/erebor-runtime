use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::physical::{ProbeCgroup, ProbeDirectory, ProbeFile};
use crate::Result;

#[derive(Clone, Copy)]
pub(super) struct NetworkActorSpec {
    pub(super) name: &'static str,
    pub(super) binding_id: &'static str,
    pub(super) label: char,
    pub(super) initial_role: bool,
    pub(super) private_network_namespace: bool,
}

pub(super) struct NetworkActor {
    pub(super) spec: NetworkActorSpec,
    pub(super) cgroup: ProbeCgroup,
}

const ACTORS: [NetworkActorSpec; 7] = [
    NetworkActorSpec {
        name: "main",
        binding_id: "99999999-9999-4999-8999-999999999991",
        label: 'a',
        initial_role: true,
        private_network_namespace: false,
    },
    NetworkActorSpec {
        name: "server",
        binding_id: "99999999-9999-4999-8999-999999999992",
        label: 'b',
        initial_role: true,
        private_network_namespace: false,
    },
    NetworkActorSpec {
        name: "converter-receiver",
        binding_id: "99999999-9999-4999-8999-999999999994",
        label: 'd',
        initial_role: true,
        private_network_namespace: false,
    },
    NetworkActorSpec {
        name: "namespace-external",
        binding_id: "99999999-9999-4999-8999-999999999995",
        label: 'e',
        initial_role: false,
        private_network_namespace: true,
    },
    NetworkActorSpec {
        name: "namespace-converter",
        binding_id: "99999999-9999-4999-8999-999999999996",
        label: 'f',
        initial_role: true,
        private_network_namespace: true,
    },
    NetworkActorSpec {
        name: "proxy-requester",
        binding_id: "99999999-9999-4999-8999-999999999997",
        label: 'g',
        initial_role: true,
        private_network_namespace: false,
    },
    NetworkActorSpec {
        name: "proxy-delegate",
        binding_id: "99999999-9999-4999-8999-999999999998",
        label: 'h',
        initial_role: true,
        private_network_namespace: false,
    },
];

pub(super) struct NetworkProbeFixture {
    actors: Vec<NetworkActor>,
    cgroup: ProbeCgroup,
    pin: ProbeDirectory,
    lease: ProbeFile,
    transport: ProbeDirectory,
    fixture: ProbeDirectory,
}

impl NetworkProbeFixture {
    pub(super) fn start(output: &Path, pin: &Path, lease: &Path, cgroup: &Path) -> Result<Self> {
        ensure!(
            !pin.exists() && !lease.exists() && !cgroup.exists(),
            InvalidInputSnafu {
                path: output,
                reason: "network probe paths must not exist before the run",
            }
        );
        fs::create_dir_all(output).context(IoSnafu { path: output })?;
        let fixture_path = output.join("network-runtime");
        fs::create_dir(&fixture_path).context(IoSnafu {
            path: &fixture_path,
        })?;
        let fixture_path = fs::canonicalize(&fixture_path).context(IoSnafu {
            path: &fixture_path,
        })?;
        let fixture = ProbeDirectory::new(&fixture_path);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                InvalidInputSnafu {
                    path: output,
                    reason: format!("the system clock is invalid: {error}"),
                }
                .build()
            })?
            .as_nanos();
        let transport_path =
            PathBuf::from(format!("/tmp/mithril-net-{}-{stamp}", std::process::id()));
        let transport = ProbeDirectory::create(&transport_path)?;
        let pin = ProbeDirectory::new(pin);
        let lease = ProbeFile::new(lease);
        let cgroup = ProbeCgroup::create(cgroup)?;
        let actors = ACTORS
            .into_iter()
            .map(|spec| {
                Ok(NetworkActor {
                    cgroup: ProbeCgroup::create(&cgroup.path().join(spec.name))?,
                    spec,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            actors,
            cgroup,
            pin,
            lease,
            transport,
            fixture,
        })
    }

    pub(super) fn fixture_root(&self) -> &Path {
        self.fixture.path()
    }

    pub(super) fn transport_root(&self) -> &Path {
        self.transport.path()
    }

    pub(super) fn cgroup_root(&self) -> &Path {
        self.cgroup.path()
    }

    pub(super) fn actors(&self) -> &[NetworkActor] {
        &self.actors
    }

    pub(super) fn stop(mut self) -> Result<()> {
        self.pin.cleanup()?;
        self.lease.cleanup()?;
        while let Some(actor) = self.actors.pop() {
            actor.cgroup.cleanup()?;
        }
        self.cgroup.cleanup()?;
        self.transport.cleanup()?;
        self.fixture.cleanup()
    }
}
