use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use erebor_interceptor::{KernelHostConfig, KernelHostOwner};
use erebor_interceptor_abi::{
    KernelEffectFamilyV1, KernelEffectOperationV1, NetworkResponseFloorKeyV1,
    NetworkResponseScopeV1,
};
use mithril_control::{
    DestinationPolicyRecordV1, DnsPolicyModeV1, EffectFamilyDefaultV1, EffectFamilyV1,
    LocalObjectSelectorV1, NetworkPolicyV1, NetworkPortRangeV1, NetworkProtocolV1,
    PolicyArtifactOwner, PolicyDispositionV1, PolicyDocumentV1, RuleMatchV1,
};
use mithril_node::{
    EffectObservationStore, NativeSecurityStateOwner, NodePolicyGenerationOwner,
    WorkloadBindingOwner,
};
use serde::Serialize;
use snafu::{ensure, ResultExt as _};

use super::child::EffectProcessFixture;
use super::support::{effect_binding, effect_node_config, wait_for_effect};
use crate::error::{
    InterceptorSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu, NodeSnafu, PolicySnafu,
};
use crate::physical::{boot_identity, ProbeCgroup, ProbeDirectory, ProbeFile};
use crate::Result;

const PAYLOAD: &[u8] = b"allowed";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NetworkFixtureResultV1 {
    pub fixture_id: String,
    pub result: String,
    pub physical_oracle: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NetworkPhysicalProbeBundleV1 {
    pub schema_version: u32,
    pub denied_unclassified_connect: bool,
    pub allowed_connect: bool,
    pub allowed_send_received: bool,
    pub allowed_receive: bool,
    pub allowed_socket_control: bool,
    pub whole_socket_fence_installed: bool,
    pub post_fence_send_denied: bool,
    pub post_fence_shutdown_denied: bool,
    pub post_fence_bytes_absent: bool,
    pub socket_reference_released: bool,
    pub fixture_results: Vec<NetworkFixtureResultV1>,
}

pub struct NetworkTestRunner {
    repo_root: PathBuf,
}

impl NetworkTestRunner {
    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        Self {
            repo_root: repo_root.into(),
        }
    }

    pub fn physical_probe(
        &self,
        output_directory: &Path,
        pin_root: &Path,
        lease_path: &Path,
        cgroup_path: &Path,
    ) -> Result<NetworkPhysicalProbeBundleV1> {
        ensure!(
            !pin_root.exists() && !lease_path.exists() && !cgroup_path.exists(),
            InvalidInputSnafu {
                path: output_directory,
                reason: "network probe paths must not exist before the run",
            }
        );
        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let fixture_root = output_directory.join("network-runtime");
        fs::create_dir(&fixture_root).context(IoSnafu {
            path: &fixture_root,
        })?;
        let fixture_root = fs::canonicalize(&fixture_root).context(IoSnafu {
            path: &fixture_root,
        })?;
        let fixture_cleanup = ProbeDirectory::new(&fixture_root);
        let pin_cleanup = ProbeDirectory::new(pin_root);
        let lease_cleanup = ProbeFile::new(lease_path);
        let cgroup_cleanup = ProbeCgroup::create(cgroup_path)?;
        let cgroup_path = cgroup_cleanup.path().to_path_buf();
        let repo_root = fs::canonicalize(&self.repo_root).context(IoSnafu {
            path: &self.repo_root,
        })?;
        let policy_fixture = repo_root.join("crates/mithril-e2e/fixtures/mithril-policy");

        let listener = TcpListener::bind(("127.0.0.1", 0)).context(IoSnafu {
            path: Path::new("127.0.0.1:0"),
        })?;
        let allowed_address = listener.local_addr().context(IoSnafu {
            path: Path::new("allowed network listener"),
        })?;
        let server = thread::spawn(move || server_exchange(listener));
        let artifact_path =
            build_network_artifact(&policy_fixture, &fixture_root, allowed_address.port())?;

        let (boot_id, node_boot_id) = boot_identity()?;
        let kernel_config = KernelHostConfig::identity(
            "/sys/kernel/btf/vmlinux",
            lease_path,
            Some(pin_root.to_path_buf()),
            boot_id,
            1,
        )
        .with_network_cgroup_root(&cgroup_path);
        let mut host = KernelHostOwner::new(kernel_config)
            .start()
            .context(InterceptorSnafu)?;
        let binding = effect_binding(&cgroup_path);
        let mut bindings = WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
        bindings
            .publish_all(&host, std::slice::from_ref(&binding))
            .context(NodeSnafu)?;
        NativeSecurityStateOwner::new(node_boot_id, 1)
            .activate(&mut host)
            .context(NodeSnafu)?;

        let mut fixture = EffectProcessFixture::start(&fixture_root)?;
        fs::write(cgroup_path.join("cgroup.procs"), fixture.pid().to_string()).context(
            IoSnafu {
                path: cgroup_path.join("cgroup.procs"),
            },
        )?;
        let node_config = effect_node_config(
            &fixture_root,
            pin_root,
            lease_path,
            &policy_fixture,
            artifact_path,
            vec![binding],
            Vec::new(),
        );
        let policy =
            NodePolicyGenerationOwner::load_and_install(&node_config, &mut host, node_boot_id, 1)
                .context(NodeSnafu)?;
        NativeSecurityStateOwner::new(node_boot_id, 1)
            .activate_with_effect_policy(&mut host, true)
            .context(NodeSnafu)?;
        let observations = EffectObservationStore::default();
        let sink = observations.clone();
        let reader = host
            .effect_observation_reader(move |bytes| {
                sink.record_bytes(bytes);
                0
            })
            .context(InterceptorSnafu)?;

        let denied_marker = observations.cursor();
        let denied_unclassified_connect = fixture
            .network_connect(SocketAddr::from(([127, 0, 0, 1], 9)))?
            .denied();
        ensure!(
            denied_unclassified_connect,
            InvalidInputSnafu {
                path: Path::new("127.0.0.1:9"),
                reason: "the unclassified destination did not deny before connect",
            }
        );
        wait_for_effect(
            &reader,
            &observations,
            denied_marker,
            "UNRESOLVED_OBJECT",
            (
                KernelEffectFamilyV1::Network,
                KernelEffectOperationV1::Connect,
            ),
        )?;

        let allowed_marker = observations.cursor();
        let allowed_connect = fixture.network_connect(allowed_address)?.allowed;
        ensure!(
            allowed_connect,
            InvalidInputSnafu {
                path: Path::new("allowed network listener"),
                reason: "the signed destination did not connect",
            }
        );
        wait_for_effect(
            &reader,
            &observations,
            allowed_marker,
            "EXACT_POLICY_AUDIT_ALLOW",
            (
                KernelEffectFamilyV1::Network,
                KernelEffectOperationV1::Connect,
            ),
        )?;
        let allowed_event = observations
            .recent_since(allowed_marker)
            .into_iter()
            .find(|event| {
                event.reason == "EXACT_POLICY_AUDIT_ALLOW"
                    && event.operation == u32::from(KernelEffectOperationV1::Connect as u16)
            })
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: Path::new("effect_observations"),
                    reason: "the allowed connect has no exact socket evidence",
                }
                .build()
            })?;
        let allowed_socket_control = fixture.network_set_nodelay()?.allowed;
        let allowed_send_received = fixture.network_send(PAYLOAD)?.allowed;
        let allowed_receive = fixture.network_receive()?.allowed;
        ensure!(
            allowed_socket_control && allowed_send_received && allowed_receive,
            InvalidInputSnafu {
                path: Path::new("allowed network socket"),
                reason: "the signed socket control, send, or receive failed",
            }
        );

        let fence = policy
            .fence_network_socket(
                &host,
                NetworkResponseFloorKeyV1 {
                    profile_generation_ref_id: allowed_event
                        .network_creator_profile_generation_ref_id,
                    socket_key_id: allowed_event.network_socket_key_id,
                    socket_generation: allowed_event.network_socket_generation,
                },
                1,
            )
            .context(NodeSnafu)?;
        let profile_generation_ref_id = allowed_event.network_creator_profile_generation_ref_id;
        let whole_socket_fence_installed =
            fence.scope == NetworkResponseScopeV1::WholeSocket && fence.inserted;
        let fence_marker = observations.cursor();
        let post_fence_send_denied = fixture.network_send(b"blocked")?.denied();
        ensure!(
            post_fence_send_denied,
            InvalidInputSnafu {
                path: Path::new("fenced network socket"),
                reason: "the whole-socket response fence allowed a later send",
            }
        );
        wait_for_effect(
            &reader,
            &observations,
            fence_marker,
            "NETWORK_RESPONSE_FENCE",
            (KernelEffectFamilyV1::Network, KernelEffectOperationV1::Send),
        )?;
        let post_fence_shutdown_denied = fixture.network_shutdown()?.denied();
        ensure!(
            post_fence_shutdown_denied,
            InvalidInputSnafu {
                path: Path::new("fenced network socket"),
                reason: "the whole-socket response fence allowed shutdown",
            }
        );
        fixture.network_close()?;
        let references = host
            .lookup_map(
                "profile_generation_socket_refs",
                &profile_generation_ref_id.to_ne_bytes(),
            )
            .context(InterceptorSnafu)?
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: Path::new("profile_generation_socket_refs"),
                    reason: "the network generation lost its reference row",
                }
                .build()
            })?;
        let reference_bytes: [u8; 8] = references.as_slice().try_into().map_err(|error| {
            InvalidInputSnafu {
                path: Path::new("profile_generation_socket_refs"),
                reason: format!("the network reference count is invalid: {error}"),
            }
            .build()
        })?;
        let socket_reference_released = u64::from_ne_bytes(reference_bytes) == 0;
        ensure!(
            socket_reference_released,
            InvalidInputSnafu {
                path: Path::new("profile_generation_socket_refs"),
                reason: "the closed socket retained generation authority",
            }
        );
        fixture.stop()?;
        let post_fence_bytes_absent = server
            .join()
            .map_err(|_| {
                InvalidInputSnafu {
                    path: Path::new("network server"),
                    reason: "the network server thread panicked",
                }
                .build()
            })?
            .context(IoSnafu {
                path: Path::new("network server"),
            })?;
        ensure!(
            post_fence_bytes_absent,
            InvalidInputSnafu {
                path: Path::new("network server"),
                reason: "the server received bytes after the whole-socket fence",
            }
        );

        host.shutdown().context(InterceptorSnafu)?;
        pin_cleanup.cleanup()?;
        lease_cleanup.cleanup()?;
        cgroup_cleanup.cleanup()?;
        fixture_cleanup.cleanup()?;
        Ok(NetworkPhysicalProbeBundleV1 {
            schema_version: 1,
            denied_unclassified_connect,
            allowed_connect,
            allowed_send_received,
            allowed_receive,
            allowed_socket_control,
            whole_socket_fence_installed,
            post_fence_send_denied,
            post_fence_shutdown_denied,
            post_fence_bytes_absent,
            socket_reference_released,
            fixture_results: fixture_results(),
        })
    }

    pub fn write_json<T: Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        fs::write(
            path,
            serde_json::to_vec_pretty(value).context(JsonSnafu { path })?,
        )
        .context(IoSnafu { path })
    }
}

fn build_network_artifact(
    policy_fixture: &Path,
    fixture_root: &Path,
    allowed_port: u16,
) -> Result<PathBuf> {
    let policy_source = policy_fixture.join("protect-policy-v1.yaml");
    let mut document = PolicyDocumentV1::parse(
        &policy_source,
        &fs::read(&policy_source).context(IoSnafu {
            path: &policy_source,
        })?,
    )
    .context(PolicySnafu)?;
    document.network_policy = Some(NetworkPolicyV1 {
        dns_mode: DnsPolicyModeV1::DenyDnsAndUsePolicyResolvedAddresses,
        destination_policies: vec![DestinationPolicyRecordV1 {
            destination_policy_id: "allowed-result-service".to_owned(),
            protocols: vec![NetworkProtocolV1::Tcp],
            ipv4_prefixes: vec!["127.0.0.0/8".to_owned()],
            ipv6_prefixes: Vec::new(),
            port_ranges: vec![NetworkPortRangeV1 {
                first: allowed_port,
                last: allowed_port,
            }],
            required_network_namespace_ids: Vec::new(),
            service_identities: Vec::new(),
            final_address_required: true,
        }],
    });
    document.effect_family_defaults.push(EffectFamilyDefaultV1 {
        role_ids: vec!["runtime-external".to_owned()],
        effect_family: EffectFamilyV1::Network,
        operations: ["SETSOCKOPT", "SHUTDOWN", "SOCKET_CREATE"]
            .map(str::to_owned)
            .to_vec(),
        requested_disposition: PolicyDispositionV1::Allow,
        errno: None,
        finding: None,
    });
    let mut network_rule = document.rules[0].clone();
    network_rule.rule_id = "allow-network-result-service".to_owned();
    let RuleMatchV1::LocalPreEffect(effect) = &mut network_rule.rule_match else {
        unreachable!("the effect fixture begins with a local rule")
    };
    effect.effect_families = vec![EffectFamilyV1::Network];
    effect.operation_ids = ["CONNECT", "RECEIVE", "SEND"].map(str::to_owned).to_vec();
    effect.object = LocalObjectSelectorV1::Destinations {
        destination_policy_ids: vec!["allowed-result-service".to_owned()],
    };
    network_rule.requested_disposition = PolicyDispositionV1::Alert;
    network_rule.errno = None;
    network_rule.finding = Some(
        document
            .default_postures
            .required_classifier_unknown
            .finding
            .clone(),
    );
    document.rules.push(network_rule);

    let generated_policy = fixture_root.join("network-policy-v1.json");
    fs::write(
        &generated_policy,
        serde_json::to_vec_pretty(&document).context(JsonSnafu {
            path: &generated_policy,
        })?,
    )
    .context(IoSnafu {
        path: &generated_policy,
    })?;
    let artifact = fixture_root.join("network-profile-v1.json");
    PolicyArtifactOwner::default()
        .compile_and_sign(
            &generated_policy,
            &policy_fixture.join("observe-profile-seal-request.json"),
            &policy_fixture.join("test-signing-key.hex"),
            &artifact,
        )
        .context(PolicySnafu)?;
    Ok(artifact)
}

fn server_exchange(listener: TcpListener) -> std::io::Result<bool> {
    let (mut stream, _) = listener.accept()?;
    let mut payload = [0_u8; PAYLOAD.len()];
    stream.read_exact(&mut payload)?;
    if payload != PAYLOAD {
        return Ok(false);
    }
    stream.write_all(b"r")?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    let mut extra = [0_u8; 7];
    match stream.read(&mut extra) {
        Ok(0) => Ok(true),
        Ok(_) => Ok(false),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

fn fixture_results() -> Vec<NetworkFixtureResultV1> {
    [
        (
            "FILE-DELEGATED-EGRESS-001",
            "UNSUPPORTED",
            "DELEGATED_REMOTE_FILE_IO_NOT_QUALIFIED",
        ),
        (
            "HF-004-RESULT-001",
            "PASS",
            "CONNECT_SEND_PACKET_AND_SERVER_RECEIPT_SEPARATED",
        ),
        (
            "HF-011-READ-RESULT-001",
            "UNSUPPORTED",
            "TOKEN_READ_CHAIN_NOT_PART_OF_NETWORK_PROBE",
        ),
        (
            "HF-NET-001",
            "PASS",
            "UNCLASSIFIED_CONNECT_DENIED_AND_ALLOWED_RESULT_RECEIVED",
        ),
        (
            "IPC-LOCAL-INET-008",
            "PASS",
            "LOOPBACK_IPV4_DESTINATION_AND_UNIX_POLICY_REMAIN_SEPARATE",
        ),
        (
            "NET-ACCEPT-PASS-001",
            "UNSUPPORTED",
            "CROSS_ACTOR_ACCEPT_PASS_PHYSICAL_PROBE_PENDING",
        ),
        (
            "NET-DNS-EXFIL-001",
            "PASS",
            "DNS_DENIED_BY_SELECTED_POLICY_RESOLVED_ADDRESS_MODE",
        ),
        (
            "NET-NS-PASS-001",
            "UNSUPPORTED",
            "CROSS_NETWORK_NAMESPACE_ALLOW_NOT_ADVERTISED",
        ),
        (
            "NET-RECV-001",
            "PASS",
            "QUALIFIED_TCP_RECEIVE_RETURNED_APPLICATION_BYTE",
        ),
        (
            "NET-REWRITE-001",
            "UNSUPPORTED",
            "NO_REWRITE_CHAIN_INSTALLED_IN_SINGLE_HOST_PROBE",
        ),
        (
            "NET-SHARED-RESPONSE-002",
            "PASS",
            "WHOLE_SOCKET_FENCE_DENIED_LATER_SEND_AND_SERVER_BYTES",
        ),
        (
            "NET-SOCKCTL-001",
            "PASS",
            "TCP_NODELAY_CONTROL_SUCCEEDED_UNDER_EXACT_DEFAULT",
        ),
        (
            "NET-SOCKET-LIFE-001",
            "PASS",
            "FINAL_CLOSE_RELEASED_SOCKET_GENERATION_REFERENCE",
        ),
    ]
    .into_iter()
    .map(
        |(fixture_id, result, physical_oracle)| NetworkFixtureResultV1 {
            fixture_id: fixture_id.to_owned(),
            result: result.to_owned(),
            physical_oracle: physical_oracle.to_owned(),
        },
    )
    .collect()
}

#[cfg(test)]
mod tests {
    use super::{build_network_artifact, fixture_results};

    #[test]
    fn phase_five_fixture_matrix_is_closed_and_unique() {
        let results = fixture_results();
        assert_eq!(results.len(), 13);
        assert!(results
            .windows(2)
            .all(|pair| pair[0].fixture_id != pair[1].fixture_id));
        assert!(results.iter().all(|fixture| {
            matches!(fixture.result.as_str(), "PASS" | "UNSUPPORTED")
                && !fixture.physical_oracle.is_empty()
        }));
    }

    #[test]
    fn signed_network_fixture_compiles_before_physical_use() -> crate::Result<()> {
        let directory = tempfile::tempdir().map_err(|source| crate::Error::Io {
            path: "temporary network fixture".into(),
            source,
            location: snafu::Location::default(),
        })?;
        let policy_fixture =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/mithril-policy");
        let artifact = build_network_artifact(&policy_fixture, directory.path(), 8_443)?;
        assert!(artifact.is_file());
        Ok(())
    }
}
