use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use erebor_interceptor::{KernelHost, KernelHostConfig, KernelHostOwner};
use erebor_interceptor_abi::{
    KernelEffectFamilyV1, KernelEffectOperationV1, NetworkResponseFloorKeyV1,
};
use mithril_control::{
    DestinationPolicyRecordV1, DnsPolicyModeV1, EffectFamilyDefaultV1, EffectFamilyV1, EntryKindV1,
    LocalObjectSelectorV1, NetworkPolicyV1, NetworkPortRangeV1, NetworkProtocolV1,
    PolicyArtifactOwner, PolicyDispositionV1, PolicyDocumentV1, RuleMatchV1,
};
use mithril_node::{
    EffectObservationStore, ExactFileObjectResolver, NativeIdentityInspector,
    NativeSecurityStateOwner, NodePolicyGenerationOwner, WorkloadBindingOwner,
};
use serde::Serialize;
use snafu::{ensure, ResultExt as _};
use zerocopy::{FromBytes as _, IntoBytes as _};

use super::child::EffectProcessFixture;
use super::support::{
    effect_binding_with_identity, effect_node_config, inode_generation, mount_views_are_clean,
    wait_for_effect,
};
use crate::error::{
    InterceptorSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu, NodeSnafu, PolicySnafu,
};
use crate::physical::{boot_identity, ProbeCgroup, ProbeDirectory, ProbeFile};
use crate::Result;

const PAYLOAD: &[u8] = b"allowed";
const DUP_PAYLOAD: &[u8] = b"dup";
const FORK_PAYLOAD: &[u8] = b"fork";
const SENDMSG_PAYLOAD: &[u8] = b"sendmsg";
const TOKEN_PAYLOAD: &[u8] = b"token";
const TOKEN_OBJECT_KEY_ID: u64 = 9_001;
pub const NETWORK_PEER_TCP_PORT: u16 = 46_051;
pub const NETWORK_PEER_UDP_PORT: u16 = 46_052;
pub const NETWORK_PEER_DENIED_PORT: u16 = 46_053;
const NETWORK_PEER_TCP_PAYLOAD: &[u8] = b"peer-tcp";
const NETWORK_PEER_UDP_PAYLOAD: &[u8] = b"peer-udp";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkPeerTargetV1 {
    pub address: IpAddr,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub denied_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NetworkPeerServerResultV1 {
    pub schema_version: u32,
    pub tcp_payload_received: bool,
    pub udp_payload_received: bool,
    pub denied_connection_absent: bool,
}

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
    pub sendmsg_allowed: bool,
    pub sendfile_allowed: bool,
    pub splice_allowed: bool,
    pub allowed_receive: bool,
    pub allowed_socket_control: bool,
    pub whole_socket_fence_installed: bool,
    pub restart_preserved_task_state: bool,
    pub restart_preserved_socket_state: bool,
    pub restart_preserved_response_floor: bool,
    pub restart_preserved_mount_state: bool,
    pub restart_preserved_active_generation: bool,
    pub post_fence_send_denied: bool,
    pub post_fence_shutdown_denied: bool,
    pub post_fence_bytes_absent: bool,
    pub post_fence_bypass_packets_absent: bool,
    pub socket_reference_released: bool,
    pub tcp_ipv6_allowed: bool,
    pub udp_connected_allowed: bool,
    pub udp_unconnected_allowed: bool,
    pub dns_and_alternate_resolver_denied: bool,
    pub unsupported_network_families_denied: bool,
    pub io_uring_sqpoll_denied: bool,
    pub tun_tap_setup_denied: bool,
    pub bpf_setup_denied: bool,
    pub unsafe_socket_control_denied: bool,
    pub accepted_socket_narrow_actor_denied: bool,
    pub accepted_socket_approved_actor_allowed: bool,
    pub cross_namespace_narrow_actor_denied: bool,
    pub cross_namespace_approved_actor_allowed: bool,
    pub cross_namespace_evidence_distinct: bool,
    pub rewritten_forbidden_packet_absent: bool,
    pub rewritten_allowed_destination_received: bool,
    pub delegated_forbidden_request_absent: bool,
    pub delegated_allowed_request_received: bool,
    pub read_results_separate: bool,
    pub provider_write_observed: bool,
    pub shared_socket_holders_denied: bool,
    pub cloned_socket_allowed: bool,
    pub inherited_socket_allowed: bool,
    pub socket_generation_not_reused: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_tcp_allowed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_udp_allowed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_denied_connect: Option<bool>,
    pub fixture_results: Vec<NetworkFixtureResultV1>,
}

#[derive(Default)]
struct NetworkFixtureProof {
    delegated_egress: bool,
    hf_result: bool,
    hf_read_result: bool,
    hf_network: bool,
    local_inet: bool,
    accept_pass: bool,
    dns_exfil: bool,
    namespace_pass: bool,
    receive: bool,
    rewrite: bool,
    shared_response: bool,
    socket_control: bool,
    socket_life: bool,
}

#[derive(Clone, Copy)]
struct NetworkActorSpec {
    name: &'static str,
    binding_id: &'static str,
    label: char,
    initial_role: bool,
    private_network_namespace: bool,
}

struct NetworkActor {
    spec: NetworkActorSpec,
    cgroup: ProbeCgroup,
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
        peer: Option<NetworkPeerTargetV1>,
    ) -> Result<NetworkPhysicalProbeBundleV1> {
        validate_network_peer(peer)?;
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
        let transport_root = PathBuf::from(format!(
            "/tmp/mithril-net-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| invalid_probe(format!("the system clock is invalid: {error}")))?
                .as_nanos()
        ));
        fs::create_dir(&transport_root).context(IoSnafu {
            path: &transport_root,
        })?;
        let transport_cleanup = ProbeDirectory::new(&transport_root);
        let pin_cleanup = ProbeDirectory::new(pin_root);
        let lease_cleanup = ProbeFile::new(lease_path);
        let cgroup_cleanup = ProbeCgroup::create(cgroup_path)?;
        let cgroup_path = cgroup_cleanup.path().to_path_buf();
        let actor_specs = [
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
                name: "external-receiver",
                binding_id: "99999999-9999-4999-8999-999999999993",
                label: 'c',
                initial_role: false,
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
        let mut actors = actor_specs
            .into_iter()
            .map(|spec| {
                Ok(NetworkActor {
                    cgroup: ProbeCgroup::create(&cgroup_path.join(spec.name))?,
                    spec,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let repo_root = fs::canonicalize(&self.repo_root).context(IoSnafu {
            path: &self.repo_root,
        })?;
        let policy_fixture = repo_root.join("crates/mithril-e2e/fixtures/mithril-policy");

        let listener = tcp_listener(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let allowed_address = listener.local_addr().context(IoSnafu {
            path: Path::new("allowed network listener"),
        })?;
        let lifecycle_listener = tcp_listener(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let lifecycle_address = lifecycle_listener.local_addr().context(IoSnafu {
            path: Path::new("lifecycle network listener"),
        })?;
        let ipv6_listener = tcp_listener(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 0)))?;
        let ipv6_address = ipv6_listener.local_addr().context(IoSnafu {
            path: Path::new("IPv6 network listener"),
        })?;
        let rewrite_listener = tcp_listener(SocketAddr::from(([127, 0, 0, 4], 0)))?;
        let rewrite_address = rewrite_listener.local_addr().context(IoSnafu {
            path: Path::new("rewrite network listener"),
        })?;
        let delegated_listener = tcp_listener(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let delegated_address = delegated_listener.local_addr().context(IoSnafu {
            path: Path::new("delegated network listener"),
        })?;
        let delegated_denied_listener = tcp_listener(SocketAddr::from(([127, 0, 0, 53], 0)))?;
        let delegated_denied_address = delegated_denied_listener.local_addr().context(IoSnafu {
            path: Path::new("denied delegated network listener"),
        })?;
        let provider_listener = tcp_listener(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let provider_address = provider_listener.local_addr().context(IoSnafu {
            path: Path::new("provider-result listener"),
        })?;
        let udp_ipv4 = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).context(IoSnafu {
            path: Path::new("IPv4 UDP listener"),
        })?;
        let udp_ipv4_address = udp_ipv4.local_addr().context(IoSnafu {
            path: Path::new("IPv4 UDP listener"),
        })?;
        let udp_ipv6 =
            UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 0))).context(IoSnafu {
                path: Path::new("IPv6 UDP listener"),
            })?;
        let udp_ipv6_address = udp_ipv6.local_addr().context(IoSnafu {
            path: Path::new("IPv6 UDP listener"),
        })?;
        let accepted_address = available_tcp_address([127, 0, 0, 2])?;

        let (boot_id, node_boot_id) = boot_identity()?;
        let mut kernel_config = KernelHostConfig::identity(
            "/sys/kernel/btf/vmlinux",
            lease_path,
            Some(pin_root.to_path_buf()),
            boot_id,
            1,
        );
        kernel_config.network_cgroup_root = cgroup_path.clone();
        let mut host = KernelHostOwner::new(kernel_config.clone())
            .start()
            .context(InterceptorSnafu)?;
        let binding_specs = actors
            .iter()
            .map(|actor| {
                effect_binding_with_identity(
                    actor.cgroup.path(),
                    actor.spec.binding_id,
                    actor.spec.label,
                    actor.spec.name,
                    actor.spec.initial_role,
                )
            })
            .collect::<Vec<_>>();
        let mut bindings = WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
        bindings
            .publish_all(&host, &binding_specs)
            .context(NodeSnafu)?;
        NativeSecurityStateOwner::new(node_boot_id, 1)
            .activate(&mut host)
            .context(NodeSnafu)?;

        let main_root = actor_root(&fixture_root, actors[0].spec.name)?;
        let token_path = main_root.join("token");
        fs::write(&token_path, TOKEN_PAYLOAD).context(IoSnafu { path: &token_path })?;
        let mut fixture = EffectProcessFixture::start(&main_root)?;
        move_actor(&fixture, actors[0].cgroup.path())?;
        let mut server_fixture = start_actor(
            &fixture_root,
            actors[1].spec.name,
            actors[1].cgroup.path(),
            actors[1].spec.private_network_namespace,
        )?;
        let mut external_receiver = start_actor(
            &fixture_root,
            actors[2].spec.name,
            actors[2].cgroup.path(),
            actors[2].spec.private_network_namespace,
        )?;
        let mut converter_receiver = start_actor(
            &fixture_root,
            actors[3].spec.name,
            actors[3].cgroup.path(),
            actors[3].spec.private_network_namespace,
        )?;
        let mut namespace_external = start_actor(
            &fixture_root,
            actors[4].spec.name,
            actors[4].cgroup.path(),
            actors[4].spec.private_network_namespace,
        )?;
        let mut namespace_converter = start_actor(
            &fixture_root,
            actors[5].spec.name,
            actors[5].cgroup.path(),
            actors[5].spec.private_network_namespace,
        )?;
        let mut proxy_requester = start_actor(
            &fixture_root,
            actors[6].spec.name,
            actors[6].cgroup.path(),
            actors[6].spec.private_network_namespace,
        )?;
        let mut proxy_delegate = start_actor(
            &fixture_root,
            actors[7].spec.name,
            actors[7].cgroup.path(),
            actors[7].spec.private_network_namespace,
        )?;
        for actor in [
            &mut fixture,
            &mut server_fixture,
            &mut external_receiver,
            &mut converter_receiver,
            &mut namespace_external,
            &mut namespace_converter,
            &mut proxy_requester,
            &mut proxy_delegate,
        ] {
            ensure!(
                actor
                    .network_socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP)?
                    .allowed,
                InvalidInputSnafu {
                    path: Path::new("network actor classification"),
                    reason: "an actor could not complete its pre-policy classification operation",
                }
            );
        }
        let external_pass = transport_root.join("external.sock");
        let converter_pass = transport_root.join("converter.sock");
        let proxy_path = transport_root.join("proxy.sock");
        fixture.prepare_file(&token_path)?;
        let read_results = fixture.network_read_results(&token_path)?;
        let token_object = ExactFileObjectResolver::resolve(
            fixture.pid(),
            &token_path,
            1,
            TOKEN_OBJECT_KEY_ID,
            "NETWORK_TOKEN".to_owned(),
            inode_generation(fixture.pid(), &token_path)?,
            None,
        )
        .context(NodeSnafu)?;
        let token_mount_namespaces = BTreeSet::from([token_object.mount_namespace_inode]);
        let artifact_path = build_network_artifact(&policy_fixture, &fixture_root, peer)?;
        let node_config = effect_node_config(
            &fixture_root,
            pin_root,
            lease_path,
            &policy_fixture,
            artifact_path,
            binding_specs,
            vec![token_object],
        );
        let mut policy =
            NodePolicyGenerationOwner::load_and_install(&node_config, &mut host, node_boot_id, 1)
                .context(NodeSnafu)?;
        ensure!(
            mount_views_are_clean(&host, &token_mount_namespaces)?,
            InvalidInputSnafu {
                path: Path::new("mount_security_views"),
                reason: "network token policy activation did not produce a clean mount view",
            }
        );
        NativeSecurityStateOwner::new(node_boot_id, 1)
            .activate_with_effect_policy(&mut host, true)
            .context(NodeSnafu)?;
        let observations = EffectObservationStore::default();
        let sink = observations.clone();
        let mut reader = host
            .effect_observation_reader(move |bytes| {
                sink.record_bytes(bytes);
                0
            })
            .context(InterceptorSnafu)?;
        let transport_marker = observations.cursor();
        let transport_prepared = [
            external_receiver.network_prepare_pass_receiver(&external_pass)?,
            converter_receiver.network_prepare_pass_receiver(&converter_pass)?,
            proxy_delegate.network_prepare_proxy(&proxy_path)?,
        ];
        reader
            .poll(Duration::from_millis(100))
            .context(InterceptorSnafu)?;
        ensure!(
            transport_prepared.iter().all(|outcome| outcome.allowed),
            InvalidInputSnafu {
                path: &transport_root,
                reason: format!(
                    "a Unix transport endpoint could not be prepared; outcomes={transport_prepared:?}, observations={:?}",
                    observations
                        .recent_since(transport_marker)
                        .into_iter()
                        .map(|event| (
                            event.reason,
                            event.effect_family,
                            event.operation,
                            event.active_role_id,
                            event.entry_kind,
                            event.exact_object_key_id,
                        ))
                        .collect::<Vec<_>>()
                ),
            }
        );

        let server = thread::spawn(move || {
            server_exchange(
                listener,
                &[
                    PAYLOAD,
                    DUP_PAYLOAD,
                    FORK_PAYLOAD,
                    SENDMSG_PAYLOAD,
                    TOKEN_PAYLOAD,
                    TOKEN_PAYLOAD,
                ]
                .concat(),
            )
        });
        let lifecycle_server = thread::spawn(move || server_receive(lifecycle_listener, b"new"));
        let ipv6_server = thread::spawn(move || server_receive(ipv6_listener, b"ipv6"));
        let rewrite_server = thread::spawn(move || server_receive(rewrite_listener, b"rewrite"));
        let delegated_server =
            thread::spawn(move || server_receive(delegated_listener, b"delegated"));
        let delegated_denied_server =
            thread::spawn(move || server_absent(delegated_denied_listener));
        let provider_server = thread::spawn(move || server_receive(provider_listener, b"provider"));
        let governed_read = fixture.read_prepared()?;
        let governed_mmap = fixture.mmap_prepared()?;
        let governed_read_allowed = governed_read.allowed;
        let governed_mmap_allowed = governed_mmap.allowed;

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
                    && event.operation == KernelEffectOperationV1::Connect as u32
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
        fixture.network_clone()?;
        let cloned_socket_allowed = fixture.network_clone_send(DUP_PAYLOAD)?.allowed;
        let inherited_socket_allowed = fixture.network_fork_send(FORK_PAYLOAD)?.allowed;
        let sendmsg_allowed = fixture.network_sendmsg(SENDMSG_PAYLOAD)?.allowed;
        let sendfile_allowed = fixture.network_sendfile(&token_path)?.allowed;
        let splice_allowed = fixture.network_splice(&token_path)?.allowed;
        let unsafe_socket_control_denied = fixture.network_set_mark(7)?.denied();
        ensure!(
            cloned_socket_allowed
                && inherited_socket_allowed
                && sendmsg_allowed
                && sendfile_allowed
                && splice_allowed
                && unsafe_socket_control_denied,
            InvalidInputSnafu {
                path: Path::new("network socket variants"),
                reason: "a socket transfer path, inherited path, or unsafe control failed",
            }
        );

        let fence_key = NetworkResponseFloorKeyV1 {
            profile_generation_ref_id: allowed_event.network_creator_profile_generation_ref_id,
            socket_key_id: allowed_event.network_socket_key_id,
            socket_generation: allowed_event.network_socket_generation,
        };
        let fence = policy
            .fence_network_socket(&host, fence_key)
            .context(NodeSnafu)?;
        let profile_generation_ref_id = allowed_event.network_creator_profile_generation_ref_id;
        let whole_socket_fence_installed = fence;
        let identity_inspector = NativeIdentityInspector::new(pin_root);
        let task_state_before = identity_inspector
            .snapshot(fixture.pid())
            .context(NodeSnafu)?
            .ok_or_else(|| invalid_probe("the live network task has no retained identity"))?;
        let response_floor_before = host
            .lookup_map("network_response_floors", fence_key.as_bytes())
            .context(InterceptorSnafu)?
            .ok_or_else(|| invalid_probe("the installed network response floor is missing"))?;
        let mount_state_before = map_snapshot(&host, "mount_security_views")?;
        let active_generation_before = map_snapshot(&host, "active_profile_generations")?;
        ensure!(
            !mount_state_before.is_empty() && !active_generation_before.is_empty(),
            InvalidInputSnafu {
                path: Path::new("retained recovery maps"),
                reason: "the restart fixture has no live mount or generation state",
            }
        );

        drop(reader);
        host.shutdown().context(InterceptorSnafu)?;
        host = KernelHostOwner::new(kernel_config.clone())
            .start()
            .context(InterceptorSnafu)?;
        let mut recovered_bindings =
            WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
        recovered_bindings
            .publish_all(&host, &node_config.workload_bindings)
            .context(NodeSnafu)?;
        policy = policy
            .reload_and_install(&node_config, &mut host, node_boot_id, 1)
            .context(NodeSnafu)?;
        NativeSecurityStateOwner::new(node_boot_id, 1)
            .activate_with_effect_policy(&mut host, true)
            .context(NodeSnafu)?;
        let sink = observations.clone();
        reader = host
            .effect_observation_reader(move |bytes| {
                sink.record_bytes(bytes);
                0
            })
            .context(InterceptorSnafu)?;
        let restart_preserved_task_state = identity_inspector
            .snapshot(fixture.pid())
            .context(NodeSnafu)?
            .as_ref()
            == Some(&task_state_before);
        let restart_preserved_response_floor = host
            .lookup_map("network_response_floors", fence_key.as_bytes())
            .context(InterceptorSnafu)?
            .as_deref()
            == Some(response_floor_before.as_slice());
        let restart_preserved_mount_state =
            map_snapshot(&host, "mount_security_views")? == mount_state_before;
        let restart_preserved_active_generation =
            map_snapshot(&host, "active_profile_generations")? == active_generation_before;
        ensure!(
            restart_preserved_task_state
                && restart_preserved_response_floor
                && restart_preserved_mount_state
                && restart_preserved_active_generation,
            InvalidInputSnafu {
                path: Path::new("retained recovery maps"),
                reason:
                    "loader restart changed retained task, response, mount, or generation state",
            }
        );
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
        let restart_preserved_socket_state =
            observations.recent_since(fence_marker).iter().any(|event| {
                event.reason == "NETWORK_RESPONSE_FENCE"
                    && event.network_creator_profile_generation_ref_id
                        == allowed_event.network_creator_profile_generation_ref_id
                    && event.network_socket_key_id == allowed_event.network_socket_key_id
                    && event.network_socket_generation == allowed_event.network_socket_generation
            });
        ensure!(
            restart_preserved_socket_state,
            InvalidInputSnafu {
                path: Path::new("retained network socket"),
                reason: "the post-restart fence did not retain the exact live socket identity",
            }
        );
        let post_fence_shutdown_denied = fixture.network_shutdown()?.denied();
        let post_fence_sendmsg = fixture.network_sendmsg(b"sendmsg-blocked")?;
        let post_fence_sendfile = fixture.network_sendfile(&token_path)?;
        let post_fence_splice = fixture.network_splice(&token_path)?;
        let shared_clone_denied = fixture.network_clone_send(b"clone-blocked")?.denied();
        ensure!(
            post_fence_shutdown_denied
                && shared_clone_denied
                && (post_fence_sendmsg.allowed || post_fence_sendmsg.denied())
                && (post_fence_sendfile.allowed || post_fence_sendfile.denied())
                && (post_fence_splice.allowed || post_fence_splice.denied()),
            InvalidInputSnafu {
                path: Path::new("fenced network socket"),
                reason: "a fenced bypass path returned an unqualified result",
            }
        );
        fixture.network_close()?;
        let socket_reference_released =
            socket_reference_count(&host, profile_generation_ref_id)? == 0;
        ensure!(
            socket_reference_released,
            InvalidInputSnafu {
                path: Path::new("profile_generation_socket_refs"),
                reason: "the closed socket retained generation authority",
            }
        );
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
        let post_fence_bypass_packets_absent = post_fence_bytes_absent;

        let reuse_marker = observations.cursor();
        let lifecycle_connect = fixture.network_connect(lifecycle_address)?.allowed;
        wait_for_effect(
            &reader,
            &observations,
            reuse_marker,
            "EXACT_POLICY_AUDIT_ALLOW",
            (
                KernelEffectFamilyV1::Network,
                KernelEffectOperationV1::Connect,
            ),
        )?;
        let reused_event = observations
            .recent_since(reuse_marker)
            .into_iter()
            .rev()
            .find(|event| event.operation == KernelEffectOperationV1::Connect as u32)
            .ok_or_else(|| invalid_probe("the reused socket has no connect observation"))?;
        let socket_generation_not_reused =
            reused_event.network_socket_generation != allowed_event.network_socket_generation;
        let lifecycle_send = fixture.network_send(b"new")?.allowed;
        let lifecycle_shutdown = fixture.network_shutdown()?.allowed;
        fixture.network_close()?;
        let lifecycle_received = join_server(lifecycle_server, "lifecycle server")?;
        ensure!(
            lifecycle_connect
                && lifecycle_send
                && lifecycle_shutdown
                && lifecycle_received
                && socket_generation_not_reused,
            InvalidInputSnafu {
                path: Path::new("socket lifecycle"),
                reason: "a new socket reused authority or failed its positive lifecycle",
            }
        );

        let tcp_ipv6_allowed = fixture.network_connect(ipv6_address)?.allowed
            && fixture.network_send(b"ipv6")?.allowed;
        fixture.network_close()?;
        ensure!(
            tcp_ipv6_allowed && join_server(ipv6_server, "IPv6 server")?,
            InvalidInputSnafu {
                path: Path::new("IPv6 network path"),
                reason: "the signed IPv6 TCP control failed",
            }
        );
        let udp_ipv4_server =
            thread::spawn(move || udp_receive(udp_ipv4, [b"u4".as_slice(), b"c4".as_slice()]));
        let udp_ipv6_server =
            thread::spawn(move || udp_receive(udp_ipv6, [b"u6".as_slice(), b"c6".as_slice()]));
        let udp_unconnected_allowed = fixture
            .network_udp_send(udp_ipv4_address, b"u4", false)?
            .allowed
            && fixture
                .network_udp_send(udp_ipv6_address, b"u6", false)?
                .allowed;
        let udp_connected_allowed = fixture
            .network_udp_send(udp_ipv4_address, b"c4", true)?
            .allowed
            && fixture
                .network_udp_send(udp_ipv6_address, b"c6", true)?
                .allowed;
        ensure!(
            udp_unconnected_allowed
                && udp_connected_allowed
                && join_server(udp_ipv4_server, "IPv4 UDP server")?
                && join_server(udp_ipv6_server, "IPv6 UDP server")?,
            InvalidInputSnafu {
                path: Path::new("UDP network paths"),
                reason: "a connected or unconnected IPv4/IPv6 UDP control failed",
            }
        );

        let dns_and_alternate_resolver_denied = [
            SocketAddr::from(([127, 0, 0, 1], 53)),
            SocketAddr::from(([127, 0, 0, 53], 853)),
            SocketAddr::from(([127, 0, 0, 53], 443)),
        ]
        .into_iter()
        .map(|address| fixture.network_connect(address))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .all(super::child::IoOutcome::denied)
            && fixture
                .network_udp_send(SocketAddr::from(([127, 0, 0, 1], 53)), b"dns", false)?
                .denied()
            && fixture
                .network_udp_send(SocketAddr::from(([8, 8, 8, 8], 53)), b"dns", true)?
                .denied()
            && fixture
                .network_udp_send(SocketAddr::from(([127, 0, 0, 53], 5_353)), b"dns", false)?
                .denied();
        let (peer_tcp_allowed, peer_udp_allowed, peer_denied_connect) = match peer {
            Some(peer) => {
                let denied = fixture
                    .network_connect(SocketAddr::new(peer.address, peer.denied_port))?
                    .denied();
                let tcp = fixture
                    .network_connect(SocketAddr::new(peer.address, peer.tcp_port))?
                    .allowed
                    && fixture.network_send(NETWORK_PEER_TCP_PAYLOAD)?.allowed;
                fixture.network_close()?;
                let udp = fixture
                    .network_udp_send(
                        SocketAddr::new(peer.address, peer.udp_port),
                        NETWORK_PEER_UDP_PAYLOAD,
                        false,
                    )?
                    .allowed;
                ensure!(
                    denied && tcp && udp,
                    InvalidInputSnafu {
                        path: Path::new("two-node network peer"),
                        reason: "the remote network deny or legitimate control failed",
                    }
                );
                (Some(tcp), Some(udp), Some(denied))
            }
            None => (None, None, None),
        };
        let peer_network_passed = peer_tcp_allowed.unwrap_or(true)
            && peer_udp_allowed.unwrap_or(true)
            && peer_denied_connect.unwrap_or(true);
        let unsupported_network_families_denied = [
            (libc::AF_PACKET, libc::SOCK_RAW, 0),
            (libc::AF_NETLINK, libc::SOCK_RAW, 0),
            (libc::AF_VSOCK, libc::SOCK_STREAM, 0),
            (27, libc::SOCK_RAW, 0),
            (44, libc::SOCK_RAW, 0),
            (libc::AF_INET, libc::SOCK_STREAM, 132),
            (libc::AF_INET6, libc::SOCK_STREAM, 262),
        ]
        .into_iter()
        .map(|(family, socket_type, protocol)| {
            fixture.network_socket(family, socket_type, protocol)
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .all(super::child::IoOutcome::denied);
        let io_uring_marker = observations.cursor();
        let io_uring_sqpoll_denied = fixture.network_io_uring_sqpoll()?.denied();
        wait_for_effect(
            &reader,
            &observations,
            io_uring_marker,
            "UNSUPPORTED_OBJECT",
            (
                KernelEffectFamilyV1::Privilege,
                KernelEffectOperationV1::IoUringSqpoll,
            ),
        )?;
        let tun_tap_setup_denied = fixture.network_tun_tap()?.denied();
        let bpf_marker = observations.cursor();
        let bpf_setup_denied = fixture.network_bpf_setup()?.denied();
        wait_for_effect(
            &reader,
            &observations,
            bpf_marker,
            "UNSUPPORTED_OBJECT",
            (
                KernelEffectFamilyV1::Privilege,
                KernelEffectOperationV1::Bpf,
            ),
        )?;
        ensure!(
            dns_and_alternate_resolver_denied
                && unsupported_network_families_denied
                && io_uring_sqpoll_denied
                && tun_tap_setup_denied
                && bpf_setup_denied,
            InvalidInputSnafu {
                path: Path::new("closed network paths"),
                reason: "a DNS, tunnel, delegated setup, or protocol path remained open",
            }
        );

        let listen_marker = observations.cursor();
        let listen = server_fixture.network_listen(accepted_address)?;
        reader
            .poll(Duration::from_millis(100))
            .context(InterceptorSnafu)?;
        ensure!(
            listen.outcome.allowed,
            InvalidInputSnafu {
                path: Path::new("accepted-socket listener"),
                reason: format!(
                    "the approved listener bind failed; observations: {:?}",
                    observations
                        .recent_since(listen_marker)
                        .into_iter()
                        .map(|event| (
                            event.reason,
                            event.active_role_id,
                            event.entry_kind,
                            event.operation,
                            event.network_destination_policy_handle,
                            event.network_peer_port,
                        ))
                        .collect::<Vec<_>>()
                ),
            }
        );
        let server_address = listen
            .address
            .ok_or_else(|| invalid_probe("the approved listener returned no address"))?;

        let mut external_client = TcpStream::connect(server_address).context(IoSnafu {
            path: Path::new("external accepted-socket client"),
        })?;
        let external_marker = observations.cursor();
        let external_accept = server_fixture.network_accept()?.allowed;
        let external_passed =
            external_accept && server_fixture.network_pass(&external_pass)?.allowed;
        reader
            .poll(Duration::from_millis(100))
            .context(InterceptorSnafu)?;
        ensure!(
            external_accept && external_passed,
            InvalidInputSnafu {
                path: &external_pass,
                reason: format!(
                    "the accepted socket did not reach the narrow receiver; accept={external_accept}, pass={external_passed}, observations={:?}",
                    observations
                        .recent_since(external_marker)
                        .into_iter()
                        .map(|event| (
                            event.reason,
                            event.effect_family,
                            event.operation,
                            event.operation_argument,
                            event.active_role_id,
                            event.target_role_id,
                        ))
                        .collect::<Vec<_>>()
                ),
            }
        );
        let external_transfer = external_receiver.network_receive_passed()?;
        external_client.write_all(b"q").context(IoSnafu {
            path: Path::new("external accepted-socket client"),
        })?;
        let accepted_socket_narrow_actor_denied = external_transfer.installed_descriptors == 1
            && external_receiver.network_send(b"blocked")?.denied()
            && external_receiver.network_receive()?.denied();
        external_receiver.network_close()?;
        server_fixture.network_close()?;

        let mut converter_client = TcpStream::connect(server_address).context(IoSnafu {
            path: Path::new("converter accepted-socket client"),
        })?;
        ensure!(
            server_fixture.network_accept()?.allowed
                && server_fixture.network_pass(&converter_pass)?.allowed,
            InvalidInputSnafu {
                path: &converter_pass,
                reason: "the accepted socket did not reach the approved receiver",
            }
        );
        let converter_transfer = converter_receiver.network_receive_passed()?;
        let shared_marker = observations.cursor();
        let approved_send = converter_receiver.network_send(b"ok")?.allowed;
        wait_for_effect(
            &reader,
            &observations,
            shared_marker,
            "EXACT_POLICY_AUDIT_ALLOW",
            (KernelEffectFamilyV1::Network, KernelEffectOperationV1::Send),
        )?;
        let shared_event = observations
            .recent_since(shared_marker)
            .into_iter()
            .rev()
            .find(|event| event.operation == KernelEffectOperationV1::Send as u32)
            .ok_or_else(|| invalid_probe("the passed socket has no send observation"))?;
        let mut approved_bytes = [0_u8; 2];
        converter_client
            .read_exact(&mut approved_bytes)
            .context(IoSnafu {
                path: Path::new("converter accepted-socket client"),
            })?;
        let shared_floor = policy
            .fence_network_socket(
                &host,
                NetworkResponseFloorKeyV1 {
                    profile_generation_ref_id: shared_event
                        .network_creator_profile_generation_ref_id,
                    socket_key_id: shared_event.network_socket_key_id,
                    socket_generation: shared_event.network_socket_generation,
                },
            )
            .context(NodeSnafu)?;
        let receiver_fenced = converter_receiver
            .network_send(b"receiver-blocked")?
            .denied();
        let accepter_fenced = server_fixture.network_send(b"accepter-blocked")?.denied();
        converter_client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .context(IoSnafu {
                path: Path::new("converter accepted-socket client"),
            })?;
        let shared_bytes_absent = read_is_absent(&mut converter_client).context(IoSnafu {
            path: Path::new("converter accepted-socket client"),
        })?;
        let accepted_socket_approved_actor_allowed = converter_transfer.installed_descriptors == 1
            && approved_send
            && approved_bytes == *b"ok";
        let shared_socket_holders_denied =
            shared_floor && receiver_fenced && accepter_fenced && shared_bytes_absent;
        server_fixture.network_close()?;
        ensure!(
            socket_reference_count(
                &host,
                shared_event.network_creator_profile_generation_ref_id
            )? > 0,
            InvalidInputSnafu {
                path: Path::new("shared socket reference"),
                reason: "one descriptor close released a still-shared socket",
            }
        );
        converter_receiver.network_close()?;

        let namespace_external_client = TcpStream::connect(server_address).context(IoSnafu {
            path: Path::new("namespace external client"),
        })?;
        ensure!(
            server_fixture.network_accept()?.allowed,
            InvalidInputSnafu {
                path: Path::new("namespace external socket"),
                reason: "the accepter did not create the narrow namespace socket",
            }
        );
        let namespace_descriptor = server_fixture.network_descriptor()?;
        ensure!(
            server_fixture
                .network_allow_ptracer(namespace_external.pid())?
                .allowed,
            InvalidInputSnafu {
                path: Path::new("namespace external pidfd transfer"),
                reason: "the accepter could not authorize the narrow receiver",
            }
        );
        let namespace_external_transfer = namespace_external
            .network_duplicate_socket(server_fixture.pid(), namespace_descriptor)?;
        let cross_namespace_narrow_actor_denied = namespace_external_transfer.installed_descriptors
            == 1
            && namespace_external.network_send(b"blocked")?.denied();
        namespace_external.network_close()?;
        server_fixture.network_close()?;
        drop(namespace_external_client);

        let mut namespace_converter_client =
            TcpStream::connect(server_address).context(IoSnafu {
                path: Path::new("namespace converter client"),
            })?;
        ensure!(
            server_fixture.network_accept()?.allowed,
            InvalidInputSnafu {
                path: Path::new("namespace converter socket"),
                reason: "the accepter did not create the approved namespace socket",
            }
        );
        let namespace_descriptor = server_fixture.network_descriptor()?;
        ensure!(
            server_fixture
                .network_allow_ptracer(namespace_converter.pid())?
                .allowed,
            InvalidInputSnafu {
                path: Path::new("namespace converter pidfd transfer"),
                reason: "the accepter could not authorize the approved receiver",
            }
        );
        let namespace_converter_transfer = namespace_converter
            .network_duplicate_socket(server_fixture.pid(), namespace_descriptor)?;
        let namespace_marker = observations.cursor();
        let namespace_send = namespace_converter.network_send(b"n")?.allowed;
        wait_for_effect(
            &reader,
            &observations,
            namespace_marker,
            "EXACT_POLICY_AUDIT_ALLOW",
            (KernelEffectFamilyV1::Network, KernelEffectOperationV1::Send),
        )?;
        let namespace_event = observations
            .recent_since(namespace_marker)
            .into_iter()
            .rev()
            .find(|event| event.operation == KernelEffectOperationV1::Send as u32)
            .ok_or_else(|| invalid_probe("the namespace socket has no send observation"))?;
        let mut namespace_byte = [0_u8; 1];
        namespace_converter_client
            .read_exact(&mut namespace_byte)
            .context(IoSnafu {
                path: Path::new("namespace converter client"),
            })?;
        let cross_namespace_approved_actor_allowed =
            namespace_converter_transfer.installed_descriptors == 1
                && namespace_send
                && namespace_byte == *b"n";
        let cross_namespace_evidence_distinct = namespace_event.network_namespace_inode != 0
            && namespace_event.network_current_namespace_inode != 0
            && namespace_event.network_namespace_inode
                != namespace_event.network_current_namespace_inode;
        namespace_converter.network_close()?;
        server_fixture.network_close()?;

        ensure!(
            accepted_socket_narrow_actor_denied
                && accepted_socket_approved_actor_allowed
                && shared_socket_holders_denied
                && cross_namespace_narrow_actor_denied
                && cross_namespace_approved_actor_allowed
                && cross_namespace_evidence_distinct,
            InvalidInputSnafu {
                path: Path::new("accepted and namespace socket transfer"),
                reason: format!(
                    "a transferred socket widened authority or lost namespace evidence: accepted_narrow={accepted_socket_narrow_actor_denied}, accepted_approved={accepted_socket_approved_actor_allowed}, shared_fence={shared_socket_holders_denied} (inserted={}, receiver_denied={receiver_fenced}, accepter_denied={accepter_fenced}, bytes_absent={shared_bytes_absent}), namespace_narrow={cross_namespace_narrow_actor_denied}, namespace_approved={cross_namespace_approved_actor_allowed}, namespace_evidence={cross_namespace_evidence_distinct}",
                    shared_floor,
                ),
            }
        );

        let denied_request_sent = proxy_requester
            .network_proxy_request(&proxy_path, "deny-1", delegated_denied_address)?
            .allowed;
        let denied_delegate = proxy_delegate.network_proxy_once()?;
        let allowed_request_sent = proxy_requester
            .network_proxy_request(&proxy_path, "allow-1", delegated_address)?
            .allowed;
        let allowed_delegate = proxy_delegate.network_proxy_once()?;
        let delegated_send = proxy_delegate.network_send(b"delegated")?.allowed;
        proxy_delegate.network_close()?;
        let delegated_allowed_request_received = allowed_request_sent
            && allowed_delegate.request_id == "allow-1"
            && allowed_delegate.connect.allowed
            && delegated_send
            && join_server(delegated_server, "delegated server")?;
        let delegated_forbidden_request_absent = denied_request_sent
            && denied_delegate.request_id == "deny-1"
            && denied_delegate.connect.denied()
            && join_server(delegated_denied_server, "denied delegated server")?;

        let provider_connect = fixture.network_connect(provider_address)?.allowed;
        let provider_send = fixture.network_send(b"provider")?.allowed;
        fixture.network_close()?;
        let provider_write_observed = provider_connect
            && provider_send
            && join_server(provider_server, "provider-result server")?;
        let read_results_separate = read_results.zero_byte
            && read_results.end_of_file
            && read_results.io_error
            && read_results.partial_positive
            && read_results.mapped
            && read_results.inherited_descriptor
            && governed_read_allowed
            && governed_mmap_allowed
            && denied_unclassified_connect
            && provider_write_observed;

        let rewrite = NetworkRewriteOwner::install(rewrite_address.port())?;
        let rewritten_marker = observations.cursor();
        let rewritten_denied =
            fixture.network_connect(SocketAddr::from(([198, 18, 0, 1], rewrite_address.port())))?;
        wait_for_effect(
            &reader,
            &observations,
            rewritten_marker,
            "EXACT_POLICY_DENY",
            (KernelEffectFamilyV1::Network, KernelEffectOperationV1::Send),
        )?;
        let rewritten_forbidden_packet_absent = rewritten_denied.failed();
        ensure!(
            rewritten_forbidden_packet_absent,
            InvalidInputSnafu {
                path: Path::new("forbidden rewritten flow"),
                reason: format!("connect result was {rewritten_denied:?}"),
            }
        );
        let rewritten_connect =
            fixture.network_connect(SocketAddr::from(([198, 18, 0, 2], rewrite_address.port())))?;
        ensure!(
            rewritten_connect.allowed,
            InvalidInputSnafu {
                path: Path::new("allowed rewritten flow"),
                reason: format!("connect result was {rewritten_connect:?}"),
            }
        );
        let rewritten_send = fixture.network_send(b"rewrite")?;
        ensure!(
            rewritten_send.allowed,
            InvalidInputSnafu {
                path: Path::new("allowed rewritten flow"),
                reason: format!("send result was {rewritten_send:?}"),
            }
        );
        fixture.network_close()?;
        let rewritten_allowed_destination_received = join_server(rewrite_server, "rewrite server")?;
        ensure!(
            rewritten_allowed_destination_received,
            InvalidInputSnafu {
                path: Path::new("allowed rewritten flow"),
                reason: "the rewritten server did not receive the payload",
            }
        );
        rewrite.cleanup()?;

        let proof = NetworkFixtureProof {
            delegated_egress: delegated_forbidden_request_absent
                && delegated_allowed_request_received,
            hf_result: denied_unclassified_connect
                && allowed_send_received
                && post_fence_send_denied
                && provider_write_observed,
            hf_read_result: read_results_separate,
            hf_network: denied_unclassified_connect
                && dns_and_alternate_resolver_denied
                && unsupported_network_families_denied
                && io_uring_sqpoll_denied
                && tun_tap_setup_denied
                && bpf_setup_denied
                && sendmsg_allowed
                && sendfile_allowed
                && splice_allowed
                && post_fence_bypass_packets_absent
                && peer_network_passed
                && allowed_send_received,
            local_inet: allowed_connect
                && tcp_ipv6_allowed
                && accepted_socket_approved_actor_allowed,
            accept_pass: accepted_socket_narrow_actor_denied
                && accepted_socket_approved_actor_allowed,
            dns_exfil: dns_and_alternate_resolver_denied && allowed_connect,
            namespace_pass: cross_namespace_narrow_actor_denied
                && cross_namespace_approved_actor_allowed
                && cross_namespace_evidence_distinct,
            receive: allowed_receive && accepted_socket_narrow_actor_denied,
            rewrite: rewritten_forbidden_packet_absent && rewritten_allowed_destination_received,
            shared_response: shared_socket_holders_denied,
            socket_control: allowed_socket_control
                && unsafe_socket_control_denied
                && lifecycle_shutdown,
            socket_life: socket_reference_released
                && cloned_socket_allowed
                && inherited_socket_allowed
                && socket_generation_not_reused,
        };
        let fixture_results = proof.results();
        ensure!(
            fixture_results.iter().all(|result| result.result == "PASS"),
            InvalidInputSnafu {
                path: Path::new("network fixture matrix"),
                reason: format!(
                    "one or more required network fixtures did not pass: {:?}; read results: {read_results:?}; governed read={governed_read:?}; governed mmap={governed_mmap:?}",
                    fixture_results
                        .iter()
                        .filter(|result| result.result != "PASS")
                        .map(|result| result.fixture_id.as_str())
                        .collect::<Vec<_>>()
                ),
            }
        );

        proxy_delegate.stop()?;
        proxy_requester.stop()?;
        namespace_converter.stop()?;
        namespace_external.stop()?;
        converter_receiver.stop()?;
        external_receiver.stop()?;
        server_fixture.stop()?;
        fixture.stop()?;

        host.shutdown().context(InterceptorSnafu)?;
        pin_cleanup.cleanup()?;
        lease_cleanup.cleanup()?;
        while let Some(actor) = actors.pop() {
            actor.cgroup.cleanup()?;
        }
        cgroup_cleanup.cleanup()?;
        transport_cleanup.cleanup()?;
        fixture_cleanup.cleanup()?;
        Ok(NetworkPhysicalProbeBundleV1 {
            schema_version: 1,
            denied_unclassified_connect,
            allowed_connect,
            allowed_send_received,
            sendmsg_allowed,
            sendfile_allowed,
            splice_allowed,
            allowed_receive,
            allowed_socket_control,
            whole_socket_fence_installed,
            restart_preserved_task_state,
            restart_preserved_socket_state,
            restart_preserved_response_floor,
            restart_preserved_mount_state,
            restart_preserved_active_generation,
            post_fence_send_denied,
            post_fence_shutdown_denied,
            post_fence_bytes_absent,
            post_fence_bypass_packets_absent,
            socket_reference_released,
            tcp_ipv6_allowed,
            udp_connected_allowed,
            udp_unconnected_allowed,
            dns_and_alternate_resolver_denied,
            unsupported_network_families_denied,
            io_uring_sqpoll_denied,
            tun_tap_setup_denied,
            bpf_setup_denied,
            unsafe_socket_control_denied,
            accepted_socket_narrow_actor_denied,
            accepted_socket_approved_actor_allowed,
            cross_namespace_narrow_actor_denied,
            cross_namespace_approved_actor_allowed,
            cross_namespace_evidence_distinct,
            rewritten_forbidden_packet_absent,
            rewritten_allowed_destination_received,
            delegated_forbidden_request_absent,
            delegated_allowed_request_received,
            read_results_separate,
            provider_write_observed,
            shared_socket_holders_denied,
            cloned_socket_allowed,
            inherited_socket_allowed,
            socket_generation_not_reused,
            peer_tcp_allowed,
            peer_udp_allowed,
            peer_denied_connect,
            fixture_results,
        })
    }

    pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
        fs::write(
            path,
            serde_json::to_vec_pretty(value).context(JsonSnafu { path })?,
        )
        .context(IoSnafu { path })
    }
}

pub fn run_network_peer_server(
    bind_address: IpAddr,
    tcp_port: u16,
    udp_port: u16,
    denied_port: u16,
    ready_path: &Path,
) -> Result<NetworkPeerServerResultV1> {
    validate_peer_ports(tcp_port, udp_port, denied_port)?;
    let tcp = tcp_listener(SocketAddr::new(bind_address, tcp_port))?;
    let denied = tcp_listener(SocketAddr::new(bind_address, denied_port))?;
    let udp = UdpSocket::bind(SocketAddr::new(bind_address, udp_port)).context(IoSnafu {
        path: Path::new("two-node UDP peer"),
    })?;
    tcp.set_nonblocking(true).context(IoSnafu {
        path: Path::new("two-node TCP peer"),
    })?;
    denied.set_nonblocking(true).context(IoSnafu {
        path: Path::new("two-node denied peer"),
    })?;
    udp.set_nonblocking(true).context(IoSnafu {
        path: Path::new("two-node UDP peer"),
    })?;
    fs::write(ready_path, b"ready\n").context(IoSnafu { path: ready_path })?;

    let deadline = Instant::now() + Duration::from_secs(120);
    let mut tcp_payload_received = false;
    let mut udp_payload_received = false;
    let mut denied_connection_absent = true;
    let mut completed_at = None;
    while Instant::now() < deadline {
        match denied.accept() {
            Ok(_) => {
                denied_connection_absent = false;
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => {
                return Err(crate::Error::Io {
                    path: PathBuf::from("two-node denied peer"),
                    source: error,
                    location: snafu::Location::default(),
                });
            }
        }
        if !tcp_payload_received {
            match tcp.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .context(IoSnafu {
                            path: Path::new("two-node TCP peer"),
                        })?;
                    let mut payload = [0_u8; NETWORK_PEER_TCP_PAYLOAD.len()];
                    stream.read_exact(&mut payload).context(IoSnafu {
                        path: Path::new("two-node TCP peer"),
                    })?;
                    tcp_payload_received = payload == NETWORK_PEER_TCP_PAYLOAD;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    return Err(crate::Error::Io {
                        path: PathBuf::from("two-node TCP peer"),
                        source: error,
                        location: snafu::Location::default(),
                    });
                }
            }
        }
        if !udp_payload_received {
            let mut payload = [0_u8; NETWORK_PEER_UDP_PAYLOAD.len()];
            match udp.recv_from(&mut payload) {
                Ok((length, _)) => {
                    udp_payload_received =
                        length == payload.len() && payload == NETWORK_PEER_UDP_PAYLOAD;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    return Err(crate::Error::Io {
                        path: PathBuf::from("two-node UDP peer"),
                        source: error,
                        location: snafu::Location::default(),
                    });
                }
            }
        }
        if tcp_payload_received && udp_payload_received {
            let completed = completed_at.get_or_insert_with(Instant::now);
            if completed.elapsed() >= Duration::from_millis(500) {
                break;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    ensure!(
        tcp_payload_received && udp_payload_received && denied_connection_absent,
        InvalidInputSnafu {
            path: Path::new("two-node network peer"),
            reason: "the peer did not receive both controls or accepted a denied connection",
        }
    );
    Ok(NetworkPeerServerResultV1 {
        schema_version: 1,
        tcp_payload_received,
        udp_payload_received,
        denied_connection_absent,
    })
}

fn validate_network_peer(peer: Option<NetworkPeerTargetV1>) -> Result<()> {
    let Some(peer) = peer else {
        return Ok(());
    };
    ensure!(
        !peer.address.is_unspecified()
            && !peer.address.is_loopback()
            && !peer.address.is_multicast(),
        InvalidInputSnafu {
            path: Path::new("two-node network peer"),
            reason: "the peer address must identify a remote unicast interface",
        }
    );
    validate_peer_ports(peer.tcp_port, peer.udp_port, peer.denied_port)
}

fn validate_peer_ports(tcp_port: u16, udp_port: u16, denied_port: u16) -> Result<()> {
    ensure!(
        tcp_port != 0
            && udp_port != 0
            && denied_port != 0
            && tcp_port != udp_port
            && tcp_port != denied_port
            && udp_port != denied_port,
        InvalidInputSnafu {
            path: Path::new("two-node network peer"),
            reason: "the peer ports must be nonzero and distinct",
        }
    );
    Ok(())
}

fn build_network_artifact(
    policy_fixture: &Path,
    fixture_root: &Path,
    peer: Option<NetworkPeerTargetV1>,
) -> Result<PathBuf> {
    let policy_source = policy_fixture.join("protect-policy-v1.yaml");
    let mut document = PolicyDocumentV1::parse(
        &policy_source,
        &fs::read(&policy_source).context(IoSnafu {
            path: &policy_source,
        })?,
    )
    .context(PolicySnafu)?;
    let mut network_rule = document.rules[0].clone();
    let mut token_rule = document.rules[0].clone();
    let mut converter_ptrace_rule = document.rules[0].clone();
    let mut external_ptrace_rule = document.rules[0].clone();
    document.protected_universe.object_class_ids = vec!["NETWORK_TOKEN".to_owned()];
    document
        .protected_universe
        .role_ids
        .retain(|role| role != "runtime-external-administrative");
    document
        .protected_universe
        .entry_kind_ids
        .retain(|entry| *entry != EntryKindV1::ApprovedAdministrativeExec);
    document.classifier_bindings.clear();
    document
        .roles
        .retain(|role| role.role_id != "runtime-external-administrative");
    document
        .entry_role_assignments
        .retain(|assignment| assignment.resulting_role_id != "runtime-external-administrative");
    let mut converter_relationship = document.ipc_relationship_rules[0].clone();
    converter_relationship.relationship_rule_id = "converter-converter-stream".to_owned();
    converter_relationship.source_role_ids = vec!["converter".to_owned()];
    converter_relationship.peer_role_ids = vec!["converter".to_owned()];
    converter_relationship.channel_class_ids = vec!["UNIX_STREAM".to_owned()];
    converter_relationship.operations = vec!["IPC_ACCESS".to_owned()];
    converter_relationship.requested_disposition = PolicyDispositionV1::Allow;
    converter_relationship.errno = None;
    let mut external_relationship = converter_relationship.clone();
    external_relationship.relationship_rule_id = "converter-runtime-stream".to_owned();
    external_relationship.peer_role_ids = vec!["runtime-external".to_owned()];
    document.ipc_relationship_rules = vec![converter_relationship, external_relationship];
    document.effect_family_defaults.clear();
    document.exceptions.clear();
    document.rules.clear();
    let mut destination_policies = vec![
        DestinationPolicyRecordV1 {
            destination_policy_id: "allowed-result-service".to_owned(),
            protocols: vec![NetworkProtocolV1::Tcp, NetworkProtocolV1::Udp],
            ipv4_prefixes: vec!["127.0.0.1/32".to_owned(), "127.0.0.2/32".to_owned()],
            ipv6_prefixes: vec!["::1/128".to_owned()],
            port_ranges: vec![NetworkPortRangeV1 {
                first: 1_024,
                last: u16::MAX,
            }],
            required_network_namespace_ids: Vec::new(),
            service_identities: Vec::new(),
            final_address_required: true,
        },
        DestinationPolicyRecordV1 {
            destination_policy_id: "allowed-rewrite-service".to_owned(),
            protocols: vec![NetworkProtocolV1::Tcp],
            ipv4_prefixes: vec!["127.0.0.4/32".to_owned(), "198.18.0.2/32".to_owned()],
            ipv6_prefixes: Vec::new(),
            port_ranges: vec![NetworkPortRangeV1 {
                first: 1_024,
                last: u16::MAX,
            }],
            required_network_namespace_ids: Vec::new(),
            service_identities: Vec::new(),
            final_address_required: true,
        },
        DestinationPolicyRecordV1 {
            destination_policy_id: "requested-rewrite".to_owned(),
            protocols: vec![NetworkProtocolV1::Tcp],
            ipv4_prefixes: vec!["198.18.0.1/32".to_owned()],
            ipv6_prefixes: Vec::new(),
            port_ranges: vec![NetworkPortRangeV1 {
                first: 1_024,
                last: u16::MAX,
            }],
            required_network_namespace_ids: Vec::new(),
            service_identities: Vec::new(),
            final_address_required: true,
        },
    ];
    let mut destination_policy_ids = [
        "allowed-result-service",
        "allowed-rewrite-service",
        "requested-rewrite",
    ]
    .map(str::to_owned)
    .to_vec();
    if let Some(peer) = peer {
        let (ipv4_prefixes, ipv6_prefixes) = match peer.address {
            IpAddr::V4(address) => (vec![format!("{address}/32")], Vec::new()),
            IpAddr::V6(address) => (Vec::new(), vec![format!("{address}/128")]),
        };
        let mut port_ranges = [peer.tcp_port, peer.udp_port]
            .map(|port| NetworkPortRangeV1 {
                first: port,
                last: port,
            })
            .to_vec();
        port_ranges.sort_by_key(|range| range.first);
        destination_policies.push(DestinationPolicyRecordV1 {
            destination_policy_id: "allowed-two-node-peer".to_owned(),
            protocols: vec![NetworkProtocolV1::Tcp, NetworkProtocolV1::Udp],
            ipv4_prefixes,
            ipv6_prefixes,
            port_ranges,
            required_network_namespace_ids: Vec::new(),
            service_identities: Vec::new(),
            final_address_required: true,
        });
        destination_policy_ids.push("allowed-two-node-peer".to_owned());
    }
    destination_policies
        .sort_by(|left, right| left.destination_policy_id.cmp(&right.destination_policy_id));
    destination_policy_ids.sort();
    document.network_policy = Some(NetworkPolicyV1 {
        dns_mode: DnsPolicyModeV1::DenyDnsAndUsePolicyResolvedAddresses,
        destination_policies,
    });
    document.effect_family_defaults.push(EffectFamilyDefaultV1 {
        role_ids: vec!["converter".to_owned()],
        effect_family: EffectFamilyV1::Network,
        operations: [
            "ACCEPT",
            "LISTEN",
            "SETSOCKOPT",
            "SHUTDOWN",
            "SOCKET_CREATE",
        ]
        .map(str::to_owned)
        .to_vec(),
        requested_disposition: PolicyDispositionV1::Allow,
        errno: None,
        finding: None,
    });
    network_rule.rule_id = "allow-network-fixture-destinations".to_owned();
    let RuleMatchV1::LocalPreEffect(effect) = &mut network_rule.rule_match else {
        unreachable!("the effect fixture begins with a local rule")
    };
    effect.subject.entry_kind_ids = vec![EntryKindV1::ContainerStart];
    effect.subject.role_ids = vec!["converter".to_owned()];
    effect.effect_families = vec![EffectFamilyV1::Network];
    effect.operation_ids = ["ACCEPT", "BIND", "CONNECT", "RECEIVE", "SEND"]
        .map(str::to_owned)
        .to_vec();
    effect.object = LocalObjectSelectorV1::Destinations {
        destination_policy_ids,
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

    token_rule.rule_id = "allow-network-token-read".to_owned();
    let RuleMatchV1::LocalPreEffect(effect) = &mut token_rule.rule_match else {
        unreachable!("the effect fixture begins with a local rule")
    };
    effect.subject.entry_kind_ids = vec![EntryKindV1::ContainerStart];
    effect.subject.role_ids = vec!["converter".to_owned()];
    effect.effect_families = vec![EffectFamilyV1::File];
    effect.operation_ids = ["MMAP_READ", "OPEN_READ", "READ"]
        .map(str::to_owned)
        .to_vec();
    effect.object = LocalObjectSelectorV1::ExactObjectKeys {
        exact_object_key_ids: vec![TOKEN_OBJECT_KEY_ID],
    };
    token_rule.requested_disposition = PolicyDispositionV1::Allow;
    token_rule.errno = None;
    token_rule.finding = None;
    document.rules.push(token_rule);

    converter_ptrace_rule.rule_id = "allow-converter-pidfd-socket-transfer".to_owned();
    let RuleMatchV1::LocalPreEffect(effect) = &mut converter_ptrace_rule.rule_match else {
        unreachable!("the effect fixture begins with a local rule")
    };
    effect.subject.entry_kind_ids = vec![EntryKindV1::ContainerStart];
    effect.subject.role_ids = vec!["converter".to_owned()];
    effect.effect_families = vec![EffectFamilyV1::Privilege];
    effect.operation_ids = vec!["PTRACE_ACCESS_18".to_owned()];
    effect.object = LocalObjectSelectorV1::SecurityObjects {
        security_object_ids: vec!["PROCESS".to_owned()],
        target_selector_ids: vec!["converter".to_owned()],
    };
    converter_ptrace_rule.requested_disposition = PolicyDispositionV1::Allow;
    converter_ptrace_rule.errno = None;
    converter_ptrace_rule.finding = None;
    document.rules.push(converter_ptrace_rule);

    external_ptrace_rule.rule_id = "allow-external-pidfd-socket-transfer".to_owned();
    let RuleMatchV1::LocalPreEffect(effect) = &mut external_ptrace_rule.rule_match else {
        unreachable!("the effect fixture begins with a local rule")
    };
    effect.subject.entry_kind_ids = vec![EntryKindV1::ExternalRuntimeUnknown];
    effect.subject.role_ids = vec!["runtime-external".to_owned()];
    effect.effect_families = vec![EffectFamilyV1::Privilege];
    effect.operation_ids = vec!["PTRACE_ACCESS_18".to_owned()];
    effect.object = LocalObjectSelectorV1::SecurityObjects {
        security_object_ids: vec!["PROCESS".to_owned()],
        target_selector_ids: vec!["converter".to_owned()],
    };
    external_ptrace_rule.requested_disposition = PolicyDispositionV1::Allow;
    external_ptrace_rule.errno = None;
    external_ptrace_rule.finding = None;
    document.rules.push(external_ptrace_rule);

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

fn tcp_listener(address: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(address).context(IoSnafu {
        path: Path::new("network listener"),
    })
}

fn available_tcp_address(address: [u8; 4]) -> Result<SocketAddr> {
    let listener = tcp_listener(SocketAddr::from((address, 0)))?;
    listener.local_addr().context(IoSnafu {
        path: Path::new("available network listener"),
    })
}

fn actor_root(fixture_root: &Path, name: &str) -> Result<PathBuf> {
    let root = fixture_root.join(name);
    fs::create_dir(&root).context(IoSnafu { path: &root })?;
    Ok(root)
}

fn move_actor(fixture: &EffectProcessFixture, cgroup: &Path) -> Result<()> {
    let procs = cgroup.join("cgroup.procs");
    fs::write(&procs, fixture.pid().to_string()).context(IoSnafu { path: &procs })
}

fn start_actor(
    fixture_root: &Path,
    name: &str,
    cgroup: &Path,
    private_network_namespace: bool,
) -> Result<EffectProcessFixture> {
    let root = actor_root(fixture_root, name)?;
    let mut fixture = EffectProcessFixture::start(&root)?;
    if private_network_namespace {
        fixture.network_enter_namespace()?;
    }
    move_actor(&fixture, cgroup)?;
    Ok(fixture)
}

fn socket_reference_count(host: &KernelHost, profile_generation_ref_id: u64) -> Result<u64> {
    let Some(bytes) = host
        .lookup_map(
            "profile_generation_socket_refs",
            &profile_generation_ref_id.to_ne_bytes(),
        )
        .context(InterceptorSnafu)?
    else {
        return Ok(0);
    };
    u64::read_from_bytes(&bytes)
        .map_err(|error| invalid_probe(format!("the socket reference count is invalid: {error}")))
}

fn map_snapshot(host: &KernelHost, map: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut keys = host.map_keys(map).context(InterceptorSnafu)?;
    keys.sort_unstable();
    keys.into_iter()
        .map(|key| {
            let value = host
                .lookup_map(map, &key)
                .context(InterceptorSnafu)?
                .ok_or_else(|| {
                    invalid_probe(format!("map `{map}` changed during recovery snapshot"))
                })?;
            Ok((key, value))
        })
        .collect()
}

fn invalid_probe(reason: impl Into<String>) -> crate::Error {
    InvalidInputSnafu {
        path: Path::new("network physical probe"),
        reason: reason.into(),
    }
    .build()
}

fn join_server(server: thread::JoinHandle<io::Result<bool>>, label: &'static str) -> Result<bool> {
    server
        .join()
        .map_err(|_| invalid_probe(format!("the {label} thread panicked")))?
        .context(IoSnafu {
            path: Path::new(label),
        })
}

fn server_exchange(listener: TcpListener, expected: &[u8]) -> io::Result<bool> {
    let (mut stream, _) = listener.accept()?;
    let mut payload = [0_u8; PAYLOAD.len()];
    stream.read_exact(&mut payload)?;
    if payload != PAYLOAD {
        return Ok(false);
    }
    stream.write_all(b"r")?;
    let mut remainder = vec![0_u8; expected.len().saturating_sub(PAYLOAD.len())];
    stream.read_exact(&mut remainder)?;
    if expected.get(PAYLOAD.len()..) != Some(remainder.as_slice()) {
        return Ok(false);
    }
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    read_is_absent(&mut stream)
}

fn server_receive(listener: TcpListener, expected: &[u8]) -> io::Result<bool> {
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut payload = vec![0_u8; expected.len()];
    stream.read_exact(&mut payload)?;
    Ok(payload == expected)
}

fn server_absent(listener: TcpListener) -> io::Result<bool> {
    listener.set_nonblocking(true)?;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        match listener.accept() {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

fn udp_receive<const N: usize>(socket: UdpSocket, expected: [&[u8]; N]) -> io::Result<bool> {
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buffer = [0_u8; 64];
    let mut received_messages = Vec::with_capacity(expected.len());
    for expected_payload in expected {
        let received = socket.recv(&mut buffer).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "received UDP payloads {received_messages:?} before receive failed: {error}"
                ),
            )
        })?;
        if received == 0 {
            return Ok(false);
        }
        if buffer.get(..received) != Some(expected_payload) {
            return Ok(false);
        }
        received_messages.push(buffer[..received].to_vec());
    }
    Ok(true)
}

fn read_is_absent(stream: &mut TcpStream) -> io::Result<bool> {
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => Ok(true),
        Ok(_) => Ok(false),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

struct NetworkRewriteOwner {
    table: String,
    active: bool,
}

impl NetworkRewriteOwner {
    fn install(port: u16) -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| invalid_probe(format!("the system clock is invalid: {error}")))?
            .as_nanos();
        let mut owner = Self {
            table: format!("mithril_net_{}_{}", std::process::id(), timestamp),
            active: false,
        };
        run_nft(&["add", "table", "ip", &owner.table])?;
        owner.active = true;
        let result = owner.configure(port);
        if let Err(error) = result {
            let _cleanup = owner.cleanup_inner();
            return Err(error);
        }
        Ok(owner)
    }

    fn configure(&self, port: u16) -> Result<()> {
        run_nft(&[
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
            run_nft(&[
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

    fn cleanup(mut self) -> Result<()> {
        let result = self.cleanup_inner();
        self.active = false;
        result
    }

    fn cleanup_inner(&self) -> Result<()> {
        if self.active {
            run_nft(&["delete", "table", "ip", &self.table])?;
        }
        Ok(())
    }
}

impl Drop for NetworkRewriteOwner {
    fn drop(&mut self) {
        let _result = self.cleanup_inner();
    }
}

fn run_nft(arguments: &[&str]) -> Result<()> {
    let status = Command::new("nft")
        .args(arguments)
        .status()
        .context(IoSnafu {
            path: Path::new("nft"),
        })?;
    ensure!(
        status.success(),
        InvalidInputSnafu {
            path: Path::new("nft"),
            reason: format!("nft exited with {status}"),
        }
    );
    Ok(())
}

impl NetworkFixtureProof {
    fn results(&self) -> Vec<NetworkFixtureResultV1> {
        [
            (
                "FILE-DELEGATED-EGRESS-001",
                self.delegated_egress,
                "DELEGATE_REQUEST_ID_AND_FINAL_DESTINATION_ENFORCED",
            ),
            (
                "HF-004-RESULT-001",
                self.hf_result,
                "DENIAL_SEND_AND_PROVIDER_RECEIPT_RESULTS_SEPARATED",
            ),
            (
                "HF-011-READ-RESULT-001",
                self.hf_read_result,
                "READ_RETURN_CLASSES_AND_GOVERNED_TOKEN_READ_PROVED",
            ),
            (
                "HF-NET-001",
                self.hf_network,
                "NETWORK_FAMILY_PROTOCOL_DNS_DENIAL_AND_ALLOWED_SEND_PROVED",
            ),
            (
                "IPC-LOCAL-INET-008",
                self.local_inet,
                "IPV4_IPV6_LOOPBACK_AND_UNIX_RELATIONSHIPS_REMAIN_SEPARATE",
            ),
            (
                "NET-ACCEPT-PASS-001",
                self.accept_pass,
                "ACCEPTED_SOCKET_DENIES_NARROW_ACTOR_AND_ALLOWS_APPROVED_ACTOR",
            ),
            (
                "NET-DNS-EXFIL-001",
                self.dns_exfil,
                "DNS_ALTERNATE_RESOLVER_AND_ENCRYPTED_ENDPOINTS_DENIED",
            ),
            (
                "NET-NS-PASS-001",
                self.namespace_pass,
                "CROSS_NAMESPACE_AUTHORITY_INTERSECTION_AND_EVIDENCE_PROVED",
            ),
            (
                "NET-RECV-001",
                self.receive,
                "APPROVED_RECEIVE_SUCCEEDED_AND_NARROW_RECEIVE_DENIED",
            ),
            (
                "NET-REWRITE-001",
                self.rewrite,
                "FINAL_DESTINATION_MISMATCH_DROPPED_AND_MATCH_RECEIVED",
            ),
            (
                "NET-SHARED-RESPONSE-002",
                self.shared_response,
                "WHOLE_SOCKET_FENCE_DENIED_ALL_SHARED_HOLDERS",
            ),
            (
                "NET-SOCKCTL-001",
                self.socket_control,
                "SAFE_SOCKET_CONTROLS_ALLOWED_AND_UNSAFE_CONTROL_DENIED",
            ),
            (
                "NET-SOCKET-LIFE-001",
                self.socket_life,
                "CLONE_FORK_CLOSE_AND_NEW_GENERATION_LIFECYCLE_PROVED",
            ),
        ]
        .into_iter()
        .map(
            |(fixture_id, passed, physical_oracle)| NetworkFixtureResultV1 {
                fixture_id: fixture_id.to_owned(),
                result: if passed { "PASS" } else { "FAIL" }.to_owned(),
                physical_oracle: physical_oracle.to_owned(),
            },
        )
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::io::Write as _;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
    use std::thread;
    use std::time::{Duration, Instant};

    use snafu::ResultExt as _;

    use super::{
        build_network_artifact, run_network_peer_server, NetworkFixtureProof,
        NETWORK_PEER_TCP_PAYLOAD, NETWORK_PEER_UDP_PAYLOAD,
    };
    use crate::error::IoSnafu;

    #[test]
    fn network_fixture_matrix_requires_physical_proof() {
        let failed = NetworkFixtureProof::default().results();
        assert!(failed.iter().all(|fixture| fixture.result == "FAIL"));

        let results = NetworkFixtureProof {
            delegated_egress: true,
            hf_result: true,
            hf_read_result: true,
            hf_network: true,
            local_inet: true,
            accept_pass: true,
            dns_exfil: true,
            namespace_pass: true,
            receive: true,
            rewrite: true,
            shared_response: true,
            socket_control: true,
            socket_life: true,
        }
        .results();
        assert_eq!(results.len(), 13);
        assert_eq!(
            results
                .iter()
                .map(|fixture| fixture.fixture_id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            results.len()
        );
        assert!(results
            .iter()
            .all(|fixture| fixture.result == "PASS" && !fixture.physical_oracle.is_empty()));
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
        let artifact = build_network_artifact(&policy_fixture, directory.path(), None)?;
        assert!(artifact.is_file());
        Ok(())
    }

    #[test]
    fn signed_network_fixture_compiles_two_node_peer() -> crate::Result<()> {
        let directory = tempfile::tempdir().map_err(|source| crate::Error::Io {
            path: "temporary two-node network fixture".into(),
            source,
            location: snafu::Location::default(),
        })?;
        let policy_fixture =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/mithril-policy");
        let artifact = build_network_artifact(
            &policy_fixture,
            directory.path(),
            Some(super::NetworkPeerTargetV1 {
                address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)),
                tcp_port: super::NETWORK_PEER_TCP_PORT,
                udp_port: super::NETWORK_PEER_UDP_PORT,
                denied_port: super::NETWORK_PEER_DENIED_PORT,
            }),
        )?;
        assert!(artifact.is_file());
        Ok(())
    }

    #[test]
    fn network_peer_server_requires_controls_and_denied_absence() -> crate::Result<()> {
        let directory = tempfile::tempdir().map_err(|source| crate::Error::Io {
            path: "temporary network peer".into(),
            source,
            location: snafu::Location::default(),
        })?;
        let address = SocketAddr::from(([127, 0, 0, 1], 0));
        let tcp_reservation = UdpSocket::bind(address).context(IoSnafu {
            path: "temporary TCP peer port",
        })?;
        let udp_reservation = UdpSocket::bind(address).context(IoSnafu {
            path: "temporary UDP peer port",
        })?;
        let denied_reservation = UdpSocket::bind(address).context(IoSnafu {
            path: "temporary denied peer port",
        })?;
        let tcp_port = tcp_reservation
            .local_addr()
            .context(IoSnafu {
                path: "temporary TCP peer port",
            })?
            .port();
        let udp_port = udp_reservation
            .local_addr()
            .context(IoSnafu {
                path: "temporary UDP peer port",
            })?
            .port();
        let denied_port = denied_reservation
            .local_addr()
            .context(IoSnafu {
                path: "temporary denied peer port",
            })?
            .port();
        drop((tcp_reservation, udp_reservation, denied_reservation));
        let ready = directory.path().join("ready");
        let ready_for_server = ready.clone();
        let server = thread::spawn(move || {
            run_network_peer_server(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                tcp_port,
                udp_port,
                denied_port,
                &ready_for_server,
            )
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.is_file() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.is_file());
        let mut tcp =
            TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], tcp_port))).map_err(|source| {
                crate::Error::Io {
                    path: "temporary TCP peer".into(),
                    source,
                    location: snafu::Location::default(),
                }
            })?;
        tcp.write_all(NETWORK_PEER_TCP_PAYLOAD)
            .map_err(|source| crate::Error::Io {
                path: "temporary TCP peer".into(),
                source,
                location: snafu::Location::default(),
            })?;
        let udp = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).map_err(|source| {
            crate::Error::Io {
                path: "temporary UDP peer".into(),
                source,
                location: snafu::Location::default(),
            }
        })?;
        udp.send_to(
            NETWORK_PEER_UDP_PAYLOAD,
            SocketAddr::from(([127, 0, 0, 1], udp_port)),
        )
        .map_err(|source| crate::Error::Io {
            path: "temporary UDP peer".into(),
            source,
            location: snafu::Location::default(),
        })?;
        let result = server
            .join()
            .map_err(|_| super::invalid_probe("the network peer server thread panicked"))??;
        assert!(
            result.tcp_payload_received
                && result.udp_payload_received
                && result.denied_connection_absent
        );
        Ok(())
    }
}
