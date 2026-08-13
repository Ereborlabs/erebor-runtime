use std::{error::Error as StdError, fs, os::unix::fs::MetadataExt as _};

use erebor_interceptor::{KernelLinkManifestV1, KernelObjectManifestV1, KernelPreflightV1};
use erebor_runtime_client::MithrilObservationClient;
use mithril_control::CapabilityRecord;
use mithril_node::{NodeReadinessV1, RuntimeObservationConfig, RuntimeObservationServer};
use rustix::process::geteuid;
use tokio::sync::watch;

#[tokio::test]
async fn runtime_client_is_peer_authenticated_cgroup_scoped_and_read_only(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("mithril-observation.sock");
    let cgroup_scope = current_cgroup_scope()?;
    let (readiness, readiness_receiver) = watch::channel(NodeReadinessV1 {
        kernel_ready: true,
        identity_ready: true,
        control_ready: true,
        admission_ready: true,
        effect_prevention_claims_enabled: true,
    });
    let server = RuntimeObservationServer::bind(
        RuntimeObservationConfig {
            socket_path: socket.clone(),
            allowed_uid: geteuid().as_raw(),
            cgroup_scope: cgroup_scope.clone(),
        },
        &manifest(),
        &[
            CapabilityRecord {
                capability_id: "EXACT_NATIVE_IDENTITY".to_owned(),
                state: "SUPPORTED".to_owned(),
                reason_code: "EXACT_ATTACH_AND_RECONCILIATION".to_owned(),
            },
            CapabilityRecord {
                capability_id: "LOCAL_EFFECT_PREVENTION".to_owned(),
                state: "DEGRADED".to_owned(),
                reason_code: "SIGNED_ACTIVE_QUALIFIED_LOCAL_SLICE".to_owned(),
            },
            CapabilityRecord {
                capability_id: "RUNTIME_READ_ONLY_OBSERVATION".to_owned(),
                state: "SUPPORTED".to_owned(),
                reason_code: "PEER_CREDENTIAL_AND_CGROUP_SCOPED".to_owned(),
            },
        ],
        readiness_receiver,
    )?;
    assert_eq!(fs::metadata(&socket)?.uid(), geteuid().as_raw());
    let (shutdown, receiver) = watch::channel(false);
    let task = tokio::spawn(server.serve(receiver));
    let snapshot = MithrilObservationClient::new(socket.clone(), cgroup_scope.clone())
        .snapshot()
        .await?;
    assert!(snapshot.kernel_ready);
    assert_eq!(snapshot.cgroup_scope, cgroup_scope);
    assert_eq!(snapshot.program_digest, "a".repeat(64));
    assert_eq!(snapshot.capabilities.len(), 3);
    assert_eq!(
        snapshot.capabilities[1].capability_id,
        "LOCAL_EFFECT_PREVENTION"
    );
    assert_eq!(snapshot.capabilities[1].state, "DEGRADED");

    readiness.send_replace(NodeReadinessV1 {
        control_ready: true,
        ..NodeReadinessV1::default()
    });
    let snapshot = MithrilObservationClient::new(socket.clone(), cgroup_scope.clone())
        .snapshot()
        .await?;
    assert!(!snapshot.kernel_ready);
    assert_eq!(snapshot.capabilities[0].state, "UNHEALTHY");
    assert_eq!(snapshot.capabilities[1].state, "UNHEALTHY");
    assert_eq!(
        snapshot.capabilities[1].reason_code,
        "LIVE_KERNEL_MANIFEST_MISMATCH"
    );
    assert_eq!(snapshot.capabilities[2].state, "SUPPORTED");

    assert!(
        MithrilObservationClient::new(socket, "/not-the-peer-cgroup".to_owned())
            .snapshot()
            .await
            .is_err()
    );
    shutdown.send_replace(true);
    task.await??;
    Ok(())
}

fn current_cgroup_scope() -> Result<String, Box<dyn StdError>> {
    let cgroups = fs::read_to_string("/proc/self/cgroup")?;
    cgroups
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
        .ok_or_else(|| "process has no unified cgroup".into())
}

fn manifest() -> KernelObjectManifestV1 {
    KernelObjectManifestV1 {
        schema_version: 1,
        node_boot_id: "00112233445566778899aabbccddeeff".to_owned(),
        label_epoch: 3,
        preflight: KernelPreflightV1 {
            kernel_release: "test".to_owned(),
            active_lsm_order: "bpf".to_owned(),
            runtime_btf_sha256: "b".repeat(64),
            cgroup_v2: true,
        },
        object_sha256: "a".repeat(64),
        maps: Vec::new(),
        links: vec![KernelLinkManifestV1 {
            program: "qualification_file_open".to_owned(),
            link_id: 1,
            program_id: 2,
            pin_path: None,
        }],
        ready: true,
    }
}
