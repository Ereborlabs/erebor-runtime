use std::error::Error as StdError;

use erebor_interceptor::{KernelLinkManifestV1, KernelObjectManifestV1, KernelPreflightV1};
use erebor_runtime_client::MithrilObservationClient;
use mithril_control::CapabilityRecord;
use mithril_node::{RuntimeObservationConfig, RuntimeObservationServer};
use rustix::process::geteuid;
use tokio::sync::watch;

#[tokio::test]
async fn runtime_client_is_peer_authenticated_cgroup_scoped_and_read_only(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("mithril-observation.sock");
    let server = RuntimeObservationServer::bind(
        RuntimeObservationConfig {
            socket_path: socket.clone(),
            allowed_uid: geteuid().as_raw(),
            cgroup_scope: "/erebor/session-a".to_owned(),
        },
        &manifest(),
        &[CapabilityRecord {
            capability_id: "KERNEL_LSM_CHASSIS".to_owned(),
            state: "SUPPORTED".to_owned(),
            reason_code: "EXACT_ATTACH_READBACK".to_owned(),
        }],
    )?;
    let (shutdown, receiver) = watch::channel(false);
    let task = tokio::spawn(server.serve(receiver));
    let snapshot = MithrilObservationClient::new(socket.clone(), "/erebor/session-a".to_owned())
        .snapshot()
        .await?;
    assert!(snapshot.kernel_ready);
    assert_eq!(snapshot.cgroup_scope, "/erebor/session-a");
    assert_eq!(snapshot.program_digest, "a".repeat(64));

    assert!(
        MithrilObservationClient::new(socket, "/erebor/session-b".to_owned())
            .snapshot()
            .await
            .is_err()
    );
    shutdown.send_replace(true);
    task.await??;
    Ok(())
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
            program: "phase0_file_open".to_owned(),
            link_id: 1,
            program_id: 2,
            pin_path: None,
        }],
        ready: true,
    }
}
