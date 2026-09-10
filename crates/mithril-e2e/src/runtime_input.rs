use std::collections::HashMap;
use std::path::Path;

use k8s_cri::v1::{
    Container, ContainerMetadata, ContainerState, ContainerStatus, ContainerStatusResponse,
};
use mithril_node::{CriRuntimeContainerObservationV1, WorkloadBindingConfig};
use snafu::OptionExt as _;

use crate::error::InvalidInputSnafu;
use crate::Result;

pub(crate) fn runtime_observation(
    binding: &WorkloadBindingConfig,
    init_pid: u32,
    state: ContainerState,
) -> Result<CriRuntimeContainerObservationV1> {
    let cgroup = binding
        .root_cgroup_path
        .as_ref()
        .context(InvalidInputSnafu {
            path: Path::new("runtime observation"),
            reason: "the runtime fixture has no cgroup path",
        })?;
    let relative = cgroup.strip_prefix("/sys/fs/cgroup").map_err(|source| {
        InvalidInputSnafu {
            path: cgroup,
            reason: format!("the runtime cgroup is outside the unified root: {source}"),
        }
        .build()
    })?;
    let labels = [
        (
            "io.kubernetes.pod.namespace".to_owned(),
            binding.namespace.clone(),
        ),
        ("io.kubernetes.pod.uid".to_owned(), binding.pod_uid.clone()),
        (
            "io.kubernetes.container.name".to_owned(),
            binding.container_name.clone(),
        ),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>();
    let metadata = Some(ContainerMetadata {
        name: binding.container_name.clone(),
        attempt: 0,
    });
    let state = state as i32;
    Ok(CriRuntimeContainerObservationV1 {
        listed: Container {
            id: binding.container_id.clone(),
            pod_sandbox_id: binding.sandbox_id.clone(),
            metadata: metadata.clone(),
            image_ref: "sha256:local-content-id".to_owned(),
            state,
            labels: labels.clone(),
            ..Container::default()
        },
        status: ContainerStatusResponse {
            status: Some(ContainerStatus {
                id: binding.container_id.clone(),
                metadata,
                state,
                created_at: i64::try_from(binding.container_generation).map_err(|source| {
                    InvalidInputSnafu {
                        path: cgroup,
                        reason: format!("the runtime generation is invalid: {source}"),
                    }
                    .build()
                })?,
                image_ref: format!("fixture@{}", binding.image_digest),
                labels,
                ..ContainerStatus::default()
            }),
            info: [(
                "info".to_owned(),
                serde_json::json!({
                    "pid": init_pid,
                    "runtimeSpec": {
                        "process": { "cwd": "/", "env": ["PATH=/bin:/usr/bin"] },
                        "linux": { "cgroupsPath": Path::new("/").join(relative) }
                    }
                })
                .to_string(),
            )]
            .into_iter()
            .collect(),
        },
    })
}
