use std::path::PathBuf;

use erebor_runtime_ipc::{
    transport::{connect_unix, MAX_GRPC_MESSAGE_BYTES},
    v1::{
        runtime_observation_service_client::RuntimeObservationServiceClient,
        MithrilObservationSnapshot, MithrilObservationSnapshotRequest,
    },
};
use tonic::Request;

use crate::{error::ProtocolSnafu, rpc, DaemonClientError, Result};

#[derive(Clone, Debug)]
pub struct MithrilObservationClient {
    socket_path: PathBuf,
    cgroup_scope: String,
}

impl MithrilObservationClient {
    #[must_use]
    pub fn new(socket_path: PathBuf, cgroup_scope: String) -> Self {
        Self {
            socket_path,
            cgroup_scope,
        }
    }

    pub async fn snapshot(&self) -> Result<MithrilObservationSnapshot> {
        let channel =
            connect_unix(&self.socket_path)
                .await
                .map_err(|source| DaemonClientError::Connect {
                    path: self.socket_path.clone(),
                    source,
                    location: snafu::Location::default(),
                })?;
        let mut client = RuntimeObservationServiceClient::new(channel)
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES);
        let response = rpc(client
            .get_snapshot(Request::new(MithrilObservationSnapshotRequest {
                cgroup_scope: self.cgroup_scope.clone(),
            }))
            .await)?;
        if !response.accepted {
            return ProtocolSnafu {
                reason: response.reason,
            }
            .fail();
        }
        let snapshot = response.snapshot.ok_or_else(|| {
            ProtocolSnafu {
                reason: String::from("Mithril accepted an observation request without a snapshot"),
            }
            .build()
        })?;
        if snapshot.cgroup_scope != self.cgroup_scope {
            return ProtocolSnafu {
                reason: String::from(
                    "Mithril returned a snapshot outside the requested cgroup scope",
                ),
            }
            .fail();
        }
        Ok(snapshot)
    }
}
