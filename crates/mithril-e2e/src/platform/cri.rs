use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{mpsc, Arc, RwLock};
use std::thread;
use std::time::Duration;

use k8s_cri::v1::{self as cri};
use mithril_node::CriRuntimeContainerObservationV1;
use tokio::net::UnixListener;
use tokio::sync::oneshot;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};

use super::TestResult;
use crate::physical::{wait_for, ProbeFile};

const WAIT_LIMIT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Default)]
struct CriService {
    value: Arc<RwLock<Option<CriRuntimeContainerObservationV1>>>,
}

pub(crate) struct CriFixture {
    path: PathBuf,
    service: CriService,
    stop: Option<oneshot::Sender<()>>,
    task: Option<thread::JoinHandle<Result<(), String>>>,
}

impl CriFixture {
    pub(crate) fn start(path: &Path) -> TestResult<Self> {
        let service = CriService::default();
        let server = service.clone();
        let socket = path.to_path_buf();
        let (stop, stopped) = oneshot::channel();
        let (ready, started) = mpsc::sync_channel(1);
        let task = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?;
            runtime.block_on(async move {
                let listener = UnixListener::bind(&socket).map_err(|error| error.to_string())?;
                let _result = ready.send(());
                tonic::transport::Server::builder()
                    .add_service(cri::runtime_service_server::RuntimeServiceServer::new(
                        server,
                    ))
                    .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async move {
                        let _result = stopped.await;
                    })
                    .await
                    .map_err(|error| error.to_string())
            })
        });
        started
            .recv_timeout(WAIT_LIMIT)
            .map_err(|error| format!("CRI fixture did not bind {}: {error}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            service,
            stop: Some(stop),
            task: Some(task),
        })
    }

    pub(crate) fn set(&self, value: CriRuntimeContainerObservationV1) -> TestResult<()> {
        *self
            .service
            .value
            .write()
            .map_err(|_error| "CRI fixture state is poisoned")? = Some(value);
        Ok(())
    }

    pub(crate) fn stop(&mut self) -> TestResult<()> {
        if let Some(stop) = self.stop.take() {
            let _result = stop.send(());
        }
        if let Some(task) = self.task.as_ref() {
            wait_for(
                &self.path,
                "CRI fixture shutdown",
                WAIT_LIMIT,
                || Ok(task.is_finished().then_some(())),
                || "the CRI fixture thread is still running".to_owned(),
            )?;
        }
        if let Some(task) = self.task.take() {
            task.join()
                .map_err(|_panic| "CRI fixture thread panicked")?
                .map_err(std::io::Error::other)?;
        }
        ProbeFile::new(&self.path).cleanup()?;
        Ok(())
    }
}

impl Drop for CriFixture {
    fn drop(&mut self) {
        let _result = self.stop();
    }
}

impl CriService {
    fn unused() -> Status {
        Status::unimplemented("unused CRI fixture operation")
    }
}

#[tonic::async_trait]
impl cri::runtime_service_server::RuntimeService for CriService {
    async fn version(
        &self,
        _request: Request<cri::VersionRequest>,
    ) -> Result<Response<cri::VersionResponse>, Status> {
        Ok(Response::new(cri::VersionResponse {
            version: "0.1.0".to_owned(),
            runtime_name: "mithril-e2e".to_owned(),
            runtime_version: "1".to_owned(),
            runtime_api_version: "v1".to_owned(),
        }))
    }

    async fn list_containers(
        &self,
        _request: Request<cri::ListContainersRequest>,
    ) -> Result<Response<cri::ListContainersResponse>, Status> {
        let value = self
            .value
            .read()
            .map_err(|_error| Status::internal("CRI fixture state is poisoned"))?;
        Ok(Response::new(cri::ListContainersResponse {
            containers: value.iter().map(|value| value.listed.clone()).collect(),
        }))
    }

    async fn container_status(
        &self,
        request: Request<cri::ContainerStatusRequest>,
    ) -> Result<Response<cri::ContainerStatusResponse>, Status> {
        let id = request.into_inner().container_id;
        let value = self
            .value
            .read()
            .map_err(|_error| Status::internal("CRI fixture state is poisoned"))?;
        let value = value
            .as_ref()
            .filter(|value| value.listed.id == id)
            .ok_or_else(|| Status::not_found("container is absent"))?;
        Ok(Response::new(value.status.clone()))
    }

    async fn run_pod_sandbox(
        &self,
        _request: Request<cri::RunPodSandboxRequest>,
    ) -> Result<Response<cri::RunPodSandboxResponse>, Status> {
        Err(Self::unused())
    }

    async fn stop_pod_sandbox(
        &self,
        _request: Request<cri::StopPodSandboxRequest>,
    ) -> Result<Response<cri::StopPodSandboxResponse>, Status> {
        Err(Self::unused())
    }

    async fn remove_pod_sandbox(
        &self,
        _request: Request<cri::RemovePodSandboxRequest>,
    ) -> Result<Response<cri::RemovePodSandboxResponse>, Status> {
        Err(Self::unused())
    }

    async fn pod_sandbox_status(
        &self,
        _request: Request<cri::PodSandboxStatusRequest>,
    ) -> Result<Response<cri::PodSandboxStatusResponse>, Status> {
        Err(Self::unused())
    }

    async fn list_pod_sandbox(
        &self,
        _request: Request<cri::ListPodSandboxRequest>,
    ) -> Result<Response<cri::ListPodSandboxResponse>, Status> {
        Err(Self::unused())
    }

    async fn create_container(
        &self,
        _request: Request<cri::CreateContainerRequest>,
    ) -> Result<Response<cri::CreateContainerResponse>, Status> {
        Err(Self::unused())
    }

    async fn start_container(
        &self,
        _request: Request<cri::StartContainerRequest>,
    ) -> Result<Response<cri::StartContainerResponse>, Status> {
        Err(Self::unused())
    }

    async fn stop_container(
        &self,
        _request: Request<cri::StopContainerRequest>,
    ) -> Result<Response<cri::StopContainerResponse>, Status> {
        Err(Self::unused())
    }

    async fn remove_container(
        &self,
        _request: Request<cri::RemoveContainerRequest>,
    ) -> Result<Response<cri::RemoveContainerResponse>, Status> {
        Err(Self::unused())
    }

    async fn update_container_resources(
        &self,
        _request: Request<cri::UpdateContainerResourcesRequest>,
    ) -> Result<Response<cri::UpdateContainerResourcesResponse>, Status> {
        Err(Self::unused())
    }

    async fn reopen_container_log(
        &self,
        _request: Request<cri::ReopenContainerLogRequest>,
    ) -> Result<Response<cri::ReopenContainerLogResponse>, Status> {
        Err(Self::unused())
    }

    async fn exec_sync(
        &self,
        _request: Request<cri::ExecSyncRequest>,
    ) -> Result<Response<cri::ExecSyncResponse>, Status> {
        Err(Self::unused())
    }

    async fn exec(
        &self,
        _request: Request<cri::ExecRequest>,
    ) -> Result<Response<cri::ExecResponse>, Status> {
        Err(Self::unused())
    }

    async fn attach(
        &self,
        _request: Request<cri::AttachRequest>,
    ) -> Result<Response<cri::AttachResponse>, Status> {
        Err(Self::unused())
    }

    async fn port_forward(
        &self,
        _request: Request<cri::PortForwardRequest>,
    ) -> Result<Response<cri::PortForwardResponse>, Status> {
        Err(Self::unused())
    }

    async fn container_stats(
        &self,
        _request: Request<cri::ContainerStatsRequest>,
    ) -> Result<Response<cri::ContainerStatsResponse>, Status> {
        Err(Self::unused())
    }

    async fn list_container_stats(
        &self,
        _request: Request<cri::ListContainerStatsRequest>,
    ) -> Result<Response<cri::ListContainerStatsResponse>, Status> {
        Err(Self::unused())
    }

    async fn pod_sandbox_stats(
        &self,
        _request: Request<cri::PodSandboxStatsRequest>,
    ) -> Result<Response<cri::PodSandboxStatsResponse>, Status> {
        Err(Self::unused())
    }

    async fn list_pod_sandbox_stats(
        &self,
        _request: Request<cri::ListPodSandboxStatsRequest>,
    ) -> Result<Response<cri::ListPodSandboxStatsResponse>, Status> {
        Err(Self::unused())
    }

    async fn update_runtime_config(
        &self,
        _request: Request<cri::UpdateRuntimeConfigRequest>,
    ) -> Result<Response<cri::UpdateRuntimeConfigResponse>, Status> {
        Err(Self::unused())
    }

    async fn status(
        &self,
        _request: Request<cri::StatusRequest>,
    ) -> Result<Response<cri::StatusResponse>, Status> {
        Err(Self::unused())
    }

    async fn checkpoint_container(
        &self,
        _request: Request<cri::CheckpointContainerRequest>,
    ) -> Result<Response<cri::CheckpointContainerResponse>, Status> {
        Err(Self::unused())
    }

    type GetContainerEventsStream = Pin<
        Box<
            dyn tonic::codegen::tokio_stream::Stream<
                    Item = Result<cri::ContainerEventResponse, Status>,
                > + Send,
        >,
    >;

    async fn get_container_events(
        &self,
        _request: Request<cri::GetEventsRequest>,
    ) -> Result<Response<Self::GetContainerEventsStream>, Status> {
        Err(Self::unused())
    }
}
