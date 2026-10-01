use std::{
    error::Error,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use tokio::io::AsyncWriteExt as _;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

use crate::control_fixture::CertificateFiles;

mod protocol {
    tonic::include_proto!("erebor.mithril.e2e.v1");
}

use protocol::grpc_throughput_client::GrpcThroughputClient;
use protocol::grpc_throughput_server::{GrpcThroughput, GrpcThroughputServer};
use protocol::{FileChunk, FileReceipt};

const CHUNK_BYTES: usize = 3 * 1_024 * 1_024;
const MESSAGE_BYTES: usize = 4 * 1_024 * 1_024;
const WINDOW_BYTES: u32 = 16 * 1_024 * 1_024;
const TRANSFER_LIMIT: Duration = Duration::from_secs(30);
const STOP_LIMIT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(super) struct GrpcTransfer {
    path: Option<PathBuf>,
}

impl GrpcTransfer {
    pub(super) fn new(path: Option<PathBuf>) -> Self {
        Self { path }
    }

    pub(super) async fn measure(
        self,
        files: &CertificateFiles,
        total: u64,
    ) -> Result<(Duration, f64), Box<dyn Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let path = self
            .path
            .clone()
            .unwrap_or_else(|| address.to_string().into());
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                fs::read(&files.server_certificate)?,
                fs::read(&files.server_key)?,
            ))
            .client_ca_root(Certificate::from_pem(fs::read(&files.ca)?));
        let (shutdown, receiver) = oneshot::channel();
        let mut server = tokio::spawn(async move {
            Server::builder()
                .initial_stream_window_size(WINDOW_BYTES)
                .initial_connection_window_size(WINDOW_BYTES)
                .tls_config(tls)?
                .add_service(
                    GrpcThroughputServer::new(self)
                        .max_decoding_message_size(MESSAGE_BYTES)
                        .max_encoding_message_size(MESSAGE_BYTES),
                )
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                    let _result = receiver.await;
                })
                .await
        });

        let result = tokio::time::timeout(TRANSFER_LIMIT, async {
            let tls = ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(fs::read(&files.ca)?))
                .identity(Identity::from_pem(
                    fs::read(&files.node_certificate)?,
                    fs::read(&files.node_key)?,
                ))
                .domain_name("localhost");
            let channel = Endpoint::from_shared(format!("https://{address}"))?
                .tls_config(tls)?
                .connect_timeout(STOP_LIMIT)
                .initial_stream_window_size(WINDOW_BYTES)
                .initial_connection_window_size(WINDOW_BYTES)
                .connect()
                .await?;
            let mut client = GrpcThroughputClient::new(channel)
                .max_decoding_message_size(MESSAGE_BYTES)
                .max_encoding_message_size(MESSAGE_BYTES);
            let (output, input) = mpsc::channel(8);
            let source = prost::bytes::Bytes::from(vec![0xa5; CHUNK_BYTES]);
            let started = Instant::now();
            let upload = async {
                Ok::<_, Box<dyn Error>>(
                    client
                        .upload(Request::new(ReceiverStream::new(input)))
                        .await?
                        .into_inner(),
                )
            };
            let send = async {
                let mut remaining = total;
                while remaining > 0 {
                    let count = remaining.min(CHUNK_BYTES as u64) as usize;
                    output
                        .send(FileChunk {
                            payload: source.slice(..count),
                        })
                        .await
                        .map_err(|error| format!("{address}: send file chunk: {error}"))?;
                    remaining -= count as u64;
                }
                drop(output);
                Ok::<_, Box<dyn Error>>(())
            };
            let (receipt, ()) = tokio::try_join!(upload, send)?;
            let elapsed = started.elapsed();
            if receipt.received_bytes != total {
                return Err(format!(
                    "{address}: received {} of {total} bytes",
                    receipt.received_bytes
                )
                .into());
            }
            Ok::<_, Box<dyn Error>>((elapsed, total as f64 / 1_048_576.0 / elapsed.as_secs_f64()))
        })
        .await
        .map_err(|error| {
            format!(
                "{}: transfer {total} bytes at {address}: {error}; server finished: {}",
                path.display(),
                server.is_finished()
            )
        })
        .and_then(|result| result.map_err(|error| error.to_string()));

        let _result = shutdown.send(());
        let stopped = match tokio::time::timeout(STOP_LIMIT, &mut server).await {
            Ok(result) => result
                .map_err(|error| error.to_string())
                .and_then(|result| result.map_err(|error| error.to_string())),
            Err(error) => {
                server.abort();
                let _result = server.await;
                Err(format!(
                    "{}: stop transfer server at {address}: {error}",
                    path.display()
                ))
            }
        };
        match (result, stopped) {
            (Ok(measured), Ok(())) => Ok(measured),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error.into()),
            (Err(error), Err(cleanup)) => Err(format!("{error}; cleanup: {cleanup}").into()),
        }
    }
}

#[tonic::async_trait]
impl GrpcThroughput for GrpcTransfer {
    async fn upload(
        &self,
        request: Request<tonic::Streaming<FileChunk>>,
    ) -> Result<Response<FileReceipt>, Status> {
        let mut input = request.into_inner();
        let mut file = match &self.path {
            Some(path) => Some(tokio::fs::File::create(path).await.map_err(|error| {
                Status::internal(format!("{}: create transfer file: {error}", path.display()))
            })?),
            None => None,
        };
        let mut received = 0_u64;
        while let Some(chunk) = input.message().await? {
            received = received
                .checked_add(chunk.payload.len() as u64)
                .ok_or_else(|| Status::out_of_range("transfer byte count exhausted"))?;
            if let Some(file) = &mut file {
                file.write_all(&chunk.payload)
                    .await
                    .map_err(|error| Status::internal(format!("write transfer file: {error}")))?;
            }
        }
        if let Some(file) = file {
            file.sync_data()
                .await
                .map_err(|error| Status::internal(format!("sync transfer file: {error}")))?;
        }
        Ok(Response::new(FileReceipt {
            received_bytes: received,
        }))
    }
}
