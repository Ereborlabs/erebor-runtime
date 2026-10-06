use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use erebor_runtime_ipc::{
    araphor::{self as wire, araphor_client_service_client::AraphorClientServiceClient},
    transport::MAX_GRPC_MESSAGE_BYTES,
};
use serde::Deserialize;
use tonic::{
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
    Request, Streaming,
};
use uuid::Uuid;

mod error;
pub use error::AraphorError;
pub type AraphorResult<T> = std::result::Result<T, AraphorError>;

const FILE_BYTES: usize = 64 * 1024;
const TOKEN_BYTES: usize = 16 * 1024;
const RPC_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AraphorProfile {
    pub endpoint: String,
    pub tenant_id: String,
    pub credential_file: PathBuf,
    pub ca_file: Option<PathBuf>,
}

impl AraphorProfile {
    pub fn read(path: &Path) -> AraphorResult<Self> {
        let bytes = Self::file(path, FILE_BYTES)?;
        let mut profile: Self =
            serde_json::from_slice(&bytes).map_err(|_| Self::invalid("profile JSON"))?;
        if let Some(base) = path.parent() {
            if profile.credential_file.is_relative() {
                profile.credential_file = base.join(&profile.credential_file);
            }
            if let Some(path) = &mut profile.ca_file {
                if path.is_relative() {
                    *path = base.join(&*path);
                }
            }
        }
        profile.validate()?;
        Ok(profile)
    }

    fn validate(&self) -> AraphorResult<()> {
        let endpoint = Endpoint::from_shared(self.endpoint.clone())
            .map_err(|_| Self::invalid("TLS endpoint"))?;
        let uri = endpoint.uri();
        if uri.scheme_str() != Some("https")
            || uri.host().is_none()
            || uri
                .authority()
                .is_some_and(|value| value.as_str().contains('@'))
            || !matches!(uri.path(), "" | "/")
            || uri.query().is_some()
        {
            return Err(Self::invalid(
                "HTTPS endpoint without credentials or RPC path",
            ));
        }
        let tenant = Uuid::parse_str(&self.tenant_id).map_err(|_| Self::invalid("tenant UUID"))?;
        if tenant.is_nil() || self.credential_file.as_os_str().is_empty() {
            return Err(Self::invalid("tenant or credential file"));
        }
        Ok(())
    }

    fn file(path: &Path, limit: usize) -> AraphorResult<Vec<u8>> {
        let read = || -> std::io::Result<Vec<u8>> {
            let file = File::open(path)?;
            if !file.metadata()?.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "a regular file is required",
                ));
            }
            let mut bytes = Vec::new();
            file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
            Ok(bytes)
        };
        let bytes = read().map_err(|source| AraphorError::Read {
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        })?;
        if bytes.len() > limit {
            return Err(Self::invalid("file byte limit"));
        }
        Ok(bytes)
    }

    fn invalid(field: &'static str) -> AraphorError {
        AraphorError::Invalid {
            field,
            location: snafu::Location::default(),
        }
    }
}

#[derive(Clone)]
pub struct AraphorClient {
    profile: AraphorProfile,
    channel: Channel,
}

impl AraphorClient {
    pub async fn connect(profile: AraphorProfile) -> AraphorResult<Self> {
        profile.validate()?;
        let mut tls = ClientTlsConfig::new().with_native_roots();
        if let Some(path) = &profile.ca_file {
            tls = tls.ca_certificate(Certificate::from_pem(AraphorProfile::file(
                path, FILE_BYTES,
            )?));
        }
        let endpoint = Endpoint::from_shared(profile.endpoint.clone())
            .map_err(|_| AraphorProfile::invalid("TLS endpoint"))?
            .tls_config(tls)
            .map_err(Self::connection)?
            .connect_timeout(RPC_TIMEOUT)
            .timeout(RPC_TIMEOUT);
        let channel = endpoint.connect().await.map_err(Self::connection)?;
        Ok(Self { profile, channel })
    }

    pub async fn query(
        &self,
        query: wire::QueryRequest,
    ) -> AraphorResult<Streaming<wire::QueryFrame>> {
        self.service()
            .query(self.request(query)?)
            .await
            .map(tonic::Response::into_inner)
            .map_err(Self::rpc_error)
    }

    pub async fn submit_trace(
        &self,
        trace: wire::SubmitTraceRequest,
    ) -> AraphorResult<wire::TraceReceipt> {
        if trace.idempotency_key.len() != 16 || trace.idempotency_key.iter().all(|byte| *byte == 0)
        {
            return Err(AraphorProfile::invalid("trace idempotency UUID"));
        }
        for attempt in 0..3 {
            let result = self
                .service()
                .submit_trace(self.unary(trace.clone())?)
                .await
                .map(tonic::Response::into_inner)
                .map_err(Self::rpc_error);
            match result {
                Err(error) if error.retryable() && attempt < 2 => {
                    tokio::time::sleep(Duration::from_millis(250 * (attempt + 1))).await;
                }
                result => return result,
            }
        }
        Err(AraphorProfile::invalid("trace retry state"))
    }

    pub async fn get_trace(
        &self,
        request: wire::GetTraceRequest,
    ) -> AraphorResult<wire::TraceDetail> {
        self.service()
            .get_trace(self.unary(request)?)
            .await
            .map(tonic::Response::into_inner)
            .map_err(Self::rpc_error)
    }

    pub async fn watch_trace(
        &self,
        request: wire::WatchTraceRequest,
    ) -> AraphorResult<Streaming<wire::TraceFrame>> {
        self.service()
            .watch_trace(self.request(request)?)
            .await
            .map(tonic::Response::into_inner)
            .map_err(Self::rpc_error)
    }

    pub async fn cancel_trace(
        &self,
        request: wire::CancelTraceRequest,
    ) -> AraphorResult<wire::CancelTraceReceipt> {
        self.service()
            .cancel_trace(self.unary(request)?)
            .await
            .map(tonic::Response::into_inner)
            .map_err(Self::rpc_error)
    }

    fn service(&self) -> AraphorClientServiceClient<Channel> {
        AraphorClientServiceClient::new(self.channel.clone())
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES)
    }

    fn request<T>(&self, message: T) -> AraphorResult<Request<T>> {
        let bytes = AraphorProfile::file(&self.profile.credential_file, TOKEN_BYTES)?;
        let token = std::str::from_utf8(&bytes)
            .map_err(|_| AraphorProfile::invalid("service credential encoding"))?
            .trim();
        if token.is_empty() || token.chars().any(char::is_whitespace) {
            return Err(AraphorProfile::invalid("service credential"));
        }
        let mut bearer = MetadataValue::try_from(format!("Bearer {token}"))
            .map_err(|_| AraphorProfile::invalid("service credential metadata"))?;
        bearer.set_sensitive(true);
        let tenant = Uuid::parse_str(&self.profile.tenant_id)
            .map_err(|_| AraphorProfile::invalid("tenant UUID"))?
            .to_string();
        let tenant = MetadataValue::try_from(tenant)
            .map_err(|_| AraphorProfile::invalid("tenant metadata"))?;
        let mut request = Request::new(message);
        request.metadata_mut().insert("authorization", bearer);
        request.metadata_mut().insert("x-araphor-tenant", tenant);
        Ok(request)
    }

    fn unary<T>(&self, message: T) -> AraphorResult<Request<T>> {
        let mut request = self.request(message)?;
        request.set_timeout(RPC_TIMEOUT);
        Ok(request)
    }

    fn connection(source: tonic::transport::Error) -> AraphorError {
        AraphorError::Connect {
            source,
            location: snafu::Location::default(),
        }
    }

    pub fn rpc_error(source: tonic::Status) -> AraphorError {
        AraphorError::Rpc {
            source: Box::new(source),
            location: snafu::Location::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CredentialFile(PathBuf);

    impl CredentialFile {
        fn new() -> std::io::Result<Self> {
            let path = std::env::temp_dir().join(format!("araphor-credential-{}", Uuid::new_v4()));
            File::options().write(true).create_new(true).open(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for CredentialFile {
        fn drop(&mut self) {
            let _cleanup = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn profile_rejects_local_transport() {
        let mut profile = AraphorProfile {
            endpoint: "https://control.example".into(),
            tenant_id: "10000000-0000-0000-0000-000000000001".into(),
            credential_file: PathBuf::from("credential"),
            ca_file: None,
        };
        assert!(profile.validate().is_ok());
        for endpoint in [
            "http://control.example",
            "unix:///run/erebor/daemon.sock",
            "https://user@control.example",
            "https://control.example/rpc",
            "https://control.example/?token=x",
        ] {
            profile.endpoint = endpoint.into();
            assert!(profile.validate().is_err());
        }
    }

    #[test]
    fn expiry_never_retries() {
        let expired =
            AraphorClient::rpc_error(tonic::Status::out_of_range("retained cursor expired"));
        assert!(expired.expired());
        assert!(!expired.retryable());
        assert!(!AraphorClient::rpc_error(tonic::Status::permission_denied("denied")).retryable());
        assert!(AraphorClient::rpc_error(tonic::Status::unavailable("closed")).retryable());
    }

    #[tokio::test]
    async fn observability_client_fresh_credentials(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let file = CredentialFile::new()?;
        let client = AraphorClient {
            profile: AraphorProfile {
                endpoint: "https://control.example".into(),
                tenant_id: "10000000000000000000000000000001".into(),
                credential_file: file.0.clone(),
                ca_file: None,
            },
            channel: Endpoint::from_static("https://control.example").connect_lazy(),
        };
        std::fs::write(&file.0, "first-token\n")?;
        let first = client.request(())?;
        assert_eq!(
            first
                .metadata()
                .get("x-araphor-tenant")
                .ok_or_else(|| AraphorProfile::invalid("test tenant metadata"))?
                .to_str()?,
            "10000000-0000-0000-0000-000000000001"
        );
        assert!(first
            .metadata()
            .get("authorization")
            .ok_or_else(|| AraphorProfile::invalid("test credential metadata"))?
            .is_sensitive());
        std::fs::write(&file.0, "second-token\n")?;
        let second = client.request(())?;
        assert_eq!(
            first
                .metadata()
                .get("authorization")
                .ok_or_else(|| AraphorProfile::invalid("test credential metadata"))?
                .to_str()?,
            "Bearer first-token"
        );
        assert_eq!(
            second
                .metadata()
                .get("authorization")
                .ok_or_else(|| AraphorProfile::invalid("test credential metadata"))?
                .to_str()?,
            "Bearer second-token"
        );
        std::fs::write(&file.0, vec![b'x'; TOKEN_BYTES + 1])?;
        assert!(client.request(()).is_err());
        Ok(())
    }
}
