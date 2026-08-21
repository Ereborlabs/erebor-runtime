use std::{
    io,
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
};

use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{UnixListener, UnixStream},
};
use tonic::transport::{server::Connected, Channel, Endpoint, Uri};
use tower::service_fn;

pub const MAX_GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
pub const IDEMPOTENCY_KEY_METADATA: &str = "erebor-idempotency-key";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixPeerIdentity {
    pub pid: Option<i32>,
    pub uid: u32,
    pub gid: u32,
}

pub struct AuthenticatedUnixStream {
    stream: UnixStream,
    peer: UnixPeerIdentity,
}

impl AuthenticatedUnixStream {
    fn new(stream: UnixStream) -> io::Result<Self> {
        let credentials = stream.peer_cred()?;
        Ok(Self {
            stream,
            peer: UnixPeerIdentity {
                pid: credentials.pid(),
                uid: credentials.uid(),
                gid: credentials.gid(),
            },
        })
    }
}

impl Connected for AuthenticatedUnixStream {
    type ConnectInfo = UnixPeerIdentity;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.peer
    }
}

impl AsyncRead for AuthenticatedUnixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for AuthenticatedUnixStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

pub struct UnixIncoming {
    listener: UnixListener,
}

impl UnixIncoming {
    #[must_use]
    pub const fn new(listener: UnixListener) -> Self {
        Self { listener }
    }
}

impl futures_util::Stream for UnixIncoming {
    type Item = io::Result<AuthenticatedUnixStream>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.get_mut().listener.poll_accept(context) {
            Poll::Ready(Ok((stream, _address))) => {
                Poll::Ready(Some(AuthenticatedUnixStream::new(stream)))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub async fn connect_unix(path: impl AsRef<Path>) -> Result<Channel, tonic::transport::Error> {
    let path = PathBuf::from(path.as_ref());
    Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_uri: Uri| {
            let path = path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await
}
