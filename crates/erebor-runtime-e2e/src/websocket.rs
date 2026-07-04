use std::{net::SocketAddr, sync::Arc, time::Duration};

use erebor_runtime_telemetry::{debug, error, info, warn};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use snafu::ResultExt;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::timeout,
};
use tokio_tungstenite::{
    accept_async, connect_async,
    tungstenite::{Error as WebSocketError, Message},
};

use crate::{
    error::{
        ClosedSnafu, IoSnafu, JsonSnafu, TimeoutSnafu, UnexpectedMessageSnafu,
        UnsupportedWebSocketMessageSnafu, WebSocketSnafu,
    },
    system::MiniSystem,
    E2eError,
};

pub const DEFAULT_E2E_TIMEOUT: Duration = Duration::from_secs(2);

pub type JsonWebSocketHandler = Arc<dyn Fn(Value) -> Option<Value> + Send + Sync + 'static>;

pub struct MiniJsonWebSocketServer {
    endpoint: String,
    received: mpsc::UnboundedReceiver<Value>,
}

impl MiniJsonWebSocketServer {
    pub async fn spawn(
        system: &mut MiniSystem,
        handler: JsonWebSocketHandler,
    ) -> Result<Self, E2eError> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .context(IoSnafu)?;
        let local_addr = listener.local_addr().context(IoSnafu)?;
        let endpoint = format!("ws://{local_addr}");
        let (received_tx, received) = mpsc::unbounded_channel();

        system.spawn(
            "mini-json-websocket-server",
            run_json_websocket_server(listener, handler, received_tx),
        );

        info!("started e2e mini JSON websocket server", endpoint = %endpoint);
        Ok(Self { endpoint, received })
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn next_message(&mut self) -> Result<Value, E2eError> {
        timeout(DEFAULT_E2E_TIMEOUT, self.received.recv())
            .await
            .map_err(|_| {
                TimeoutSnafu {
                    operation: String::from("mini JSON websocket message"),
                }
                .build()
            })?
            .ok_or_else(|| {
                ClosedSnafu {
                    operation: String::from("mini JSON websocket message"),
                }
                .build()
            })
    }

    pub async fn assert_no_message(&mut self, duration: Duration) -> Result<(), E2eError> {
        match timeout(duration, self.received.recv()).await {
            Err(_) => Ok(()),
            Ok(None) => ClosedSnafu {
                operation: String::from("mini JSON websocket message"),
            }
            .fail(),
            Ok(Some(message)) => UnexpectedMessageSnafu {
                channel: String::from("mini JSON websocket"),
                message: message.to_string(),
            }
            .fail(),
        }
    }
}

pub async fn send_json_request(endpoint: &str, request: Value) -> Result<Value, E2eError> {
    let (mut socket, _response) = connect_async(endpoint).await.context(WebSocketSnafu)?;
    socket
        .send(Message::Text(request.to_string().into()))
        .await
        .context(WebSocketSnafu)?;

    read_json_message(&mut socket, "JSON websocket response").await
}

pub async fn assert_json_request_has_no_response(
    endpoint: &str,
    request: Value,
    duration: Duration,
) -> Result<(), E2eError> {
    let (mut socket, _response) = connect_async(endpoint).await.context(WebSocketSnafu)?;
    socket
        .send(Message::Text(request.to_string().into()))
        .await
        .context(WebSocketSnafu)?;

    assert_no_json_message(&mut socket, "JSON websocket response", duration).await
}

async fn run_json_websocket_server(
    listener: TcpListener,
    handler: JsonWebSocketHandler,
    received: mpsc::UnboundedSender<Value>,
) {
    loop {
        let (stream, address) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                error!(%error; "mini JSON websocket accept failed");
                break;
            }
        };
        let handler = Arc::clone(&handler);
        let received = received.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_json_websocket_connection(stream, handler, received).await {
                warn!(
                    error;
                    "mini JSON websocket connection failed",
                    client = %address,
                );
            }
        });
    }
}

async fn handle_json_websocket_connection(
    stream: TcpStream,
    handler: JsonWebSocketHandler,
    received: mpsc::UnboundedSender<Value>,
) -> Result<(), E2eError> {
    let socket = accept_async(stream).await.context(WebSocketSnafu)?;
    let (mut write, mut read) = socket.split();

    while let Some(message) = read.next().await {
        let message = message.context(WebSocketSnafu)?;
        if message.is_close() {
            break;
        }
        if !message.is_text() {
            continue;
        }

        let source = message.into_text().context(WebSocketSnafu)?.to_string();
        let request: Value = serde_json::from_str(&source).context(JsonSnafu)?;
        debug!("mini JSON websocket received request", request = %request);
        let _result = received.send(request.clone());

        if let Some(response) = handler(request) {
            write
                .send(Message::Text(response.to_string().into()))
                .await
                .context(WebSocketSnafu)?;
        }
    }

    Ok(())
}

async fn read_json_message<S>(socket: &mut S, operation: &str) -> Result<Value, E2eError>
where
    S: StreamExt<Item = Result<Message, WebSocketError>> + Unpin,
{
    let message = timeout(DEFAULT_E2E_TIMEOUT, socket.next())
        .await
        .map_err(|_| {
            TimeoutSnafu {
                operation: operation.to_owned(),
            }
            .build()
        })?
        .ok_or_else(|| {
            ClosedSnafu {
                operation: operation.to_owned(),
            }
            .build()
        })?
        .context(WebSocketSnafu)?;

    if !message.is_text() {
        return UnsupportedWebSocketMessageSnafu {
            operation: operation.to_owned(),
        }
        .fail();
    }

    let source = message.into_text().context(WebSocketSnafu)?.to_string();
    serde_json::from_str(&source).context(JsonSnafu)
}

async fn assert_no_json_message<S>(
    socket: &mut S,
    operation: &str,
    duration: Duration,
) -> Result<(), E2eError>
where
    S: StreamExt<Item = Result<Message, WebSocketError>> + Unpin,
{
    match timeout(duration, socket.next()).await {
        Err(_) => Ok(()),
        Ok(None) => ClosedSnafu {
            operation: operation.to_owned(),
        }
        .fail(),
        Ok(Some(Err(error))) => Err(E2eError::WebSocket {
            source: Box::new(error),
            location: snafu::Location::default(),
        }),
        Ok(Some(Ok(message))) => UnexpectedMessageSnafu {
            channel: operation.to_owned(),
            message: message.to_string(),
        }
        .fail(),
    }
}
