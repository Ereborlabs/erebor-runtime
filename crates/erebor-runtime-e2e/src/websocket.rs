use std::{net::SocketAddr, sync::Arc, time::Duration};

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::timeout,
};
use tokio_tungstenite::{
    accept_async, connect_async,
    tungstenite::{Error as WebSocketError, Message},
};
use tracing::{debug, error, info, warn};

use crate::{system::MiniSystem, E2eError};

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
            .map_err(E2eError::io)?;
        let local_addr = listener.local_addr().map_err(E2eError::io)?;
        let endpoint = format!("ws://{local_addr}");
        let (received_tx, received) = mpsc::unbounded_channel();

        system.spawn(
            "mini-json-websocket-server",
            run_json_websocket_server(listener, handler, received_tx),
        );

        info!(endpoint = %endpoint, "started e2e mini JSON websocket server");
        Ok(Self { endpoint, received })
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn next_message(&mut self) -> Result<Value, E2eError> {
        timeout(DEFAULT_E2E_TIMEOUT, self.received.recv())
            .await
            .map_err(|_| E2eError::timeout("mini JSON websocket message"))?
            .ok_or_else(|| E2eError::closed("mini JSON websocket message"))
    }

    pub async fn assert_no_message(&mut self, duration: Duration) -> Result<(), E2eError> {
        match timeout(duration, self.received.recv()).await {
            Err(_) => Ok(()),
            Ok(None) => Err(E2eError::closed("mini JSON websocket message")),
            Ok(Some(message)) => Err(E2eError::unexpected_message(
                "mini JSON websocket",
                message.to_string(),
            )),
        }
    }
}

pub async fn send_json_request(endpoint: &str, request: Value) -> Result<Value, E2eError> {
    let (mut socket, _response) = connect_async(endpoint).await.map_err(E2eError::websocket)?;
    socket
        .send(Message::Text(request.to_string().into()))
        .await
        .map_err(E2eError::websocket)?;

    read_json_message(&mut socket, "JSON websocket response").await
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
                error!(error = %error, "mini JSON websocket accept failed");
                break;
            }
        };
        let handler = Arc::clone(&handler);
        let received = received.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_json_websocket_connection(stream, handler, received).await {
                warn!(
                    client = %address,
                    error = %error,
                    "mini JSON websocket connection failed"
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
    let socket = accept_async(stream).await.map_err(E2eError::websocket)?;
    let (mut write, mut read) = socket.split();

    while let Some(message) = read.next().await {
        let message = message.map_err(E2eError::websocket)?;
        if message.is_close() {
            break;
        }
        if !message.is_text() {
            continue;
        }

        let source = message
            .into_text()
            .map_err(E2eError::websocket)?
            .to_string();
        let request: Value = serde_json::from_str(&source).map_err(E2eError::json)?;
        debug!(request = %request, "mini JSON websocket received request");
        let _result = received.send(request.clone());

        if let Some(response) = handler(request) {
            write
                .send(Message::Text(response.to_string().into()))
                .await
                .map_err(E2eError::websocket)?;
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
        .map_err(|_| E2eError::timeout(operation))?
        .ok_or_else(|| E2eError::closed(operation))?
        .map_err(E2eError::websocket)?;

    if !message.is_text() {
        return Err(E2eError::unsupported_websocket_message(operation));
    }

    let source = message
        .into_text()
        .map_err(E2eError::websocket)?
        .to_string();
    serde_json::from_str(&source).map_err(E2eError::json)
}
