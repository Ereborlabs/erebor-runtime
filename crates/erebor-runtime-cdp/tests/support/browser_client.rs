use std::time::Duration;

use erebor_runtime_e2e::{
    error::{JsonSnafu, WebSocketSnafu},
    E2eError,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use snafu::ResultExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

use crate::common::{closed_error, external_error, timeout_error};

pub struct BrowserLevelCdpClient {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next_id: u32,
    target_id: String,
    session_id: String,
}

impl BrowserLevelCdpClient {
    pub async fn connect(endpoint: &str) -> Result<Self, E2eError> {
        let (socket, _response) = connect_async(endpoint).await.context(WebSocketSnafu)?;
        let mut client = Self {
            socket,
            next_id: 1,
            target_id: String::new(),
            session_id: String::new(),
        };
        let target_id = client.find_or_create_page_target().await?;
        client.attach_to_target(target_id).await?;
        client.enable_page_domains().await?;

        Ok(client)
    }

    pub async fn reconnect_to(endpoint: &str, target_id: String) -> Result<Self, E2eError> {
        let (socket, _response) = connect_async(endpoint).await.context(WebSocketSnafu)?;
        let mut client = Self {
            socket,
            next_id: 1,
            target_id: String::new(),
            session_id: String::new(),
        };
        client.attach_to_target(target_id).await?;
        client.enable_page_domains().await?;

        Ok(client)
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    pub async fn navigate(&mut self, url: &str) -> Result<Value, E2eError> {
        self.session_command("Page.navigate", json!({ "url": url }))
            .await
    }

    pub async fn create_page_target(&mut self, url: &str) -> Result<String, E2eError> {
        let created = self
            .command("Target.createTarget", json!({ "url": url }))
            .await?;
        created
            .pointer("/result/targetId")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| external_error("browser-level CDP target creation", MissingTargetId))
    }

    pub async fn close_target(&mut self, target_id: &str) -> Result<Value, E2eError> {
        self.command("Target.closeTarget", json!({ "targetId": target_id }))
            .await
    }

    pub async fn evaluate(&mut self, expression: &str) -> Result<Value, E2eError> {
        self.session_command(
            "Runtime.evaluate",
            json!({
                "expression": expression,
                "returnByValue": true
            }),
        )
        .await
    }

    async fn find_or_create_page_target(&mut self) -> Result<String, E2eError> {
        let targets = self.command("Target.getTargets", json!({})).await?;
        if let Some(target_id) = targets
            .pointer("/result/targetInfos")
            .and_then(Value::as_array)
            .and_then(|targets| {
                targets.iter().find_map(|target| {
                    let is_page = target
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| kind == "page");
                    is_page.then(|| {
                        target
                            .get("targetId")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })?
                })
            })
        {
            return Ok(target_id);
        }

        self.create_page_target("about:blank").await
    }

    async fn attach_to_target(&mut self, target_id: String) -> Result<(), E2eError> {
        let attached = self
            .command(
                "Target.attachToTarget",
                json!({
                    "targetId": target_id.clone(),
                    "flatten": true
                }),
            )
            .await?;
        self.session_id = attached
            .pointer("/result/sessionId")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| external_error("browser-level CDP attach", MissingSessionId))?;
        self.target_id = target_id;

        Ok(())
    }

    async fn enable_page_domains(&mut self) -> Result<(), E2eError> {
        let _runtime = self.session_command("Runtime.enable", json!({})).await?;
        let _page = self.session_command("Page.enable", json!({})).await?;
        Ok(())
    }

    async fn command(&mut self, method: &str, params: Value) -> Result<Value, E2eError> {
        self.send_call(method, params, None).await
    }

    async fn session_command(&mut self, method: &str, params: Value) -> Result<Value, E2eError> {
        let session_id = self.session_id.clone();
        self.send_call(method, params, Some(session_id.as_str()))
            .await
    }

    async fn send_call(
        &mut self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
    ) -> Result<Value, E2eError> {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let mut payload = json!({
            "id": id,
            "method": method,
            "params": params
        });
        if let Some(session_id) = session_id {
            payload["sessionId"] = Value::String(session_id.to_owned());
        }
        self.socket
            .send(Message::Text(payload.to_string().into()))
            .await
            .context(WebSocketSnafu)?;

        loop {
            let response = read_browser_level_message(&mut self.socket).await?;
            if response.pointer("/id") == Some(&Value::from(id)) {
                return Ok(response);
            }
        }
    }
}

async fn read_browser_level_message(
    socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
) -> Result<Value, E2eError> {
    let message = timeout(Duration::from_secs(2), socket.next())
        .await
        .map_err(|_| timeout_error("browser-level CDP response"))?
        .ok_or_else(|| closed_error("browser-level CDP response"))?
        .context(WebSocketSnafu)?;
    if !message.is_text() {
        return Err(unsupported_websocket_message_error(
            "browser-level CDP response",
        ));
    }

    let source = message.into_text().context(WebSocketSnafu)?.to_string();
    serde_json::from_str(&source).context(JsonSnafu)
}

macro_rules! simple_error {
    ($name:ident, $message:literal) => {
        #[derive(Debug)]
        struct $name;

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str($message)
            }
        }

        impl std::error::Error for $name {}
    };
}

simple_error!(
    MissingTargetId,
    "browser-level CDP response did not include a target id"
);
simple_error!(
    MissingSessionId,
    "browser-level CDP response did not include a session id"
);

fn unsupported_websocket_message_error(operation: impl Into<String>) -> E2eError {
    E2eError::UnsupportedWebSocketMessage {
        operation: operation.into(),
        location: snafu::Location::default(),
    }
}
