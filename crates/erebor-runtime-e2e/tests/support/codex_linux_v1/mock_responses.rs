use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::Path,
    thread,
    time::Duration,
};

use serde_json::json;

pub(crate) struct CodexMockResponsesServer {
    uri: String,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl CodexMockResponsesServer {
    #[allow(dead_code)]
    pub(crate) fn start() -> std::io::Result<Self> {
        Self::start_with_tool_command("printf phase-0-tool")
    }

    pub(crate) fn start_with_tool_command(
        tool_command: impl Into<String>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_shutdown = std::sync::Arc::clone(&shutdown);
        let response_number = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let worker_response_number = std::sync::Arc::clone(&response_number);
        let tool_command = std::sync::Arc::new(tool_command.into());
        let worker_tool_command = std::sync::Arc::clone(&tool_command);
        let worker = thread::spawn(move || {
            while !worker_shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let number = worker_response_number
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let _result = respond_to_mock_responses_request(
                            stream,
                            number,
                            worker_tool_command.as_str(),
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            uri: format!("http://{address}"),
            shutdown,
            worker: Some(worker),
        })
    }

    pub(crate) fn uri(&self) -> &str {
        &self.uri
    }
}

impl Drop for CodexMockResponsesServer {
    fn drop(&mut self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let _result = TcpStream::connect(self.uri.trim_start_matches("http://"));
        if let Some(worker) = self.worker.take() {
            let _result = worker.join();
        }
    }
}

#[allow(dead_code)]
pub(crate) fn write_codex_mock_responses_config(
    codex_home: &Path,
    server_uri: &str,
) -> std::io::Result<()> {
    write_codex_mock_responses_config_with_sandbox(codex_home, server_uri, "read-only")
}

pub(crate) fn write_codex_mock_responses_config_with_sandbox(
    codex_home: &Path,
    server_uri: &str,
    sandbox_mode: &str,
) -> std::io::Result<()> {
    std::fs::write(
        codex_home.join("config.toml"),
        format!(
            r#"model = "erebor-phase-0-local-mock"
model_provider = "erebor-phase-0"
approval_policy = "never"
sandbox_mode = "{sandbox_mode}"

[features]
plugins = false

[model_providers.erebor-phase-0]
name = "Erebor Phase 0 local mock"
base_url = "{server_uri}/v1"
wire_api = "responses"
request_max_retries = 0
stream_max_retries = 0
supports_websockets = false
requires_openai_auth = false
"#
        ),
    )
}

fn respond_to_mock_responses_request(
    mut stream: TcpStream,
    response_number: usize,
    tool_command: &str,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::new();
    let mut buffer = [0; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > 64 * 1024 {
            return Err(std::io::Error::other(
                "mock Responses request headers exceeded 64 KiB",
            ));
        }
    }
    let response_body = mock_responses_body(response_number, tool_command);
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
        response_body.len()
    )?;
    stream.shutdown(Shutdown::Both)
}

fn mock_responses_body(response_number: usize, tool_command: &str) -> String {
    match response_number {
        0 => format!(
            "event: response.created\ndata: {}\n\nevent: response.output_item.done\ndata: {}\n\nevent: response.completed\ndata: {}\n\n",
            json!({"type":"response.created","response":{"id":"erebor-phase-0-tool"}}),
            json!({
                "type":"response.output_item.done",
                "item":{
                    "type":"function_call",
                    "call_id":"erebor-phase-0-call",
                    "name":"shell_command",
                    "arguments":json!({"command": tool_command}).to_string(),
                }
            }),
            json!({"type":"response.completed","response":{"id":"erebor-phase-0-tool","usage":{"input_tokens":0,"input_tokens_details":null,"output_tokens":0,"output_tokens_details":null,"total_tokens":0}}}),
        ),
        _ => format!(
            "event: response.created\ndata: {}\n\nevent: response.output_item.done\ndata: {}\n\nevent: response.completed\ndata: {}\n\n",
            json!({"type":"response.created","response":{"id":"erebor-phase-0-final"}}),
            json!({"type":"response.output_item.done","item":{"type":"message","role":"assistant","id":"erebor-phase-0-message","content":[{"type":"output_text","text":"phase zero complete"}]}}),
            json!({"type":"response.completed","response":{"id":"erebor-phase-0-final","usage":{"input_tokens":0,"input_tokens_details":null,"output_tokens":0,"output_tokens_details":null,"total_tokens":0}}}),
        ),
    }
}
