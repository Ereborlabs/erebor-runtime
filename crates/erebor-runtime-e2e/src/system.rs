use std::future::Future;

use erebor_runtime_telemetry::{debug, warn};
use tokio::task::JoinHandle;

use crate::{websocket::JsonWebSocketHandler, E2eError, MiniJsonWebSocketServer};

#[derive(Default)]
pub struct MiniSystem {
    tasks: Vec<MiniTask>,
}

impl MiniSystem {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn spawn<F>(&mut self, name: impl Into<String>, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let name = name.into();
        debug!("spawning e2e mini-system task", task = %name);
        self.tasks.push(MiniTask {
            name,
            handle: tokio::spawn(future),
        });
    }

    pub async fn json_websocket_server(
        &mut self,
        handler: JsonWebSocketHandler,
    ) -> Result<MiniJsonWebSocketServer, E2eError> {
        MiniJsonWebSocketServer::spawn(self, handler).await
    }
}

struct MiniTask {
    name: String,
    handle: JoinHandle<()>,
}

impl Drop for MiniTask {
    fn drop(&mut self) {
        if !self.handle.is_finished() {
            debug!("aborting e2e mini-system task", task = %self.name);
            self.handle.abort();
        } else {
            warn!("e2e mini-system task already finished", task = %self.name);
        }
    }
}
