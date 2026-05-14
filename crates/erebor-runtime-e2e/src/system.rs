use std::future::Future;

use tokio::task::JoinHandle;
use tracing::{debug, warn};

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
        debug!(task = %name, "spawning e2e mini-system task");
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
            debug!(task = %self.name, "aborting e2e mini-system task");
            self.handle.abort();
        } else {
            warn!(task = %self.name, "e2e mini-system task already finished");
        }
    }
}
