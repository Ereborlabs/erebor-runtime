use std::time::Duration;

use erebor_runtime_e2e::E2eError;
use serde_json::Value;

use crate::common::external_error;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct GovernedDiscoveryClient {
    base_url: String,
    client: reqwest::Client,
}

impl GovernedDiscoveryClient {
    pub fn from_endpoint(endpoint: &str) -> Result<Self, E2eError> {
        let port = endpoint
            .strip_prefix("ws://127.0.0.1:")
            .and_then(|suffix| suffix.trim_end_matches('/').parse::<u16>().ok())
            .ok_or_else(|| {
                external_error(
                    "governed endpoint parsing",
                    std::io::Error::other(format!("unexpected endpoint `{endpoint}`")),
                )
            })?;

        let client = reqwest::Client::builder()
            .timeout(DISCOVERY_TIMEOUT)
            .build()
            .map_err(|error| external_error("governed discovery client", error))?;

        Ok(Self {
            base_url: format!("http://127.0.0.1:{port}"),
            client,
        })
    }

    pub async fn version(&self) -> Result<Value, E2eError> {
        self.http_get_json("/json/version").await
    }

    pub async fn targets(&self) -> Result<Value, E2eError> {
        self.http_get_json("/json/list").await
    }

    async fn http_get_json(&self, path: &str) -> Result<Value, E2eError> {
        let response = self
            .client
            .get(format!("{}{path}", self.base_url))
            .send()
            .await
            .map_err(|error| external_error("governed discovery request", error))?;
        if !response.status().is_success() {
            return Err(external_error(
                "governed discovery status",
                std::io::Error::other(response.status().to_string()),
            ));
        }
        response
            .json()
            .await
            .map_err(|error| external_error("governed discovery response", error))
    }
}
