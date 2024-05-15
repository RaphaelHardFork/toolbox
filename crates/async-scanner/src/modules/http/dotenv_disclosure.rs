use super::{HttpFinding, HttpModule};
use crate::{modules::Module, Result};
use async_trait::async_trait;
use reqwest::Client;
use tracing::info;

// region:        --- Module info

pub struct DotEnvDisclosure {}

impl DotEnvDisclosure {
    pub fn new() -> Self {
        Self {}
    }
}

impl Module for DotEnvDisclosure {
    fn name(&self) -> String {
        "http/dotenv_disclosure".to_string()
    }
    fn description(&self) -> String {
        "Check if a .env file is available".to_string()
    }
}

// endregion:     --- Module info

#[async_trait]
impl HttpModule for DotEnvDisclosure {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        let url = format!("{}/.env", &endpoint);
        info!("{:12} - {:?}", "HTTP REQUEST", &url);
        let res = http_client.get(&url).send().await?;

        if res.status().is_success() {
            return Ok(Some(HttpFinding::DotEnvDisclosure(url)));
        }

        Ok(None)
    }
}
