use super::{HttpFinding, HttpModule};
use crate::modules::{http_request, Module};
use crate::Result;
use async_trait::async_trait;
use reqwest::Client;
use tracing::instrument;

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
        "Check if a .env file disclosure".to_string()
    }
}

// endregion:     --- Module info

#[async_trait]
impl HttpModule for DotEnvDisclosure {
    #[instrument(name = "check", level = "info", fields(module = self.name()), skip_all)]
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        let url = format!("{}/.env", &endpoint);
        let res = http_request(&http_client, &url).await?;

        if res.status().is_success() {
            return Ok(Some(HttpFinding::DotEnvDisclosure(url)));
        }

        Ok(None)
    }
}
