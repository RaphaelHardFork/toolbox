use super::{HttpFinding, HttpModule};
use crate::{modules::Module, Result};
use async_trait::async_trait;
use reqwest::Client;
use tracing::info;

// region:        --- Module info

pub struct GitHeadDisclosure {}

impl GitHeadDisclosure {
    pub fn new() -> Self {
        Self {}
    }

    pub fn is_head_file(&self, content: &str) -> bool {
        Some(0) == content.to_lowercase().trim().find("ref:")
    }
}

impl Module for GitHeadDisclosure {
    fn name(&self) -> String {
        "http/git_head_disclosure".to_string()
    }
    fn description(&self) -> String {
        "Check if a .git/HEAD file disclosure".to_string()
    }
}

// endregion:     --- Module info

#[async_trait]
impl HttpModule for GitHeadDisclosure {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        let url = format!("{}/.git/HEAD", &endpoint);
        info!("{:12} - {:?}", "HTTP REQUEST", &url);
        let res = http_client.get(&url).send().await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        if self.is_head_file(&body) {
            return Ok(Some(HttpFinding::GitHeadDisclosure(url)));
        }

        Ok(None)
    }
}
