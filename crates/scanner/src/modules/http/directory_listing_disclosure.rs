use super::{HttpFinding, HttpModule};
use crate::{modules::Module, Result};
use async_trait::async_trait;
use lazy_regex::regex;
use reqwest::Client;
use tracing::info;

// region:        --- Module info

pub struct DirectoryListingDisclosure {}

impl DirectoryListingDisclosure {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn is_directory_listing(&self, body: String) -> Result<bool> {
        let dir_listing_regex = regex!(r"<title>Index of .*</title>");
        let res = tokio::task::spawn_blocking(move || dir_listing_regex.is_match(&body)).await?;

        Ok(res)
    }
}

impl Module for DirectoryListingDisclosure {
    fn name(&self) -> String {
        "http/directory_listing_disclosure".to_string()
    }
    fn description(&self) -> String {
        "Check for enabled directory listing, which often leak information".to_string()
    }
}

// endregion:     --- Module info

#[async_trait]
impl HttpModule for DirectoryListingDisclosure {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        info!("{:12} - {:?}", "HTTP REQUEST", endpoint);
        let res = http_client.get(endpoint).send().await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        if self.is_directory_listing(body).await? {
            return Ok(Some(HttpFinding::DirectoryListingDisclosure(
                endpoint.to_string(),
            )));
        }

        Ok(None)
    }
}
