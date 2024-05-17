use super::{HttpFinding, HttpModule};
use crate::{
    modules::{http_request, Module},
    Result,
};
use async_trait::async_trait;
use reqwest::Client;
use tracing::{info, instrument};

// region:        --- Module info

pub struct GitlabOpenRegistrations {}

impl GitlabOpenRegistrations {
    pub fn new() -> Self {
        Self {}
    }
}

impl Module for GitlabOpenRegistrations {
    fn name(&self) -> String {
        "http/gitlab_open_registration".to_string()
    }
    fn description(&self) -> String {
        "Check if the Gitlab instance is open to registrations".to_string()
    }
}

// endregion:     --- Module info

#[async_trait]
impl HttpModule for GitlabOpenRegistrations {
    #[instrument(name = "check", level = "info", fields(module = self.name()), skip_all)]
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        let res = http_request(&http_client, endpoint).await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        if body.contains("This is a self-managed instance of GitLab") && body.contains("Register") {
            return Ok(Some(HttpFinding::GitlabOpenRegistrations(
                endpoint.to_string(),
            )));
        }

        Ok(None)
    }
}
