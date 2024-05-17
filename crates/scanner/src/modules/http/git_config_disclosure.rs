use super::{HttpFinding, HttpModule};
use crate::{
    modules::{http_request, Module},
    Result,
};
use async_trait::async_trait;
use lazy_regex::regex;
use reqwest::Client;
use tracing::{info, instrument};

// region:        --- Module info

pub struct GitConfigDisclosure {}

impl GitConfigDisclosure {
    pub fn new() -> Self {
        Self {}
    }

    async fn is_git_config_file(&self, content: String) -> Result<bool> {
        let git_config_regex = regex!(r#"\[branch "[^"]*"\]"#);
        let res = tokio::task::spawn_blocking(move || git_config_regex.is_match(&content)).await?;

        Ok(res)
    }
}

impl Module for GitConfigDisclosure {
    fn name(&self) -> String {
        "http/git_config_disclosure".to_string()
    }
    fn description(&self) -> String {
        "Check if a .git/config file disclosure".to_string()
    }
}

// endregion:     --- Module info

#[async_trait]
impl HttpModule for GitConfigDisclosure {
    #[instrument(name = "check", level = "info", fields(module = self.name()), skip_all)]
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        let url = format!("{}/.git/config", &endpoint);
        let res = http_request(&http_client, &url).await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        if self.is_git_config_file(body).await? {
            return Ok(Some(HttpFinding::GitConfigDisclosure(url)));
        }

        Ok(None)
    }
}
