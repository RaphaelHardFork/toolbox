use super::{HttpFinding, HttpModule};
use crate::modules::{http_request, Module};
use crate::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::instrument;

// region:        --- Module info

pub struct ElasticsearchUnauthenticatedAccess {}

impl ElasticsearchUnauthenticatedAccess {
    pub fn new() -> Self {
        Self {}
    }
}

impl Module for ElasticsearchUnauthenticatedAccess {
    fn name(&self) -> String {
        "http/elasticsearch_unauth_access".to_string()
    }
    fn description(&self) -> String {
        "Check for elasticsearch unauthenticated access".to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ElasticsearchInfo {
    pub name: String,
    pub cluster_name: String,
    pub tagline: String,
}

// endregion:     --- Module info

#[async_trait]
impl HttpModule for ElasticsearchUnauthenticatedAccess {
    #[instrument(name = "check", level = "info", fields(module = self.name()), skip_all)]
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        let res = http_request(&http_client, endpoint).await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let info: ElasticsearchInfo = match res.json().await {
            Ok(info) => info,
            Err(_) => return Ok(None),
        };

        if info.tagline.to_lowercase().contains("you know, for search") {
            return Ok(Some(HttpFinding::ElasticsearchUnauthenticatedAccess(
                endpoint.to_string(),
            )));
        }

        Ok(None)
    }
}
