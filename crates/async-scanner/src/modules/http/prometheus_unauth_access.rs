use super::{HttpFinding, HttpModule};
use crate::{modules::Module, Result};
use async_trait::async_trait;
use reqwest::Client;
use tracing::info;

// region:        --- Module info

pub struct PrometheusUnauthenticatedAccess {}

impl PrometheusUnauthenticatedAccess {
    pub fn new() -> Self {
        Self {}
    }
}

impl Module for PrometheusUnauthenticatedAccess {
    fn name(&self) -> String {
        "http/prometheus_unauth_access".to_string()
    }
    fn description(&self) -> String {
        "Check Prometheus unauthenticated access".to_string()
    }
}

// endregion:     --- Module info

#[async_trait]
impl HttpModule for PrometheusUnauthenticatedAccess {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        info!("{:12} - {:?}", "HTTP REQUEST", endpoint);
        let res = http_client.get(endpoint).send().await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        if body
            .contains(r#"<title>Prometheus Time Series Collection and Processing Server</title>"#)
        {
            return Ok(Some(HttpFinding::PrometheusUnauthenticatedAccess(
                endpoint.to_string(),
            )));
        }

        Ok(None)
    }
}
