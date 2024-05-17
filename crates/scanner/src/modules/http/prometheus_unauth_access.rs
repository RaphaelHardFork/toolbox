use super::{HttpFinding, HttpModule};
use crate::{
    modules::{http_request, Module},
    Result,
};
use async_trait::async_trait;
use reqwest::Client;
use tracing::{info, instrument};

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
    #[instrument(name = "check", level = "info", fields(module = self.name()), skip_all)]
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        let res = http_request(&http_client, endpoint).await?;

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
