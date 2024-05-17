use super::{HttpFinding, HttpModule};
use crate::{
    modules::{http_request, Module},
    Result,
};
use async_trait::async_trait;
use reqwest::Client;
use tracing::{info, instrument};

// region:        --- Module info

pub struct EtcdUnauthenticatedAccess {}

impl EtcdUnauthenticatedAccess {
    pub fn new() -> Self {
        Self {}
    }
}

impl Module for EtcdUnauthenticatedAccess {
    fn name(&self) -> String {
        "http/etcd_unauth_access".to_string()
    }
    fn description(&self) -> String {
        "Check for CoreOS etcd unauthenticated access".to_string()
    }
}

// endregion:     --- Module info

#[async_trait]
impl HttpModule for EtcdUnauthenticatedAccess {
    #[instrument(name = "check", level = "info", fields(module = self.name()), skip_all)]
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        let url = format!("{}/version", &endpoint);
        let res = http_request(&http_client, &url).await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        if body.contains(r#""etcdserver""#)
            && body.contains(r#""etcdcluster""#)
            && body.chars().count() < 200
        {
            return Ok(Some(HttpFinding::EtcdUnauthenticatedAccess(url)));
        }

        Ok(None)
    }
}
