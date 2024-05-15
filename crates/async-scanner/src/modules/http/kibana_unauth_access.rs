use super::{HttpFinding, HttpModule};
use crate::{modules::Module, Result};
use async_trait::async_trait;
use reqwest::Client;
use tracing::info;

// region:        --- Module info

pub struct KibanaUnauthenticatedAccess {}

impl KibanaUnauthenticatedAccess {
    pub fn new() -> Self {
        Self {}
    }
}

impl Module for KibanaUnauthenticatedAccess {
    fn name(&self) -> String {
        "http/kibana_unauth_access".to_string()
    }
    fn description(&self) -> String {
        "Check Kibana unauthenticated access".to_string()
    }
}

// endregion:     --- Module info

#[async_trait]
impl HttpModule for KibanaUnauthenticatedAccess {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        info!("{:12} - {:?}", "HTTP REQUEST", endpoint);
        let res = http_client.get(endpoint).send().await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        if body.contains(r#"</head><body kbn-chrome id="kibana-body"><kbn-initial-state"#) 
        || body.contains(r#"<div class="ui-app-loading"><h1><strong>Kibana</strong><small>&nbsp;is loading."#)
        || Some(0) == body.find(r#"|| body.contains("#)
        || body.contains(r#"<div class="kibanaWelcomeLogo"></div></div></div><div class="kibanaWelcomeText">Loading Kibana</div></div>"#) {
          return Ok(Some(HttpFinding::KibanaUnauthenticatedAccess(endpoint.to_string())))
        }

        Ok(None)
    }
}
