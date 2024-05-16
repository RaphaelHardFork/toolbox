use super::{HttpFinding, HttpModule};
use crate::{modules::Module, Result};
use async_trait::async_trait;
use reqwest::Client;
use tracing::info;

// region:        --- Module info

pub struct TraefikUnauthenticatedAccess {}

impl TraefikUnauthenticatedAccess {
    pub fn new() -> Self {
        Self {}
    }
}

impl Module for TraefikUnauthenticatedAccess {
    fn name(&self) -> String {
        "http/traefik_unauth_access".to_string()
    }
    fn description(&self) -> String {
        "Check Traefik unauthenticated access".to_string()
    }
}

// endregion:     --- Module info

#[async_trait]
impl HttpModule for TraefikUnauthenticatedAccess {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        info!("{:12} - {:?}", "HTTP REQUEST", endpoint);
        let res = http_client.get(endpoint).send().await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        if (body.contains(r#"ng-app="traefik""#)
            && body.contains(r#"href="https://docs.traefik.io""#)
            && body.contains(r#"href="https://traefik.io""#))
            || body
                .contains(r#"fixed-top"><head><meta charset="utf-8"><title>Traefik</title><base"#)
        {
            return Ok(Some(HttpFinding::TraefikUnauthenticatedAccess(
                endpoint.to_string(),
            )));
        }

        Ok(None)
    }
}
