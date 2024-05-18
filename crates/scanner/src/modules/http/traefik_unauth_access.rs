use super::{HttpFinding, HttpModule};
use crate::modules::{http_request, Module};
use crate::Result;
use async_trait::async_trait;
use reqwest::Client;
use tracing::instrument;

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
    #[instrument(name = "check", level = "info", fields(module = self.name()), skip_all)]
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>> {
        let res = http_request(&http_client, endpoint).await?;

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
