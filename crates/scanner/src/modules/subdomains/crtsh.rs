use super::SubdomainModule;
use crate::modules::http_request;
use crate::Result;
use crate::{modules::Module, Error};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{debug, instrument, trace};

// region:        --- Module info

pub struct CrtSh {}

impl CrtSh {
    pub fn new() -> Self {
        Self {}
    }
}

impl Module for CrtSh {
    fn name(&self) -> String {
        "subdomains/crtsh".to_string()
    }

    fn description(&self) -> String {
        "Use crt.sh/ to find subdomains".to_string()
    }
}

// endregion:     --- Module info

#[derive(Debug, Serialize, Deserialize)]
pub struct CrtShEntry {
    pub name_value: String,
}

#[async_trait]
impl SubdomainModule for CrtSh {
    #[instrument(name = "enumerate", level = "debug", fields(module = %self.name()), skip_all)]
    async fn enumerate(&self, http_client: &Client, domain: &str) -> Result<Vec<String>> {
        let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
        let res = http_request(&http_client, &url).await?;

        if !res.status().is_success() {
            return Err(Error::InvalidHttpResponse(self.name()));
        }

        let crtsh_entries: Vec<CrtShEntry> = match res.json().await {
            Ok(info) => info,
            Err(_) => return Err(Error::InvalidHttpResponse(self.name())),
        };

        // cleaning entries
        let mut subdomains: HashSet<String> = crtsh_entries
            .into_iter()
            .flat_map(|entry| {
                entry
                    .name_value
                    .split('\n')
                    .map(|subdomain| subdomain.trim().to_string())
                    .collect::<Vec<String>>()
            })
            .filter(|subdomain| subdomain != domain)
            .filter(|subdomain| !subdomain.contains('*'))
            .inspect(|subdomain| trace!("Collecting: {:?}", subdomain))
            .collect();

        subdomains.insert(domain.to_string());

        debug!("{} collected", subdomains.len());
        Ok(subdomains.into_iter().collect())
    }
}
