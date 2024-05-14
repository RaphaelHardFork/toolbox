use super::SubdomainModule;
use crate::{modules::Module, Error, Result};
use async_trait::async_trait;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{error, info};

pub struct WebArchive {}

impl WebArchive {
    pub fn new() -> Self {
        Self {}
    }
}

impl Module for WebArchive {
    fn name(&self) -> String {
        "subdomains/webarchive".to_string()
    }
    fn description(&self) -> String {
        "Use web.archive.org to find subdomains".to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct WebArchiveResponse(Vec<Vec<String>>);

#[async_trait]
impl SubdomainModule for WebArchive {
    async fn enumerate(&self, http_client: &Client, domain: &str) -> Result<Vec<String>> {
        let url = format!("https://web.archive.org/cdx/search/cdx?matchType=domain&fl=original&output=json&collapse=urlkey&url={}", domain);
        info!("{:12} - {:?}", "HTTP REQUEST", url);
        let res = http_client.get(url).send().await?;

        if !res.status().is_success() {
            return Err(Error::InvalidHttpResponse(self.name()));
        }

        let web_archive_urls: WebArchiveResponse = match res.json().await {
            Ok(info) => info,
            Err(_) => return Err(Error::InvalidHttpResponse(self.name())),
        };

        let subdomains: HashSet<String> = web_archive_urls
            .0
            .into_iter()
            .flatten()
            .filter_map(|url| {
                Url::parse(&url)
                    .map_err(|err| {
                        error!("{}: error parsing url: {}", self.name(), err);
                        err
                    })
                    .ok()
            })
            .filter_map(|url| url.host_str().map(|host| host.to_string()))
            .collect();

        Ok(subdomains.into_iter().collect())
    }
}
