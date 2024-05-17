use super::SubdomainModule;
use crate::{
    modules::{http_request, Module},
    Error, Result,
};
use async_trait::async_trait;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{debug, error, instrument, trace};

// region:        --- Module info

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

// endregion:     --- Module info

#[derive(Debug, Serialize, Deserialize)]
struct WebArchiveResponse(Vec<Vec<String>>);

#[async_trait]
impl SubdomainModule for WebArchive {
    #[instrument(name = "enumerate", level = "debug", fields(module = %self.name()), skip_all)]
    async fn enumerate(&self, http_client: &Client, domain: &str) -> Result<Vec<String>> {
        let url = format!("https://web.archive.org/cdx/search/cdx?url={}&output=json&matchType=domain&fl=original&collapse=urlkey", domain);
        let res = http_request(&http_client, &url).await?;

        if !res.status().is_success() {
            return Err(Error::InvalidHttpResponse(self.name()));
        }

        let web_archive_urls: Vec<String> = match res.json::<WebArchiveResponse>().await {
            Ok(info) => info.0.into_iter().flatten().collect(),
            Err(_) => return Err(Error::InvalidHttpResponse(self.name())),
        };

        let subdomains: HashSet<String> = web_archive_urls
            .into_iter()
            .filter_map(|url| {
                if url == "original" {
                    return None;
                }
                match Url::parse(&url) {
                    Ok(parsed_url) => parsed_url.host_str().map(|host| host.to_string()),
                    Err(_) => {
                        error!("Parsing url: {:?}", url);
                        None
                    }
                }
            })
            .inspect(|url| trace!("Collecting: {:?}", url))
            .collect();

        debug!("{} collected", subdomains.len());
        Ok(subdomains.into_iter().collect())
    }
}
