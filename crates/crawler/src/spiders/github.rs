use super::Spider;
use crate::{Error, Result};
use async_trait::async_trait;
use lazy_regex::regex;
use reqwest::{header, Client};
use serde::Deserialize;
use std::time::Duration;
use tracing::{debug, error, info, instrument, trace, warn};

#[derive(Debug, Deserialize)]
pub struct GitHubItem {
    login: String,
    id: u64,
    node_id: String,
    html_url: String,
    avatar_url: String,
}

pub struct GitHubSpider {
    http_client: Client,
    expected_results: usize,
}

impl GitHubSpider {
    pub fn new() -> Self {
        let http_timeout = Duration::from_millis(6000);
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "Accept",
            header::HeaderValue::from_static("application/vnd.github.v3+json"),
        );
        let http_client = Client::builder()
            .timeout(http_timeout)
            .default_headers(headers)
            .user_agent(
                "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
            )
            .build()
            .expect("spider/github: Building HTTP client");

        Self {
            http_client,
            expected_results: 100,
        }
    }

    #[instrument(name = "http_req", level = "info", skip_all)]
    async fn http_request(&self, url: &str) -> Result<Vec<GitHubItem>> {
        info!("Sending request");
        match self.http_client.get(url).send().await {
            Ok(res) => {
                info!("Receive with status: {}", res.status());
                debug!("Response: {:?}", res);
                let json: Vec<GitHubItem> = res.json().await?;
                trace!("JSON response: {:?}", json);
                Ok(json)
            }
            Err(err) => {
                error!("Reason: {}", err);
                Err(Error::Reqwest(err))
            }
        }
    }
}

#[async_trait]
impl Spider for GitHubSpider {
    type Item = GitHubItem;

    fn name(&self) -> String {
        "github".to_string()
    }

    fn start_urls(&self) -> Vec<String> {
        vec!["https://api.github.com/orgs/google/public_members?per_page=100&page=1".to_string()]
    }

    #[instrument(name = "scraping", level = "info", fields(url = url), skip_all)]
    async fn scrape(&self, url: String) -> Result<(Vec<Self::Item>, Vec<String>)> {
        let items = self.http_request(&url).await?;

        let next_pages_links = if items.len() == self.expected_results {
            let next_page_regex = regex!(".*page=([0-9]*).*");
            if let Some(old_page_number) = next_page_regex.captures(&url).unwrap().get(1) {
                let old_page_number = old_page_number.as_str().to_string();
                let mut new_page_number: usize = old_page_number.parse()?;
                new_page_number += 1;

                let next_url = url.replace(
                    format!("&page={}", old_page_number).as_str(),
                    format!("&page={}", new_page_number).as_str(),
                );
                info!("next url: {:?}", next_url);
                vec![next_url]
            } else {
                warn!("failed to capture next page on: {:?}", url);
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok((items, next_pages_links))
    }

    #[instrument(name = "processing", level = "info", skip_all)]
    async fn process(&self, item: Self::Item) -> Result<()> {
        info!("{}, {}, {}", item.login, item.html_url, item.avatar_url);

        Ok(())
    }
}
