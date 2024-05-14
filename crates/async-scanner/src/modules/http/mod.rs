pub mod directory_listing_disclosure;
pub mod gitlab_open_registrations;

use super::Module;
use crate::Result;
use async_trait::async_trait;
use reqwest::Client;

#[derive(Debug)]
pub enum HttpFinding {
    GitlabOpenRegistrations(String),
}

#[async_trait]
pub trait HttpModule: Module {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>>;
}
