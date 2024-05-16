pub mod crtsh;
pub mod web_archive;

use super::Module;
use crate::Result;
use async_trait::async_trait;
use reqwest::Client;

#[async_trait]
pub trait SubdomainModule: Module {
    async fn enumerate(&self, http_client: &Client, domain: &str) -> Result<Vec<String>>;
}
