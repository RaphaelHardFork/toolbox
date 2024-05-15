pub mod directory_listing_disclosure;
pub mod dotenv_disclosure;
pub mod ds_store_disclosure;
pub mod etcd_unauth_access;
pub mod git_head_disclosure;
pub mod gitlab_open_registrations;
pub mod kibana_unauth_access;
pub mod prometheus_unauth_access;
pub mod traefik_unauth_access;

use super::Module;
use crate::Result;
use async_trait::async_trait;
use reqwest::Client;

#[derive(Debug)]
pub enum HttpFinding {
    // -- Git related
    GitlabOpenRegistrations(String),
    GitHeadDisclosure(String),
    // -- Sensible files
    DotEnvDisclosure(String),
    DsStoreDisclosure(String),
    DirectoryListingDisclosure(String),
    // -- Database access
    EtcdUnauthenticatedAccess(String),
    // -- Admin dashboard access
    KibanaUnauthenticatedAccess(String),
    PrometheusUnauthenticatedAccess(String),
    TraefikUnauthenticatedAccess(String),
}

#[async_trait]
pub trait HttpModule: Module {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>>;
}
