pub mod cve_2017_9506;
pub mod cve_2018_7600;
pub mod directory_listing_disclosure;
pub mod dotenv_disclosure;
pub mod ds_store_disclosure;
pub mod elasticsearch_unauth_access;
pub mod etcd_unauth_access;
pub mod git_config_disclosure;
pub mod git_directory_disclosure;
pub mod git_head_disclosure;
pub mod gitlab_open_registrations;
pub mod kibana_unauth_access;
pub mod prometheus_unauth_access;
pub mod traefik_unauth_access;

use super::Module;
use crate::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum HttpFinding {
    // -- Git related
    GitlabOpenRegistrations(String),
    GitHeadDisclosure(String),
    GitDirectoryDisclosure(String),
    GitConfigDisclosure(String),

    // -- Sensible files
    DotEnvDisclosure(String),
    DsStoreDisclosure(String),
    DirectoryListingDisclosure(String),

    // -- Database access
    EtcdUnauthenticatedAccess(String),
    ElasticsearchUnauthenticatedAccess(String),

    // -- Admin dashboard access
    KibanaUnauthenticatedAccess(String),
    PrometheusUnauthenticatedAccess(String),
    TraefikUnauthenticatedAccess(String),

    // -- CVE
    Cve2017_9506(String),
    Cve2018_7600(String),
}

#[async_trait]
pub trait HttpModule: Module {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>>;
}
