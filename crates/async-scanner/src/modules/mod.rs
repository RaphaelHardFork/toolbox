pub mod http;
mod subdomains;

use self::http::HttpModule;
use self::subdomains::SubdomainModule;
use crate::modules::http::cve_2017_9506::Cve2017_9506;
use crate::modules::http::cve_2018_7600::Cve2018_7600;
use crate::modules::http::directory_listing_disclosure::DirectoryListingDisclosure;
use crate::modules::http::dotenv_disclosure::DotEnvDisclosure;
use crate::modules::http::ds_store_disclosure::DsStoreDisclosure;
use crate::modules::http::elasticsearch_unauth_access::ElasticsearchUnauthenticatedAccess;
use crate::modules::http::etcd_unauth_access::EtcdUnauthenticatedAccess;
use crate::modules::http::git_config_disclosure::GitConfigDisclosure;
use crate::modules::http::git_directory_disclosure::GitDirectoryDisclosure;
use crate::modules::http::git_head_disclosure::GitHeadDisclosure;
use crate::modules::http::gitlab_open_registrations::GitlabOpenRegistrations;
use crate::modules::http::kibana_unauth_access::KibanaUnauthenticatedAccess;
use crate::modules::http::prometheus_unauth_access::PrometheusUnauthenticatedAccess;
use crate::modules::http::traefik_unauth_access::TraefikUnauthenticatedAccess;
use crate::modules::subdomains::{crtsh::CrtSh, web_archive::WebArchive};
use crate::Result;
use async_trait::async_trait;
use reqwest::Client;

pub fn subdomains_modules() -> Vec<Box<dyn SubdomainModule>> {
    vec![Box::new(CrtSh::new()), Box::new(WebArchive::new())]
}

pub fn http_modules() -> Vec<Box<dyn HttpModule>> {
    vec![
        Box::new(GitlabOpenRegistrations::new()),
        Box::new(GitHeadDisclosure::new()),
        Box::new(GitDirectoryDisclosure::new()),
        Box::new(GitConfigDisclosure::new()),
        Box::new(DotEnvDisclosure::new()),
        Box::new(DsStoreDisclosure::new()),
        Box::new(DirectoryListingDisclosure::new()),
        Box::new(EtcdUnauthenticatedAccess::new()),
        Box::new(ElasticsearchUnauthenticatedAccess::new()),
        Box::new(KibanaUnauthenticatedAccess::new()),
        Box::new(PrometheusUnauthenticatedAccess::new()),
        Box::new(TraefikUnauthenticatedAccess::new()),
        Box::new(Cve2017_9506::new()),
        Box::new(Cve2018_7600::new()),
    ]
}

pub trait Module {
    fn name(&self) -> String;
    fn description(&self) -> String;
}
