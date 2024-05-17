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
use crate::{Error, Result};
use reqwest::{Client, Response};
use tracing::{debug, error, info, instrument};

pub trait Module {
    fn name(&self) -> String;
    fn description(&self) -> String;
}

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

pub fn display_all() {
    let subdomains_modules = subdomains_modules();
    println!("\nSubdomains modules");
    for module in subdomains_modules {
        println!("- {:25}{}", module.name(), module.description());
    }
    let http_modules = http_modules();
    println!("\nHTTP modules");
    for module in http_modules {
        println!("- {:35}{}", module.name(), module.description());
    }
}

// region:        --- HTTP requests

#[instrument(name = "HTTP_request", level = "info", skip_all, fields(url = url))]
pub async fn http_request(http_client: &Client, url: &str) -> Result<Response> {
    info!("Sending request");
    match http_client.get(url).send().await {
        Ok(res) => {
            info!("Receive with status: {}", res.status());
            debug!("Response: {:?}", res);
            Ok(res)
        }
        Err(err) => {
            error!("Reason: {}", err);
            Err(Error::Reqwest(err))
        }
    }
}

// endregion:     --- HTTP requests
