mod http;
mod subdomains;

use self::http::HttpModule;
use self::subdomains::SubdomainModule;
use crate::modules::http::gitlab_open_registrations::GitlabOpenRegistrations;
use crate::modules::subdomains::{crtsh::CrtSh, web_archive::WebArchive};
use crate::Result;
use async_trait::async_trait;
use reqwest::Client;

pub fn subdomains_modules() -> Vec<Box<dyn SubdomainModule>> {
    vec![Box::new(CrtSh::new()), Box::new(WebArchive::new())]
}

pub fn http_modules() -> Vec<Box<dyn HttpModule>> {
    vec![Box::new(GitlabOpenRegistrations::new())]
}

pub trait Module {
    fn name(&self) -> String;
    fn description(&self) -> String;
}
