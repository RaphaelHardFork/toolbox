mod subdomains;

use self::subdomains::SubdomainModule;
use crate::modules::subdomains::{crtsh::CrtSh, web_archive::WebArchive};
use crate::Result;
use async_trait::async_trait;
use reqwest::Client;

pub fn subdomains_modules() -> Vec<Box<dyn SubdomainModule>> {
    vec![Box::new(CrtSh::new()), Box::new(WebArchive::new())]
}

pub trait Module {
    fn name(&self) -> String;
    fn description(&self) -> String;
}

#[derive(Debug)]
pub enum HttpFinding {}
