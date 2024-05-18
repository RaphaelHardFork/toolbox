use crate::modules::{self, http::HttpModule};
use crate::Result;
use crate::{dns, model::Subdomain, ports};
use futures::{stream, StreamExt};
use reqwest::Client;
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tracing::{debug, error, info, instrument, trace};

// region:        --- Constants

// timeouts
const HTTP_REQUEST_TIMEOUT_MS: u64 = 7500;
pub const RESOLVE_DNS_TIMEOUT_MS: u64 = 4000;
pub const SOCKET_CON_TIMEOUT_MS: u64 = 3000;

// concurrency numbers
const SUBDOMAINS_ENUMERATION_CONCURRENCY: usize = 20;
const RESOLVE_DNS_CONCURRENCY: usize = 100;
const DOMAIN_PORT_CONCURRENCY: usize = 200;
const VULNERABILITIES_CONCURRENCY: usize = 20;

// endregion:     --- Constants

// region:        --- Scan main function

#[tokio::main]
#[instrument(name = "scan", level = "info", skip_all)]
pub async fn scan(target: &str) -> Result<Vec<Subdomain>> {
    trace!("Start scan on {}", target);

    // create http client
    let http_timeout = Duration::from_millis(HTTP_REQUEST_TIMEOUT_MS);
    let http_client = Client::builder().timeout(http_timeout).build()?;
    debug!("HTTP Client created: {:?}", http_client);

    // scan core logic
    let subdomains = scan_subdomains(&http_client, target).await?;
    let mut subdomains = scan_ports(subdomains).await;
    scan_vulnerabilities(&http_client, &mut subdomains).await;

    Ok(subdomains)
}

// endregion:     --- Scan main function

// region:        --- Scan subfunctions

#[instrument(name = "subdomains", level = "info", skip_all)]
async fn scan_subdomains(http_client: &Client, target: &str) -> Result<Vec<Subdomain>> {
    let mut subdomains: Vec<String> = stream::iter(modules::subdomains_modules().into_iter())
        .map(|module| {
            let http_client = &http_client;
            async move {
                match module.enumerate(http_client, target).await {
                    Ok(new_subdomains) => Some(new_subdomains),
                    Err(err) => {
                        error!("subdomains/{}: {}", module.name(), err);
                        None
                    }
                }
            }
        })
        .buffer_unordered(SUBDOMAINS_ENUMERATION_CONCURRENCY)
        .filter_map(|domain| async { domain })
        .collect::<Vec<Vec<String>>>()
        .await
        .into_iter()
        .flatten()
        .collect();

    subdomains.push(target.to_string());

    // dedup and convert to Vec<Subdomain>
    let subdomains: Vec<Subdomain> = HashSet::<String>::from_iter(subdomains.into_iter())
        .into_iter()
        .filter_map(|domain| {
            if domain.contains(target) {
                Some(Subdomain {
                    domain,
                    ip: String::new(),
                    open_ports: Vec::new(),
                })
            } else {
                None
            }
        })
        .collect();

    info!("{} domains to resolve", subdomains.len());

    let subdomains = resolve_subdomains(subdomains).await;
    Ok(subdomains)
}

#[instrument(name = "resolves", level = "info", skip_all)]
async fn resolve_subdomains(subdomains: Vec<Subdomain>) -> Vec<Subdomain> {
    let dns_resolver = dns::new_resolver();
    let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
        .map(|domain| dns::resolves(&dns_resolver, domain))
        .buffer_unordered(RESOLVE_DNS_CONCURRENCY)
        .filter_map(|domain| async move { domain })
        .collect()
        .await;

    info!("{} domains resolved", subdomains.len());
    subdomains
}

#[instrument(name = "ports", level = "info", skip_all)]
async fn scan_ports(subdomains: Vec<Subdomain>) -> Vec<Subdomain> {
    stream::iter(subdomains.into_iter())
        .map(|domain| ports::scan_ports(DOMAIN_PORT_CONCURRENCY, domain))
        .buffer_unordered(1)
        .collect()
        .await
}

#[instrument(name = "vulnerabilities", level = "info", skip_all)]
async fn scan_vulnerabilities(http_client: &Client, subdomains: &mut Vec<Subdomain>) {
    // create a cache for http responses (especially / & /.git/)
    // while keeping the httpModule arch ?

    // this Vec<> could be preallocated to optimise ressources
    let targets: Vec<(Box<dyn HttpModule>, String, usize, usize)> = subdomains
        .iter()
        .enumerate()
        .flat_map(|(i, subdomain)| {
            subdomain
                .open_ports
                .iter()
                .enumerate()
                .flat_map(move |(j, port)| {
                    modules::http_modules().into_iter().map(move |module| {
                        (
                            module,
                            format!("http://{}:{}", subdomain.domain, port.port),
                            i,
                            j,
                        )
                    })
                })
        })
        .collect();
    debug!("{} endpoints", targets.len());

    let subdomains = Arc::new(Mutex::new(subdomains));

    // scan
    stream::iter(targets.into_iter())
        .for_each_concurrent(VULNERABILITIES_CONCURRENCY, |(module, target, i, j)| {
            let http_client = &http_client;
            let subdomains = Arc::clone(&subdomains);
            async move {
                match module.scan(http_client, &target).await {
                    Ok(Some(finding)) => {
                        let mut subdomains = subdomains.lock().await;
                        if let Some(subdomain) = subdomains.get_mut(i) {
                            if let Some(port) = subdomain.open_ports.get_mut(j) {
                                port.findings.push(finding);
                            };
                        };
                    }

                    Ok(None) => debug!("No finding on: {}", target),
                    Err(err) => error!("On module {:?}\nReason: {:?}", module.name(), err),
                }
            }
        })
        .await;
}

// endregion:     --- Scan subfunctions
