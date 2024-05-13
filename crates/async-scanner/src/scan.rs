use crate::{dns, model::Subdomain, modules, ports, Result};
use futures::{stream, StreamExt};
use reqwest::Client;
use std::{collections::HashSet, time::Duration};
use tracing::{error, info};

// timeouts
const HTTP_REQUEST_TIMEOUT_MS: u64 = 10000;

// concurrency numbers
const SUBDOMAINS_CONCURRENCY: usize = 20;

#[tokio::main]
pub async fn scan(target: &str) -> Result<()> {
    let http_timeout = Duration::from_millis(HTTP_REQUEST_TIMEOUT_MS);
    let http_client = Client::builder().timeout(http_timeout).build()?;

    // enumerate subdomains
    let mut subdomains: Vec<String> = stream::iter(modules::subdomains_modules().into_iter())
        .map(|module| async move {
            match module.enumerate(target).await {
                Ok(new_subdomains) => Some(new_subdomains),
                Err(err) => {
                    error!("subdomains/{}: {}", module.name(), err);
                    None
                }
            }
        })
        .buffer_unordered(SUBDOMAINS_CONCURRENCY)
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
                    open_ports: Vec::new(),
                })
            } else {
                None
            }
        })
        .collect();

    info!("Found {} domains", subdomains.len());

    // filter unresolvable domains
    let dns_resolver = dns::new_resolver();
    let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
        .map(|domain| dns::resolves(&dns_resolver, domain))
        .buffer_unordered(100)
        .filter_map(|domain| async move { domain })
        .collect()
        .await;

    // scan ports
    let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
        .map(|domain| ports::scan_ports(200, domain))
        .buffer_unordered(1)
        .collect()
        .await;

    // display result
    for subdomain in &subdomains {
        println!("Open ports in {}", &subdomain.domain);
        for port in &subdomain.open_ports {
            println!("{}", port.port);
        }
    }

    Ok(())
}
