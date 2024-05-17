use crate::{
    dns,
    model::{ensure_dir, export_to_json, export_to_markdown, Port, Subdomain},
    modules::{self, http::HttpModule},
    ports, Result,
};
use futures::{stream, StreamExt};
use hickory_resolver::proto::rr::domain;
use reqwest::Client;
use std::{
    collections::HashSet,
    path::Path,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tracing::{debug, error, info, info_span, instrument, span, trace, Instrument};

// timeouts
const HTTP_REQUEST_TIMEOUT_MS: u64 = 7500;

// concurrency numbers
const SUBDOMAINS_CONCURRENCY: usize = 20;

#[tokio::main]
#[instrument(name = "scan", level = "info", skip_all)]
pub async fn scan(target: &str) -> Result<()> {
    trace!("Start scan on {}", target);

    // create output file informations
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let filename = format!("{}", timestamp);
    info!("Scanning {} (run-{})", target, timestamp);

    // create http client
    let http_timeout = Duration::from_millis(HTTP_REQUEST_TIMEOUT_MS);
    let http_client = Client::builder().timeout(http_timeout).build()?;
    debug!("HTTP Client created: {:?}", http_client);

    // scan core logic
    let subdomains = enumerate_subdomains(&http_client, target).await?;
    let subdomains = resolve_subdomains(subdomains).await;
    let mut subdomains = scan_ports(subdomains).await;
    scan_vulnerabilities(&http_client, &mut subdomains).await;

    // export results to files
    let output_dir = format!("output/scanner/{}", target);
    ensure_dir(output_dir.as_ref())?;
    let json_path = Path::new(&output_dir)
        .join(&filename)
        .with_extension("json");
    let md_path = Path::new(&output_dir).join(filename).with_extension("md");
    export_to_json(&subdomains, &json_path)?;
    export_to_markdown(&subdomains, &target, &md_path)?;

    Ok(())
}

#[instrument(name = "subdomains", level = "info", skip_all)]
async fn enumerate_subdomains(http_client: &Client, target: &str) -> Result<Vec<Subdomain>> {
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
                    ip: String::new(),
                    open_ports: Vec::new(),
                })
            } else {
                None
            }
        })
        .collect();

    info!("{} domains to resolve", subdomains.len());
    Ok(subdomains)
}

#[instrument(name = "resolve_subdomains", level = "info", skip_all)]
async fn resolve_subdomains(subdomains: Vec<Subdomain>) -> Vec<Subdomain> {
    let dns_resolver = dns::new_resolver();
    let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
        .map(|domain| dns::resolves(&dns_resolver, domain))
        .buffer_unordered(100)
        .filter_map(|domain| async move { domain })
        .collect()
        .await;

    info!("{} domains resolved", subdomains.len());
    subdomains
}

#[instrument(name = "ports", level = "info", skip_all)]
async fn scan_ports(subdomains: Vec<Subdomain>) -> Vec<Subdomain> {
    stream::iter(subdomains.into_iter())
        .map(|domain| ports::scan_ports(200, domain))
        .buffer_unordered(1)
        .collect()
        .await
}

#[instrument(name = "scan_vulnerabilities", level = "info", skip_all)]
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

    let subdomains = Arc::new(Mutex::new(subdomains));

    // scan
    stream::iter(targets.into_iter())
        .for_each_concurrent(20, |(module, target, i, j)| {
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
                        // println!("{:?}", &finding)
                    }
                    Ok(None) => {
                        let mut subdomains = subdomains.lock().await;
                        if let Some(subdomain) = subdomains.get_mut(i) {
                            if let Some(port) = subdomain.open_ports.get_mut(j) {
                                port.findings
                                    .push(modules::http::HttpFinding::DotEnvDisclosure(target));
                            };
                        };
                    }
                    Err(err) => error!(
                        "{:12} - with module \"{}\"\nReason: {:?}",
                        "DETECTION",
                        module.name(),
                        err
                    ),
                }
            }
        })
        .await;
}
