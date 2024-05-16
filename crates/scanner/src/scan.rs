use crate::{
    dns,
    model::{ensure_dir, export_to_json, export_to_markdown, Subdomain},
    modules::{self, http::HttpModule},
    ports, Result,
};
use futures::{stream, StreamExt};
use reqwest::Client;
use std::{
    collections::HashSet,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{error, info};

// timeouts
const HTTP_REQUEST_TIMEOUT_MS: u64 = 7500;

// concurrency numbers
const SUBDOMAINS_CONCURRENCY: usize = 20;

#[tokio::main]
pub async fn scan(target: &str) -> Result<()> {
    // create file
    let output_dir = format!("output/scanner/{}", target);
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let filename = format!("{}", timestamp);

    // create http client
    let http_timeout = Duration::from_millis(HTTP_REQUEST_TIMEOUT_MS);
    let http_client = Client::builder().timeout(http_timeout).build()?;

    // enumerate subdomains
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

    info!("{:12} - {} domains", "TO RESOLVE", subdomains.len());

    // filter unresolvable domains
    let dns_resolver = dns::new_resolver();
    let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
        .map(|domain| dns::resolves(&dns_resolver, domain))
        .buffer_unordered(100)
        .filter_map(|domain| async move { domain })
        .collect()
        .await;

    info!("{:12} - {} domains", "RESOLVED", subdomains.len());

    // scan ports
    let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
        .map(|domain| ports::scan_ports(200, domain))
        .buffer_unordered(1)
        .collect()
        .await;

    // ensure_dir(output_dir.as_ref())?;
    // let json_path = Path::new(&output_dir)
    //     .join(&filename)
    //     .with_extension("json");
    // let md_path = Path::new(&output_dir).join(filename).with_extension("md");
    // export_to_json(&subdomains, &json_path)?;
    // export_to_markdown(&subdomains, &target, &md_path)?;
    // return Ok(());

    // display result => TODO store it into a file
    // for subdomain in &subdomains {
    //     println!("Open ports in {}", &subdomain.domain);
    //     for port in &subdomain.open_ports {
    //         println!("{}", port.port);
    //     }
    // }

    // scan vulnerabilities
    // prepare the scan
    let mut targets: Vec<(Box<dyn HttpModule>, String)> = Vec::new();
    for subdomain in &subdomains {
        for port in &subdomain.open_ports {
            let http_modules = modules::http_modules();
            for http_module in http_modules {
                let target = format!("http://{}:{}", &subdomain.domain, port.port);
                targets.push((http_module, target));
            }
        }
    }

    // scan
    stream::iter(targets.into_iter())
        .for_each_concurrent(20, |(module, target)| {
            let http_client = &http_client;
            async move {
                match module.scan(http_client, &target).await {
                    Ok(Some(finding)) => println!("{:?}", &finding),
                    Ok(None) => println!("No finding"),
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

    ensure_dir(output_dir.as_ref())?;
    let json_path = Path::new(&output_dir)
        .join(&filename)
        .with_extension("json");
    let md_path = Path::new(&output_dir).join(filename).with_extension("md");
    export_to_json(&subdomains, &json_path)?;
    export_to_markdown(&subdomains, &target, &md_path)?;

    Ok(())
}
