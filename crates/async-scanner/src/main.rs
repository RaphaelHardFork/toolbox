use futures::{stream, StreamExt};
use model::Subdomain;
use reqwest::Client;
use std::env;
use std::time::{Duration, Instant};

pub use error::Result;

mod error;
mod model;
mod ports;
mod subdomains;

// timeouts
const HTTP_REQUEST_TIMEOUT_MS: u64 = 10000;
pub const SOCKET_CON_TIMEOUT_MS: u64 = 3000;
pub const RESOLVE_DNS_TIMEOUT_MS: u64 = 4000;

// concurrencies values
const PORTS_CONCURRENCY: usize = 200;
const SUBDOMAINS_CONCURRENCY: usize = 100;

#[tokio::main]
async fn main() -> Result<()> {
    // collect and validate args
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err(error::Error::CliUsage(
            "Usage:\ncargo run <domain>".to_string(),
        ));
    }
    let target = args[1].as_str();

    // create HTTP client
    let http_timeout = Duration::from_millis(HTTP_REQUEST_TIMEOUT_MS);
    let http_client = Client::builder().timeout(http_timeout).build()?;

    let scan_start = Instant::now();

    // enumerate subdomains
    let subdomains = subdomains::enumerate(&http_client, target).await?;

    // scan ports for each subdomains
    let scan_result: Vec<Subdomain> = stream::iter(subdomains.into_iter())
        .map(|subdomain| ports::scan_ports(PORTS_CONCURRENCY, subdomain))
        .buffer_unordered(SUBDOMAINS_CONCURRENCY)
        .collect()
        .await;

    // display result
    for subdomain in scan_result {
        println!("Open ports in {}", &subdomain.domain);
        for port in &subdomain.open_ports {
            println!("{}", port.port);
        }
    }

    let scan_duration = scan_start.elapsed();
    println!("Scan completed in {:?}", scan_duration);

    Ok(())
}
