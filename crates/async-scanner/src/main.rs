use std::time::{Duration, Instant};

pub use error::Result;
use reqwest::Client;

mod error;
mod model;
mod subdomains;

const HTTP_REQUEST_TIMEOUT_MS: u64 = 10000;
pub const RESOLVE_DNS_TIMEOUT_MS: u64 = 4000;

#[tokio::main]
async fn main() -> Result<()> {
    let http_timeout = Duration::from_millis(HTTP_REQUEST_TIMEOUT_MS);
    let http_client = Client::builder().timeout(http_timeout).build()?;

    let ports_concurrency = 200;
    let subdomains_concurrency = 100;
    let scan_start = Instant::now();

    // scan result => subdomains::enumerates

    Ok(())
}
