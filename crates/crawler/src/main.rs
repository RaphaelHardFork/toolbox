mod crawler;
mod error;
mod spiders;
mod utils;

pub use error::{Error, Result};

use crawler::Crawler;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use utils::{ensure_dir, log::init_tracing_subscriber};

#[tokio::main]
async fn main() -> Result<()> {
    // create filename
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let filename = format!("{}", timestamp);

    // create output dir
    let output_dir = format!("output/crawler/cve_details"); // need to change
    ensure_dir(output_dir.as_ref())?;

    init_tracing_subscriber(false, output_dir.as_ref(), &filename);

    // --- start here ---
    let crawler = Crawler::new(Duration::from_millis(200), 2, 500);
    // let spider = Arc::new(spiders::cve_details::CveDetailsSpider::new());
    // let spider = Arc::new(spiders::github::GitHubSpider::new());
    let spider = Arc::new(spiders::quotes::QuotesSpider::new().await);
    crawler.run(spider).await;

    Ok(())
}
