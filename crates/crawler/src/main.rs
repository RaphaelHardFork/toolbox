mod crawler;
mod error;
mod spiders;

use std::{sync::Arc, time::Duration};

use crawler::Crawler;
pub use error::{Error, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let crawler = Crawler::new(Duration::from_millis(200), 2, 500);
    let spider = Arc::new(spiders::cve_details::CveDetailsSpider::new());
    crawler.run(spider).await;

    Ok(())
}
