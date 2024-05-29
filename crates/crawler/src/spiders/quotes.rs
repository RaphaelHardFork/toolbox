use super::Spider;
use crate::Result;
use async_trait::async_trait;
use fantoccini::{Client, ClientBuilder};
use select::document::Document;
use select::predicate::{Class, Name, Predicate};
use serde_json::json;
use tokio::sync::Mutex;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct QuotesItem {
    quote: String,
    author: String,
}

pub struct QuotesSpider {
    webdriver_client: Mutex<Client>,
}

impl QuotesSpider {
    pub async fn new() -> Self {
        let mut caps = serde_json::Map::new();
        let chrome_opts = json!({"args": ["--headless", "--disable-gpu"]});
        caps.insert("goog:chromeOptions".to_string(), chrome_opts);
        let webdriver_client = ClientBuilder::rustls()
            .capabilities(caps)
            .connect("http://localhost:4444")
            .await
            .expect(
                "spider/quotes: Building WebDriver client\nMake sure a webdriver server running",
            );

        Self {
            webdriver_client: Mutex::new(webdriver_client),
        }
    }
}

#[async_trait]
impl Spider for QuotesSpider {
    type Item = QuotesItem;

    fn name(&self) -> String {
        "quotes".to_string()
    }

    fn start_urls(&self) -> Vec<String> {
        vec!["https://quotes.toscrape.com/js".to_string()]
    }

    #[instrument(name = "scraping", level = "info", fields(url = url), skip_all)]
    async fn scrape(&self, url: String) -> Result<(Vec<Self::Item>, Vec<String>)> {
        let html = {
            let webdriver = self.webdriver_client.lock().await;
            webdriver.goto(&url).await?;
            webdriver.source().await?
        };
        let document = Document::from(html.as_str());

        let items: Vec<QuotesItem> = document
            .find(Class("quote"))
            .filter_map(|quote| quote.find(Name("span")).next())
            .filter_map(|span| {
                let quote_str = span.text().trim().to_string();
                if let Some(author) = span.find(Class("author")).next() {
                    Some(QuotesItem {
                        quote: quote_str,
                        author: author.text().trim().to_string(),
                    })
                } else {
                    None
                }
            })
            .collect();

        let next_pages_link = document
            .find(
                Class("pager")
                    .descendant(Class("next"))
                    .descendant(Name("a")),
            )
            .filter_map(|n| n.attr("href"))
            .map(normalize_url)
            .collect::<Vec<String>>();

        Ok((items, next_pages_link))
    }

    #[instrument(name = "processing", level = "info", skip_all)]
    async fn process(&self, item: Self::Item) -> Result<()> {
        info!("{} by {}", item.quote, item.author);

        Ok(())
    }
}

fn normalize_url(url: &str) -> String {
    if url.trim().starts_with("/") {
        format!("https://quotes.tocrape.com{}", url)
    } else {
        url.to_string()
    }
}
