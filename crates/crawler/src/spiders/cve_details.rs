use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use select::document::Document;
use select::predicate::{Attr, Class, Name, Predicate};

use crate::Result;

use super::Spider;

pub struct CveDetailsSpider {
    http_client: Client,
}

#[derive(Debug, Clone)]
pub struct Cve {
    name: String,
    url: String,
    cwe_id: Option<String>,
    cwe_url: Option<String>,
    vulnerability_type: String,
    publish_date: String,
    update_date: String,
    score: f32,
    access: String,
    complexity: String,
    authentication: String,
    confidentiality: String,
    integrity: String,
    availability: String,
}

impl CveDetailsSpider {
    pub fn new() -> Self {
        let http_timeout = Duration::from_millis(6000);
        let http_client = Client::builder()
            .timeout(http_timeout)
            .build()
            .expect("spider/cvedetails: Building HTTP client");

        Self { http_client }
    }
}

impl CveDetailsSpider {
    fn normalize_url(&self, url: &str) -> String {
        match url.trim() {
            url_str if url.starts_with("//www.cvedetails.com") => format!("https:{}", url_str),
            url_str if url.starts_with("/") => format!("https://www.cvedetails.com{}", url_str),
            _ => url.to_string(),
        }
    }
}

fn normalize_url(url: &str) -> String {
    match url.trim() {
        url_str if url.starts_with("//www.cvedetails.com") => format!("https:{}", url_str),
        url_str if url.starts_with("/") => format!("https://www.cvedetails.com{}", url_str),
        _ => url.to_string(),
    }
}

#[async_trait]
impl Spider for CveDetailsSpider {
    type Item = Cve;

    fn name(&self) -> String {
        "cve details".to_string()
    }

    fn start_urls(&self) -> Vec<String> {
        vec!["https://www.cvedetails.com/vulnerability-list/vulnerabilities.html".to_string()]
    }

    async fn scrape(&self, url: String) -> Result<(Vec<Self::Item>, Vec<String>)> {
        println!(">> visiting: {:?}", url);

        let res = self.http_client.get(url).send().await?.text().await?;
        let mut items = Vec::new();

        let document = Document::from(res.as_str());

        let rows = document.find(Attr("id", "vulnslisttable").descendant(Class("srrowns")));
        // let rows = document.select(Attr("id", "vulnslisttable").descendant(Class("srrowns")));
        for row in rows {
            let mut columns = row.find(Name("td"));

            let _ = columns.next();
            let cve_link = columns.next().unwrap().find(Name("a")).next().unwrap();
            let cve_name = cve_link.text().trim().to_string();
            let cve_url = self.normalize_url(cve_link.attr("href").unwrap());

            let cwe = columns
                .next()
                .unwrap()
                .find(Name("a"))
                .next()
                .map(|cvec_link| {
                    (
                        cvec_link.text().trim().to_string(),
                        self.normalize_url(cvec_link.attr("href").unwrap()),
                    )
                });

            let _ = columns.next(); // # of exploits column

            let vulnerability_type = columns.next().unwrap().text().trim().to_string();
            let publish_date = columns.next().unwrap().text().trim().to_string();
            let update_date = columns.next().unwrap().text().trim().to_string();
            let score: f32 = columns
                .next()
                .unwrap()
                .text()
                .trim()
                .to_string()
                .parse()
                .unwrap();

            let _ = columns.next(); // Gained Access Level  column

            let access = columns.next().unwrap().text().trim().to_string();
            let complexity = columns.next().unwrap().text().trim().to_string();
            let authentication = columns.next().unwrap().text().trim().to_string();
            let confidentiality = columns.next().unwrap().text().trim().to_string();
            let integrity = columns.next().unwrap().text().trim().to_string();
            let availability = columns.next().unwrap().text().trim().to_string();

            let cve = Cve {
                name: cve_name,
                url: cve_url,
                cwe_id: cwe.as_ref().map(|cwe| cwe.0.clone()),
                cwe_url: cwe.as_ref().map(|cwe| cwe.1.clone()),
                vulnerability_type,
                publish_date,
                update_date,
                score,
                access,
                complexity,
                authentication,
                confidentiality,
                integrity,
                availability,
            };
            items.push(cve);
        }

        let next_pages_links: Vec<String> = document
            .find(Attr("id", "pagingb").descendant(Name("a")))
            .filter_map(|n| n.attr("href"))
            .map(normalize_url)
            .collect();

        Ok((items, next_pages_links))
    }

    async fn process(&self, item: Self::Item) -> Result<()> {
        println!(">> processing {:?}", item);
        Ok(())
    }
}
