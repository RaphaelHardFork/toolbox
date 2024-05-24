use super::Spider;
use crate::{Error, Result};
use async_trait::async_trait;
use reqwest::Client;
use select::document::Document;
use select::predicate::{self, Attr, Class, Element, Name, Predicate, Text};
use std::time::Duration;
use tracing::{debug, error, info, instrument, trace};

#[derive(Debug, Clone, Default)]
pub struct Cve {
    // info
    name: String,
    url: String,
    publish_date: String,
    update_date: String,
    // scores
    base_score: String,
    exploitability_score: String,
    impact_score: String,
    severity: String,
    score_source: String,
    // CVSS vector
    attack_vector: String,
    complexity: String,
    privileges: String,
    interaction: String,
    scope: String,
    confidentiality: String,
    integrity: String,
    availability: String,
    // references
    references: Vec<String>,
}

pub struct CveDetailsSpider {
    http_client: Client,
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

    #[instrument(name = "http_req", level = "info", skip_all)]
    async fn http_request(&self, url: &str) -> Result<String> {
        info!("Sending request");
        match self.http_client.get(url).send().await {
            Ok(res) => {
                info!("Receive with status: {}", res.status());
                debug!("Response: {:?}", res);
                let text_res = res.text().await?;
                trace!("HTML response: {:?}", text_res);
                Ok(text_res)
            }
            Err(err) => {
                error!("Reason: {}", err);
                Err(Error::Reqwest(err))
            }
        }
    }

    #[instrument(name = "pages", level = "info", skip_all)]
    fn scrape_pages(&self, document: &Document) -> Vec<String> {
        let mut cve_links: Vec<String> = document
            .find(Attr("id", "searchresults").descendant(Attr("data-tsvfield", "cveinfo")))
            .filter_map(|n| {
                n.find(Attr("data-tsvfield", "cveId").descendant(Name("a")))
                    .next()
                    .unwrap() // FIXME remove unwrap
                    .attr("href")
            })
            .map(normalize_url)
            .collect();
        info!("{} CVE links", cve_links.len());
        debug!("{:?}", cve_links);

        // find links to others pages
        let next_pages_links: Vec<String> = document
            .find(Attr("id", "pagingb").descendant(Name("a")))
            .filter_map(|n| n.attr("href"))
            .map(normalize_url)
            .collect();
        info!("{} pages links", next_pages_links.len());
        debug!("{:?}", next_pages_links);

        cve_links.extend(next_pages_links);
        cve_links
    }

    #[instrument(name = "cve", level = "info", skip_all)]
    fn scrape_cve(&self, url: &str, document: &Document) -> Vec<Cve> {
        let mut cve = Cve::default();

        cve.url = url.to_string();

        // extract name
        if let Some(title) = document
            .find(Attr("id", "cvedetails-title-div").descendant(Name("a")))
            .next()
        {
            cve.name = title.text()
        } else {
            info!("Not a CVE page");
            return vec![];
        }

        // extract dates
        document
            .find(Name("main").descendant(Name("span")))
            .filter_map(|span| span.parent())
            .for_each(|div| {
                if div.text().contains("Published") {
                    cve.publish_date = div.text().replace("Published", "").trim().to_string();
                } else if div.text().contains("Updated") {
                    cve.update_date = div.text().replace("Updated", "").trim().to_string()
                }
            });

        // extract CVSS details
        document
            .find(Attr("id", "cvss_details_row_1").descendant(Name("div")))
            .filter(|n| !n.text().contains('\t'))
            .for_each(|div| match div.text() {
                v if v.contains("Attack Vector") => {
                    cve.attack_vector = v.replace("Attack Vector:", "").trim().to_string()
                }
                v if v.contains("Attack Complexity") => {
                    cve.complexity = v.replace("Attack Complexity:", "").trim().to_string()
                }
                v if v.contains("Privileges Required") => {
                    cve.privileges = v.replace("Privileges Required:", "").trim().to_string()
                }
                v if v.contains("User Interaction") => {
                    cve.interaction = v.replace("User Interaction:", "").trim().to_string()
                }
                v if v.contains("Scope") => cve.scope = v.replace("Scope:", "").trim().to_string(),
                v if v.contains("Confidentiality") => {
                    cve.confidentiality = v.replace("Confidentiality:", "").trim().to_string()
                }
                v if v.contains("Integrity") => {
                    cve.integrity = v.replace("Integrity:", "").trim().to_string()
                }
                v if v.contains("Availability") => {
                    cve.availability = v.replace("Availability:", "").trim().to_string()
                }
                _ => {}
            });

        // extract scores, severity & source
        document
            .find(Name("tbody").descendant(Name("td")))
            .enumerate()
            .for_each(|(i, td)| {
                let td = td.text().replace("\n", "").replace("\t", "");
                match i {
                    i if i == 0 => cve.base_score = td,
                    i if i == 1 => cve.severity = td,
                    i if i == 3 => cve.exploitability_score = td,
                    i if i == 4 => cve.impact_score = td,
                    i if i == 5 => cve.score_source = td,
                    _ => {}
                }
            });

        // extract references
        let references: Vec<String> = document
            .find(Class("cved-card").descendant(Name("li").descendant(Name("a"))))
            .filter_map(|a| {
                if let Some(ref_link) = a.attr("title") {
                    if ref_link.contains("reference") {
                        return a.attr("href");
                    }
                }
                return None;
            })
            .map(String::from)
            .collect();
        cve.references = references;

        info!("{} created", cve.name);
        debug!("{:?}", cve);

        vec![cve]
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

    #[instrument(name = "scraping", level = "info", fields(url = url), skip_all)]
    async fn scrape(&self, url: String) -> Result<(Vec<Self::Item>, Vec<String>)> {
        let res = self.http_request(&url).await?;
        let document = Document::from(res.as_str());

        let links = self.scrape_pages(&document);
        let cves = self.scrape_cve(&url, &document);

        Ok((cves, links))
    }

    #[instrument(name = "processing", level = "info", skip_all)]
    async fn process(&self, item: Self::Item) -> Result<()> {
        info!("{:?}", item);
        Ok(())
    }
}

// region:        --- Utils

fn normalize_url(url: &str) -> String {
    match url.trim() {
        url_str if url.starts_with("//www.cvedetails.com") => format!("https:{}", url_str),
        url_str if url.starts_with("/") => format!("https://www.cvedetails.com{}", url_str),
        _ => url.to_string(),
    }
}

// endregion:     --- Utils
