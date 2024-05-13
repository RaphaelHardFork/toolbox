use crate::model::{CrtShEntry, Subdomain};
use crate::{Result, RESOLVE_DNS_TIMEOUT_MS};
use futures::{stream, StreamExt};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use reqwest::Client;
use std::{collections::HashSet, time::Duration};
use tracing::{debug, info};

type DnsResolver = TokioAsyncResolver;

pub async fn enumerate(http_client: &Client, target: &str) -> Result<Vec<Subdomain>> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", target);

    info!("{:12} - {:?}", "HTTP REQUEST", url);
    let entries: Vec<CrtShEntry> = http_client.get(url).send().await?.json().await?;

    // cleaning entries
    let mut subdomains: HashSet<String> = entries
        .into_iter()
        .flat_map(|entry| {
            entry
                .name_value
                .split('\n')
                .map(|subdomain| subdomain.trim().to_string())
                .collect::<Vec<String>>()
        })
        .filter(|subdomain| subdomain != target)
        .filter(|subdomain| !subdomain.contains('*'))
        .inspect(|subdomain| debug!("{:12} - {:?}", "COLLECTED", subdomain))
        .collect();
    subdomains.insert(target.to_string());

    info!("{:12} - {:?}", "TO RESOLVE", subdomains.len());

    // create a DNS resolver
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(RESOLVE_DNS_TIMEOUT_MS);
    let dns_resolver = DnsResolver::tokio(ResolverConfig::default(), opts);

    // using stream to resolve dns
    let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
        .map(|domain| Subdomain {
            domain,
            open_ports: Vec::new(),
        })
        .filter_map(|subdomain| {
            let dns_resolver = dns_resolver.clone();
            async move {
                if resolves(&dns_resolver, &subdomain).await {
                    debug!("{:12} - {:?}", "RESOLVED", subdomain.domain);
                    Some(subdomain)
                } else {
                    debug!("{:12} - {:?}", "NOT RESOLVED", subdomain.domain);
                    None
                }
            }
        })
        .collect()
        .await;

    info!("{:12} - {:?}", "RESOLVED", subdomains.len());

    Ok(subdomains)
}

pub async fn resolves(dns_resolver: &DnsResolver, domain: &Subdomain) -> bool {
    dns_resolver.lookup_ip(domain.domain.as_str()).await.is_ok()
}
